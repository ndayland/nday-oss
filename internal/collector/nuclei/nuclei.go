// Package nuclei is the ProjectDiscovery nuclei-templates CVE index
// collector (port of src/nday/collectors/nuclei.py) -> poc_published.
//
// Feed: cves.json, JSON Lines of {"ID", "Info": {...}, "file_path"}.
// Lines are split with Python's str.splitlines() semantics (pystr) and each
// parsed with pyjson. source_key = ID (stripped); one event (the template's
// CVE), dedupe_key = ID, url = template on GitHub, occurred_at = nil (the
// index has no timestamps).
package nuclei

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
)

// Name is the source name.
const Name = "nuclei"

// URLs, identical to Python.
const (
	FeedURL      = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
	sourceURLFmt = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
)

// Collector is the nuclei collector.
type Collector struct{ *feed.Base }

// New builds the collector.
func New(o feed.Options) (*Collector, error) {
	c := &Collector{}
	b, err := feed.NewBase(Name, FeedURL, c, o)
	if err != nil {
		return nil, err
	}
	c.Base = b
	return c, nil
}

// Factory is the registry entry.
func Factory(d collector.Deps) (collector.Collector, error) {
	return New(feed.Options{Transport: d.Transport})
}

// ParseItems is NucleiCollector.parse_items.
func (c *Collector) ParseItems(body []byte) ([]feed.Item, *pyjson.Object, error) {
	if !utf8.Valid(body) { // body.decode("utf-8") (strict; a BOM is kept)
		return nil, nil, errors.New("nuclei: 'utf-8' codec can't decode the body (invalid UTF-8)")
	}
	seen := map[string]bool{}
	var items []feed.Item
	lines, malformed := 0, 0
	for i, line := range pystr.Splitlines(string(body)) {
		if pystr.Strip(line) == "" {
			continue
		}
		lines++
		// json.loads(str): unlike json.loads(bytes) a leading U+FEFF is an
		// error ("Unexpected UTF-8 BOM"); pyjson.Decode would skip it.
		if strings.HasPrefix(line, "\uFEFF") {
			return nil, nil, fmt.Errorf("nuclei: line %d: Unexpected UTF-8 BOM (decode using utf-8-sig)", i+1)
		}
		obj, err := pyjson.DecodeString(line) // a broken line means a broken feed
		if err != nil {
			return nil, nil, fmt.Errorf("nuclei: line %d: %w", i+1, err)
		}
		var key *string
		if o, ok := obj.(*pyjson.Object); ok {
			key = collector.Text(o.Get("ID"))
		}
		if key == nil || seen[*key] {
			malformed++
			c.Logger.Warn("nuclei: line without ID or duplicate ID skipped: " + trunc(pyjson.Repr(obj), 200))
			continue
		}
		seen[*key] = true
		items = append(items, feed.Item{Key: *key, Payload: obj})
	}
	extra := pyjson.NewObject()
	extra.Set("lines", pyjson.IntOf(int64(lines)))
	extra.Set("malformed_skipped", pyjson.IntOf(int64(malformed)))
	return items, extra, nil
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// cveToken is Python's _cve_token.
func cveToken(p *pyjson.Object) []any {
	if tid, ok := p.Get("ID").(string); ok && feed.HasCVEPrefix(tid) {
		return []any{tid}
	}
	return nil
}

// CVETokens implements feed.Parser.
func (c *Collector) CVETokens(payload any) []any {
	p, _ := payload.(*pyjson.Object)
	if p == nil {
		return nil
	}
	return cveToken(p)
}

// Normalize is NucleiCollector.normalize.
func (c *Collector) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	p, ok := rec.Payload.(*pyjson.Object)
	if !ok {
		return nil, collector.NormalizeErrorf("payload is not an object")
	}
	tp := collector.Text(p.Get("ID"))
	if tp == nil || *tp != rec.SourceKey {
		return nil, collector.NormalizeErrorf("ID %s != source_key %s", pyjson.Repr(p.Get("ID")), rec.SourceKey)
	}
	tid := *tp
	info, isObj := p.Get("Info").(*pyjson.Object)
	path := collector.Text(p.Get("file_path"))
	if !isObj || path == nil {
		return nil, collector.NormalizeErrorf("%s: missing Info or file_path", tid)
	}
	cves, _, err := feed.RequireCVEs(tid, cveToken(p))
	if err != nil {
		return nil, err
	}
	if len(cves) != 1 { // (cve,), _ = ...: unreachable with one token
		return nil, fmt.Errorf("too many values to unpack (expected 1)")
	}
	url := sourceURLFmt + *path
	var cvss any
	if cls, ok := info.Get("Classification").(*pyjson.Object); ok {
		cvss = cls.Get("CVSSScore")
	}
	detail := map[string]any{
		"kind":          "detection_template",
		"confidence":    "curated",
		"title":         feed.Text(info.Get("Name")),
		"url":           url,
		"template_id":   tid,
		"severity":      feed.Text(info.Get("Severity")),
		"cvss_score":    cvss,
		"template_path": *path,
	}
	return &model.Normalized{Events: []model.Event{{CVEID: cves[0], Type: model.EventPocPublished, Source: Name,
		OccurredAt: nil, URL: model.Ptr(url), Detail: detail, DedupeKey: tid}}}, nil
}

var _ collector.Collector = (*Collector)(nil)
