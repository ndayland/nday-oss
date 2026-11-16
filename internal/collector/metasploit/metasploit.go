// Package metasploit is the Metasploit Framework module metadata collector
// (port of src/nday/collectors/metasploit.py) -> poc_published.
//
// Feed: db/modules_metadata_base.json, one JSON object mapping
// "<type>_<ref_name>" -> module. Scope: module types "exploit" and
// "auxiliary"; source_key = fullname (stripped); payload = the module object
// verbatim (parsed with pyjson). One event per valid CVE reference,
// dedupe_key = fullname, url = module source on GitHub, occurred_at = nil
// (disclosure_date is the vulnerability's, mod_time the file's last change).
package metasploit

import (
	"errors"
	"fmt"
	"strings"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

// Name is the source name.
const Name = "metasploit"

// URLs, identical to Python.
const (
	FeedURL      = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
	sourceURLFmt = "https://github.com/rapid7/metasploit-framework/blob/master/"
)

// rankNames is Python's RANK_NAMES (Msf::*Ranking).
var rankNames = map[pyjson.Int]string{"0": "manual", "100": "low", "200": "average", "300": "normal",
	"400": "good", "500": "great", "600": "excellent"}

// Collector is the Metasploit collector.
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

func inScope(v any) bool {
	s, ok := v.(string)
	return ok && (s == "exploit" || s == "auxiliary")
}

// ParseItems is MetasploitCollector.parse_items.
func (c *Collector) ParseItems(body []byte) ([]feed.Item, *pyjson.Object, error) {
	data, err := pyjson.Decode(body)
	if err != nil {
		return nil, nil, fmt.Errorf("metasploit metadata: %w", err)
	}
	top, ok := data.(*pyjson.Object)
	if !ok {
		return nil, nil, errors.New("metasploit metadata: expected a JSON object")
	}
	seen := map[string]bool{}
	var items []feed.Item
	outOfScope, malformed := 0, 0
	for _, k := range top.Keys() {
		mod, ok := top.Get(k).(*pyjson.Object)
		if !ok || collector.Text(mod.Get("fullname")) == nil {
			malformed++
			c.Logger.Warn("metasploit: module without fullname skipped: " + trunc(pyjson.Repr(top.Get(k)), 200))
			continue
		}
		if !inScope(mod.Get("type")) {
			outOfScope++
			continue
		}
		key := *collector.Text(mod.Get("fullname"))
		if seen[key] {
			malformed++
			c.Logger.Warn(fmt.Sprintf("metasploit: duplicate fullname %s skipped", key))
			continue
		}
		seen[key] = true
		items = append(items, feed.Item{Key: key, Payload: mod})
	}
	extra := pyjson.NewObject()
	extra.Set("modules", pyjson.IntOf(int64(top.Len())))
	extra.Set("out_of_scope_types", pyjson.IntOf(int64(outOfScope)))
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

// cveRefs is Python's _cve_refs.
func cveRefs(p *pyjson.Object) []any {
	refs, ok := p.Get("references").([]any)
	if !ok {
		return nil
	}
	var out []any
	for _, r := range refs {
		if s, ok := r.(string); ok && feed.HasCVEPrefix(s) {
			out = append(out, s)
		}
	}
	return out
}

// CVETokens implements feed.Parser.
func (c *Collector) CVETokens(payload any) []any {
	p, _ := payload.(*pyjson.Object)
	if p == nil {
		return nil
	}
	return cveRefs(p)
}

// rankName is `RANK_NAMES.get(rank) if isinstance(rank, int) else None`;
// bool is an int in Python (False == 0 -> "manual", True == 1 -> None).
func rankName(rank any) any {
	switch r := rank.(type) {
	case pyjson.Int:
		if n, ok := rankNames[r]; ok {
			return n
		}
	case bool:
		if !r {
			return rankNames["0"]
		}
	}
	return nil
}

// Normalize is MetasploitCollector.normalize.
func (c *Collector) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	p, ok := rec.Payload.(*pyjson.Object)
	if !ok {
		return nil, collector.NormalizeErrorf("payload is not an object")
	}
	fn := collector.Text(p.Get("fullname"))
	if fn == nil || *fn != rec.SourceKey {
		return nil, collector.NormalizeErrorf("fullname %s != source_key %s", pyjson.Repr(p.Get("fullname")), rec.SourceKey)
	}
	fullname := *fn
	if !inScope(p.Get("type")) {
		return nil, collector.NormalizeErrorf("%s: out-of-scope type %s", fullname, pyjson.Repr(p.Get("type")))
	}
	if _, ok := p.Get("references").([]any); !ok {
		return nil, collector.NormalizeErrorf("%s: references is not a list", fullname)
	}
	cves, dropped, err := feed.RequireCVEs(fullname, cveRefs(p))
	if err != nil {
		return nil, err
	}
	var url *string
	path := feed.Text(p.Get("path"))
	if ps, ok := path.(string); ok {
		url = model.Ptr(sourceURLFmt + strings.TrimLeft(ps, "/"))
	}
	var urlVal any
	if url != nil {
		urlVal = *url
	}
	rank := p.Get("rank")
	detail := map[string]any{
		"kind":                 "msf_module",
		"confidence":           "curated",
		"title":                feed.Text(p.Get("name")),
		"url":                  urlVal,
		"fullname":             fullname,
		"module_type":          p.Get("type"),
		"rank":                 rank,
		"rank_name":            rankName(rank),
		"vuln_disclosure_date": feed.Text(p.Get("disclosure_date")),
		"module_last_modified": feed.Text(p.Get("mod_time")),
		"path":                 path,
		"check":                p.Get("check"),
		"cve_ids":              feed.Strings(cves),
	}
	if len(dropped) > 0 {
		detail["dropped_cve_tokens"] = feed.Strings(dropped)
	}
	out := &model.Normalized{}
	for _, cve := range cves {
		out.Events = append(out.Events, model.Event{CVEID: cve, Type: model.EventPocPublished, Source: Name,
			OccurredAt: nil, URL: url, Detail: detail, DedupeKey: fullname})
	}
	return out, nil
}

var _ collector.Collector = (*Collector)(nil)
