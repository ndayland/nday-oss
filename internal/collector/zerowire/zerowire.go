// Package zerowire collects Cloudflare Radar's Zero Wire advisories (written
// by Cloudforce One about major vulnerabilities) from their RSS feed and
// attaches each one, as an analysis_published event, to every CVE and GHSA
// id it names. Go only. See docs/zerowire.md.
//
// Fetch: one GET of FeedURL per run, conditional on the ETag /
// Last-Modified we kept (Cloudflare doesn't send either today, so in
// practice it's a plain GET of ~130 KB once an hour). Every request,
// redirects included, must be https://radar.cloudflare.com/...: anything
// else is refused before it goes out. Body cap MaxBytes, 3 tries.
//
// Raw record: one per advisory, source_key = the slug from the item's
// <link> (not the guid: its "@date" suffix changes when the advisory is
// updated). Payload = slug, title (cleaned), link, pub_date (YYYY-MM-DD),
// cve_ids, ghsa_ids, categories. The description and the article body are
// read for ids only and never stored. An advisory naming no id still gets a
// raw record but gives no event.
//
// Normalize: one analysis_published event per id (CVEs first, then GHSAs,
// at most MaxIDsPerArticle), occurred_at = 00:00 UTC of pub_date with
// detail.precision "day", url = the advisory, dedupe_key = the slug, detail
// = title, precision. So an updated advisory updates its events in place
// (same cve, type, source, slug), and an id it gains adds one event. An id
// it drops keeps its old event: the pipeline never deletes events.
package zerowire

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

// Name is the source name.
const Name = "zerowire"

// Constants.
const (
	Host           = "radar.cloudflare.com"
	FeedURL        = "https://" + Host + "/zero-wire/feed"
	ArticleBaseURL = "https://" + Host + "/zero-wire/"

	MaxBytes         = 4 << 20
	MaxAttempts      = 3
	RequestTimeout   = 2 * time.Minute // whole request, per attempt
	MaxIDsPerArticle = 50
	MinCVEYear       = 1999
)

// Options configures New.
type Options struct {
	Transport http.RoundTripper // nil = the real network
	Sleep     func(ctx context.Context, d time.Duration) error
	Logger    *slog.Logger
}

// Collector implements collector.Collector.
type Collector struct {
	http   *httpc.Client
	logger *slog.Logger
}

// New builds the collector.
func New(o Options) *Collector {
	c := &Collector{logger: o.Logger}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	base := o.Transport
	if base == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.ResponseHeaderTimeout = httpc.DefaultReadTimeout
		base = t
	}
	c.http = httpc.New(httpc.Options{Transport: pinned{base}, MaxAttempts: MaxAttempts, MaxBytes: MaxBytes,
		TotalTimeout: RequestTimeout, Sleep: o.Sleep, Logger: c.logger})
	return c
}

// Factory is the registry entry.
func Factory(d collector.Deps) (collector.Collector, error) {
	return New(Options{Transport: d.Transport}), nil
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return Name }

// pinned refuses any request that isn't https to Host, so a redirect can't
// take us anywhere else (http.Client sends every hop through RoundTrip).
type pinned struct{ base http.RoundTripper }

func (p pinned) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != Host {
		return nil, fmt.Errorf("zerowire: refusing request to %s://%s (only https://%s)", r.URL.Scheme, r.URL.Host, Host)
	}
	return p.base.RoundTrip(r)
}

func headerOrNil(h http.Header, name string) any {
	if v := h.Get(name); v != "" {
		return v
	}
	return nil
}

func cursorString(cur any, key string) string {
	o, ok := cur.(*pyjson.Object)
	if !ok {
		return ""
	}
	s, _ := o.Get(key).(string)
	return s
}

// Fetch implements collector.Collector.
func (c *Collector) Fetch(ctx context.Context, state model.CollectorState) (*model.FetchResult, error) {
	etag, lm := cursorString(state.Cursor, "etag"), cursorString(state.Cursor, "last_modified")
	hdr := http.Header{}
	if etag != "" {
		hdr.Set("If-None-Match", etag)
	}
	if lm != "" {
		hdr.Set("If-Modified-Since", lm)
	}
	resp, err := c.http.Get(ctx, FeedURL, httpc.GetOptions{Header: hdr, Accept: func(s int) bool {
		return s == http.StatusNotModified || (s >= 200 && s < 300)
	}})
	if err != nil {
		return nil, fmt.Errorf("zerowire: %w", err)
	}
	// pinned already makes sure of this; belt and braces
	if u, err := url.Parse(resp.URL); err != nil || u.Scheme != "https" || u.Host != Host {
		return nil, fmt.Errorf("zerowire: answer came from %s", resp.URL)
	}
	lastRun := pyjson.NewObject()
	lastRun.Set("status", pyjson.IntOf(int64(resp.Status)))
	out := pyjson.NewObject()
	if resp.Status == http.StatusNotModified {
		out.Set("etag", nilIfEmpty(etag))
		out.Set("last_modified", nilIfEmpty(lm))
		out.Set("last_run", lastRun)
		return &model.FetchResult{Cursor: out}, nil
	}
	arts, st, err := ParseFeed(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("zerowire: %w", err)
	}
	var records []model.RawRecord
	noIDs := 0
	for _, a := range arts {
		if len(a.CVEs)+len(a.GHSAs) == 0 {
			noIDs++
		}
		records = append(records, Record(a))
	}
	if st.BadLink > 0 {
		c.logger.Warn("zerowire: items with a link that isn't a Zero Wire advisory were skipped", "count", st.BadLink)
	}
	lastRun.Set("items", pyjson.IntOf(int64(st.Items)))
	lastRun.Set("records", pyjson.IntOf(int64(len(records))))
	lastRun.Set("without_ids", pyjson.IntOf(int64(noIDs)))
	lastRun.Set("skipped_bad_link", pyjson.IntOf(int64(st.BadLink)))
	lastRun.Set("skipped_duplicate", pyjson.IntOf(int64(st.Duplicate)))
	out.Set("etag", headerOrNil(resp.Header, "ETag"))
	out.Set("last_modified", headerOrNil(resp.Header, "Last-Modified"))
	out.Set("last_run", lastRun)
	return &model.FetchResult{Records: records, Cursor: out}, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func strList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// Record is the raw record of one advisory.
func Record(a Article) model.RawRecord {
	p := pyjson.NewObject()
	p.Set("slug", a.Slug)
	p.Set("title", a.Title)
	p.Set("link", a.Link)
	if a.PubDate != "" {
		p.Set("pub_date", a.PubDate)
	} else {
		p.Set("pub_date", nil)
	}
	p.Set("cve_ids", strList(a.CVEs))
	p.Set("ghsa_ids", strList(a.GHSAs))
	p.Set("categories", strList(a.Categories))
	return model.RawRecord{Source: Name, SourceKey: a.Slug, Payload: p}
}

// plausible drops CVE ids whose year can't be right for an advisory of that
// date (before 1999, or more than a year after it). GHSA ids pass.
func plausible(id string, date *time.Time) bool {
	if !strings.HasPrefix(id, "CVE-") {
		return model.IsGHSAID(id)
	}
	if !model.IsValidCVEID(id) {
		return false
	}
	y, err := strconv.Atoi(id[4:8])
	if err != nil || y < MinCVEYear {
		return false
	}
	return date == nil || y <= date.Year()+1
}

func idList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, e := range l {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Normalize implements collector.Collector. Pure.
func (c *Collector) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	p, ok := rec.Payload.(*pyjson.Object)
	if !ok {
		return nil, collector.NormalizeErrorf("payload is not an object")
	}
	slug, _ := p.Get("slug").(string)
	if !ValidSlug(slug) || slug != rec.SourceKey {
		return nil, collector.NormalizeErrorf("bad slug: %s", pyjson.Repr(p.Get("slug")))
	}
	if link, _ := p.Get("link").(string); link != ArticleURL(slug) {
		return nil, collector.NormalizeErrorf("bad link: %s", pyjson.Repr(p.Get("link")))
	}
	var date *time.Time
	switch d := p.Get("pub_date").(type) {
	case nil:
	case string:
		t, err := time.Parse(time.DateOnly, d) // 00:00 UTC of that day
		if err != nil {
			return nil, collector.NormalizeErrorf("bad pub_date: %s", pyjson.Repr(d))
		}
		date = &t
	default:
		return nil, collector.NormalizeErrorf("bad pub_date: %s", pyjson.Repr(d))
	}
	var title any
	if s, _ := p.Get("title").(string); s != "" {
		title = s
	}

	seen := map[string]bool{}
	var ids []string
	for _, l := range [][]string{idList(p.Get("cve_ids")), idList(p.Get("ghsa_ids"))} {
		for _, id := range l {
			if seen[id] || !plausible(id, date) {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > MaxIDsPerArticle {
		ids = ids[:MaxIDsPerArticle]
	}
	n := &model.Normalized{}
	for _, id := range ids {
		detail := map[string]any{"title": title}
		if date != nil {
			detail["precision"] = "day"
		}
		u := ArticleURL(slug)
		n.Events = append(n.Events, model.Event{CVEID: id, Type: model.EventAnalysisPublished, Source: Name,
			OccurredAt: date, URL: &u, Detail: detail, DedupeKey: slug})
	}
	return n, nil
}
