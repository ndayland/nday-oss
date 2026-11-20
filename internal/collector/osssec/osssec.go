// Package osssec collects posts of the oss-security mailing list from the
// seclists.org archive and attaches each post, as an analysis_published
// event, to every CVE and GHSA id it names. Go only. See docs/osssec.md.
//
// Fetch: one GET of the current quarter's thread index
// (https://seclists.org/oss-sec/<year>/q<n>/), conditional on the ETag /
// Last-Modified we kept, then one GET per message number above the cursor,
// oldest first. Politeness: at least RequestGap between any two requests and
// at most MaxPerRun message pages per run. A failed request ends the run
// early: what was fetched is kept and the cursor stops at the last message
// we fully got (if nothing was fetched yet the run fails, so a stuck page
// shows up as an error instead of hiding behind "ok"). A message page that
// is gone (404) is skipped.
//
// The very first run (no cursor) takes only the newest MaxPerRun messages of
// the quarter; it does not crawl the archive. A backfill run
// (NDAY_OSSSEC_BACKFILL=1 in the environment of that one command) walks the
// whole current quarter from message 0 with a cap of BackfillMaxPerRun.
//
// Quarter rollover: the cursor names its quarter. When the clock is in a
// later quarter we first finish the cursor's quarter, then move to the next
// one (a new quarter's index is 404 until its first post; that's fine).
//
// Raw record: source_key "<year>/q<n>/<number>", payload = url, year,
// quarter, number, subject, author (display name only), date (UTC RFC 3339
// or null), is_reply, cve_ids, ghsa_ids, subject_ids. The message body is
// deliberately not stored, not even an excerpt: raw records are served by
// the API and the posts belong to their authors. Posts naming no id still
// get a raw record, so they are not fetched again, but give no events.
//
// Normalize: one analysis_published event per id (ids in the subject first,
// then the rest in order of appearance, at most MaxIDsPerPost), occurred_at =
// the post's Date header, url = the post, dedupe_key = source_key, detail =
// subject, author, is_reply, list. CVE ids with an implausible year are
// ignored. GHSA ids go through the pipeline's usual alias redirect.
package osssec

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

// Name is the source name.
const Name = "osssec"

// Constants.
const (
	// PublicBaseURL is the archive's address. Event and payload URLs always
	// use it, even when tests fetch from somewhere else.
	PublicBaseURL = "https://seclists.org/oss-sec/"
	ListName      = "oss-security"
	BackfillEnv   = "NDAY_OSSSEC_BACKFILL"

	MaxPerRun         = 40
	BackfillMaxPerRun = 1500
	RequestGap        = time.Second
	MaxIDsPerPost     = 50

	IndexMaxBytes = 8 << 20
	PageMaxBytes  = 2 << 20
	MaxAttempts   = 3
)

// Options configures New.
type Options struct {
	Transport http.RoundTripper
	BaseURL   string // "" = PublicBaseURL; must end in "/"
	Env       collector.Env
	Clock     func() time.Time
	Sleep     func(ctx context.Context, d time.Duration) error
	Logger    *slog.Logger
	MaxPerRun int // 0 = MaxPerRun (or BackfillMaxPerRun in backfill mode)
}

// Collector implements collector.Collector.
type Collector struct {
	base     string
	backfill bool
	maxRun   int
	clock    func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
	logger   *slog.Logger
	index    *httpc.Client
	pages    *httpc.Client
	requests int
}

// New builds the collector.
func New(o Options) (*Collector, error) {
	c := &Collector{base: o.BaseURL, clock: o.Clock, sleep: o.Sleep, logger: o.Logger, maxRun: o.MaxPerRun}
	if c.base == "" {
		c.base = PublicBaseURL
	}
	if !strings.HasSuffix(c.base, "/") {
		c.base += "/"
	}
	if o.Env != nil {
		if v, ok := o.Env(BackfillEnv); ok {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "", "0", "false", "no":
			case "1", "true", "yes":
				c.backfill = true
			default:
				return nil, fmt.Errorf("%s must be 1 or 0, got %q", BackfillEnv, v)
			}
		}
	}
	if c.maxRun <= 0 {
		c.maxRun = MaxPerRun
		if c.backfill {
			c.maxRun = BackfillMaxPerRun
		}
	}
	if c.clock == nil {
		c.clock = time.Now
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	if c.sleep == nil {
		c.sleep = sleepCtx
	}
	mk := func(max int64) *httpc.Client {
		return httpc.New(httpc.Options{Transport: o.Transport, MaxAttempts: MaxAttempts, MaxBytes: max,
			Sleep: c.sleep, Logger: c.logger})
	}
	c.index, c.pages = mk(IndexMaxBytes), mk(PageMaxBytes)
	return c, nil
}

// Factory is the registry entry.
func Factory(d collector.Deps) (collector.Collector, error) {
	return New(Options{Transport: d.Transport, Env: d.Env})
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return Name }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Quarter is one archive period, e.g. 2026/q4.
type Quarter struct{ Year, Q int }

func (q Quarter) String() string { return fmt.Sprintf("%d/q%d", q.Year, q.Q) }

// Before reports whether q is an earlier quarter than o.
func (q Quarter) Before(o Quarter) bool {
	return q.Year < o.Year || (q.Year == o.Year && q.Q < o.Q)
}

// Next is the following quarter.
func (q Quarter) Next() Quarter {
	if q.Q == 4 {
		return Quarter{q.Year + 1, 1}
	}
	return Quarter{q.Year, q.Q + 1}
}

// QuarterOf is the quarter t (taken in UTC) falls in.
func QuarterOf(t time.Time) Quarter {
	t = t.UTC()
	return Quarter{t.Year(), (int(t.Month())-1)/3 + 1}
}

var quarterRe = regexp.MustCompile(`^([0-9]{4})/q([1-4])$`)

// ParseQuarter reads "2026/q4".
func ParseQuarter(s string) (Quarter, bool) {
	m := quarterRe.FindStringSubmatch(s)
	if m == nil {
		return Quarter{}, false
	}
	y, _ := strconv.Atoi(m[1])
	q, _ := strconv.Atoi(m[2])
	return Quarter{y, q}, true
}

// MessageURL is the public address of one post.
func MessageURL(q Quarter, n int) string { return PublicBaseURL + q.String() + "/" + strconv.Itoa(n) }

// cursor is what we keep between runs. last is -1 when nothing of the
// quarter has been fetched yet. etag / lastModified belong to that quarter's
// index and are kept only when every message it listed was fetched (a
// 304 then really means "nothing new").
type cursor struct {
	quarter      Quarter
	last         int
	etag         any
	lastModified any
}

func parseCursor(v any) (*cursor, error) {
	if v == nil {
		return nil, nil
	}
	o, ok := v.(*pyjson.Object)
	if !ok {
		return nil, fmt.Errorf("osssec: cursor is not an object: %s", pyjson.Repr(v))
	}
	qs, _ := o.Get("quarter").(string)
	q, ok := ParseQuarter(qs)
	if !ok {
		return nil, fmt.Errorf("osssec: bad cursor quarter: %s", pyjson.Repr(o.Get("quarter")))
	}
	ln, ok := o.Get("last_number").(pyjson.Int)
	if !ok {
		return nil, fmt.Errorf("osssec: bad cursor last_number: %s", pyjson.Repr(o.Get("last_number")))
	}
	last, err := strconv.Atoi(string(ln))
	if err != nil || last < -1 {
		return nil, fmt.Errorf("osssec: bad cursor last_number: %s", ln)
	}
	c := &cursor{quarter: q, last: last}
	if s, ok := o.Get("etag").(string); ok && s != "" {
		c.etag = s
	}
	if s, ok := o.Get("last_modified").(string); ok && s != "" {
		c.lastModified = s
	}
	return c, nil
}

// wait keeps RequestGap between requests (none before the first).
func (c *Collector) wait(ctx context.Context) error {
	c.requests++
	if c.requests == 1 {
		return nil
	}
	return c.sleep(ctx, RequestGap)
}

func headerOrNil(h http.Header, name string) any {
	if v := h.Get(name); v != "" {
		return v
	}
	return nil
}

// quarterRun is the outcome of walking one quarter.
type quarterRun struct {
	last         int
	etag, lm     any
	complete     bool // every listed message above the cursor was handled
	indexStatus  int
	fetched      int
	missing      int
	err          error // the request or parse failure that stopped the walk
	records      []model.RawRecord
	newestOnlyOf int // first run: how many listed numbers we skipped
}

// Fetch implements collector.Collector.
func (c *Collector) Fetch(ctx context.Context, state model.CollectorState) (*model.FetchResult, error) {
	prev, err := parseCursor(state.Cursor)
	if err != nil {
		return nil, err
	}
	now := QuarterOf(c.clock())
	mode := "incremental"
	cur := cursor{quarter: now, last: -1}
	switch {
	case c.backfill:
		mode = "backfill"
	case prev == nil:
		mode = "first"
	default:
		cur = *prev
		if now.Before(cur.quarter) { // clock went backwards; stay where we were
			now = cur.quarter
		}
	}
	budget := c.maxRun
	lastRun := pyjson.NewObject()
	lastRun.Set("mode", mode)
	quarters := []any{}
	var records []model.RawRecord
	var stop error
	pages, missing := 0, 0
	for {
		r := c.walkQuarter(ctx, cur, &budget, mode == "first")
		records = append(records, r.records...)
		pages += r.fetched
		missing += r.missing
		qo := pyjson.NewObject()
		qo.Set("quarter", cur.quarter.String())
		qo.Set("index_status", pyjson.IntOf(int64(r.indexStatus)))
		qo.Set("fetched", pyjson.IntOf(int64(r.fetched)))
		if r.newestOnlyOf > 0 {
			qo.Set("skipped_older", pyjson.IntOf(int64(r.newestOnlyOf)))
		}
		quarters = append(quarters, qo)
		cur.last, cur.etag, cur.lastModified = r.last, r.etag, r.lm
		if r.err != nil {
			stop = r.err
			break
		}
		if !r.complete || !cur.quarter.Before(now) {
			break
		}
		cur = cursor{quarter: cur.quarter.Next(), last: -1}
		mode = "incremental"
	}
	if stop != nil && len(records) == 0 {
		return nil, stop
	}
	lastRun.Set("quarters", quarters)
	lastRun.Set("pages", pyjson.IntOf(int64(pages)))
	lastRun.Set("missing", pyjson.IntOf(int64(missing)))
	lastRun.Set("requests", pyjson.IntOf(int64(c.requests)))
	if stop != nil {
		c.logger.Warn("osssec: stopped early", "err", stop)
		lastRun.Set("stopped", stop.Error())
	} else {
		lastRun.Set("stopped", nil)
	}
	out := pyjson.NewObject()
	out.Set("quarter", cur.quarter.String())
	out.Set("last_number", pyjson.IntOf(int64(cur.last)))
	out.Set("etag", cur.etag)
	out.Set("last_modified", cur.lastModified)
	out.Set("last_run", lastRun)
	return &model.FetchResult{Records: records, Cursor: out}, nil
}

// walkQuarter fetches the index of cur.quarter and the messages above
// cur.last, within *budget.
func (c *Collector) walkQuarter(ctx context.Context, cur cursor, budget *int, newestOnly bool) quarterRun {
	r := quarterRun{last: cur.last, etag: cur.etag, lm: cur.lastModified}
	if err := c.wait(ctx); err != nil {
		r.err = err
		return r
	}
	hdr := http.Header{}
	if s, ok := cur.etag.(string); ok {
		hdr.Set("If-None-Match", s)
	}
	if s, ok := cur.lastModified.(string); ok {
		hdr.Set("If-Modified-Since", s)
	}
	indexURL := c.base + cur.quarter.String() + "/"
	resp, err := c.index.Get(ctx, indexURL, httpc.GetOptions{Header: hdr, Accept: func(s int) bool {
		return s == http.StatusNotModified || s == http.StatusNotFound || (s >= 200 && s < 300)
	}})
	if err != nil {
		r.err = fmt.Errorf("osssec: index %s: %w", cur.quarter, err)
		return r
	}
	r.indexStatus = resp.Status
	switch resp.Status {
	case http.StatusNotModified:
		r.complete = true
		return r
	case http.StatusNotFound: // a quarter with no post yet
		r.complete, r.etag, r.lm = true, nil, nil
		return r
	}
	var todo []int
	for _, n := range ParseIndex(resp.Body) {
		if n > cur.last {
			todo = append(todo, n)
		}
	}
	if newestOnly && len(todo) > *budget {
		r.newestOnlyOf = len(todo) - *budget
		todo = todo[len(todo)-*budget:]
	}
	// validators are only worth keeping once the whole index is handled
	r.etag, r.lm = nil, nil
	for _, n := range todo {
		if *budget <= 0 {
			return r
		}
		rec, gone, err := c.fetchMessage(ctx, cur.quarter, n)
		if err != nil {
			r.err = err
			return r
		}
		if gone {
			r.missing++
		} else {
			r.records = append(r.records, *rec)
			r.fetched++
			*budget--
		}
		r.last = n
	}
	r.complete = true
	r.etag, r.lm = headerOrNil(resp.Header, "ETag"), headerOrNil(resp.Header, "Last-Modified")
	return r
}

// fetchMessage gets and parses one message page; gone is true for a 404.
func (c *Collector) fetchMessage(ctx context.Context, q Quarter, n int) (*model.RawRecord, bool, error) {
	if err := c.wait(ctx); err != nil {
		return nil, false, err
	}
	key := q.String() + "/" + strconv.Itoa(n)
	resp, err := c.pages.Get(ctx, c.base+key, httpc.GetOptions{Accept: func(s int) bool {
		return s == http.StatusNotFound || (s >= 200 && s < 300)
	}})
	if err != nil {
		return nil, false, fmt.Errorf("osssec: %s: %w", key, err)
	}
	if resp.Status == http.StatusNotFound {
		c.logger.Warn("osssec: message is gone, skipping", "key", key)
		return nil, true, nil
	}
	m, err := ParseMessage(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("osssec: %s: %w", key, err)
	}
	r := Record(q, n, m)
	return &r, false, nil
}

// Record is the raw record of message n of quarter q.
func Record(q Quarter, n int, m *Message) model.RawRecord {
	return model.RawRecord{Source: Name, SourceKey: q.String() + "/" + strconv.Itoa(n), Payload: payload(q, n, m)}
}

func strList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// noNUL drops NUL characters (PostgreSQL text can't hold them).
func noNUL(s string) string { return strings.ReplaceAll(s, "\x00", "") }

func payload(q Quarter, n int, m *Message) *pyjson.Object {
	p := pyjson.NewObject()
	p.Set("url", MessageURL(q, n))
	p.Set("year", pyjson.IntOf(int64(q.Year)))
	p.Set("quarter", pyjson.IntOf(int64(q.Q)))
	p.Set("number", pyjson.IntOf(int64(n)))
	p.Set("subject", noNUL(m.Subject))
	p.Set("author", noNUL(m.Author))
	if m.Date != nil {
		p.Set("date", m.Date.UTC().Format(time.RFC3339))
	} else {
		p.Set("date", nil)
	}
	p.Set("is_reply", m.IsReply)
	p.Set("cve_ids", strList(m.CVEs))
	p.Set("ghsa_ids", strList(m.GHSAs))
	p.Set("subject_ids", strList(m.SubjectIDs))
	return p
}

// MinCVEYear: CVE ids start in 1999.
const MinCVEYear = 1999

// plausible drops CVE ids whose year can't be right for a post written at
// date (before 1999, or more than a year after the post). GHSA ids pass.
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
	return date == nil || y <= date.UTC().Year()+1
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
	url, _ := p.Get("url").(string)
	if !strings.HasPrefix(url, PublicBaseURL) {
		return nil, collector.NormalizeErrorf("bad url: %s", pyjson.Repr(p.Get("url")))
	}
	var date *time.Time
	switch d := p.Get("date").(type) {
	case nil:
	case string:
		t, err := time.Parse(time.RFC3339, d)
		if err != nil {
			return nil, collector.NormalizeErrorf("bad date: %s", pyjson.Repr(d))
		}
		t = t.UTC()
		date = &t
	default:
		return nil, collector.NormalizeErrorf("bad date: %s", pyjson.Repr(d))
	}
	subject, _ := p.Get("subject").(string)
	author, _ := p.Get("author").(string)
	isReply, _ := p.Get("is_reply").(bool)

	seen := map[string]bool{}
	var ids []string
	for _, l := range [][]string{idList(p.Get("subject_ids")), idList(p.Get("cve_ids")), idList(p.Get("ghsa_ids"))} {
		for _, id := range l {
			if seen[id] || !plausible(id, date) {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > MaxIDsPerPost {
		ids = ids[:MaxIDsPerPost]
	}
	n := &model.Normalized{}
	for _, id := range ids {
		var authorV any
		if author != "" {
			authorV = author
		}
		detail := map[string]any{
			"subject":  subject,
			"author":   authorV,
			"is_reply": isReply,
			"list":     ListName,
		}
		u := url
		n.Events = append(n.Events, model.Event{CVEID: id, Type: model.EventAnalysisPublished, Source: Name,
			OccurredAt: date, URL: &u, Detail: detail, DedupeKey: rec.SourceKey})
	}
	return n, nil
}
