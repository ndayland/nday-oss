package ghsa

// Port of tests/test_ghsa.py. The list endpoint is served by fakeGitHub, a
// FakeTransport handler with the same semantics as the Python FakeGitHub
// (updated>=, sort=updated asc, Link rel="next" with a base64 after= cursor);
// never the network.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

const fixDir = "tests/fixtures/ghsa/"

func deepCopy(t testing.TB, v any) any {
	t.Helper()
	s, err := pyjson.Encode(v, pyjson.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := pyjson.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func obj(v any) *pyjson.Object { return v.(*pyjson.Object) }

func str(v any) string { s, _ := v.(string); return s }

type fixtures struct {
	sample                                         []*pyjson.Object
	rateLimitedBody                                []byte
	realLink                                       string
	patched, unpatched, noCVE, withdrawnNoCVE, wdr *pyjson.Object
	newest, now                                    time.Time
}

func isPatched(a *pyjson.Object) bool {
	vs, _ := a.Get("vulnerabilities").([]any)
	for _, v := range vs {
		if collector.Text(obj(v).Get("first_patched_version")) != nil {
			return true
		}
	}
	return false
}

func load(t testing.TB) *fixtures {
	t.Helper()
	f := &fixtures{}
	v, err := pyjson.Decode(testutil.ReadFile(t, fixDir+"advisories_sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range v.([]any) {
		f.sample = append(f.sample, obj(a))
	}
	f.rateLimitedBody = testutil.ReadFile(t, fixDir+"rate_limited_403.json")
	f.realLink = strings.TrimSpace(string(testutil.ReadFile(t, fixDir+"link_header.txt")))
	pick := func(pred func(a *pyjson.Object) bool) *pyjson.Object {
		for _, a := range f.sample {
			if pred(a) {
				return obj(deepCopy(t, a))
			}
		}
		t.Fatal("no fixture advisory")
		return nil
	}
	has := func(a *pyjson.Object, k string) bool { return truthy(a.Get(k)) }
	f.patched = pick(func(a *pyjson.Object) bool {
		return has(a, "cve_id") && !has(a, "withdrawn_at") && isPatched(a) && len(FixCommitURLs(a.Get("references"))) > 0
	})
	f.unpatched = pick(func(a *pyjson.Object) bool { return has(a, "cve_id") && !has(a, "withdrawn_at") && !isPatched(a) })
	f.noCVE = pick(func(a *pyjson.Object) bool { return !has(a, "cve_id") && !has(a, "withdrawn_at") })
	f.withdrawnNoCVE = pick(func(a *pyjson.Object) bool { return has(a, "withdrawn_at") })
	f.wdr = obj(deepCopy(t, f.patched))
	f.wdr.Set("withdrawn_at", f.withdrawnNoCVE.Get("withdrawn_at"))
	for _, a := range f.sample {
		u, _ := parseTS(a.Get("updated_at"))
		if u.After(f.newest) {
			f.newest = u
		}
	}
	f.now = f.newest.Add(time.Hour)
	return f
}

func zfmt(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func atTS(t testing.TB, adv *pyjson.Object, updated string) *pyjson.Object {
	a := obj(deepCopy(t, adv))
	a.Set("updated_at", updated)
	return a
}

func withID(t testing.TB, adv *pyjson.Object, gid string) *pyjson.Object {
	a := obj(deepCopy(t, adv))
	a.Set("ghsa_id", gid)
	return a
}

func norm(t testing.TB, adv *pyjson.Object) (*model.Normalized, error) {
	c, err := New(Options{Token: ptr("")})
	if err != nil {
		t.Fatal(err)
	}
	return c.Normalize(model.RawRecord{Source: Name, SourceKey: str(adv.Get("ghsa_id")), Payload: adv})
}

func ptr[T any](v T) *T { return &v }

// ----------------------------------------------------------------- fake upstream

type cannedResp struct {
	status int
	header http.Header
	body   []byte
}

type fakeGitHub struct {
	t          testing.TB
	f          *fixtures
	mu         sync.Mutex
	advisories map[string]*pyjson.Object
	pageSize   int
	remaining  int
	fail       []cannedResp
	reset      int64
	ft         *testutil.FakeTransport
	sleeps     []time.Duration
	logs       *logCapture
}

func newFake(t testing.TB, f *fixtures, advs []*pyjson.Object, pageSize int) *fakeGitHub {
	g := &fakeGitHub{t: t, f: f, advisories: map[string]*pyjson.Object{}, pageSize: pageSize, remaining: 60,
		reset: 1794495459, logs: &logCapture{}}
	for _, a := range advs {
		g.advisories[str(a.Get("ghsa_id"))] = obj(deepCopy(t, a))
	}
	g.ft = &testutil.FakeTransport{Handler: g.handle}
	return g
}

func (g *fakeGitHub) rl() http.Header {
	return http.Header{
		"X-Ratelimit-Limit":     {"60"},
		"X-Ratelimit-Remaining": {fmt.Sprint(g.remaining)},
		"X-Ratelimit-Used":      {fmt.Sprint(60 - g.remaining)},
		"X-Ratelimit-Reset":     {fmt.Sprint(g.reset)},
		"X-Ratelimit-Resource":  {"core"},
	}
}

// orderedQuery parses a query string keeping parameter order (parse_qs order).
func orderedQuery(raw string) ([]string, map[string]string) {
	var keys []string
	vals := map[string]string{}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		if _, ok := vals[k]; !ok {
			keys = append(keys, k)
			vals[k] = v
		}
	}
	return keys, vals
}

func jsonBody(t testing.TB, v any) []byte {
	s, err := pyjson.Encode(v, pyjson.Options{Compact: true})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

func (g *fakeGitHub) handle(r *http.Request) (int, http.Header, []byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.fail) > 0 {
		c := g.fail[0]
		g.fail = g.fail[1:]
		return c.status, c.header, c.body, nil
	}
	if g.remaining <= 0 {
		return 403, g.rl(), g.f.rateLimitedBody, nil
	}
	g.remaining--
	if base := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path; base != AdvisoriesURL {
		g.t.Errorf("unexpected URL %s", r.URL)
	}
	keys, q := orderedQuery(r.URL.RawQuery)
	if q["type"] != "reviewed" || q["sort"] != "updated" || q["direction"] != "asc" || q["per_page"] != "100" ||
		!strings.HasPrefix(q["updated"], ">=") {
		g.t.Errorf("unexpected query %v", q)
	}
	since, _ := parseTS(q["updated"][2:])
	var rows []*pyjson.Object
	for _, a := range g.advisories {
		if u, _ := parseTS(a.Get("updated_at")); !u.Before(since) {
			rows = append(rows, a)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		ui, _ := parseTS(rows[i].Get("updated_at"))
		uj, _ := parseTS(rows[j].Get("updated_at"))
		if !ui.Equal(uj) {
			return ui.Before(uj)
		}
		return str(rows[i].Get("ghsa_id")) < str(rows[j].Get("ghsa_id"))
	})
	if after, ok := q["after"]; ok {
		raw, _ := base64.URLEncoding.DecodeString(after)
		key, _ := pyjson.Decode(raw)
		if key == "bogus" {
			return 422, http.Header{}, []byte(`{"message":"Validation Failed"}`), nil
		}
		k := key.([]any)
		var kept []*pyjson.Object
		for _, a := range rows {
			u, id := str(a.Get("updated_at")), str(a.Get("ghsa_id"))
			if u > k[0].(string) || (u == k[0].(string) && id > k[1].(string)) {
				kept = append(kept, a)
			}
		}
		rows = kept
	}
	page, more := rows, false
	if len(rows) > g.pageSize {
		page, more = rows[:g.pageSize], true
	}
	h := g.rl()
	if more {
		last := page[len(page)-1]
		// json.dumps([updated_at, ghsa_id]) with the default ", " separator
		tok := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`["%s", "%s"]`, str(last.Get("updated_at")), str(last.Get("ghsa_id")))))
		var kv []string
		for _, k := range keys {
			if k != "after" && k != "before" {
				kv = append(kv, k, q[k])
			}
		}
		kv = append(kv, "after", tok)
		h.Set("Link", "<"+AdvisoriesURL+"?"+EncodeParams(kv...)+`>; rel="next"`)
	}
	items := make([]any, len(page))
	for i, a := range page {
		items[i] = a
	}
	return 200, h, jsonBody(g.t, items), nil
}

type cOpts struct {
	now                                     time.Time
	bootstrap, maxRequests, overlap         int64
	token                                   *string
	env                                     map[string]string
	useEnvForSettings, useEnvToken, noLimit bool
}

func (g *fakeGitHub) collector(o cOpts) *Collector {
	g.t.Helper()
	if o.bootstrap == 0 {
		o.bootstrap = 7
	}
	if o.maxRequests == 0 {
		o.maxRequests = 10
	}
	if o.overlap < 0 {
		o.overlap = 0
	} else if o.overlap == 0 {
		o.overlap = 60
	}
	opts := Options{
		Transport: g.ft, BootstrapDays: &o.bootstrap, MaxRequests: &o.maxRequests, OverlapMinutes: &o.overlap,
		Token: ptr(""), Clock: func() time.Time { return o.now },
		Sleep:  func(_ context.Context, d time.Duration) error { g.sleeps = append(g.sleeps, d); return nil },
		Logger: slog.New(g.logs),
	}
	if o.useEnvToken {
		opts.Token = nil
		opts.Env = func(k string) (string, bool) { v, ok := o.env[k]; return v, ok }
	}
	c, err := New(opts)
	if err != nil {
		g.t.Fatal(err)
	}
	return c
}

func (g *fakeGitHub) requests() []testutil.Request { return g.ft.Requests }

func (g *fakeGitHub) clear() { g.ft.Requests = nil }

func (g *fakeGitHub) query(i int) map[string]string {
	reqs := g.requests()
	if i < 0 {
		i += len(reqs)
	}
	u, _ := url.Parse(reqs[i].URL)
	_, q := orderedQuery(u.RawQuery)
	return q
}

// logCapture is a slog.Handler keeping every message (all levels).
type logCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (l *logCapture) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	b.WriteString(r.Level.String() + " " + r.Message)
	r.Attrs(func(a slog.Attr) bool { b.WriteString(" " + a.String()); return true })
	l.msgs = append(l.msgs, b.String())
	return nil
}
func (l *logCapture) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logCapture) WithGroup(string) slog.Handler      { return l }
func (l *logCapture) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.msgs {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------- DB helpers

const countSQL = `SELECT (SELECT count(*) FROM raw_record), (SELECT count(*) FROM vuln),
                      (SELECT count(*) FROM vuln_alias), (SELECT count(*) FROM affected),
                      (SELECT count(*) FROM event)`

type counts [5]int64

func getCounts(t testing.TB, d *testutil.TestDB) counts {
	t.Helper()
	var c counts
	if err := d.Conn.QueryRow(context.Background(), countSQL).Scan(&c[0], &c[1], &c[2], &c[3], &c[4]); err != nil {
		t.Fatal(err)
	}
	return c
}

func run(t testing.TB, d *testutil.TestDB, c collector.Collector, now time.Time, renorm bool) *pipeline.Stats {
	t.Helper()
	st, err := pipeline.RunCollector(context.Background(), d.Conn, c, pipeline.Options{
		Now: func() time.Time { return now }, Renormalize: renorm, Logger: slog.New(&logCapture{})})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return st
}

func runErr(d *testutil.TestDB, c collector.Collector, now time.Time) error {
	_, err := pipeline.RunCollector(context.Background(), d.Conn, c, pipeline.Options{
		Now: func() time.Time { return now }, Logger: slog.New(&logCapture{})})
	return err
}

func cursorOf(t testing.TB, d *testutil.TestDB) *pyjson.Object {
	t.Helper()
	var s *string
	if err := d.Conn.QueryRow(context.Background(), "SELECT cursor::text FROM collector_state WHERE source='ghsa'").Scan(&s); err != nil {
		t.Fatal(err)
	}
	if s == nil {
		return nil
	}
	v, err := pyjson.DecodeString(*s)
	if err != nil {
		t.Fatal(err)
	}
	return obj(v)
}

func path(o *pyjson.Object, keys ...string) any {
	var v any = o
	for _, k := range keys {
		ob, ok := v.(*pyjson.Object)
		if !ok {
			return nil
		}
		v = ob.Get(k)
	}
	return v
}

func scalar(t testing.TB, d *testutil.TestDB, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := d.Conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ----------------------------------------------------------------- golden parity

func TestGoldenParityWithPython(t *testing.T) {
	newC := func(*testutil.FakeTransport) collector.Collector {
		c, err := New(Options{Token: ptr("")})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, g := range []string{"sample_records", "edge_records"} {
		t.Run(g, func(t *testing.T) {
			testutil.CheckGolden(t, "internal/collector/ghsa/testdata/golden/"+g+".golden.json", newC)
		})
	}
	// sample_records.json is the fixture, verbatim, one record per advisory.
	f := load(t)
	recs := decodeFile(t, "internal/collector/ghsa/testdata/sample_records.json").([]any)
	if len(recs) != len(f.sample) {
		t.Fatalf("%d records, fixture has %d", len(recs), len(f.sample))
	}
	for i, r := range recs {
		a, _ := pyjson.Canonical(f.sample[i])
		b, _ := pyjson.Canonical(obj(r).Get("payload"))
		if a != b || obj(r).Get("source_key") != f.sample[i].Get("ghsa_id") {
			t.Errorf("record %d differs from the fixture", i)
		}
	}
}

// ----------------------------------------------------------------- fixtures sanity

func TestFixtureIsRealShape(t *testing.T) {
	f := load(t)
	keys := []string{"ghsa_id", "cve_id", "url", "html_url", "summary", "description", "type", "severity",
		"source_code_location", "identifiers", "references", "published_at", "updated_at",
		"github_reviewed_at", "nvd_published_at", "withdrawn_at", "vulnerabilities", "cwes"}
	for _, a := range f.sample {
		for _, k := range keys {
			if _, ok := a.Lookup(k); !ok {
				t.Errorf("%v: missing %s", a.Get("ghsa_id"), k)
			}
		}
		if a.Get("type") != "reviewed" {
			t.Errorf("%v: type %v", a.Get("ghsa_id"), a.Get("type"))
		}
	}
	if !strings.Contains(f.realLink, `rel="next"`) || !strings.Contains(f.realLink, "after=") {
		t.Error(f.realLink)
	}
}

func TestNextURLParsedFromRealLinkHeader(t *testing.T) {
	f := load(t)
	nxt, err := nextURL(http.Header{"Link": {f.realLink}})
	if err != nil || !strings.HasPrefix(nxt, AdvisoriesURL+"?") {
		t.Fatalf("%q %v", nxt, err)
	}
	u, _ := url.Parse(nxt)
	if _, q := orderedQuery(u.RawQuery); q["after"] == "" {
		t.Error("no after")
	}
	if _, err := nextURL(http.Header{"Link": {`<https://evil.example/advisories?after=x>; rel="next"`}}); err == nil ||
		err.Error() != "unexpected Link next URL: 'https://evil.example/advisories?after=x'" {
		t.Errorf("evil link: %v", err)
	}
}

// ----------------------------------------------------------------- pure normalize

func TestNormalizePatchedAdvisory(t *testing.T) {
	f := load(t)
	a := f.patched
	n, err := norm(t, a)
	if err != nil {
		t.Fatal(err)
	}
	cve, gid := str(a.Get("cve_id")), str(a.Get("ghsa_id"))
	if len(n.Aliases) != 1 || n.Aliases[0] != (model.Alias{CVEID: cve, Alias: gid, AliasType: "ghsa"}) {
		t.Errorf("aliases %+v", n.Aliases)
	}
	if len(n.Vulns) != 1 {
		t.Fatalf("vulns %+v", n.Vulns)
	}
	v := n.Vulns[0]
	if v.CVEID != cve || *v.Title != a.Get("summary") || *v.Description != strings.TrimSpace(str(a.Get("description"))) ||
		v.Authoritative || v.PublishedAt != nil || v.ModifiedAt != nil {
		t.Errorf("vuln %+v", v)
	}
	if len(n.Affected) != 0 || len(n.Events) != 1 {
		t.Fatalf("affected/events %d/%d", len(n.Affected), len(n.Events))
	}
	e := n.Events[0]
	if e.Type != "patch_released" || e.Source != "ghsa" || e.DedupeKey != gid || *e.URL != a.Get("html_url") || e.OccurredAt != nil {
		t.Errorf("event %+v", e)
	}
	d := e.Detail
	eq := func(k string, want any) {
		g, _ := pyjson.Canonical(d[k])
		w, _ := pyjson.Canonical(want)
		if g != w {
			t.Errorf("detail[%s] = %s, want %s", k, g, w)
		}
	}
	eq("ghsa_id", gid)
	eq("advisory_published_at", a.Get("published_at"))
	eq("advisory_updated_at", a.Get("updated_at"))
	eq("github_reviewed_at", a.Get("github_reviewed_at"))
	eq("severity", a.Get("severity"))
	eq("cvss", a.Get("cvss_severities"))
	eq("cwes", a.Get("cwes"))
	var pk []any
	for _, x := range a.Get("vulnerabilities").([]any) {
		xo := obj(x)
		p := pyjson.NewObject()
		p.Set("ecosystem", path(xo, "package", "ecosystem"))
		p.Set("name", path(xo, "package", "name"))
		p.Set("vulnerable_version_range", xo.Get("vulnerable_version_range"))
		p.Set("first_patched_version", xo.Get("first_patched_version"))
		pk = append(pk, p)
	}
	eq("packages", pk)
	fix := d["fix_commit_urls"].([]any)
	refs := map[any]bool{}
	for _, r := range a.Get("references").([]any) {
		refs[r] = true
	}
	if len(fix) == 0 {
		t.Error("no fix_commit_urls")
	}
	for _, u := range fix {
		if !refs[u] {
			t.Errorf("%v not a reference", u)
		}
	}
	eq("source_code_location", a.Get("source_code_location"))
	eq("references", a.Get("references"))
	if s, _ := pyjson.Encode(d, pyjson.Options{}); strings.Contains(s, "epss") {
		t.Error("epss leaked into detail")
	}
}

func TestNormalizeUnpatchedAdvisoryNoEvent(t *testing.T) {
	f := load(t)
	n, err := norm(t, f.unpatched)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Events) != 0 || len(n.Aliases) != 1 ||
		n.Aliases[0] != (model.Alias{CVEID: str(f.unpatched.Get("cve_id")), Alias: str(f.unpatched.Get("ghsa_id")), AliasType: "ghsa"}) ||
		len(n.Vulns) != 1 || *n.Vulns[0].Title != f.unpatched.Get("summary") {
		t.Errorf("%+v", n)
	}
}

// No CVE: the vulnerability is keyed by the GHSA id; the advisory is its own
// record (authoritative vuln, disclosed event at published_at) and brings
// the same patch_released event as an advisory with a CVE.
func TestNormalizeNoCVEKeyedByGHSA(t *testing.T) {
	f := load(t)
	n, err := norm(t, f.noCVE)
	if err != nil {
		t.Fatal(err)
	}
	gid := str(f.noCVE.Get("ghsa_id"))
	pub, _ := parseTS(f.noCVE.Get("published_at"))
	upd, _ := parseTS(f.noCVE.Get("updated_at"))
	if len(n.Aliases)+len(n.Affected) != 0 || len(n.Vulns) != 1 || len(n.Events) != 2 {
		t.Fatalf("%+v", n)
	}
	v := n.Vulns[0]
	if v.CVEID != gid || !v.Authoritative || *v.Title != f.noCVE.Get("summary") || *v.Description != f.noCVE.Get("description") ||
		!v.PublishedAt.Equal(pub) || !v.ModifiedAt.Equal(upd) {
		t.Errorf("vuln %+v", v)
	}
	e := n.Events[0]
	if e.CVEID != gid || e.Type != model.EventDisclosed || e.Source != Name || e.DedupeKey != gid ||
		e.OccurredAt == nil || !e.OccurredAt.Equal(pub) || *e.URL != f.noCVE.Get("html_url") ||
		e.Detail["state"] != "PUBLISHED" || e.Detail["ghsa_id"] != gid || e.Detail["withdrawn_at"] != nil {
		t.Errorf("disclosed %+v", e)
	}
	if p := n.Events[1]; p.CVEID != gid || p.Type != model.EventPatchReleased || p.OccurredAt != nil || p.DedupeKey != gid {
		t.Errorf("patch %+v", p)
	}
	if err := n.Validate(); err != nil {
		t.Error(err)
	}
	// no patched version: vuln and disclosed event only
	a := obj(deepCopy(t, f.noCVE))
	for _, v := range a.Get("vulnerabilities").([]any) {
		obj(v).Set("first_patched_version", nil)
	}
	if n, err := norm(t, a); err != nil || len(n.Vulns) != 1 || len(n.Events) != 1 || n.Events[0].Type != model.EventDisclosed {
		t.Errorf("unpatched %+v %v", n, err)
	}
}

func TestNormalizeWithdrawn(t *testing.T) {
	f := load(t)
	// without a CVE: only the disclosed event, state REJECTED (written only
	// when the GHSA-keyed vuln already exists; see the pipeline tests)
	n0, err := norm(t, f.withdrawnNoCVE)
	if err != nil || len(n0.Vulns)+len(n0.Aliases)+len(n0.Affected) != 0 || len(n0.Events) != 1 {
		t.Fatalf("%+v %v", n0, err)
	}
	if e := n0.Events[0]; e.Type != model.EventDisclosed || e.Detail["state"] != "REJECTED" ||
		e.Detail["withdrawn_at"] != f.withdrawnNoCVE.Get("withdrawn_at") || e.CVEID != str(f.withdrawnNoCVE.Get("ghsa_id")) {
		t.Errorf("%+v", e)
	}
	// with a CVE: alias only, as before
	n, err := norm(t, f.wdr)
	if err != nil || len(n.Aliases) != 1 ||
		n.Aliases[0] != (model.Alias{CVEID: str(f.wdr.Get("cve_id")), Alias: str(f.wdr.Get("ghsa_id")), AliasType: "ghsa"}) ||
		len(n.Vulns)+len(n.Events)+len(n.Affected) != 0 {
		t.Errorf("%+v %v", n, err)
	}
}

func TestPatchedVersionWhitespaceOrNullIsUnpatched(t *testing.T) {
	f := load(t)
	a := obj(deepCopy(t, f.patched))
	for _, v := range a.Get("vulnerabilities").([]any) {
		obj(v).Set("first_patched_version", "  ")
	}
	if n, err := norm(t, a); err != nil || len(n.Events) != 0 {
		t.Fatalf("%+v %v", n, err)
	}
	legacy := pyjson.NewObject()
	legacy.Set("identifier", "1.2.3")
	obj(a.Get("vulnerabilities").([]any)[0]).Set("first_patched_version", legacy)
	n, err := norm(t, a)
	if err != nil || len(n.Events) != 1 {
		t.Fatalf("%+v %v", n, err)
	}
	if got := path(obj(n.Events[0].Detail["packages"].([]any)[0]), "first_patched_version"); got != "1.2.3" {
		t.Errorf("%v", got)
	}
}

func TestFixCommitURLExtraction(t *testing.T) {
	refs := []any{
		"https://nvd.nist.gov/vuln/detail/CVE-2026-1",
		"https://github.com/acme/widget/commit/0123456789abcdef0123456789abcdef01234567",
		"https://github.com/acme/widget/commit/0123456789abcdef0123456789abcdef01234567",
		"https://github.com/acme/widget/pull/42",
		"https://github.com/acme/widget/pull/42/commits/abcdef1",
		"https://github.com/github/advisory-database/pull/10102",
		"https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx",
		"https://github.com/acme/widget/releases/tag/v1.2.3",
		"https://github.com/acme/widget/issues/7",
		"https://github.com/advisories/GHSA-2222-3333-4444",
		"https://github.com/acme/widget/commits/main",
		"https://gitlab.com/group/sub/proj/-/commit/89abcdef0123",
		"https://gitlab.example.org/team/proj/-/merge_requests/9",
		"https://gitlab.com/group/proj/-/issues/3",
		"https://bitbucket.org/o/r/commits/deadbeefcafe",
		"https://example.com/commit/0123456789abcdef",
		nil,
		"",
	}
	want := []any{
		"https://github.com/acme/widget/commit/0123456789abcdef0123456789abcdef01234567",
		"https://github.com/acme/widget/pull/42",
		"https://github.com/acme/widget/pull/42/commits/abcdef1",
		"https://gitlab.com/group/sub/proj/-/commit/89abcdef0123",
		"https://gitlab.example.org/team/proj/-/merge_requests/9",
		"https://bitbucket.org/o/r/commits/deadbeefcafe",
	}
	g, _ := pyjson.Canonical(FixCommitURLs(refs))
	w, _ := pyjson.Canonical(want)
	if g != w {
		t.Errorf("got %s\nwant %s", g, w)
	}
	if got := FixCommitURLs(nil); len(got) != 0 {
		t.Error(got)
	}
}

func TestFixCommitURLsFromRealReferences(t *testing.T) {
	f := load(t)
	found := map[string]bool{}
	for _, a := range f.sample {
		for _, u := range FixCommitURLs(a.Get("references")) {
			found[u.(string)] = true
		}
	}
	if len(found) == 0 {
		t.Fatal("none found")
	}
	for u := range found {
		if !(strings.Contains(u, "/commit/") || strings.Contains(u, "/pull/") || strings.Contains(u, "/merge_requests/")) ||
			strings.Contains(u, "/advisories/") || strings.Contains(u, "advisory-database") {
			t.Errorf("%s", u)
		}
	}
	for _, a := range f.sample {
		if a.Get("ghsa_id") == "GHSA-7ph3-grqh-pv9v" {
			n, err := norm(t, a)
			if err != nil {
				t.Fatal(err)
			}
			g, _ := pyjson.Canonical(n.Events[0].Detail["fix_commit_urls"])
			if g != `["https://github.com/apache/gravitino/pull/8000","https://github.com/apache/gravitino/commit/5355bd075d54cad1323606723e72cc32ca564f24"]` {
				t.Error(g)
			}
		}
	}
}

func TestNormalizeMalformed(t *testing.T) {
	f := load(t)
	// Messages are Python's (tests/test_ghsa.py only checks the type; the
	// golden edge cases check the exact texts too).
	cases := []struct {
		name   string
		mutate func(a *pyjson.Object)
		msg    string
	}{
		{"ghsa_id", func(a *pyjson.Object) { a.Set("ghsa_id", "GHSA-nope") }, "bad ghsa_id: 'GHSA-nope'"},
		{"updated_at", func(a *pyjson.Object) { a.Set("updated_at", "yesterday") }, "GHSA-7ph3-grqh-pv9v: bad updated_at: 'yesterday'"},
		{"published_at", func(a *pyjson.Object) {
			b := pyjson.NewObject()
			for _, k := range a.Keys() {
				if k != "published_at" {
					b.Set(k, a.Get(k))
				}
			}
			*a = *b
		}, "GHSA-7ph3-grqh-pv9v: bad published_at: None"},
		{"cve_id", func(a *pyjson.Object) { a.Set("cve_id", "CVE-26-1") }, "GHSA-7ph3-grqh-pv9v: bad cve_id 'CVE-26-1'"},
		{"vulnerabilities", func(a *pyjson.Object) { a.Set("vulnerabilities", "x") }, "GHSA-7ph3-grqh-pv9v: vulnerabilities is not a list"},
		{"references", func(a *pyjson.Object) {
			o := pyjson.NewObject()
			o.Set("a", pyjson.IntOf(1))
			a.Set("references", o)
		}, "GHSA-7ph3-grqh-pv9v: references is not a list"},
		{"junk", func(a *pyjson.Object) { a.Set("vulnerabilities", append(a.Get("vulnerabilities").([]any), "junk")) },
			"GHSA-7ph3-grqh-pv9v: vulnerability entry is not an object"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := obj(deepCopy(t, f.patched))
			key := str(a.Get("ghsa_id"))
			c.mutate(a)
			_, err := New(Options{Token: ptr("")})
			if err != nil {
				t.Fatal(err)
			}
			cc, _ := New(Options{Token: ptr("")})
			_, err = cc.Normalize(model.RawRecord{Source: Name, SourceKey: key, Payload: a})
			var ne *collector.NormalizeError
			if !errors.As(err, &ne) || ne.Msg != c.msg {
				t.Errorf("got %v, want NormalizeError %q", err, c.msg)
			}
		})
	}
}

func TestNormalizeRejectsKeyMismatch(t *testing.T) {
	f := load(t)
	c, _ := New(Options{Token: ptr("")})
	_, err := c.Normalize(model.RawRecord{Source: Name, SourceKey: str(f.unpatched.Get("ghsa_id")), Payload: f.patched})
	var ne *collector.NormalizeError
	if !errors.As(err, &ne) || ne.Msg != "ghsa_id GHSA-7ph3-grqh-pv9v != source_key GHSA-9754-6rhw-gj3h" {
		t.Errorf("%v", err)
	}
}

// ----------------------------------------------------------------- fetch + pipeline

func TestFirstRunWindowPaginationAndHeaders(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample, 2)
	st := run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	pages := (len(f.sample) + 1) / 2
	reqs := gh.requests()
	if len(reqs) != pages {
		t.Fatalf("%d requests, want %d", len(reqs), pages)
	}
	if gh.query(0)["updated"] != ">="+zfmt(f.now.AddDate(0, 0, -7)) {
		t.Errorf("first query %v", gh.query(0))
	}
	if _, ok := gh.query(0)["after"]; ok {
		t.Error("after on first page")
	}
	for i := 1; i < pages; i++ {
		if _, ok := gh.query(i)["after"]; !ok {
			t.Errorf("page %d without after", i)
		}
	}
	wantFirst := "https://api.github.com/advisories?type=reviewed&sort=updated&direction=asc&per_page=100&updated=%3E%3D" +
		strings.ReplaceAll(zfmt(f.now.AddDate(0, 0, -7)), ":", "%3A")
	if reqs[0].URL != wantFirst {
		t.Errorf("first URL %s\nwant %s", reqs[0].URL, wantFirst)
	}
	for _, r := range reqs {
		if r.Header.Get("User-Agent") != httpc.UserAgent || r.Header.Get("Accept") != "application/vnd.github+json" ||
			r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || len(r.Header.Values("Authorization")) != 0 {
			t.Errorf("headers %v", r.Header)
		}
	}
	if !st.IsBackfill || st.Fetched != len(f.sample) || st.RawNew != len(f.sample) || st.NormalizeErrors != 0 {
		t.Errorf("stats %+v", st)
	}
	withCVE, patchedLive, noCVELive := 0, 0, 0
	for _, a := range f.sample {
		if truthy(a.Get("cve_id")) {
			withCVE++
		} else if !truthy(a.Get("withdrawn_at")) {
			noCVELive++
		}
		if !truthy(a.Get("withdrawn_at")) && isPatched(a) {
			patchedLive++
		}
	}
	if noCVELive == 0 {
		t.Fatal("the sample has no live advisory without a CVE")
	}
	if n := scalar(t, d, "SELECT count(*) FROM raw_record WHERE source='ghsa'"); n != int64(len(f.sample)) {
		t.Errorf("raw %d", n)
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln_alias"); n != int64(withCVE) {
		t.Errorf("aliases %d", n)
	}
	// patch_released (no time) for every live patched advisory; a disclosed
	// event (published_at) only for the live ones without a CVE, whose vuln
	// is keyed by the GHSA id; the withdrawn one without a CVE stores nothing
	var n, nPatch, nDisc int64
	var bf bool
	_ = d.Conn.QueryRow(context.Background(), `SELECT count(*),
            count(*) FILTER (WHERE type = 'patch_released' AND occurred_at IS NULL),
            count(*) FILTER (WHERE type = 'disclosed' AND occurred_at IS NOT NULL AND cve_id LIKE 'GHSA-%'),
            bool_and(is_backfill) FROM event`).Scan(&n, &nPatch, &nDisc, &bf)
	if nPatch != int64(patchedLive) || nDisc != int64(noCVELive) || n != nPatch+nDisc || !bf {
		t.Errorf("events %d patch %d disclosed %d backfill %v", n, nPatch, nDisc, bf)
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln WHERE cve_id LIKE 'GHSA-%'"); n != int64(noCVELive) {
		t.Errorf("GHSA-keyed vulns %d, want %d", n, noCVELive)
	}
	cur := cursorOf(t, d)
	if cur.Get("since") != zfmt(f.newest) || cur.Get("pending") != nil || len(cur.Get("gaps").([]any)) != 0 ||
		path(cur, "bootstrap", "days") != pyjson.IntOf(7) ||
		path(cur, "last_run", "pages") != pyjson.IntOf(int64(pages)) ||
		path(cur, "last_run", "advisories") != pyjson.IntOf(int64(len(f.sample))) ||
		path(cur, "last_run", "rate_limit", "remaining") != pyjson.IntOf(int64(60-pages)) {
		t.Errorf("cursor %s", pyjson.Repr(cur))
	}
	// Full cursor (jsonb order) — the same shape Python stores.
	nowZ, winZ := zfmt(f.now), zfmt(f.now.AddDate(0, 0, -7))
	want := fmt.Sprintf(`{"gaps": [], "since": "%s", "pending": null, "last_run": {"pages": 3, "stopped": null, "advisories": 5, "rate_limit": {"limit": 60, "reset_at": "2026-11-12T14:57:39Z", "remaining": 57}, "query_since": "%s", "http_requests": 3}, "bootstrap": {"at": "%s", "days": 7, "window_from": "%s"}}`,
		zfmt(f.newest), winZ, nowZ, winZ)
	var got string
	_ = d.Conn.QueryRow(context.Background(), "SELECT cursor::text FROM collector_state").Scan(&got)
	if got != want {
		t.Errorf("cursor\n got  %s\n want %s", got, want)
	}
}

func TestFirstRunWindowExcludesOlder(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	old := atTS(t, withID(t, f.patched, "GHSA-2222-3333-4444"), "2020-01-01T00:00:00Z")
	gh := newFake(t, f, append(append([]*pyjson.Object{}, f.sample...), old), 2)
	if st := run(t, d, gh.collector(cOpts{now: f.now}), f.now, false); st.Fetched != len(f.sample) {
		t.Errorf("%+v", st)
	}
}

func TestSecondRunIsIdempotentAndOverlaps(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample, 100)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	before := getCounts(t, d)
	gh.clear()
	later := f.now.Add(time.Hour)
	st := run(t, d, gh.collector(cOpts{now: later}), later, false)
	if len(gh.requests()) != 1 {
		t.Errorf("%d requests", len(gh.requests()))
	}
	if gh.query(-1)["updated"] != ">="+zfmt(f.newest.Add(-60*time.Minute)) {
		t.Errorf("%v", gh.query(-1))
	}
	if st.RawNew != 0 || st.RawUnchanged != st.Fetched || st.Fetched < 1 || st.IsBackfill {
		t.Errorf("%+v", st)
	}
	if getCounts(t, d) != before {
		t.Error("rows added")
	}
	run(t, d, gh.collector(cOpts{now: f.now}), later.Add(time.Hour), true)
	if getCounts(t, d) != before {
		t.Error("renormalize added rows")
	}
}

func TestSameTimestampOverlapIsSafe(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	ts := "2026-11-12T10:00:00Z"
	gh := newFake(t, f, []*pyjson.Object{atTS(t, f.patched, ts)}, 100)
	run(t, d, gh.collector(cOpts{now: f.now, overlap: -1}), f.now, false)
	if cursorOf(t, d).Get("since") != ts {
		t.Fatal(pyjson.Repr(cursorOf(t, d)))
	}
	late := atTS(t, f.unpatched, ts)
	gh.advisories[str(late.Get("ghsa_id"))] = late
	later := f.now.Add(time.Hour)
	st := run(t, d, gh.collector(cOpts{now: later, overlap: -1}), later, false)
	if gh.query(-1)["updated"] != ">="+ts || st.RawNew != 1 || st.RawUnchanged != 1 {
		t.Errorf("%v %+v", gh.query(-1), st)
	}
	if n := scalar(t, d, "SELECT count(*) FROM raw_record WHERE source_key=$1", late.Get("ghsa_id")); n != 1 {
		t.Error(n)
	}
}

func TestRequestCapCarriesPendingOver(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample, 2)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	burstTS := zfmt(f.now.Add(30 * time.Minute))
	ids := []string{"GHSA-2222-2222-2222", "GHSA-3333-3333-3333", "GHSA-4444-4444-4444", "GHSA-5555-5555-5555", "GHSA-6666-6666-6666"}
	for i, gid := range ids {
		b := atTS(t, withID(t, f.sample[i%len(f.sample)], gid), burstTS)
		gh.advisories[gid] = b
	}
	later := f.now.Add(time.Hour)
	gh.clear()
	st := run(t, d, gh.collector(cOpts{now: later, maxRequests: 2, overlap: -1}), later, false)
	if len(gh.requests()) != 2 {
		t.Errorf("%d requests", len(gh.requests()))
	}
	cur := cursorOf(t, d)
	nextURL := str(path(cur, "pending", "next_url"))
	if path(cur, "pending", "reason") != "request_cap" || !strings.Contains(nextURL, "after=") ||
		path(cur, "last_run", "stopped") != "request_cap" || cur.Get("since") != burstTS {
		t.Errorf("cursor %s", pyjson.Repr(cur))
	}
	gotFirst := st.RawNew
	gh.clear()
	l2 := later.Add(time.Hour)
	st2 := run(t, d, gh.collector(cOpts{now: l2, maxRequests: 2, overlap: -1}), l2, false)
	if gh.requests()[0].URL != nextURL {
		t.Errorf("resumed %s, want %s", gh.requests()[0].URL, nextURL)
	}
	if cursorOf(t, d).Get("pending") != nil || gotFirst+st2.RawNew != len(ids) {
		t.Errorf("%s %d+%d", pyjson.Repr(cursorOf(t, d)), gotFirst, st2.RawNew)
	}
	if n := scalar(t, d, "SELECT count(*) FROM raw_record WHERE source_key = ANY($1)", ids); n != int64(len(ids)) {
		t.Error(n)
	}
}

func TestStalePendingURLFallsBackToSince(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample, 100)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	lu, _ := ListURL(f.newest)
	p := fmt.Sprintf(`{"next_url": %q, "query_since": "2026-11-12T00:00:00Z", "reason": "request_cap"}`,
		lu+"&after="+base64.URLEncoding.EncodeToString([]byte(`"bogus"`)))
	if _, err := d.Conn.Exec(context.Background(), `UPDATE collector_state SET cursor = jsonb_set(cursor, '{pending}', $1::jsonb)`, p); err != nil {
		t.Fatal(err)
	}
	gh.clear()
	later := f.now.Add(time.Hour)
	c := gh.collector(cOpts{now: later})
	run(t, d, c, later, false)
	if len(gh.requests()) != 2 {
		t.Fatalf("%d requests", len(gh.requests()))
	}
	if _, ok := gh.query(1)["after"]; ok || cursorOf(t, d).Get("pending") != nil {
		t.Errorf("%v %s", gh.query(1), pyjson.Repr(cursorOf(t, d)))
	}
	if !gh.logs.contains("ghsa: pending next URL rejected (422); restarting from since") ||
		!gh.logs.contains("ghsa: resuming pending pagination (request_cap, query since 2026-11-12T00:00:00Z)") {
		t.Errorf("logs %v", gh.logs.msgs)
	}
}

func TestRateLimitMidRunKeepsFetchedAndPersistsProgress(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample[:1], 2)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	for i, gid := range []string{"GHSA-2222-2222-2222", "GHSA-3333-3333-3333", "GHSA-4444-4444-4444"} {
		gh.advisories[gid] = atTS(t, withID(t, f.unpatched, gid), zfmt(f.now.Add(time.Duration(i+1)*time.Minute)))
	}
	gh.remaining = 1
	later := f.now.Add(time.Hour)
	gh.clear()
	c := gh.collector(cOpts{now: later, overlap: -1})
	st := run(t, d, c, later, false)
	if len(gh.requests()) != 1 || st.RawNew != 1 {
		t.Errorf("%d requests, %+v", len(gh.requests()), st)
	}
	var status string
	_ = d.Conn.QueryRow(context.Background(), "SELECT last_status FROM collector_state").Scan(&status)
	cur := cursorOf(t, d)
	if status != "ok" || path(cur, "pending", "reason") != "rate_limited" ||
		path(cur, "last_run", "rate_limit", "reset_at") != "2026-11-12T14:57:39Z" {
		t.Errorf("%s %s", status, pyjson.Repr(cur))
	}
	if !gh.logs.contains("stopped early (rate_limited)") {
		t.Errorf("logs %v", gh.logs.msgs)
	}
	gh.remaining = 60
	gh.clear()
	l2 := later.Add(time.Hour)
	st = run(t, d, gh.collector(cOpts{now: l2}), l2, false)
	if st.RawNew != 2 || cursorOf(t, d).Get("pending") != nil {
		t.Errorf("%+v %s", st, pyjson.Repr(cursorOf(t, d)))
	}
}

func TestRateLimited403OnFirstRequestOfIncrementalRun(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample, 100)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	before := cursorOf(t, d)
	gh.remaining = 0
	later := f.now.Add(time.Hour)
	gh.sleeps = nil
	st := run(t, d, gh.collector(cOpts{now: later}), later, false)
	if st.Fetched != 0 || len(gh.sleeps) != 0 {
		t.Errorf("%+v %v", st, gh.sleeps)
	}
	cur := cursorOf(t, d)
	reqs := gh.requests()
	if cur.Get("since") != before.Get("since") || path(cur, "pending", "reason") != "rate_limited" ||
		path(cur, "pending", "next_url") != reqs[len(reqs)-1].URL {
		t.Errorf("%s", pyjson.Repr(cur))
	}
}

func TestRateLimitedFirstRunFailsWithoutStoring(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample, 2)
	gh.remaining = 1
	err := runErr(d, gh.collector(cOpts{now: f.now}), f.now)
	if err == nil || !strings.Contains(err.Error(), "rate_limited") {
		t.Fatalf("%v", err)
	}
	want := "ghsa: stopped (rate_limited) after 1 page(s) during the first-run window: {'status': None, 'limit': 60, 'remaining': 0, 'used': 60, 'reset': 1794495459, 'reset_at': '2026-11-12T14:57:39Z'}. Nothing stored; retry later, lower NDAY_GHSA_BOOTSTRAP_DAYS, raise NDAY_GHSA_MAX_REQUESTS or set NDAY_GITHUB_TOKEN."
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error text\n got  %s\n want %s", err, want)
	}
	if getCounts(t, d) != (counts{}) {
		t.Error("rows stored")
	}
	var status string
	var cur *string
	var okAt *time.Time
	_ = d.Conn.QueryRow(context.Background(), "SELECT last_status, cursor::text, last_success_at FROM collector_state").Scan(&status, &cur, &okAt)
	if status != "error" || cur != nil || okAt != nil {
		t.Errorf("%s %v %v", status, cur, okAt)
	}
}

func TestSecondaryRateLimitRetryAfterThenSuccess(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample, 100)
	gh.fail = []cannedResp{
		{429, http.Header{"Retry-After": {"5"}, "X-Ratelimit-Remaining": {"40"}}, []byte(`{"message":"You have exceeded a secondary rate limit."}`)},
		{502, http.Header{}, nil},
	}
	c := gh.collector(cOpts{now: f.now})
	st := run(t, d, c, f.now, false)
	if len(gh.sleeps) != 2 || gh.sleeps[0] != 5*time.Second || gh.sleeps[1] != 2*time.Second || st.Fetched != len(f.sample) {
		t.Errorf("%v %+v", gh.sleeps, st)
	}
	if c.RequestsMade != 3 {
		t.Errorf("requests_made %d", c.RequestsMade)
	}
}

func TestOther4xxFailsRun(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample, 2)
	gh.fail = []cannedResp{{403, http.Header{"X-Ratelimit-Remaining": {"55"}}, []byte(`{"message":"Resource not accessible"}`)}}
	err := runErr(d, gh.collector(cOpts{now: f.now}), f.now)
	var se *httpc.StatusError
	if !errors.As(err, &se) || se.Status != 403 {
		t.Fatalf("%v", err)
	}
}

func TestFallingBehindRecordsGap(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	gh := newFake(t, f, f.sample[:1], 1)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	for i := 0; i < 3; i++ {
		gid := fmt.Sprintf("GHSA-%d%d%d%d-2222-2222", i+2, i+2, i+2, i+2)
		gh.advisories[gid] = atTS(t, withID(t, f.unpatched, gid), zfmt(f.now.Add(time.Duration(i+1)*time.Hour)))
	}
	much := f.now.AddDate(0, 0, 3)
	run(t, d, gh.collector(cOpts{now: much, maxRequests: 1, overlap: -1}), much, false)
	if !gh.logs.contains("fell behind") {
		t.Errorf("logs %v", gh.logs.msgs)
	}
	cur := cursorOf(t, d)
	gaps := cur.Get("gaps").([]any)
	if len(gaps) == 0 || path(obj(gaps[0]), "reason") != "request_cap" || cur.Get("pending") == nil {
		t.Errorf("%s", pyjson.Repr(cur))
	}
}

func TestUnpatchedToPatchedCreatesNonBackfillEvent(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	adv := atTS(t, f.unpatched, zfmt(f.now.Add(-2*time.Hour)))
	gh := newFake(t, f, []*pyjson.Object{adv}, 100)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	if n := scalar(t, d, "SELECT count(*) FROM event"); n != 0 {
		t.Fatal(n)
	}
	var alias string
	_ = d.Conn.QueryRow(ctx, "SELECT alias FROM vuln_alias WHERE cve_id=$1", adv.Get("cve_id")).Scan(&alias)
	if alias != adv.Get("ghsa_id") {
		t.Fatal(alias)
	}
	fixed := atTS(t, adv, zfmt(f.now.Add(20*time.Minute)))
	obj(fixed.Get("vulnerabilities").([]any)[0]).Set("first_patched_version", "9.9.9")
	refs, _ := fixed.Get("references").([]any)
	fixed.Set("references", append(append([]any{}, refs...), "https://github.com/acme/widget/commit/0123456789abcdef"))
	gh.advisories[str(fixed.Get("ghsa_id"))] = fixed
	later := f.now.Add(time.Hour)
	st := run(t, d, gh.collector(cOpts{now: later}), later, false)
	if st.EventInserted != 1 || st.RawNew != 1 {
		t.Errorf("%+v", st)
	}
	var typ, dk, detail string
	var occ *time.Time
	var obs time.Time
	var bf bool
	if err := d.Conn.QueryRow(ctx, "SELECT type, occurred_at, observed_at, is_backfill, dedupe_key, detail::text FROM event WHERE cve_id=$1",
		adv.Get("cve_id")).Scan(&typ, &occ, &obs, &bf, &dk, &detail); err != nil {
		t.Fatal(err)
	}
	dv, _ := pyjson.DecodeString(detail)
	if typ != "patch_released" || occ != nil || !obs.Equal(later) || bf || dk != adv.Get("ghsa_id") ||
		path(obj(obj(dv).Get("packages").([]any)[0]), "first_patched_version") != "9.9.9" ||
		pyjson.Repr(obj(dv).Get("fix_commit_urls")) != "['https://github.com/acme/widget/commit/0123456789abcdef']" {
		t.Errorf("%s %v %v %v %s %s", typ, occ, obs, bf, dk, detail)
	}
}

func TestStubVulnDoesNotOverrideCvelist(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	if _, err := d.Conn.Exec(ctx, "INSERT INTO vuln (cve_id, title, description, first_seen_at) VALUES ($1, 'CNA title', 'CNA desc', now())",
		f.patched.Get("cve_id")); err != nil {
		t.Fatal(err)
	}
	gh := newFake(t, f, []*pyjson.Object{f.patched}, 100)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	var title, desc string
	_ = d.Conn.QueryRow(ctx, "SELECT title, description FROM vuln WHERE cve_id=$1", f.patched.Get("cve_id")).Scan(&title, &desc)
	if title != "CNA title" || desc != "CNA desc" {
		t.Errorf("%q %q", title, desc)
	}
}

func TestTokenHeaderOnlyWhenConfigured(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	secret := "ghp_testtoken_not_real_000000000000"
	gh := newFake(t, f, f.sample, 100)
	c := gh.collector(cOpts{now: f.now, useEnvToken: true, env: map[string]string{TokenEnv: " " + secret + "\n"}})
	plog := &logCapture{}
	if _, err := pipeline.RunCollector(context.Background(), d.Conn, c, pipeline.Options{
		Now: func() time.Time { return f.now }, Logger: slog.New(plog)}); err != nil {
		t.Fatal(err)
	}
	if got := gh.requests()[0].Header.Get("Authorization"); got != "Bearer "+secret {
		t.Errorf("Authorization %q", got)
	}
	for _, m := range append(append([]string{}, gh.logs.msgs...), plog.msgs...) {
		if strings.Contains(m, secret) {
			t.Errorf("token logged: %s", m)
		}
	}
	var cur string
	_ = d.Conn.QueryRow(context.Background(), "SELECT cursor::text FROM collector_state").Scan(&cur)
	if strings.Contains(cur, secret) {
		t.Error("token in cursor")
	}
	// Errors never carry it either (a rejected request, a rate-limit stop).
	gh2 := newFake(t, f, f.sample, 100)
	gh2.fail = []cannedResp{{401, http.Header{}, []byte(`{"message":"Bad credentials"}`)}}
	c2 := gh2.collector(cOpts{now: f.now, useEnvToken: true, env: map[string]string{TokenEnv: secret}})
	if _, err := c2.Fetch(context.Background(), model.CollectorState{Source: Name}); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("%v", err)
	}
	gh3 := newFake(t, f, f.sample, 100)
	gh3.remaining = 0
	c3 := gh3.collector(cOpts{now: f.now, useEnvToken: true, env: map[string]string{TokenEnv: secret}})
	if _, err := c3.Fetch(context.Background(), model.CollectorState{Source: Name}); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("%v", err)
	}
	// Not configured (unset, or only whitespace): no header.
	for _, env := range []map[string]string{{}, {TokenEnv: " \t"}} {
		gh.clear()
		cn := gh.collector(cOpts{now: f.now, useEnvToken: true, env: env})
		if _, err := cn.Fetch(context.Background(), model.CollectorState{Source: Name}); err != nil {
			t.Fatal(err)
		}
		if len(gh.requests()[0].Header.Values("Authorization")) != 0 || cn.HasToken() {
			t.Error("Authorization sent without a token")
		}
	}
}

func TestSettingsFromEnv(t *testing.T) {
	envOf := func(m map[string]string) collector.Env {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	c, err := New(Options{Env: envOf(map[string]string{BootstrapEnv: "3", MaxRequestsEnv: "4", OverlapEnv: "0"})})
	if err != nil || c.BootstrapDays != 3 || c.MaxRequests != 4 || c.OverlapMinutes != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = New(Options{Env: envOf(map[string]string{BootstrapEnv: " ", MaxRequestsEnv: "", OverlapEnv: "+0_60"})})
	if err != nil || c.BootstrapDays != 7 || c.MaxRequests != 10 || c.OverlapMinutes != 60 {
		t.Fatalf("defaults %+v %v", c, err)
	}
	for _, x := range []struct {
		env map[string]string
		msg string
	}{
		{map[string]string{BootstrapEnv: "91"}, "bootstrap_days must be 0..90, got 91"},
		{map[string]string{BootstrapEnv: "-1"}, "bootstrap_days must be 0..90, got -1"},
		{map[string]string{BootstrapEnv: "7", MaxRequestsEnv: "0"}, "max_requests must be >= 1, got 0"},
		{map[string]string{OverlapEnv: "-5"}, "overlap_minutes must be >= 0, got -5"},
		{map[string]string{MaxRequestsEnv: "ten"}, "NDAY_GHSA_MAX_REQUESTS must be an integer, got 'ten'"},
		{map[string]string{BootstrapEnv: "1.5"}, "NDAY_GHSA_BOOTSTRAP_DAYS must be an integer, got '1.5'"},
	} {
		if _, err := New(Options{Env: envOf(x.env)}); err == nil || err.Error() != x.msg {
			t.Errorf("%v: %v, want %q", x.env, err, x.msg)
		}
	}
}

// The rate-limit 403 body from the real API is recognised by its text even
// without the headers (Python: "rate limit" in resp.text.lower()).
func TestRateLimitBodyDetection(t *testing.T) {
	f := load(t)
	if !isRateLimited(&response{Status: 403, Header: http.Header{}, Body: f.rateLimitedBody}) ||
		isRateLimited(&response{Status: 403, Header: http.Header{}, Body: []byte(`{"message":"Resource not accessible"}`)}) ||
		!isRateLimited(&response{Status: 403, Header: http.Header{"Retry-After": {"x"}}, Body: nil}) ||
		!isRateLimited(&response{Status: 429, Header: http.Header{}}) ||
		isRateLimited(&response{Status: 401, Header: http.Header{"X-Ratelimit-Remaining": {"0"}}}) ||
		!isRateLimited(&response{Status: 403, Header: http.Header{}, Body: []byte("RATE LIMIT")}) {
		t.Error("isRateLimited")
	}
}

// httpx.Client(follow_redirects=False) + raise_for_status: a 3xx fails the
// run and is not followed (Go: CheckRedirect = ErrUseLastResponse).
func TestRedirectIsNotFollowed(t *testing.T) {
	f := load(t)
	gh := newFake(t, f, f.sample, 100)
	gh.fail = []cannedResp{{301, http.Header{"Location": {"https://evil.example/advisories"}}, nil}}
	c := gh.collector(cOpts{now: f.now})
	_, err := c.Fetch(context.Background(), model.CollectorState{Source: Name})
	var se *httpc.StatusError
	if !errors.As(err, &se) || se.Status != 301 || len(gh.requests()) != 1 {
		t.Fatalf("%v, %d requests", err, len(gh.requests()))
	}
}
