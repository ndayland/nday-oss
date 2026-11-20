package osssec_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/collector/osssec"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseMessage788(t *testing.T) {
	m, err := osssec.ParseMessage(fixture(t, "msg_788.html"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "CVE-2026-124749: pam-mysql: inverted PAM_DISALLOW_NULL_AUTHTOK gives a pre-auth authentication bypass" {
		t.Errorf("subject %q", m.Subject)
	}
	if m.Author != "Andrey Vasilevsky" {
		t.Errorf("author %q", m.Author)
	}
	if m.Date == nil || m.Date.Format(time.RFC3339) != "2026-11-19T16:59:24Z" {
		t.Errorf("date %v", m.Date)
	}
	if m.IsReply {
		t.Error("788 is not a reply")
	}
	if !slices.Equal(m.CVEs, []string{"CVE-2026-124749"}) || len(m.GHSAs) != 0 || !slices.Equal(m.SubjectIDs, []string{"CVE-2026-124749"}) {
		t.Errorf("ids %v %v %v", m.CVEs, m.GHSAs, m.SubjectIDs)
	}
}

func TestParseMessageReply(t *testing.T) {
	m, err := osssec.ParseMessage(fixture(t, "msg_794.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsReply || m.Author != "Dominique Martinet" {
		t.Errorf("reply %v author %q", m.IsReply, m.Author)
	}
	if m.Date == nil || m.Date.Format(time.RFC3339) != "2026-11-20T00:45:22Z" { // +0900 -> UTC
		t.Errorf("date %v", m.Date)
	}
	if !slices.Equal(m.CVEs, []string{"CVE-2026-99288"}) {
		t.Errorf("cves %v", m.CVEs)
	}
}

func TestParseMessageDigest(t *testing.T) {
	m, err := osssec.ParseMessage(fixture(t, "msg_797.html"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2026-126540", "CVE-2026-126568", "CVE-2026-126576", "CVE-2026-126682",
		"CVE-2026-126819", "CVE-2026-126956", "CVE-2026-131868", "CVE-2026-131877"}
	if !slices.Equal(m.CVEs, want) || len(m.SubjectIDs) != 0 || m.IsReply {
		t.Errorf("cves %v subject ids %v reply %v", m.CVEs, m.SubjectIDs, m.IsReply)
	}
	if m.Date == nil || m.Date.Format(time.RFC3339) != "2026-11-20T02:09:52Z" {
		t.Errorf("date %v", m.Date)
	}
}

// synthPage builds a minimal MHonArc message page.
func synthPage(subject, from, date, body, refs string) []byte {
	return []byte(`<!-- MHonArc v2.6.19 -->
<html><body>
<!--X-Subject-Header-Begin-->
<h1 class="m-title">` + subject + `</h1>
<hr>
<!--X-Subject-Header-End-->
<!--X-Head-of-Message-->
<em>From</em>: ` + from + `<br>
<em>Date</em>: ` + date + `<br>
<!--X-Head-of-Message-End-->
<!--X-Body-of-Message-->
<pre style="margin: 0em;">` + body + `</pre>
<!--X-Body-of-Message-End-->
<!--X-References-->
` + refs + `
<!--X-References-End-->
</body></html>
`)
}

func TestParseMessageGHSAAndAddressOnly(t *testing.T) {
	page := synthPage("Advisory for libfoo", "someone () example org", "Mon, 2 Nov 2026 10:00:00 +0000 (UTC)",
		`See <a href="https://github.com/advisories/GHSA-2CM2-M3W5-GP2F">https://github.com/advisories/GHSA-2CM2-M3W5-GP2F</a>
and CVE&#45;2026&#45;5555<br>CVE-2026-5556, plus GHSA-zzzz-zzzz-zzzz (not GitHub's alphabet).`,
		`<ul><li><strong><a name="00001" href="1">Previous</a></strong></li></ul>`)
	m, err := osssec.ParseMessage(page)
	if err != nil {
		t.Fatal(err)
	}
	if m.Author != "" {
		t.Errorf("author %q: an address alone must not become the author", m.Author)
	}
	if !m.IsReply {
		t.Error("X-References present: a reply")
	}
	if !slices.Equal(m.GHSAs, []string{"GHSA-2cm2-m3w5-gp2f"}) || !slices.Equal(m.CVEs, []string{"CVE-2026-5555", "CVE-2026-5556"}) {
		t.Errorf("ids %v %v", m.GHSAs, m.CVEs)
	}
	if m.Date == nil || m.Date.Format(time.RFC3339) != "2026-11-02T10:00:00Z" {
		t.Errorf("date %v", m.Date)
	}
	// Re: in the subject alone also makes a reply
	m, _ = osssec.ParseMessage(synthPage("RE: [oss-security] x", `"Jane Doe" &lt;jd () example org&gt;`, "garbage", "", ""))
	if !m.IsReply || m.Author != "Jane Doe" || m.Date != nil {
		t.Errorf("%+v", m)
	}
}

func TestParseMessageNotAMessage(t *testing.T) {
	if _, err := osssec.ParseMessage([]byte("<html><body>Not Found</body></html>")); err == nil {
		t.Fatal("no error")
	}
}

func TestParseIndex(t *testing.T) {
	got := osssec.ParseIndex(fixture(t, "index_q4_sample.html"))
	want := []int{784, 787, 788, 789, 790, 792, 794, 795, 797, 798, 799, 800, 801}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
}

// --- fake archive ---

type site struct {
	mu      sync.Mutex
	srv     *httptest.Server
	index   map[string][]int // quarter -> numbers; missing = 404
	etag    map[string]string
	fail    map[string]int // path -> status to return
	pages   map[string][]byte
	reqs    []string
	indexes int
}

func newSite(t *testing.T) *site {
	s := &site{index: map[string][]int{}, etag: map[string]string{}, fail: map[string]int{}, pages: map[string][]byte{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func indexHTML(nums []int) []byte {
	var b strings.Builder
	b.WriteString("<!-- SecLists-Message-Count: " + strconv.Itoa(len(nums)) + " -->\n<ul class=\"thread\">\n")
	for i := len(nums) - 1; i >= 0; i-- { // order on the page doesn't matter
		fmt.Fprintf(&b, "<li><a name=\"%d\" href=\"%d\">Subject %d</a> <em>Someone (Nov 19)</em></li>\n", nums[i], nums[i], nums[i])
	}
	b.WriteString("</ul>\n")
	return []byte(b.String())
}

func (s *site) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/oss-sec/")
	s.reqs = append(s.reqs, p)
	if st, ok := s.fail[p]; ok {
		w.WriteHeader(st)
		return
	}
	if strings.HasSuffix(p, "/") { // index
		s.indexes++
		q := strings.TrimSuffix(p, "/")
		nums, ok := s.index[q]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if e := s.etag[q]; e != "" {
			if r.Header.Get("If-None-Match") == e {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", e)
		}
		_, _ = w.Write(indexHTML(nums))
		return
	}
	if b, ok := s.pages[p]; ok {
		_, _ = w.Write(b)
		return
	}
	i := strings.LastIndex(p, "/")
	q := p[:i]
	n, _ := strconv.Atoi(p[i+1:])
	if !slices.Contains(s.index[q], n) {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(synthPage(fmt.Sprintf("Post %d about CVE-2026-%d", n, 10000+n), "Poster &lt;p () example org&gt;",
		"Thu, 19 Nov 2026 08:59:24 -0800", "nothing else", ""))
}

func (s *site) messageReqs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.reqs {
		if !strings.HasSuffix(r, "/") {
			out = append(out, r)
		}
	}
	return out
}

func (s *site) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs, s.indexes = nil, 0
}

func rangeInts(a, b int) []int {
	var out []int
	for i := a; i <= b; i++ {
		out = append(out, i)
	}
	return out
}

type run struct {
	c      *osssec.Collector
	sleeps []time.Duration
}

func newCollector(t *testing.T, s *site, now time.Time, env map[string]string, maxRun int) *run {
	t.Helper()
	r := &run{}
	c, err := osssec.New(osssec.Options{BaseURL: s.srv.URL + "/oss-sec/", Clock: func() time.Time { return now },
		Env: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Sleep: func(_ context.Context, d time.Duration) error {
			r.sleeps = append(r.sleeps, d)
			return nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), MaxPerRun: maxRun})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	return r
}

var nov20 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func cursorOf(q string, last int, etag any) any {
	o := pyjson.NewObject()
	o.Set("quarter", q)
	o.Set("last_number", pyjson.IntOf(int64(last)))
	o.Set("etag", etag)
	o.Set("last_modified", nil)
	return o
}

func keys(recs []model.RawRecord) []string {
	var out []string
	for _, r := range recs {
		out = append(out, r.SourceKey)
	}
	return out
}

func keysOf(q string, nums ...int) []string {
	var out []string
	for _, n := range nums {
		out = append(out, q+"/"+strconv.Itoa(n))
	}
	return out
}

func cur(t *testing.T, res *model.FetchResult) (string, int, any) {
	t.Helper()
	o := res.Cursor.(*pyjson.Object)
	n, _ := strconv.Atoi(string(o.Get("last_number").(pyjson.Int)))
	return o.Get("quarter").(string), n, o.Get("etag")
}

func TestFirstRunTakesNewest40(t *testing.T) {
	s := newSite(t)
	s.index["2026/q4"] = rangeInts(0, 99)
	s.etag["2026/q4"] = `"e1"`
	r := newCollector(t, s, nov20, nil, 0)
	res, err := r.c.Fetch(context.Background(), model.CollectorState{})
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(res.Records); !slices.Equal(got, keysOf("2026/q4", rangeInts(60, 99)...)) {
		t.Errorf("records %v", got)
	}
	if q, n, e := cur(t, res); q != "2026/q4" || n != 99 || e != `"e1"` {
		t.Errorf("cursor %s %d %v", q, n, e)
	}
	// politeness: one gap of at least a second before every request but the first
	if len(r.sleeps) != 40 {
		t.Errorf("%d sleeps for 41 requests", len(r.sleeps))
	}
	for _, d := range r.sleeps {
		if d < time.Second {
			t.Errorf("gap %s", d)
		}
	}
	// the payload
	p := res.Records[0].Payload.(*pyjson.Object)
	want := `{"url": "https://seclists.org/oss-sec/2026/q4/60", "year": 2026, "quarter": 4, "number": 60, "subject": "Post 60 about CVE-2026-10060", "author": "Poster", "date": "2026-11-19T16:59:24Z", "is_reply": false, "cve_ids": ["CVE-2026-10060"], "ghsa_ids": [], "subject_ids": ["CVE-2026-10060"]}`
	if got, _ := pyjson.Encode(p, pyjson.Options{}); got != want {
		t.Errorf("payload\n%s\nwant\n%s", got, want)
	}
}

func TestIncremental(t *testing.T) {
	s := newSite(t)
	s.index["2026/q4"] = rangeInts(0, 59)
	s.etag["2026/q4"] = `"e2"`
	ctx := context.Background()

	// only numbers above the cursor, ascending
	res, err := newCollector(t, s, nov20, nil, 0).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 55, `"e1"`)})
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(res.Records); !slices.Equal(got, keysOf("2026/q4", 56, 57, 58, 59)) {
		t.Errorf("records %v", got)
	}
	if q, n, e := cur(t, res); q != "2026/q4" || n != 59 || e != `"e2"` {
		t.Errorf("cursor %s %d %v", q, n, e)
	}

	// cap respected; the index validators are dropped (the index isn't done)
	s.reset()
	res, err = newCollector(t, s, nov20, nil, 2).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 55, `"e1"`)})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.messageReqs(); !slices.Equal(got, keysOf("2026/q4", 56, 57)) {
		t.Errorf("requests %v", got)
	}
	if q, n, e := cur(t, res); q != "2026/q4" || n != 57 || e != nil {
		t.Errorf("cursor %s %d %v", q, n, e)
	}

	// 304 on the index: no message request at all
	s.reset()
	res, err = newCollector(t, s, nov20, nil, 0).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 59, `"e2"`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || len(s.messageReqs()) != 0 || s.indexes != 1 {
		t.Errorf("%d records, requests %v", len(res.Records), s.reqs)
	}
	if q, n, e := cur(t, res); q != "2026/q4" || n != 59 || e != `"e2"` {
		t.Errorf("cursor %s %d %v", q, n, e)
	}

	// a gone message is skipped and the cursor moves past it
	s.reset()
	s.fail["2026/q4/57"] = http.StatusNotFound
	res, err = newCollector(t, s, nov20, nil, 0).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 55, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(res.Records); !slices.Equal(got, keysOf("2026/q4", 56, 58, 59)) {
		t.Errorf("records %v", got)
	}
	if _, n, _ := cur(t, res); n != 59 {
		t.Errorf("cursor %d", n)
	}
}

func TestStopsOnFailure(t *testing.T) {
	s := newSite(t)
	s.index["2026/q4"] = rangeInts(0, 59)
	s.etag["2026/q4"] = `"e2"`
	s.fail["2026/q4/58"] = http.StatusInternalServerError
	ctx := context.Background()
	res, err := newCollector(t, s, nov20, nil, 0).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 55, `"e1"`)})
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(res.Records); !slices.Equal(got, keysOf("2026/q4", 56, 57)) {
		t.Errorf("records %v", got)
	}
	if q, n, e := cur(t, res); q != "2026/q4" || n != 57 || e != nil {
		t.Errorf("cursor %s %d %v", q, n, e)
	}
	lr := res.Cursor.(*pyjson.Object).Get("last_run").(*pyjson.Object)
	if st, _ := lr.Get("stopped").(string); !strings.Contains(st, "2026/q4/58") {
		t.Errorf("stopped %v", lr.Get("stopped"))
	}
	// nothing fetched before the failure: the run fails and the cursor stays
	if _, err := newCollector(t, s, nov20, nil, 0).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 57, nil)}); err == nil {
		t.Error("no error")
	}
	// a page that isn't a message page stops the run the same way
	s.fail = map[string]int{}
	s.pages["2026/q4/58"] = []byte("<html>maintenance</html>")
	if _, err := newCollector(t, s, nov20, nil, 0).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 57, nil)}); err == nil ||
		!strings.Contains(err.Error(), "MHonArc") {
		t.Errorf("err %v", err)
	}
}

func TestQuarterRollover(t *testing.T) {
	s := newSite(t)
	s.index["2026/q4"] = rangeInts(0, 60)
	jan := time.Date(2027, 1, 1, 0, 30, 0, 0, time.UTC)
	ctx := context.Background()

	// the old quarter is finished, the new one has no index yet
	res, err := newCollector(t, s, jan, nil, 0).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 58, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(res.Records); !slices.Equal(got, keysOf("2026/q4", 59, 60)) {
		t.Errorf("records %v", got)
	}
	if q, n, _ := cur(t, res); q != "2027/q1" || n != -1 {
		t.Errorf("cursor %s %d", q, n)
	}
	// next run: the new quarter has posts, taken from 0 (not "first run")
	s.index["2027/q1"] = rangeInts(0, 2)
	res, err = newCollector(t, s, jan, nil, 0).c.Fetch(ctx, model.CollectorState{Cursor: res.Cursor})
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(res.Records); !slices.Equal(got, keysOf("2027/q1", 0, 1, 2)) {
		t.Errorf("records %v", got)
	}
	// both quarters in one run, the cap shared
	s.reset()
	res, err = newCollector(t, s, jan, nil, 3).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 58, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(res.Records); !slices.Equal(got, append(keysOf("2026/q4", 59, 60), keysOf("2027/q1", 0)...)) {
		t.Errorf("records %v", got)
	}
	if q, n, _ := cur(t, res); q != "2027/q1" || n != 0 {
		t.Errorf("cursor %s %d", q, n)
	}
	// the old quarter's leftovers are not lost when the cap ends the run there
	res, err = newCollector(t, s, jan, nil, 1).c.Fetch(ctx, model.CollectorState{Cursor: cursorOf("2026/q4", 58, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if q, n, _ := cur(t, res); q != "2026/q4" || n != 59 {
		t.Errorf("cursor %s %d", q, n)
	}
}

func TestBackfill(t *testing.T) {
	s := newSite(t)
	s.index["2026/q4"] = rangeInts(0, 59)
	r := newCollector(t, s, nov20, map[string]string{osssec.BackfillEnv: "1"}, 0)
	res, err := r.c.Fetch(context.Background(), model.CollectorState{Cursor: cursorOf("2026/q4", 59, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 60 || res.Records[0].SourceKey != "2026/q4/0" {
		t.Errorf("%d records", len(res.Records))
	}
	if q, n, _ := cur(t, res); q != "2026/q4" || n != 59 {
		t.Errorf("cursor %s %d", q, n)
	}
	for _, d := range r.sleeps {
		if d < time.Second {
			t.Errorf("gap %s", d)
		}
	}
	if _, err := osssec.New(osssec.Options{Env: func(string) (string, bool) { return "maybe", true }}); err == nil {
		t.Error("bad backfill value accepted")
	}
}

func rec(t *testing.T, name, key string) model.RawRecord {
	t.Helper()
	m, err := osssec.ParseMessage(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return msgRecord(key, m)
}

// msgRecord builds the raw record Fetch would store for key.
func msgRecord(key string, m *osssec.Message) model.RawRecord {
	i := strings.LastIndex(key, "/")
	q, _ := osssec.ParseQuarter(key[:i])
	n, _ := strconv.Atoi(key[i+1:])
	return osssec.Record(q, n, m)
}

func TestNormalize(t *testing.T) {
	c, _ := osssec.New(osssec.Options{})
	n, err := c.Normalize(rec(t, "msg_788.html", "2026/q4/788"))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Events) != 1 || len(n.Vulns) != 0 {
		t.Fatalf("%+v", n)
	}
	e := n.Events[0]
	if e.CVEID != "CVE-2026-124749" || e.Type != model.EventAnalysisPublished || e.Source != "osssec" || e.DedupeKey != "2026/q4/788" ||
		*e.URL != "https://seclists.org/oss-sec/2026/q4/788" || e.OccurredAt.Format(time.RFC3339) != "2026-11-19T16:59:24Z" {
		t.Errorf("%+v", e)
	}
	d, _ := pyjson.Encode(e.Detail, pyjson.Options{SortKeys: true})
	if d != `{"author": "Andrey Vasilevsky", "is_reply": false, "list": "oss-security", "subject": "CVE-2026-124749: pam-mysql: inverted PAM_DISALLOW_NULL_AUTHTOK gives a pre-auth authentication bypass"}` {
		t.Errorf("detail %s", d)
	}

	// no id: no event
	m, _ := osssec.ParseMessage(synthPage("Hello", "A &lt;a () b c&gt;", "Thu, 19 Nov 2026 08:59:24 -0800", "no ids here", ""))
	if n, err := c.Normalize(msgRecord("2026/q4/1", m)); err != nil || len(n.Events) != 0 {
		t.Errorf("%v %+v", err, n)
	}

	// GHSA ids give GHSA-keyed events; implausible years are dropped; at most 50 ids
	var body strings.Builder
	body.WriteString("GHSA-2cm2-m3w5-gp2f CVE-1998-1234 CVE-2031-1234 ")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&body, "CVE-2026-%d ", 20000+i)
	}
	m, _ = osssec.ParseMessage(synthPage("Digest CVE-2026-29999", "A &lt;a () b c&gt;", "Thu, 19 Nov 2026 08:59:24 -0800", body.String(), ""))
	n, err = c.Normalize(msgRecord("2026/q4/2", m))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range n.Events {
		ids = append(ids, e.CVEID)
	}
	if len(ids) != osssec.MaxIDsPerPost || ids[0] != "CVE-2026-29999" || slices.Contains(ids, "CVE-1998-1234") || slices.Contains(ids, "CVE-2031-1234") {
		t.Errorf("ids %v", ids)
	}
	m.CVEs = m.CVEs[:3]
	n, _ = c.Normalize(msgRecord("2026/q4/2", m))
	ids = nil
	for _, e := range n.Events {
		ids = append(ids, e.CVEID)
	}
	if !slices.Equal(ids, []string{"CVE-2026-29999", "GHSA-2cm2-m3w5-gp2f"}) {
		t.Errorf("ids %v", ids)
	}

	// a malformed payload is a NormalizeError
	if _, err := c.Normalize(model.RawRecord{Source: "osssec", SourceKey: "x", Payload: "nope"}); err == nil {
		t.Error("no error")
	}
}
