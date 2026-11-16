package cvelist_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/cvelist"
	"nday.land/nday/internal/collector/kev"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

// Ports of tests/test_cvelist.py and tests/test_cvelist_backfill.py. Besides
// the assertions of the Python tests, every run is compared with what the
// Python implementation produced in the same scenario (stats JSON and the
// FULL stored cursor JSON), recorded by testdata/record_runs.py into
// testdata/python_runs.json.

var (
	NOW   = time.Date(2026, 11, 12, 14, 0, 0, 0, time.UTC)
	TODAY = time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	H     = time.Hour
)

const countSQL = `SELECT (SELECT count(*) FROM raw_record), (SELECT count(*) FROM vuln),
                      (SELECT count(*) FROM vuln_alias), (SELECT count(*) FROM affected),
                      (SELECT count(*) FROM event)`

type counts [5]int64

func getCounts(t *testing.T, d *testutil.TestDB) counts {
	t.Helper()
	var c counts
	if err := d.Conn.QueryRow(context.Background(), countSQL).Scan(&c[0], &c[1], &c[2], &c[3], &c[4]); err != nil {
		t.Fatal(err)
	}
	return c
}

// changeSet has the same shape as a real deltaLog entry.
func changeSet(fetchTime string, newIDs, updated []string) *pyjson.Object {
	items := func(ids []string) []any {
		out := []any{}
		for _, c := range ids {
			o := pyjson.NewObject()
			o.Set("cveId", c)
			o.Set("cveOrgLink", "https://www.cve.org/CVERecord?id="+c)
			o.Set("githubLink", cvelist.RecordURL(c))
			o.Set("dateUpdated", fetchTime)
			out = append(out, o)
		}
		return out
	}
	o := pyjson.NewObject()
	o.Set("fetchTime", fetchTime)
	o.Set("numberOfChanges", pyjson.IntOf(int64(len(newIDs)+len(updated))))
	o.Set("new", items(newIDs))
	o.Set("updated", items(updated))
	o.Set("error", []any{})
	return o
}

type zipEntry struct {
	id      string
	payload *pyjson.Object
}

// upstream is FakeUpstream: deltaLog (newest first), end-of-day zips, record files.
type upstream struct {
	t      *testing.T
	mu     sync.Mutex
	log    []*pyjson.Object
	zips   map[string][]zipEntry // day -> members
	files  map[string]*pyjson.Object
	fail   map[string][]int // url -> statuses to return first
	ft     *testutil.FakeTransport
	sleeps []time.Duration
	logBuf *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

func encode(t testing.TB, v any) []byte {
	s, err := pyjson.Encode(v, pyjson.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{t: t, zips: map[string][]zipEntry{}, files: map[string]*pyjson.Object{},
		fail: map[string][]int{}, logBuf: &syncBuffer{}}
	for _, c := range ALL {
		u.files[c] = rec(t, c)
	}
	u.ft = &testutil.FakeTransport{Handler: u.handle}
	return u
}

func (u *upstream) handle(r *http.Request) (int, http.Header, []byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	url := r.URL.String()
	if f := u.fail[url]; len(f) > 0 {
		u.fail[url] = f[1:]
		return f[0], nil, nil, nil
	}
	if url == cvelist.DeltaLogURL {
		l := make([]any, len(u.log))
		for i, e := range u.log {
			l[i] = e
		}
		return 200, nil, encode(u.t, l), nil
	}
	for day, recs := range u.zips {
		d, _ := time.Parse("2006-01-02", day)
		if url == cvelist.EODZipURL(d) {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for _, e := range recs {
				w, _ := zw.Create("deltaCves/" + e.id + ".json")
				_, _ = w.Write(encode(u.t, e.payload))
			}
			_ = zw.Close()
			return 200, nil, buf.Bytes(), nil
		}
	}
	for c, p := range u.files {
		if url == cvelist.RecordURL(c) {
			return 200, nil, encode(u.t, p), nil
		}
	}
	return 404, nil, nil, nil
}

func (u *upstream) urls() []string {
	var out []string
	for _, r := range u.ft.Requests {
		out = append(out, r.URL)
	}
	return out
}

func (u *upstream) clear() { u.ft.Requests = nil }

func (u *upstream) fetchedFiles() map[string]bool {
	out := map[string]bool{}
	for _, x := range u.urls() {
		if x != cvelist.DeltaLogURL {
			out[x] = true
		}
	}
	return out
}

func urlSet(ids ...string) map[string]bool {
	out := map[string]bool{}
	for _, c := range ids {
		out[cvelist.RecordURL(c)] = true
	}
	return out
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

type opts struct {
	bootstrapDays, maxFiles, retryDays *int
	maxMissing, concurrency            int
}

func ip(n int) *int { return &n }

// collector is FakeUpstream.collector: bootstrap_days=2, max_files=100 by default.
func (u *upstream) collector(now time.Time, o opts) *cvelist.Collector {
	if o.bootstrapDays == nil {
		o.bootstrapDays = ip(2)
	}
	if o.maxFiles == nil {
		o.maxFiles = ip(100)
	}
	u.sleeps = nil
	c, err := cvelist.New(cvelist.Options{
		Transport: u.ft, BootstrapDays: o.bootstrapDays, MaxFiles: o.maxFiles, BackfillRetryDays: o.retryDays,
		Clock: func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error {
			u.mu.Lock()
			u.sleeps = append(u.sleeps, d)
			u.mu.Unlock()
			return nil
		},
		Logger:             slog.New(slog.NewTextHandler(u.logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		MaxBackfillMissing: o.maxMissing,
		Concurrency:        o.concurrency,
	})
	if err != nil {
		u.t.Fatal(err)
	}
	return c
}

// pyRuns compares each pipeline run with the Python run at the same index.
type pyRuns struct {
	t    *testing.T
	d    *testutil.TestDB
	runs []any
	i    int
}

var (
	pyRunsOnce sync.Once
	pyRunsAll  *pyjson.Object
)

func newPyRuns(t *testing.T, d *testutil.TestDB, test string) *pyRuns {
	pyRunsOnce.Do(func() {
		v, err := pyjson.Decode(testutil.ReadFile(t, "internal/collector/cvelist/testdata/python_runs.json"))
		if err != nil {
			t.Fatal(err)
		}
		pyRunsAll = v.(*pyjson.Object)
	})
	runs, ok := pyRunsAll.Get(test).([]any)
	if !ok {
		t.Fatalf("no recorded Python runs for %s", test)
	}
	p := &pyRuns{t: t, d: d, runs: runs}
	t.Cleanup(func() {
		if !t.Failed() && p.i != len(runs) {
			t.Errorf("%d runs, Python made %d", p.i, len(runs))
		}
	})
	return p
}

func (p *pyRuns) run(c collector.Collector, now time.Time, renorm bool) (*pipeline.Stats, error) {
	p.t.Helper()
	st, err := pipeline.RunCollector(context.Background(), p.d.Conn, c, pipeline.Options{
		Now: func() time.Time { return now }, Renormalize: renorm})
	if p.i >= len(p.runs) {
		p.t.Fatalf("run %d: Python made only %d runs", p.i, len(p.runs))
	}
	want := p.runs[p.i].(*pyjson.Object)
	p.i++
	if e, ok := want.Lookup("error"); ok {
		if err == nil {
			p.t.Errorf("run %d: Go succeeded, Python raised %v", p.i, e)
		}
	} else if err != nil {
		p.t.Fatalf("run %d: %v", p.i, err)
	} else {
		b, _ := json.Marshal(st)
		got, _ := pyjson.Decode(b)
		if canon(p.t, got) != canon(p.t, want.Get("stats")) {
			p.t.Errorf("run %d stats:\n got  %s\n want %s", p.i, canon(p.t, got), canon(p.t, want.Get("stats")))
		}
	}
	var cur, status *string
	_ = p.d.Conn.QueryRow(context.Background(),
		"SELECT cursor::text, last_status FROM collector_state WHERE source='cvelist'").Scan(&cur, &status)
	var gotCur any
	if cur != nil {
		gotCur, _ = pyjson.DecodeString(*cur)
	}
	if g, w := canon(p.t, gotCur), canon(p.t, want.Get("cvelist_cursor")); g != w {
		p.t.Errorf("run %d cursor:\n got  %s\n want %s", p.i, g, w)
	}
	var gs any
	if status != nil {
		gs = *status
	}
	if gs != want.Get("cvelist_status") {
		p.t.Errorf("run %d status %v, Python %v", p.i, gs, want.Get("cvelist_status"))
	}
	return st, err
}

func (p *pyRuns) mustRun(c collector.Collector, now time.Time) *pipeline.Stats {
	p.t.Helper()
	st, err := p.run(c, now, false)
	if err != nil {
		p.t.Fatal(err)
	}
	return st
}

func cursorOf(t *testing.T, d *testutil.TestDB) *pyjson.Object {
	t.Helper()
	var s string
	if err := d.Conn.QueryRow(context.Background(), "SELECT cursor::text FROM collector_state WHERE source='cvelist'").Scan(&s); err != nil {
		t.Fatal(err)
	}
	v, err := pyjson.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*pyjson.Object)
}

func lastRun(t *testing.T, d *testutil.TestDB) *pyjson.Object {
	return obj(cursorOf(t, d).Get("last_run"))
}

func n(v any) pyjson.Int { return v.(pyjson.Int) }

func i64(x int) pyjson.Int { return pyjson.IntOf(int64(x)) }

// standardUp is the `up` fixture of test_cvelist.py.
func standardUp(t *testing.T) *upstream {
	u := newUpstream(t)
	d1, d2 := TODAY.AddDate(0, 0, -2).Format("2006-01-02"), TODAY.AddDate(0, 0, -1).Format("2006-01-02")
	u.zips = map[string][]zipEntry{
		d1: {{TYPICAL, rec(t, TYPICAL)}, {NO_TITLE, rec(t, NO_TITLE)}},
		d2: {{V4, rec(t, V4)}, {NA, rec(t, NA)}},
	}
	u.log = []*pyjson.Object{
		changeSet("2026-11-12T09:00:00.000Z", []string{KEVREC}, nil),
		changeSet("2026-11-12T08:00:00.000Z", nil, []string{REJECTED, TYPICAL}),
		changeSet("2026-11-11T10:00:00.000Z", []string{V4, NA}, nil),
		changeSet("2026-11-10T10:00:00.000Z", []string{TYPICAL, NO_TITLE}, nil),
		changeSet("2026-10-13T13:54:47.805Z", []string{"CVE-2026-100000"}, nil),
	}
	return u
}

// ----------------------------------------------------------------- test_cvelist.py

func TestFirstRunUsesZipsThenDeltaLogForToday(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_first_run_uses_zips_then_deltalog_for_today")
	up := standardUp(t)
	st := py.mustRun(up.collector(NOW, opts{}), NOW)

	urls := up.urls()
	if urls[0] != cvelist.DeltaLogURL || !strings.Contains(strings.Join(urls, " "), cvelist.EODZipURL(TODAY.AddDate(0, 0, -2))) ||
		!strings.Contains(strings.Join(urls, " "), cvelist.EODZipURL(TODAY.AddDate(0, 0, -1))) {
		t.Errorf("urls %v", urls)
	}
	files := map[string]bool{}
	for _, x := range urls {
		if strings.Contains(x, "raw.githubusercontent.com") && x != cvelist.DeltaLogURL {
			files[x] = true
		}
	}
	if !sameSet(files, urlSet(KEVREC, REJECTED, TYPICAL)) || len(urls) != 6 {
		t.Errorf("files %v", files)
	}
	for _, r := range up.ft.Requests {
		if r.Header.Get("User-Agent") != httpc.UserAgent {
			t.Errorf("UA %q", r.Header.Get("User-Agent"))
		}
	}
	if !st.IsBackfill || st.Fetched != 6 || st.RawNew != 6 || st.NormalizeErrors != 0 {
		t.Errorf("stats %+v", st)
	}
	if c := getCounts(t, d); c[0] != 6 || c[1] != 6 {
		t.Errorf("counts %v", c)
	}
	var nbf int
	_ = d.Conn.QueryRow(context.Background(), "SELECT count(*) FROM event WHERE type='disclosed' AND is_backfill").Scan(&nbf)
	if nbf != 6 {
		t.Errorf("backfill events %d", nbf)
	}
	cur := cursorOf(t, d)
	bs := obj(cur.Get("bootstrap"))
	if cur.Get("last_fetch_time") != "2026-11-12T09:00:00.000Z" || len(cur.Get("pending").([]any)) != 0 ||
		len(cur.Get("gaps").([]any)) != 0 || canon(t, bs.Get("zip_days")) != `["2026-11-10","2026-11-11"]` ||
		bs.Get("deltalog_from") != "2026-11-12T00:00:00+00:00" {
		t.Errorf("cursor %s", canon(t, cur))
	}
	lr := obj(cur.Get("last_run"))
	if lr.Get("files_fetched") != i64(3) || lr.Get("http_requests") != i64(6) {
		t.Errorf("last_run %s", canon(t, lr))
	}
}

func TestFirstRunFallsBackToDeltaLogWhenZipMissing(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_first_run_falls_back_to_deltalog_when_zip_missing")
	up := standardUp(t)
	delete(up.zips, TODAY.AddDate(0, 0, -1).Format("2006-01-02")) // yesterday's release not published yet
	py.mustRun(up.collector(NOW, opts{}), NOW)
	files := map[string]bool{}
	for _, x := range up.urls() {
		if strings.HasSuffix(x, ".json") && x != cvelist.DeltaLogURL {
			files[x] = true
		}
	}
	if !sameSet(files, urlSet(V4, NA, REJECTED, TYPICAL, KEVREC)) {
		t.Errorf("files %v", files)
	}
	bs := obj(cursorOf(t, d).Get("bootstrap"))
	if canon(t, bs.Get("zip_days")) != `["2026-11-10"]` || bs.Get("deltalog_from") != "2026-11-11T00:00:00+00:00" {
		t.Errorf("bootstrap %s", canon(t, bs))
	}
}

func TestSecondRunIsIdempotent(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_second_run_is_idempotent")
	up := standardUp(t)
	py.mustRun(up.collector(NOW, opts{}), NOW)
	before := getCounts(t, d)
	up.clear()
	st := py.mustRun(up.collector(NOW.Add(H), opts{}), NOW.Add(H))
	if u := up.urls(); len(u) != 1 || u[0] != cvelist.DeltaLogURL {
		t.Errorf("urls %v", u)
	}
	if st.Fetched != 0 || st.IsBackfill || getCounts(t, d) != before {
		t.Errorf("stats %+v", st)
	}
	// renormalize of unchanged data adds nothing either (Python: collector clock defaults to NOW)
	if _, err := py.run(up.collector(NOW, opts{}), NOW.Add(2*H), true); err != nil {
		t.Fatal(err)
	}
	if getCounts(t, d) != before {
		t.Error("renormalize added rows")
	}
}

func TestIncrementalFetchesOnlyNewChangeSets(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	py := newPyRuns(t, d, "test_incremental_fetches_only_new_change_sets")
	up := standardUp(t)
	py.mustRun(up.collector(NOW, opts{}), NOW)
	later := NOW.Add(H)
	changed := rec(t, NA)
	obj(changed.Get("cveMetadata")).Set("dateUpdated", "2026-11-12T14:30:00.000Z")
	up.files[NA] = changed
	up.log = append([]*pyjson.Object{changeSet("2026-11-12T14:30:00.000Z", nil, []string{NA})}, up.log...)
	up.clear()

	st := py.mustRun(up.collector(later, opts{}), later)
	if u := up.urls(); len(u) != 2 || u[0] != cvelist.DeltaLogURL || u[1] != cvelist.RecordURL(NA) {
		t.Errorf("urls %v", u)
	}
	if st.Fetched != 1 || st.RawNew != 1 || st.EventInserted != 0 || st.EventUpdated != 0 || st.VulnUpdated != 1 {
		t.Errorf("stats %+v", st)
	}
	var mod time.Time
	_ = d.Conn.QueryRow(ctx, "SELECT modified_at FROM vuln WHERE cve_id=$1", NA).Scan(&mod)
	if !mod.Equal(ts("2026-11-12T14:30:00+00:00")) {
		t.Errorf("modified_at %v", mod)
	}
	var cnt int
	var allBF bool
	_ = d.Conn.QueryRow(ctx, "SELECT count(*), bool_and(is_backfill) FROM event WHERE cve_id=$1", NA).Scan(&cnt, &allBF)
	if cnt != 1 || !allBF {
		t.Errorf("events %d %v", cnt, allBF)
	}
	cur := cursorOf(t, d)
	if cur.Get("last_fetch_time") != "2026-11-12T14:30:00.000Z" || obj(cur.Get("last_run")).Get("change_sets") != i64(1) {
		t.Errorf("cursor %s", canon(t, cur))
	}

	// a genuinely new CVE after bootstrap is not backfill
	nw := rec(t, NA)
	obj(nw.Get("cveMetadata")).Set("cveId", "CVE-2026-999999")
	up.files["CVE-2026-999999"] = nw
	up.log = append([]*pyjson.Object{changeSet("2026-11-12T15:30:00.000Z", []string{"CVE-2026-999999"}, nil)}, up.log...)
	py.mustRun(up.collector(NOW, opts{}), later.Add(H))
	var bf bool
	var obs time.Time
	_ = d.Conn.QueryRow(ctx, "SELECT is_backfill, observed_at FROM event WHERE cve_id='CVE-2026-999999'").Scan(&bf, &obs)
	if bf || !obs.Equal(later.Add(H)) {
		t.Errorf("new CVE %v %v", bf, obs)
	}
}

func TestFallingBehindWarnsAndRecordsGap(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_falling_behind_warns_and_records_gap")
	up := standardUp(t)
	py.mustRun(up.collector(NOW, opts{}), NOW)
	muchLater := NOW.Add(40 * 24 * H)
	up.log = []*pyjson.Object{
		changeSet("2026-12-22T10:00:00.000Z", []string{NA}, nil),
		changeSet("2026-11-22T10:00:00.000Z", []string{V4}, nil),
	}
	up.logBuf.Reset()
	py.mustRun(up.collector(muchLater, opts{}), muchLater)
	if !strings.Contains(up.logBuf.String(), "fell behind") {
		t.Error("no fell-behind warning")
	}
	cur := cursorOf(t, d)
	want := `[{"detected_at":"2026-12-22T14:00:00+00:00","log_starts":"2026-11-22T10:00:00.000Z","missed_from":"2026-11-12T09:00:00.000Z"}]`
	if canon(t, cur.Get("gaps")) != want || cur.Get("last_fetch_time") != "2026-12-22T10:00:00.000Z" {
		t.Errorf("cursor %s", canon(t, cur))
	}
	// no false alarm when the log still covers the cursor
	up.logBuf.Reset()
	up.log = append([]*pyjson.Object{changeSet("2026-12-22T11:00:00.000Z", []string{NA}, nil)}, up.log...)
	py.mustRun(up.collector(NOW, opts{}), muchLater.Add(H))
	if strings.Contains(up.logBuf.String(), "fell behind") {
		t.Error("false fell-behind warning")
	}
	if len(cursorOf(t, d).Get("gaps").([]any)) != 1 {
		t.Error("gaps grew")
	}
}

func TestPerRunCapKeepsBacklogPending(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_per_run_cap_keeps_backlog_pending")
	up := standardUp(t)
	up.zips = map[string][]zipEntry{}
	py.mustRun(up.collector(NOW, opts{bootstrapDays: ip(0), maxFiles: ip(2)}), NOW)
	if !sameSet(up.fetchedFiles(), urlSet(REJECTED, TYPICAL)) { // oldest change sets first
		t.Errorf("files %v", up.fetchedFiles())
	}
	cur := cursorOf(t, d)
	if canon(t, cur.Get("pending")) != `["`+KEVREC+`"]` || cur.Get("last_fetch_time") != "2026-11-12T09:00:00.000Z" {
		t.Errorf("cursor %s", canon(t, cur))
	}
	up.log = append([]*pyjson.Object{changeSet("2026-11-12T15:00:00.000Z", []string{NA, V4}, nil)}, up.log...)
	up.clear()
	py.mustRun(up.collector(NOW, opts{maxFiles: ip(2)}), NOW.Add(H))
	if !sameSet(up.fetchedFiles(), urlSet(KEVREC, NA)) {
		t.Errorf("files %v", up.fetchedFiles())
	}
	cur = cursorOf(t, d)
	if canon(t, cur.Get("pending")) != `["`+V4+`"]` || obj(cur.Get("last_run")).Get("ids_queued") != i64(3) {
		t.Errorf("cursor %s", canon(t, cur))
	}
}

func TestRetryWithBackoffThenFailureStaysPending(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_retry_with_backoff_then_failure_stays_pending")
	up := standardUp(t)
	up.zips = map[string][]zipEntry{}
	up.fail[cvelist.RecordURL(TYPICAL)] = []int{503, 429}          // recovers on 3rd attempt
	up.fail[cvelist.RecordURL(KEVREC)] = []int{500, 500, 500, 500} // exhausts retries
	c := up.collector(NOW, opts{bootstrapDays: ip(0)})
	st := py.mustRun(c, NOW)
	sl := append([]time.Duration{}, up.sleeps...)
	sort.Slice(sl, func(i, j int) bool { return sl[i] < sl[j] })
	if canon(t, durations(sl)) != `[1,1,2,2,4]` {
		t.Errorf("sleeps %v", sl)
	}
	if st.Fetched != 2 {
		t.Errorf("stats %+v", st)
	}
	cur := cursorOf(t, d)
	if canon(t, cur.Get("pending")) != `["`+KEVREC+`"]` || obj(cur.Get("last_run")).Get("files_failed") != i64(1) {
		t.Errorf("cursor %s", canon(t, cur))
	}
}

func durations(ds []time.Duration) []any {
	out := []any{}
	for _, d := range ds {
		out = append(out, pyjson.IntOf(int64(d/time.Second)))
	}
	return out
}

func TestMissingRecordFileIsDropped(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_missing_record_file_is_dropped")
	up := standardUp(t)
	up.zips = map[string][]zipEntry{}
	delete(up.files, KEVREC)
	py.mustRun(up.collector(NOW, opts{bootstrapDays: ip(0)}), NOW)
	cur := cursorOf(t, d)
	if len(cur.Get("pending").([]any)) != 0 || canon(t, obj(cur.Get("last_run")).Get("files_missing")) != `["`+KEVREC+`"]` {
		t.Errorf("cursor %s", canon(t, cur))
	}
}

func TestDeltaLogFailureFailsRunAndKeepsCursor(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_deltalog_failure_fails_run_and_keeps_cursor")
	up := standardUp(t)
	py.mustRun(up.collector(NOW, opts{}), NOW)
	before := canon(t, cursorOf(t, d))
	up.fail[cvelist.DeltaLogURL] = []int{502, 502, 502, 502}
	_, err := py.run(up.collector(NOW, opts{}), NOW.Add(H), false)
	var se *httpc.StatusError
	if !errors.As(err, &se) || se.Status != 502 {
		t.Fatalf("want 502 StatusError, got %v", err)
	}
	var status string
	_ = d.Conn.QueryRow(context.Background(), "SELECT last_status FROM collector_state").Scan(&status)
	if canon(t, cursorOf(t, d)) != before || status != "error" {
		t.Errorf("state %s", status)
	}
}

// ----------------------------------------------------------------- test_cvelist_backfill.py

// clone is a real record re-labelled as another CVE (datePublished overridable; "" = removed).
func clone(t *testing.T, base, cve string, published *string) *pyjson.Object {
	p := rec(t, base)
	m := obj(p.Get("cveMetadata"))
	m.Set("cveId", cve)
	if published == nil {
		q := pyjson.NewObject()
		for _, k := range m.Keys() {
			if k != "datePublished" {
				q.Set(k, m.Get(k))
			}
		}
		p.Set("cveMetadata", q)
	} else {
		m.Set("datePublished", *published)
	}
	return p
}

var defaultPub = model.Ptr("2021-11-30T00:00:00.000Z")

func addStub(t *testing.T, d *testutil.TestDB, cves ...string) {
	for _, c := range cves {
		if _, err := d.Conn.Exec(context.Background(), "INSERT INTO vuln (cve_id, first_seen_at) VALUES ($1, now())", c); err != nil {
			t.Fatal(err)
		}
	}
}

// backfillUp is the `up` fixture of test_cvelist_backfill.py (deltaLog only).
func backfillUp(t *testing.T) *upstream {
	u := newUpstream(t)
	u.log = []*pyjson.Object{
		changeSet("2026-11-12T09:00:00.000Z", []string{KEVREC}, nil),
		changeSet("2026-11-12T08:00:00.000Z", nil, []string{REJECTED, TYPICAL}),
	}
	return u
}

func bootstrap(t *testing.T, py *pyRuns, up *upstream, o opts) {
	if o.bootstrapDays == nil {
		o.bootstrapDays = ip(0)
	}
	py.mustRun(up.collector(NOW, o), NOW)
	up.clear()
}

func TestMissingCVEsQueryExcludesStoredAndOrdersNumerically(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	addStub(t, d, "CVE-2025-1234", "CVE-2026-99999", "CVE-2024-50000", "CVE-2026-100000", "CVE-2026-1000", "CVE-2023-0001")
	reserved := clone(t, NA, "CVE-2023-0001", defaultPub)
	obj(reserved.Get("cveMetadata")).Set("state", "RESERVED")
	if _, err := d.Conn.Exec(ctx, `INSERT INTO raw_record (source, source_key, fetched_at, content_hash, payload)
           VALUES ('cvelist', 'CVE-2023-0001', now(), 'h', $1::jsonb)`, string(encode(t, reserved))); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO raw_record (source, source_key, fetched_at, content_hash, payload)
           VALUES ('kev', 'CVE-2025-1234', now(), 'h', '{}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	m := func(src string, limit int) string {
		ids, err := pipeline.MissingCVEs(ctx, d.Conn, src, limit)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(ids, ",")
	}
	if got := m("cvelist", 100); got != "CVE-2026-100000,CVE-2026-99999,CVE-2026-1000,CVE-2025-1234,CVE-2024-50000" {
		t.Errorf("100: %s", got)
	}
	if got := m("cvelist", 2); got != "CVE-2026-100000,CVE-2026-99999" {
		t.Errorf("2: %s", got)
	}
	if got := m("cvelist", 0); got != "" {
		t.Errorf("0: %s", got)
	}
	if strings.Contains(m("kev", 100), "CVE-2025-1234") {
		t.Error("kev")
	}
}

type spy struct {
	name   string
	limit  int
	states []model.CollectorState
}

func (s *spy) Name() string { return s.name }
func (s *spy) Fetch(_ context.Context, st model.CollectorState) (*model.FetchResult, error) {
	s.states = append(s.states, st)
	return &model.FetchResult{Cursor: pyjson.NewObject()}, nil
}
func (s *spy) Normalize(model.RawRecord) (*model.Normalized, error) { return &model.Normalized{}, nil }

type wantingSpy struct{ spy }

func (w *wantingSpy) WantedLimit() int { return w.limit }

type kevSpy struct {
	collector.Collector
	states []model.CollectorState
}

func (k *kevSpy) Fetch(ctx context.Context, st model.CollectorState) (*model.FetchResult, error) {
	k.states = append(k.states, st)
	return k.Collector.Fetch(ctx, st)
}

func kevCollector(t *testing.T) collector.Collector {
	return kev.New(kev.Options{Transport: testutil.Serve(testutil.ReadFile(t, "tests/fixtures/kev_sample.json"))})
}

func TestPipelineFillsWantedOnlyForOptedIn(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_pipeline_fills_wanted_only_for_opted_in")
	addStub(t, d, "CVE-2026-5000", "CVE-2026-100001", "CVE-2020-0001")
	plainSpy, wanting := &spy{name: "spy"}, &wantingSpy{spy{name: "wspy", limit: 2}}
	py.mustRun(plainSpy, NOW)
	py.mustRun(wanting, NOW)
	if len(plainSpy.states[0].Wanted) != 0 || strings.Join(wanting.states[0].Wanted, ",") != "CVE-2026-100001,CVE-2026-5000" {
		t.Errorf("wanted %v / %v", plainSpy.states[0].Wanted, wanting.states[0].Wanted)
	}
	k := &kevSpy{Collector: kevCollector(t)}
	st := py.mustRun(k, NOW)
	if len(k.states[0].Wanted) != 0 || !st.IsBackfill || st.RawNew != 5 {
		t.Errorf("kev %+v %v", st, k.states[0].Wanted)
	}
	var all bool
	_ = d.Conn.QueryRow(context.Background(), "SELECT bool_and(is_backfill) FROM event WHERE source='kev'").Scan(&all)
	if !all {
		t.Error("kev events not backfill")
	}
}

func TestBootstrapIgnoresWanted(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_bootstrap_ignores_wanted")
	up := backfillUp(t)
	addStub(t, d, "CVE-2021-43890")
	up.files["CVE-2021-43890"] = clone(t, TYPICAL, "CVE-2021-43890", defaultPub)
	bootstrap(t, py, up, opts{})
	cur := cursorOf(t, d)
	_, a := cur.Lookup("backfill_missing")
	_, b := obj(cur.Get("last_run")).Lookup("backfill_wanted")
	var cnt int
	_ = d.Conn.QueryRow(context.Background(), "SELECT count(*) FROM raw_record WHERE source_key='CVE-2021-43890'").Scan(&cnt)
	if a || b || cnt != 0 {
		t.Errorf("cursor %s raw %d", canon(t, cur), cnt)
	}
}

func TestQueueOrderPendingThenChangesThenWantedUnderCap(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	py := newPyRuns(t, d, "test_queue_order_pending_then_changes_then_wanted_under_cap")
	up := backfillUp(t)
	bootstrap(t, py, up, opts{maxFiles: ip(2)}) // REJECTED, TYPICAL fetched; KEVREC pending
	if canon(t, cursorOf(t, d).Get("pending")) != `["`+KEVREC+`"]` {
		t.Fatal("pending")
	}
	wanted := []string{"CVE-2026-90003", "CVE-2026-90002", "CVE-2026-90001"}
	addStub(t, d, wanted...)
	for _, w := range wanted {
		up.files[w] = clone(t, TYPICAL, w, defaultPub)
	}
	up.log = append([]*pyjson.Object{changeSet("2026-11-12T15:00:00.000Z", []string{NA}, nil)}, up.log...)

	// Python intercepts _fetch_records; with concurrency 1 the request order IS the batch order.
	st := py.mustRun(up.collector(NOW.Add(H), opts{maxFiles: ip(3), concurrency: 1}), NOW.Add(H))
	got := up.urls()[1:]
	want := []string{cvelist.RecordURL(KEVREC), cvelist.RecordURL(NA), cvelist.RecordURL("CVE-2026-90003")}
	if strings.Join(got, " ") != strings.Join(want, " ") { // pending -> change set -> newest wanted
		t.Errorf("batch %v", got)
	}
	cur := cursorOf(t, d)
	lr := obj(cur.Get("last_run"))
	if len(cur.Get("pending").([]any)) != 0 { // overflow wanted ids are NOT persisted
		t.Error("pending")
	}
	if canon(t, []any{lr.Get("backfill_wanted"), lr.Get("backfill_queued"), lr.Get("backfill_fetched"),
		lr.Get("backfill_dropped"), lr.Get("files_fetched"), lr.Get("ids_queued")}) != `[3,1,1,2,3,2]` || st.Fetched != 3 {
		t.Errorf("last_run %s", canon(t, lr))
	}
	rows, _ := d.Conn.Query(ctx, "SELECT cve_id, is_backfill FROM event WHERE type='disclosed' AND cve_id = ANY($1)",
		[]string{NA, KEVREC, "CVE-2026-90003"})
	gotBF := map[string]bool{}
	for rows.Next() {
		var id string
		var bf bool
		_ = rows.Scan(&id, &bf)
		gotBF[id] = bf
	}
	if len(gotBF) != 3 || gotBF[NA] || gotBF[KEVREC] || !gotBF["CVE-2026-90003"] {
		t.Errorf("backfill flags %v", gotBF)
	}

	up.clear()
	py.mustRun(up.collector(NOW.Add(2*H), opts{maxFiles: ip(3)}), NOW.Add(2*H))
	if !sameSet(up.fetchedFiles(), urlSet("CVE-2026-90002", "CVE-2026-90001")) {
		t.Errorf("files %v", up.fetchedFiles())
	}
	up.clear()
	py.mustRun(up.collector(NOW.Add(3*H), opts{maxFiles: ip(3)}), NOW.Add(3*H))
	if u := up.urls(); len(u) != 1 || lastRun(t, d).Get("backfill_wanted") != i64(0) {
		t.Errorf("not settled: %v", u)
	}
}

func TestWantedIDAlreadyInChangeSetIsNotBackfill(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_wanted_id_already_in_change_set_is_not_backfill")
	up := backfillUp(t)
	bootstrap(t, py, up, opts{})
	addStub(t, d, NA)
	up.log = append([]*pyjson.Object{changeSet("2026-11-12T15:00:00.000Z", nil, []string{NA})}, up.log...)
	py.mustRun(up.collector(NOW.Add(H), opts{}), NOW.Add(H))
	nNA := 0
	for _, u := range up.urls() {
		if u == cvelist.RecordURL(NA) {
			nNA++
		}
	}
	var bf bool
	_ = d.Conn.QueryRow(context.Background(), "SELECT is_backfill FROM event WHERE cve_id=$1", NA).Scan(&bf)
	if nNA != 1 || bf || lastRun(t, d).Get("backfill_queued") != i64(0) {
		t.Errorf("fetched %d times, backfill %v", nNA, bf)
	}
}

func TestKevOnlyVulnGainsDisclosure(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	py := newPyRuns(t, d, "test_kev_only_vuln_gains_disclosure")
	up := backfillUp(t)
	bootstrap(t, py, up, opts{})
	py.mustRun(kevCollector(t), NOW) // stubs + kev_added
	kv, _ := pyjson.Decode(testutil.ReadFile(t, "tests/fixtures/kev_sample.json"))
	var kevIDs []string
	for _, v := range obj(kv).Get("vulnerabilities").([]any) {
		kevIDs = append(kevIDs, obj(v).Get("cveID").(string))
	}
	old := "CVE-2021-43890"
	up.files[old] = clone(t, TYPICAL, old, model.Ptr("2021-12-14T18:00:00.000Z"))
	rejected := "CVE-2026-59310" // REJECTED without datePublished
	up.files[rejected] = clone(t, REJECTED, rejected, nil)
	var before *string
	_ = d.Conn.QueryRow(ctx, "SELECT title FROM vuln WHERE cve_id=$1", old).Scan(&before)

	st := py.mustRun(up.collector(NOW.Add(H), opts{}), NOW.Add(H))
	if st.IsBackfill || !sameSet(up.fetchedFiles(), urlSet(kevIDs...)) {
		t.Errorf("stats %+v files %v", st, up.fetchedFiles())
	}
	cur := cursorOf(t, d)
	lr := obj(cur.Get("last_run"))
	if lr.Get("backfill_fetched") != i64(2) || lr.Get("backfill_missing") != i64(3) || len(cur.Get("pending").([]any)) != 0 {
		t.Errorf("cursor %s", canon(t, cur))
	}
	var title, desc string
	var pub time.Time
	_ = d.Conn.QueryRow(ctx, "SELECT title, description, published_at FROM vuln WHERE cve_id=$1", old).Scan(&title, &desc, &pub)
	cnaObj := obj(obj(up.files[old].Get("containers")).Get("cna"))
	if title != cnaObj.Get("title") || (before != nil && title == *before) ||
		desc != obj(cnaObj.Get("descriptions").([]any)[0]).Get("value") || !pub.Equal(ts("2021-12-14T18:00:00+00:00")) {
		t.Errorf("vuln %q %q %v", title, desc, pub)
	}
	var occ, obs time.Time
	var bf bool
	_ = d.Conn.QueryRow(ctx, "SELECT occurred_at, observed_at, is_backfill FROM event WHERE cve_id=$1 AND type='disclosed'", old).Scan(&occ, &obs, &bf)
	if !occ.Equal(ts("2021-12-14T18:00:00+00:00")) || !obs.Equal(NOW.Add(H)) || !bf {
		t.Errorf("event %v %v %v", occ, obs, bf)
	}
	var disc *time.Time
	var days float64
	_ = d.Conn.QueryRow(ctx, "SELECT disclosed_at, round(days_disclosed_to_exploited, 2)::float8 FROM vuln_state WHERE cve_id=$1", old).Scan(&disc, &days)
	if disc == nil || !disc.Equal(ts("2021-12-14T18:00:00+00:00")) || days != 0.25 {
		t.Errorf("vuln_state %v %v", disc, days)
	}
	var occR *time.Time
	_ = d.Conn.QueryRow(ctx, "SELECT occurred_at, is_backfill FROM event WHERE cve_id=$1 AND type='disclosed'", rejected).Scan(&occR, &bf)
	if occR != nil || !bf {
		t.Errorf("rejected event %v %v", occR, bf)
	}
	var isRej bool
	disc = nil
	_ = d.Conn.QueryRow(ctx, "SELECT disclosed_at, is_rejected FROM vuln_state WHERE cve_id=$1", rejected).Scan(&disc, &isRej)
	if disc != nil || !isRej {
		t.Errorf("rejected state %v %v", disc, isRej)
	}

	up.clear()
	st2 := py.mustRun(up.collector(NOW.Add(2*H), opts{}), NOW.Add(2*H))
	lr = lastRun(t, d)
	if len(up.urls()) != 1 || st2.Fetched != 0 || canon(t, []any{lr.Get("backfill_wanted"), lr.Get("backfill_skipped_missing"), lr.Get("backfill_queued")}) != `[3,3,0]` {
		t.Errorf("second run %v %s", up.urls(), canon(t, lr))
	}
}

func TestMissing404TrackedSkippedThenRetriedAndBounded(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_404_tracked_skipped_then_retried_and_bounded")
	up := backfillUp(t)
	bootstrap(t, py, up, opts{})
	gone := []string{"CVE-2026-80003", "CVE-2026-80002", "CVE-2026-80001"}
	addStub(t, d, gone...)

	py.mustRun(up.collector(NOW.Add(H), opts{}), NOW.Add(H))
	if !sameSet(up.fetchedFiles(), urlSet(gone...)) {
		t.Errorf("files %v", up.fetchedFiles())
	}
	cur := cursorOf(t, d)
	iso := "2026-11-12T15:00:00+00:00"
	if canon(t, cur.Get("backfill_missing")) != `{"CVE-2026-80001":"`+iso+`","CVE-2026-80002":"`+iso+`","CVE-2026-80003":"`+iso+`"}` ||
		obj(cur.Get("last_run")).Get("backfill_missing") != i64(3) || len(cur.Get("pending").([]any)) != 0 {
		t.Errorf("cursor %s", canon(t, cur))
	}

	up.clear() // within 7 days: skipped
	py.mustRun(up.collector(NOW.Add(6*24*H), opts{}), NOW.Add(6*24*H))
	if len(up.urls()) != 1 || lastRun(t, d).Get("backfill_skipped_missing") != i64(3) {
		t.Errorf("skip %v", up.urls())
	}

	up.files["CVE-2026-80002"] = clone(t, TYPICAL, "CVE-2026-80002", defaultPub)
	up.clear()
	later := NOW.Add(8 * 24 * H)
	py.mustRun(up.collector(later, opts{}), later)
	if !sameSet(up.fetchedFiles(), urlSet(gone...)) {
		t.Errorf("files %v", up.fetchedFiles())
	}
	cur = cursorOf(t, d)
	iso = "2026-11-20T14:00:00+00:00"
	if canon(t, cur.Get("backfill_missing")) != `{"CVE-2026-80001":"`+iso+`","CVE-2026-80003":"`+iso+`"}` ||
		obj(cur.Get("last_run")).Get("backfill_fetched") != i64(1) {
		t.Errorf("cursor %s", canon(t, cur))
	}

	up.clear() // custom retry interval (0 days = retry every run)
	py.mustRun(up.collector(later.Add(H), opts{retryDays: ip(0)}), later.Add(H))
	if len(up.fetchedFiles()) != 2 {
		t.Errorf("files %v", up.fetchedFiles())
	}

	// bounded map: keeps the most recent 404s (Python monkeypatches MAX_BACKFILL_MISSING = 2)
	addStub(t, d, "CVE-2026-80000")
	py.mustRun(up.collector(later.Add(30*24*H), opts{maxMissing: 2}), later.Add(30*24*H))
	cur = cursorOf(t, d)
	lr := obj(cur.Get("last_run"))
	if obj(cur.Get("backfill_missing")).Len() != 2 || lr.Get("backfill_missing") != i64(3) || lr.Get("backfill_missing_tracked") != i64(2) {
		t.Errorf("cursor %s", canon(t, cur))
	}
}

func TestMissingMapPrunedWhenNoLongerWanted(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_missing_map_pruned_when_no_longer_wanted")
	up := backfillUp(t)
	bootstrap(t, py, up, opts{})
	addStub(t, d, "CVE-2026-80001")
	py.mustRun(up.collector(NOW.Add(H), opts{}), NOW.Add(H))
	if canon(t, obj(cursorOf(t, d).Get("backfill_missing")).Keys()) != `["CVE-2026-80001"]` {
		t.Error("not tracked")
	}
	_, _ = d.Conn.Exec(context.Background(), "DELETE FROM vuln WHERE cve_id='CVE-2026-80001'")
	py.mustRun(up.collector(NOW.Add(2*H), opts{}), NOW.Add(2*H))
	if obj(cursorOf(t, d).Get("backfill_missing")).Len() != 0 {
		t.Error("not pruned")
	}
}

func TestTransientFailureOfWantedIsDroppedNotPending(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	py := newPyRuns(t, d, "test_transient_failure_of_wanted_is_dropped_not_pending")
	up := backfillUp(t)
	bootstrap(t, py, up, opts{})
	w := "CVE-2026-70001"
	addStub(t, d, w)
	up.files[w] = clone(t, TYPICAL, w, defaultPub)
	up.fail[cvelist.RecordURL(w)] = []int{500, 500, 500, 500}
	st := py.mustRun(up.collector(NOW.Add(H), opts{}), NOW.Add(H)) // only wanted ids: must not fail
	var status string
	_ = d.Conn.QueryRow(context.Background(), "SELECT last_status FROM collector_state").Scan(&status)
	cur := cursorOf(t, d)
	if status != "ok" || st.Fetched != 0 || len(cur.Get("pending").([]any)) != 0 ||
		obj(cur.Get("backfill_missing")).Len() != 0 || obj(cur.Get("last_run")).Get("backfill_failed") != i64(1) {
		t.Errorf("%s %+v %s", status, st, canon(t, cur))
	}

	up.fail[cvelist.RecordURL(w)] = []int{500, 500, 500, 500}
	up.log = append([]*pyjson.Object{changeSet("2026-11-12T16:00:00.000Z", []string{V4}, nil)}, up.log...)
	py.mustRun(up.collector(NOW.Add(2*H), opts{}), NOW.Add(2*H))
	cur = cursorOf(t, d)
	if len(cur.Get("pending").([]any)) != 0 || obj(cur.Get("last_run")).Get("files_fetched") != i64(1) {
		t.Errorf("cursor %s", canon(t, cur))
	}

	up.clear()
	py.mustRun(up.collector(NOW.Add(3*H), opts{}), NOW.Add(3*H))
	if !sameSet(up.fetchedFiles(), urlSet(w)) {
		t.Errorf("files %v", up.fetchedFiles())
	}
}
