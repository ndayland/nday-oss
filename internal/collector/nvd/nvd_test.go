package nvd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/testutil"
)

var (
	feedTime = time.Date(2026, 11, 13, 15, 0, 8, 0, time.UTC)
	runTime  = time.Date(2026, 11, 13, 15, 30, 0, 0, time.UTC)
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// feedServer serves nvdcve-2.0-<name>.meta / .json.gz from files, counts
// requests and can be told to misbehave.
type feedServer struct {
	mu    sync.Mutex
	files map[string][]byte // path -> body
	etags map[string]string
	hits  map[string]int
	fail  map[string][]int // path -> statuses to return first
	ts    *httptest.Server
}

func newFeedServer(t *testing.T) *feedServer {
	s := &feedServer{files: map[string][]byte{}, etags: map[string]string{}, hits: map[string]int{}, fail: map[string][]int{}}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/feeds/")
		s.hits[p]++
		if r.Header.Get("User-Agent") != httpc.UserAgent {
			http.Error(w, "ua", 400)
			return
		}
		if st := s.fail[p]; len(st) > 0 {
			s.fail[p] = st[1:]
			w.WriteHeader(st[0])
			return
		}
		b, ok := s.files[p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if et := s.etags[p]; et != "" {
			w.Header().Set("ETag", et)
			if r.Header.Get("If-None-Match") == et {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Write(b)
	}))
	t.Cleanup(s.ts.Close)
	return s
}

// publish puts a feed document (unpacked JSON) and its .meta.
func (s *feedServer) publish(t *testing.T, name string, doc []byte, lastMod time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z := gz(t, doc)
	s.files["nvdcve-2.0-"+name+".json.gz"] = z
	s.files["nvdcve-2.0-"+name+".meta"] = []byte(metaFor(doc, z, lastMod))
	s.etags["nvdcve-2.0-"+name+".meta"] = fmt.Sprintf(`W/"%x"`, lastMod.Unix())
}

// set replaces a file (and drops its ETag).
func (s *feedServer) set(path string, b []byte) {
	s.mu.Lock()
	s.files[path] = b
	delete(s.etags, path)
	s.mu.Unlock()
}

// withSHA replaces the checksum of a .meta by another valid one.
func withSHA(meta []byte) []byte {
	lines := strings.Split(string(meta), "\r\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "sha256:") {
			lines[i] = "sha256:" + strings.Repeat("AB", 32)
		}
	}
	return []byte(strings.Join(lines, "\r\n"))
}
func (s *feedServer) hit(path string) int { s.mu.Lock(); defer s.mu.Unlock(); return s.hits[path] }

func (s *feedServer) collector() *Collector {
	c := New(Options{Base: s.ts.URL + "/feeds", Logger: quiet(),
		Sleep: func(context.Context, time.Duration) error { return nil }})
	return c
}

type dbEnv struct {
	t    *testing.T
	ctx  context.Context
	conn *pgx.Conn
	d    *testutil.TestDB
}

func newDB(t *testing.T) *dbEnv {
	d := testutil.NewMigratedDB(t)
	return &dbEnv{t: t, ctx: context.Background(), conn: d.Conn, d: d}
}

func (e *dbEnv) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.conn.QueryRow(e.ctx, sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// fingerprint of everything NVD must never touch.
func (e *dbEnv) fingerprint() string {
	e.t.Helper()
	var parts []string
	for _, tbl := range []string{"event", "vuln", "vuln_alias", "affected", "vuln_state", "vuln_state_mat"} {
		var s string
		if err := e.conn.QueryRow(e.ctx, `SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY t::text), '')) FROM `+tbl+` t`).Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		parts = append(parts, tbl+"="+s)
	}
	return strings.Join(parts, " ")
}

func (e *dbEnv) state() (status string, cursor string, lastErr *string) {
	e.t.Helper()
	var c *string
	err := e.conn.QueryRow(e.ctx, `SELECT last_status, cursor::text, last_error FROM collector_state WHERE source = 'nvd'`).Scan(&status, &c, &lastErr)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	if c != nil {
		cursor = *c
	}
	return
}

func run(t *testing.T, e *dbEnv, c *Collector, at time.Time) (*RunStats, error) {
	t.Helper()
	return c.Run(e.ctx, e.conn, RunOptions{Now: func() time.Time { return at }})
}

// a document with the given entries (raw JSON of "cve" objects)
func doc(entries ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `{"resultsPerPage":%d,"startIndex":0,"totalResults":%d,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-13T10:00:00.000","vulnerabilities":[`, len(entries), len(entries))
	for i, x := range entries {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"cve":` + x + `}`)
	}
	b.WriteString("]}")
	return []byte(b.String())
}

func entry(id, cwe string) string {
	return fmt.Sprintf(`{"id":%q,"vulnStatus":"Analyzed","weaknesses":[{"source":"nvd@nist.gov","type":"Primary","description":[{"lang":"en","value":%q}]}],"metrics":{}}`, id, cwe)
}

func TestRunIncremental(t *testing.T) {
	e := newDB(t)
	// a vuln with an event: NVD must leave it and vuln_state alone
	if _, err := e.conn.Exec(e.ctx, `INSERT INTO vuln (cve_id, title) VALUES ('CVE-2018-0125', 't');
        INSERT INTO event (cve_id, type, observed_at, source, detail) VALUES ('CVE-2018-0125', 'disclosed', now(), 'cvelist', '{"state":"PUBLISHED"}')`); err != nil {
		t.Fatal(err)
	}
	before := e.fingerprint()
	s := newFeedServer(t)
	s.publish(t, "modified", fixtureJSON(t), feedTime)
	c := s.collector()

	st, err := run(t, e, c, runTime)
	if err != nil {
		t.Fatal(err)
	}
	if st.Outcome != "modified" || st.Total.New != 24 || st.Total.Entries != 24 || len(st.Warnings) != 1 {
		t.Errorf("first run %+v", st)
	}
	if n := e.count(`SELECT count(*) FROM raw_record WHERE source = 'nvd' AND fetched_at = $1`, feedTime); n != 24 {
		t.Errorf("raw rows at the feed snapshot: %d", n)
	}
	status, cur, _ := e.state()
	if status != "ok" || !strings.Contains(cur, `"synced_through": "2026-11-13T15:00:08Z"`) {
		t.Errorf("state %s %s", status, cur)
	}
	if after := e.fingerprint(); after != before {
		t.Errorf("NVD changed vuln/event/state tables:\n%s\n%s", before, after)
	}
	if e.count(`SELECT count(*) FROM vuln`) != 1 {
		t.Error("NVD created vuln rows")
	}
	// the payload is the "cve" object as delivered (pyjson canonical form)
	var payload string
	if err := e.conn.QueryRow(e.ctx, `SELECT payload->>'vulnStatus' FROM raw_record WHERE source = 'nvd' AND source_key = 'CVE-2010-0735'`).Scan(&payload); err != nil || payload != "Rejected" {
		t.Errorf("payload %q %v", payload, err)
	}

	// unchanged: 304 on the .meta, feed not downloaded again
	gzHits := s.hit("nvdcve-2.0-modified.json.gz")
	st, err = run(t, e, c, runTime.Add(time.Hour))
	if err != nil || st.Outcome != "unchanged" || s.hit("nvdcve-2.0-modified.json.gz") != gzHits {
		t.Fatalf("304 run: %+v %v", st, err)
	}
	// unchanged sha256 without an ETag match (e.g. ETag changed): still no download
	s.mu.Lock()
	s.etags["nvdcve-2.0-modified.meta"] = `W/"other"`
	s.mu.Unlock()
	st, err = run(t, e, c, runTime.Add(2*time.Hour))
	if err != nil || st.Outcome != "unchanged" || s.hit("nvdcve-2.0-modified.json.gz") != gzHits {
		t.Fatalf("same-sha run: %+v %v", st, err)
	}

	// a new feed with one changed and one new record: exactly two raw rows
	s.publish(t, "modified", doc(entry("CVE-2010-0157", "CWE-23"), entry("CVE-2026-0001", "CWE-79"), strings.TrimSpace(firstEntry(t, "CVE-2010-0158"))), feedTime.Add(2*time.Hour))
	st, err = run(t, e, c, runTime.Add(3*time.Hour))
	if err != nil || st.Total.New != 2 || st.Total.Unchanged != 1 {
		t.Fatalf("delta run %+v %v", st, err)
	}
	// idempotent: a run that finds a new .meta with the same content writes nothing
	s.publish(t, "modified", doc(entry("CVE-2010-0157", "CWE-23"), entry("CVE-2026-0001", "CWE-79")), feedTime.Add(3*time.Hour))
	st, err = run(t, e, c, runTime.Add(4*time.Hour))
	if err != nil || st.Total.New+st.Total.Reverted != 0 || st.Total.Unchanged != 2 {
		t.Fatalf("idempotent %+v %v", st, err)
	}
	// revert to an older content version: fetched_at bumped, no new row
	n := e.count(`SELECT count(*) FROM raw_record WHERE source = 'nvd'`)
	s.publish(t, "modified", doc(strings.TrimSpace(firstEntry(t, "CVE-2010-0157"))), feedTime.Add(4*time.Hour))
	st, err = run(t, e, c, runTime.Add(5*time.Hour))
	if err != nil || st.Total.Reverted != 1 || e.count(`SELECT count(*) FROM raw_record WHERE source = 'nvd'`) != n {
		t.Fatalf("revert %+v %v", st, err)
	}
	if e.fingerprint() != before {
		t.Error("NVD changed vuln/event/state tables")
	}
}

// firstEntry returns the "cve" object of id from the fixture.
func firstEntry(t *testing.T, id string) string {
	t.Helper()
	var out string
	_, _, err := Parse(bytes.NewReader(fixtureJSON(t)), 0, func(e Entry) error {
		if e.ID == id {
			out = string(e.CVE)
		}
		return nil
	})
	if err != nil || out == "" {
		t.Fatal(id, err)
	}
	return out
}

// A failed run changes nothing and keeps the cursor.
func TestRunFailuresChangeNothing(t *testing.T) {
	e := newDB(t)
	s := newFeedServer(t)
	s.publish(t, "modified", doc(entry("CVE-2026-0001", "CWE-79")), feedTime)
	c := s.collector()
	if _, err := run(t, e, c, runTime); err != nil {
		t.Fatal(err)
	}
	_, cur0, _ := e.state()
	rows0 := e.count(`SELECT count(*) FROM raw_record`)
	good := doc(entry("CVE-2026-0001", "CWE-80"), entry("CVE-2026-0002", "CWE-79"))
	z := gz(t, good)
	meta := []byte(metaFor(good, z, feedTime.Add(time.Hour)))

	cases := []struct {
		name  string
		setup func()
		want  string
	}{
		{"wrong checksum", func() {
			s.set("nvdcve-2.0-modified.json.gz", z)
			s.set("nvdcve-2.0-modified.meta", withSHA(meta))
		}, "sha256"},
		{"truncated gzip", func() {
			cut := z[:len(z)-30]
			s.set("nvdcve-2.0-modified.json.gz", cut)
			s.set("nvdcve-2.0-modified.meta", []byte(strings.Replace(string(meta), fmt.Sprintf("gzSize:%d", len(z)), fmt.Sprintf("gzSize:%d", len(cut)), 1)))
		}, "unexpected EOF"},
		{"short download", func() {
			s.set("nvdcve-2.0-modified.json.gz", z[:len(z)/2])
			s.set("nvdcve-2.0-modified.meta", meta)
		}, "truncated or changed"},
		{"5xx", func() {
			s.set("nvdcve-2.0-modified.json.gz", z)
			s.set("nvdcve-2.0-modified.meta", meta)
			s.mu.Lock()
			s.fail["nvdcve-2.0-modified.json.gz"] = []int{500, 502, 503, 503, 503}
			s.mu.Unlock()
		}, "HTTP status 503"},
		{"meta not a meta", func() {
			s.mu.Lock()
			s.fail = map[string][]int{}
			s.mu.Unlock()
			s.set("nvdcve-2.0-modified.meta", []byte("<html>blocked</html>"))
		}, "nvd meta"},
	}
	for _, tc := range cases {
		tc.setup()
		_, err := run(t, e, c, runTime.Add(time.Hour))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
		status, cur, lastErr := e.state()
		if status != "error" || cur != cur0 || lastErr == nil || e.count(`SELECT count(*) FROM raw_record`) != rows0 {
			t.Errorf("%s: state %s %s %v rows %d", tc.name, status, cur, lastErr, e.count(`SELECT count(*) FROM raw_record`))
		}
	}
	// oversized body (cap 1 KiB)
	c.Fetcher = NewFetcher(FetcherOptions{Base: s.ts.URL + "/feeds", MaxGz: 1024, Logger: quiet(),
		Sleep: func(context.Context, time.Duration) error { return nil }})
	s.set("nvdcve-2.0-modified.meta", meta)
	big := doc(entry("CVE-2026-0001", "CWE-80"), entry("CVE-2026-0002", strings.Repeat("A", 5000)), entry("CVE-2026-0003", "CWE-1"))
	bz := gz(t, big)
	for len(bz) < 2048 {
		big = append(big[:len(big)-2], []byte(`,{"cve":`+entry(fmt.Sprintf("CVE-2026-%04d", 1000+len(bz)), fmt.Sprintf("CWE-%d", len(bz)))+`}]}`)...)
		bz = gz(t, big)
	}
	s.set("nvdcve-2.0-modified.json.gz", bz)
	s.set("nvdcve-2.0-modified.meta", []byte(metaFor(big, bz, feedTime.Add(time.Hour))))
	var tl *httpc.TooLargeError
	if _, err := run(t, e, c, runTime.Add(time.Hour)); !errors.As(err, &tl) {
		t.Errorf("oversized: %v", err)
	}
	if _, cur, _ := e.state(); cur != cur0 {
		t.Error("cursor moved")
	}
	// transient 5xx then success: retried, applied
	c = s.collector()
	s.set("nvdcve-2.0-modified.json.gz", z)
	s.set("nvdcve-2.0-modified.meta", meta)
	s.mu.Lock()
	s.fail["nvdcve-2.0-modified.json.gz"] = []int{503, 502}
	s.mu.Unlock()
	st, err := run(t, e, c, runTime.Add(2*time.Hour))
	if err != nil || st.Total.New != 2 {
		t.Fatalf("after transient 5xx: %+v %v", st, err)
	}
	if status, cur, _ := e.state(); status != "ok" || cur == cur0 {
		t.Errorf("state %s %s", status, cur)
	}
}

// A cursor older than the modified feed's window re-reads the yearly files
// whose .meta changed since the cursor, then the modified feed.
func TestRunFallbackToYearly(t *testing.T) {
	e := newDB(t)
	s := newFeedServer(t)
	c := s.collector()
	c.Years = func(time.Time) []int { return []int{2010, 2018} }
	s.publish(t, "modified", doc(entry("CVE-2026-0001", "CWE-79")), feedTime)
	if _, err := run(t, e, c, runTime); err != nil {
		t.Fatal(err)
	}
	// 10 days later: the cursor (feedTime) is outside the 7-day window
	later := feedTime.Add(10 * 24 * time.Hour)
	s.publish(t, "modified", doc(entry("CVE-2026-0001", "CWE-89")), later)
	s.publish(t, "2010", doc(entry("CVE-2010-0001", "CWE-22"), entry("CVE-2010-0002", "NVD-CWE-noinfo")), later.Add(-time.Hour))
	s.publish(t, "2018", doc(entry("CVE-2018-0001", "CWE-20")), feedTime.Add(-time.Hour)) // not changed since the cursor
	st, err := run(t, e, c, later.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if st.Outcome != "fallback+modified" || st.Total.New != 3 || len(st.Feeds) != 2 || st.Feeds[0].Label != "2010" {
		t.Errorf("%+v", st)
	}
	if s.hit("nvdcve-2.0-2018.json.gz") != 0 || s.hit("nvdcve-2.0-2018.meta") != 1 || s.hit("nvdcve-2.0-2010.json.gz") != 1 {
		t.Errorf("hits %v", s.hits)
	}
	_, cur, _ := e.state()
	if !strings.Contains(cur, `"files": ["2010"]`) || !strings.Contains(cur, later.Format(time.RFC3339)) {
		t.Errorf("cursor %s", cur)
	}
	// a fallback whose yearly file fails keeps the old cursor
	s.publish(t, "modified", doc(entry("CVE-2026-0001", "CWE-90")), later.Add(10*24*time.Hour))
	s.publish(t, "2010", doc(entry("CVE-2010-0001", "CWE-23")), later.Add(9*24*time.Hour))
	s.set("nvdcve-2.0-2010.json.gz", []byte("garbage"))
	if _, err := run(t, e, c, later.Add(10*24*time.Hour)); err == nil {
		t.Fatal("broken yearly file accepted")
	}
	if _, cur2, _ := e.state(); cur2 != cur {
		t.Error("cursor moved after a failed fallback")
	}
}

func writeDir(t *testing.T, dir, name string, d []byte, lastMod time.Time, withMeta bool) {
	t.Helper()
	z := gz(t, d)
	if err := os.WriteFile(filepath.Join(dir, "nvdcve-2.0-"+name+".json.gz"), z, 0o644); err != nil {
		t.Fatal(err)
	}
	if withMeta {
		if err := os.WriteFile(filepath.Join(dir, "nvdcve-2.0-"+name+".meta"), []byte(metaFor(d, z, lastMod)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBaselineDirIdempotentAndStale(t *testing.T) {
	e := newDB(t)
	before := e.fingerprint()
	dir := t.TempDir()
	writeDir(t, dir, "2010", fixtureJSON(t), feedTime, true)
	writeDir(t, dir, "2018", doc(entry("CVE-2018-0001", "CWE-20"), `{"id":"bad id"}`, `{"vulnStatus":"x"}`), feedTime, false)
	o := BaselineOptions{Dir: dir, Years: []int{2010, 2018, 2019}, Logger: quiet(), BatchSize: 5}
	dry := o
	dry.DryRun = true
	st, err := ImportBaseline(e.ctx, e.conn, dry)
	if err != nil || st.Total.New != 25 || e.count(`SELECT count(*) FROM raw_record`) != 0 {
		t.Fatalf("dry run %+v %v", st, err)
	}
	st, err = ImportBaseline(e.ctx, e.conn, o)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(st)
	if st.Total.New != 25 || st.Total.BadEntries != 2 || len(st.Missing) != 1 || len(st.Unverified) != 1 || !st.Files[0].Verified || st.Files[1].Verified {
		t.Errorf("%s", b)
	}
	st, err = ImportBaseline(e.ctx, e.conn, o)
	if err != nil || st.Total.New+st.Total.Reverted != 0 || st.Total.Unchanged != 25 {
		t.Errorf("second run %+v %v", st.Total, err)
	}
	// a newer snapshot of a record exists (e.g. from `collect nvd`): an older
	// file never regresses it
	if err := pgx.BeginFunc(e.ctx, e.conn, func(tx pgx.Tx) error {
		rec, bad := decodeEntry(Entry{ID: "CVE-2018-0001", CVE: json.RawMessage(entry("CVE-2018-0001", "CWE-99"))})
		if bad != "" {
			return errors.New(bad)
		}
		_, err := pipeline.StoreRaw(e.ctx, tx, rec.rec, rec.hash, feedTime.Add(48*time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	writeDir(t, dir, "2018", doc(entry("CVE-2018-0001", "CWE-21")), feedTime.Add(24*time.Hour), true)
	st, err = ImportBaseline(e.ctx, e.conn, BaselineOptions{Dir: dir, Years: []int{2018}, Logger: quiet()})
	if err != nil || st.Total.Stale != 1 || st.Total.New != 0 {
		t.Errorf("stale %+v %v", st.Total, err)
	}
	// a corrupt file next to its .meta is refused before anything is written
	n := e.count(`SELECT count(*) FROM raw_record`)
	os.WriteFile(filepath.Join(dir, "nvdcve-2.0-2018.json.gz"), []byte("garbage"), 0o644)
	if _, err := ImportBaseline(e.ctx, e.conn, BaselineOptions{Dir: dir, Years: []int{2018}, Logger: quiet()}); err == nil {
		t.Error("corrupt file accepted")
	}
	if e.count(`SELECT count(*) FROM raw_record`) != n || e.fingerprint() != before {
		t.Error("something was written")
	}
	// --limit
	e2 := newDB(t)
	st, err = ImportBaseline(e2.ctx, e2.conn, BaselineOptions{Dir: dir, Years: []int{2010}, Logger: quiet(), BatchSize: 4, Limit: 6})
	if err != nil || st.Total.New != 8 || !st.Files[0].LimitReached {
		t.Errorf("limit: %+v %v", st.Total, err)
	}
}

func TestBaselineDownload(t *testing.T) {
	e := newDB(t)
	s := newFeedServer(t)
	s.publish(t, "2010", fixtureJSON(t), feedTime)
	s.publish(t, "2011", doc(entry("CVE-2011-0001", "CWE-79")), feedTime)
	f := NewFetcher(FetcherOptions{Base: s.ts.URL + "/feeds", Logger: quiet(), Sleep: func(context.Context, time.Duration) error { return nil }})
	st, err := ImportBaseline(e.ctx, e.conn, BaselineOptions{Fetcher: f, Years: []int{2010, 2011}, Logger: quiet()})
	if err != nil || st.Total.New != 25 || !st.Files[1].Verified {
		t.Fatalf("%+v %v", st, err)
	}
	// wrong checksum on both attempts: error, nothing from that file
	s.set("nvdcve-2.0-2011.meta", withSHA(s.files["nvdcve-2.0-2011.meta"]))
	s.publish(t, "2010", doc(entry("CVE-2010-0157", "CWE-1")), feedTime.Add(time.Hour))
	_, err = ImportBaseline(e.ctx, e.conn, BaselineOptions{Fetcher: f, Years: []int{2011}, Logger: quiet()})
	var ce *ChecksumError
	if !errors.As(err, &ce) || s.hit("nvdcve-2.0-2011.json.gz") != 3 {
		t.Errorf("%v hits=%d", err, s.hit("nvdcve-2.0-2011.json.gz"))
	}
}
