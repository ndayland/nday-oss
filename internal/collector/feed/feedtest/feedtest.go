// Package feedtest holds the Go port of tests/poc_feed_helpers.py: a fake
// feed server (ETag on 200, 304 on a matching If-None-Match, optional gzip,
// scripted 429/5xx, optional missing Content-Length) and per-source adapters
// that load the recorded fixtures and serialize them back to the exact
// upstream wire format Python's helpers produce (byte-identical, see
// TestAdaptersDumpLikePython). Used only by tests.
package feedtest

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/exploitdb"
	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/collector/metasploit"
	"nday.land/nday/internal/collector/nuclei"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
	"nday.land/nday/internal/testutil"
)

// ------------------------------------------------------------------ server

// Server is Python's FeedServer.
type Server struct {
	t             testing.TB
	URL           string
	mu            sync.Mutex
	body          []byte
	etag          string
	Gzip          bool
	Script        []int // statuses served first (with Retry-After: 1)
	ContentLength bool  // false: streamed body without Content-Length
	FT            *testutil.FakeTransport
}

// NewServer serves body under url with the given ETag.
func NewServer(t testing.TB, url string, body []byte, etag string) *Server {
	s := &Server{t: t, URL: url, body: body, etag: etag, ContentLength: true}
	s.FT = &testutil.FakeTransport{Handler: s.handle}
	return s
}

// Set replaces the served body and ETag.
func (s *Server) Set(body []byte, etag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.etag = body, etag
}

func (s *Server) handle(r *http.Request) (int, http.Header, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.String() != s.URL {
		s.t.Errorf("unexpected URL %s", r.URL)
	}
	if len(s.Script) > 0 {
		st := s.Script[0]
		s.Script = s.Script[1:]
		return st, http.Header{"Retry-After": {"1"}}, nil, nil
	}
	if r.Header.Get("If-None-Match") == s.etag {
		return 304, http.Header{"Etag": {s.etag}}, nil, nil
	}
	h := http.Header{"Etag": {s.etag}}
	body := s.body
	if s.Gzip {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		_, _ = zw.Write(body)
		_ = zw.Close()
		body = b.Bytes()
		h.Set("Content-Encoding", "gzip")
	}
	return 200, h, body, nil
}

// Requests are the requests seen so far.
func (s *Server) Requests() []testutil.Request { return s.FT.Requests }

// RoundTrip implements http.RoundTripper (ContentLength -1 when !ContentLength).
func (s *Server) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := s.FT.RoundTrip(r)
	if resp != nil && !s.ContentLength {
		resp.ContentLength = -1
		resp.Body = io.NopCloser(onlyReader{resp.Body})
	}
	return resp, err
}

type onlyReader struct{ io.Reader }

// ------------------------------------------------------------------ adapters

// Adapter is one source's fixture loader / wire serializer (poc_feed_helpers).
type Adapter struct {
	Name        string
	URL         string
	NewKey      string // held back on run 1, "appears" on run 2
	ChangeKey   string
	CVEOfChange string
	Load        func(t testing.TB) any
	Dump        func(t testing.TB, data any) []byte
	Without     func(data any, key string) any
	Changed     func(t testing.TB, data any, key string) any
	New         func(o feed.Options) (collector.Collector, error)
}

func read(t testing.TB, rel string) string { return string(testutil.ReadFile(t, rel)) }

// Edb is EdbFeed.
var Edb = &Adapter{
	Name: "exploitdb", URL: exploitdb.FeedURL, NewKey: "52705", ChangeKey: "52675", CVEOfChange: "CVE-2026-9198",
	Load: func(t testing.TB) any {
		rows, err := exploitdb.ParseCSV(read(t, "tests/fixtures/exploitdb/files_exploits.csv"))
		if err != nil {
			t.Fatal(err)
		}
		return rows
	},
	Dump: func(_ testing.TB, data any) []byte { return []byte(writeCSV(data.([][]string))) },
	Without: func(data any, key string) any {
		var out [][]string
		for _, r := range data.([][]string) {
			if r[0] != key {
				out = append(out, r)
			}
		}
		return out
	},
	Changed: func(_ testing.TB, data any, key string) any {
		var out [][]string
		for _, r := range data.([][]string) {
			r = append([]string(nil), r...)
			if r[0] == key {
				r[2] += " (updated)"
			}
			out = append(out, r)
		}
		return out
	},
	New: func(o feed.Options) (collector.Collector, error) { return exploitdb.New(o) },
}

// writeCSV is csv.writer(buf, lineterminator="\n").writerows(rows) with the
// excel dialect (QUOTE_MINIMAL).
func writeCSV(rows [][]string) string {
	var b strings.Builder
	for _, r := range rows {
		for i, f := range r {
			if i > 0 {
				b.WriteByte(',')
			}
			if strings.ContainsAny(f, ",\"\r\n") || (f == "" && len(r) == 1) {
				b.WriteString(`"` + strings.ReplaceAll(f, `"`, `""`) + `"`)
			} else {
				b.WriteString(f)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func decode(t testing.TB, s string) any {
	v, err := pyjson.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func encode(t testing.TB, v any, o pyjson.Options) string {
	s, err := pyjson.Encode(v, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// deepCopy is json.loads(json.dumps(x)).
func deepCopy(t testing.TB, v any) any { return decode(t, encode(t, v, pyjson.Options{})) }

// Msf is MsfFeed.
var Msf = &Adapter{
	Name: "metasploit", URL: metasploit.FeedURL, NewKey: "exploit/multi/http/langflow_unauth_rce_cve_2026_9198",
	ChangeKey: "auxiliary/admin/2wire/xslt_password_reset", CVEOfChange: "CVE-2007-4387",
	Load: func(t testing.TB) any {
		return decode(t, read(t, "tests/fixtures/metasploit/modules_metadata_base.json"))
	},
	Dump: func(t testing.TB, data any) []byte {
		return []byte(encode(t, data, pyjson.Options{Indent: 2, EnsureASCII: true}))
	},
	Without: func(data any, fullname string) any {
		in, out := data.(*pyjson.Object), pyjson.NewObject()
		for _, k := range in.Keys() {
			if in.Get(k).(*pyjson.Object).Get("fullname") != fullname {
				out.Set(k, in.Get(k))
			}
		}
		return out
	},
	Changed: func(t testing.TB, data any, fullname string) any {
		out := deepCopy(t, data).(*pyjson.Object)
		for _, k := range out.Keys() {
			v := out.Get(k).(*pyjson.Object)
			if v.Get("fullname") == fullname {
				v.Set("mod_time", "2026-11-12 10:00:00 +0000")
				v.Set("name", v.Get("name").(string)+" (updated)")
			}
		}
		return out
	},
	New: func(o feed.Options) (collector.Collector, error) { return metasploit.New(o) },
}

// Nuclei is NucleiFeed.
var Nuclei = &Adapter{
	Name: "nuclei", URL: nuclei.FeedURL, NewKey: "CVE-2026-41940", ChangeKey: "CVE-2021-44228", CVEOfChange: "CVE-2021-44228",
	Load: func(t testing.TB) any {
		var out []any
		for _, line := range pystr.Splitlines(read(t, "tests/fixtures/nuclei/cves.json")) {
			if pystr.Strip(line) != "" {
				out = append(out, decode(t, line))
			}
		}
		return out
	},
	Dump: func(t testing.TB, data any) []byte {
		var b strings.Builder
		for _, o := range data.([]any) {
			b.WriteString(encode(t, o, pyjson.Options{Compact: true, EnsureASCII: true}) + "\n")
		}
		return []byte(b.String())
	},
	Without: func(data any, key string) any {
		var out []any
		for _, o := range data.([]any) {
			if o.(*pyjson.Object).Get("ID") != key {
				out = append(out, o)
			}
		}
		return out
	},
	Changed: func(t testing.TB, data any, key string) any {
		out := deepCopy(t, data).([]any)
		for _, o := range out {
			if o.(*pyjson.Object).Get("ID") == key {
				info := o.(*pyjson.Object).Get("Info").(*pyjson.Object)
				info.Set("Name", info.Get("Name").(string)+" (updated)")
			}
		}
		return out
	},
	New: func(o feed.Options) (collector.Collector, error) { return nuclei.New(o) },
}

// Adapters is ADAPTERS, in sorted name order (pytest params order).
var Adapters = []*Adapter{Edb, Msf, Nuclei}

// NoSleep is no_sleep; it records the requested delays.
type NoSleep struct {
	mu    sync.Mutex
	Slept []time.Duration
}

// Sleep implements feed.Options.Sleep.
func (n *NoSleep) Sleep(_ context.Context, d time.Duration) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Slept = append(n.Slept, d)
	return nil
}

// New is poc_feed_helpers.collector(adapter, server, max_bytes=...): the
// collector talks to the server only; maxBytes 0 = default cap.
func New(t testing.TB, a *Adapter, s *Server, maxBytes int64) collector.Collector {
	t.Helper()
	c, err := a.New(feed.Options{Transport: s, Sleep: (&NoSleep{}).Sleep, MaxBytes: maxBytes})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ------------------------------------------------------------------ DB helpers

// Run is run_collector(conn, c, now=now[, renormalize=True]); fails the test on error.
func Run(t testing.TB, d *testutil.TestDB, c collector.Collector, now time.Time, renorm bool) *pipeline.Stats {
	t.Helper()
	st, err := TryRun(d, c, now, renorm)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return st
}

// TryRun runs the pipeline and returns its error.
func TryRun(d *testutil.TestDB, c collector.Collector, now time.Time, renorm bool) (*pipeline.Stats, error) {
	return pipeline.RunCollector(context.Background(), d.Conn, c,
		pipeline.Options{Now: func() time.Time { return now }, Renormalize: renorm})
}

// CursorText is collector_state.cursor::text (single row).
func CursorText(t testing.TB, d *testutil.TestDB) string {
	t.Helper()
	var s string
	if err := d.Conn.QueryRow(context.Background(), "SELECT cursor::text FROM collector_state").Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// Cursor is the decoded cursor.
func Cursor(t testing.TB, d *testutil.TestDB) *pyjson.Object {
	t.Helper()
	return decode(t, CursorText(t, d)).(*pyjson.Object)
}

// Count runs a count(*) query.
func Count(t testing.TB, d *testutil.TestDB, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := d.Conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Strings runs a one-text-column query.
func Strings(t testing.TB, d *testutil.TestDB, sql string, args ...any) []string {
	t.Helper()
	rows, err := d.Conn.Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// Counts is the COUNTS query of test_poc_feeds_pipeline.py.
func Counts(t testing.TB, d *testutil.TestDB) [5]int64 {
	t.Helper()
	var c [5]int64
	err := d.Conn.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM raw_record), (SELECT count(*) FROM vuln),
                   (SELECT count(*) FROM vuln_alias), (SELECT count(*) FROM affected),
                   (SELECT count(*) FROM event)`).Scan(&c[0], &c[1], &c[2], &c[3], &c[4])
	if err != nil {
		t.Fatal(err)
	}
	return c
}
