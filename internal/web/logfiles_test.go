package web_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
)

// loc8 is a fixed UTC+8 zone (like the VPS's Asia/Singapore).
var loc8 = time.FixedZone("UTC+8", 8*3600)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time     { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Set(t time.Time)    { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func at(s string) time.Time             { t, _ := time.Parse(time.RFC3339, s); return t }
func local(day, clock string) time.Time { return at(day + "T" + clock + "+08:00") }

// failingSrc makes every query fail while fail is set (a 500 on the API).
type failingSrc struct {
	site.ConnSource
	fail atomic.Bool
}

func (f *failingSrc) WithConn(ctx context.Context, fn func(*pgx.Conn) error) error {
	if f.fail.Load() {
		return errors.New("database down (test)")
	}
	return f.ConnSource.WithConn(ctx, fn)
}

type logEnv struct {
	ts     *httptest.Server
	logs   *web.LogFiles
	dir    string
	stderr *syncBuf
	clock  *fakeClock
	src    *failingSrc
}

// newLogEnv runs a two-host server writing log files to a temp dir, wired
// like `nday serve` (stderr text handler teed with the error file). withDB
// seeds a database (needed for API 200s); otherwise only fake pages work.
func newLogEnv(t *testing.T, withDB bool, start time.Time, before func(dir string)) *logEnv {
	t.Helper()
	t.Parallel()
	e := &logEnv{dir: t.TempDir(), stderr: &syncBuf{}, clock: &fakeClock{t: start}}
	if before != nil {
		before(e.dir)
	}
	logs, err := web.OpenLogFiles(web.LogOptions{Dir: e.dir, Now: e.clock.Now, Location: loc8,
		Stderr: slog.New(slog.NewTextHandler(e.stderr, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logs.Close() })
	e.logs = logs
	log := slog.New(web.TeeHandler(slog.NewTextHandler(e.stderr, nil), logs.ErrorHandler()))
	wc := web.Config{Logger: log, PublicURL: testPublic, APIURL: testAPI, Logs: logs}
	if withDB {
		d := testutil.NewMigratedDB(t)
		sitetest.Seed(t, d.Conn)
		cfg, err := pgx.ParseConfig(d.URL)
		if err != nil {
			t.Fatal(err)
		}
		pool := dbpool.New(cfg, dbpool.Options{Size: 3, Dial: testutil.Dial(cfg)})
		t.Cleanup(pool.Close)
		e.src = &failingSrc{ConnSource: pool}
		wc.Store = site.New(e.src).WithClock(func() time.Time { return sitetest.Now })
	}
	srv := gated(web.New(wc))
	registerFakeSite(srv)
	srv.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("kaboom") })
	srv.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) })
	e.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(e.ts.Close)
	return e
}

func (e *logEnv) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// lines decodes a JSON-lines file; every line must be one valid object.
func lines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("not one JSON object per line: %q: %v", ln, err)
		}
		out = append(out, m)
	}
	return out
}

func TestLogFilesBothHosts(t *testing.T) {
	e := newLogEnv(t, true, local("2026-11-13", "15:30:00.123"), nil)
	type req struct {
		host, path string
		status     int
		fail       bool
	}
	reqs := []req{
		{"www.nday.land", "/about", 200, false},
		{"www.nday.land", "/nope", 404, false},
		{"www.nday.land", "/boom", 500, false},
		{apiHost, "/v1/stats", 200, false},
		{apiHost, "/nope", 404, false},
		{apiHost, "/v1/search?q=nothing-cached", 500, true},
	}
	for _, r := range reqs {
		e.src.fail.Store(r.fail)
		resp, b := do(t, e.ts, "GET", r.host, r.path, "CF-Connecting-IP", "203.0.113.7", "CF-Ray", "8f00aa-SIN",
			"CF-IPCountry", "SG", "User-Agent", "curl/8.7.1", "Referer", "https://www.nday.land/vuln?q=secret#x",
			"X-Forwarded-For", "198.51.100.1, 10.0.0.1")
		if resp.StatusCode != r.status {
			t.Fatalf("%s%s: %d %s", r.host, r.path, resp.StatusCode, b)
		}
		if r.status == 500 && (!json.Valid(b) || !strings.Contains(string(b), `"internal"`)) {
			t.Errorf("%s: 500 body %s", r.path, b)
		}
	}
	e.src.fail.Store(false)
	acc := lines(t, e.read(t, "access-2026-11-13.log"))
	if len(acc) != len(reqs) {
		t.Fatalf("access lines %d", len(acc))
	}
	port := float64(e.ts.Listener.Addr().(*net.TCPAddr).Port)
	for i, r := range reqs {
		m := acc[i]
		domain := strings.Split(r.host, ":")[0]
		if m["host"] != r.host || m["domain"] != domain || m["uri"] != r.path || m["status"] != float64(r.status) ||
			m["method"] != "GET" || m["time"] != "2026-11-13T15:30:00.123+08:00" || m["client_ip"] != "203.0.113.7" ||
			m["remote_addr"] != "127.0.0.1" || m["cf_ray"] != "8f00aa-SIN" || m["country"] != "SG" ||
			m["proto"] != "HTTP/1.1" || m["user_agent"] != "curl/8.7.1" || m["server_port"] != port ||
			m["referer"] != "https://www.nday.land/vuln?q=secret" || m["http_x_forwarded_for"] != "198.51.100.1, 10.0.0.1" ||
			m["ssl_protocol"] != "" || m["ssl_cipher"] != "" {
			t.Errorf("access line %d: %v", i, m)
		}
		if _, ok := m["request_time"].(float64); !ok {
			t.Errorf("request_time %T", m["request_time"])
		}
		if n, ok := m["bytes_sent"].(float64); !ok || (r.status == 200 && n == 0) {
			t.Errorf("bytes_sent %v", m["bytes_sent"])
		}
	}
	errs := e.read(t, "error-2026-11-13.log")
	el := lines(t, errs)
	var panics, fivexx, failed int
	for _, m := range el {
		if m["time"] != "2026-11-13T15:30:00.123+08:00" {
			t.Errorf("error time %v", m["time"])
		}
		switch m["msg"] {
		case "panic":
			panics++
			if !strings.Contains(fmt.Sprint(m["stack"]), "goroutine") || m["panic"] != "kaboom" {
				t.Errorf("panic record %v", m)
			}
		case "http 5xx":
			fivexx++
			if m["status"] != float64(500) || m["cf_ray"] != "8f00aa-SIN" || m["level"] != "ERROR" {
				t.Errorf("5xx record %v", m)
			}
		case "request failed":
			failed++
		}
	}
	if panics != 1 || fivexx != 2 || failed != 1 {
		t.Errorf("error file: panics=%d 5xx=%d failed=%d\n%s", panics, fivexx, failed, errs)
	}
	// stderr: the same WARN+ records, and no access lines.
	se := e.stderr.String()
	if !strings.Contains(se, "msg=panic") || strings.Count(se, `msg="http 5xx"`) != 2 || strings.Contains(se, "msg=http ") {
		t.Errorf("stderr:\n%s", se)
	}
}

func TestLogFilesRedactionAndInjection(t *testing.T) {
	e := newLogEnv(t, false, local("2026-11-13", "09:00:00"), nil)
	resp, _ := do(t, e.ts, "GET", "www.nday.land",
		"/auth/github/callback?code=SECRETCODE&state=SECRETSTATE&ticket=SECRETTICKET&return=/x",
		"Cookie", "nday_session=COOKIESECRET", "Authorization", "Bearer AUTHSECRET",
		"Referer", "https://www.nday.land/auth/github/start?ticket=REFTICKET&code=REFCODE#REFFRAG")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	// CR/LF and quotes cannot arrive in an HTTP/1.1 header on the wire, so
	// drive the handler directly.
	h := e.ts.Config.Handler
	r := httptest.NewRequest("GET", "http://www.nday.land/x", nil)
	r.URL.Path = "/nope\r\n{\"forged\":\"line\"}\"\x00"
	r.Header.Set("User-Agent", "ua\r\n{\"forged\":1}\"")
	r.Header.Set("X-Forwarded-For", "1.2.3.4\r\n{\"forged\":2}")
	r.Header.Set("Referer", "https://www.nday.land/a\"b%0D%0A?q=x")
	h.ServeHTTP(httptest.NewRecorder(), r)
	r = httptest.NewRequest("GET", "http://www.nday.land/x", nil)
	r.Header.Set("Referer", "javascript:alert(1)")
	r.URL.Path = "/boom"
	r.Host = "WWW.NDAY.LAND\r\nX: y"
	h.ServeHTTP(httptest.NewRecorder(), r)
	// the hostile Host is foreign: answered 308 by the host gate (foreign.go),
	// never reaching /boom, but still logged with the host sanitized
	// the same /boom through a served host keeps the 500 + hostile Referer case
	r = httptest.NewRequest("GET", "http://www.nday.land/x", nil)
	r.Header.Set("Referer", "javascript:alert(1)")
	r.URL.Path = "/boom"
	h.ServeHTTP(httptest.NewRecorder(), r)

	raw := e.read(t, "access-2026-11-13.log") + e.read(t, "error-2026-11-13.log")
	for _, secret := range []string{"SECRETCODE", "SECRETSTATE", "SECRETTICKET", "COOKIESECRET", "AUTHSECRET",
		"REFTICKET", "REFCODE", "REFFRAG", "nday_session", "Bearer"} {
		if strings.Contains(raw, secret) {
			t.Errorf("%s in log files", secret)
		}
	}
	acc := lines(t, e.read(t, "access-2026-11-13.log"))
	if len(acc) != 4 {
		t.Fatalf("lines %d: %s", len(acc), raw)
	}
	if q := acc[0]["uri"]; q != "/auth/github/callback?code=REDACTED&state=REDACTED&ticket=REDACTED&return=/x" {
		t.Errorf("uri %v", q)
	}
	if acc[0]["referer"] != "https://www.nday.land/auth/github/start?ticket=REDACTED&code=REDACTED" {
		t.Errorf("referer %v", acc[0]["referer"])
	}
	if acc[1]["uri"] != "/nope%0D%0A%7B%22forged%22:%22line%22%7D%22%00" || acc[1]["user_agent"] != "ua\r\n{\"forged\":1}\"" ||
		acc[1]["referer"] != "https://www.nday.land/a%22b%0D%0A?q=x" || acc[1]["http_x_forwarded_for"] != "1.2.3.4\r\n{\"forged\":2}" {
		t.Errorf("injection line %q", acc[1])
	}
	if acc[2]["host"] != "www.nday.land\r\nx: y" || acc[2]["domain"] != "" || acc[2]["referer"] != "javascript:alert(1)" ||
		acc[2]["status"] != float64(308) {
		t.Errorf("host line %v", acc[2])
	}
	if acc[3]["host"] != "www.nday.land" || acc[3]["uri"] != "/boom" || acc[3]["referer"] != "javascript:alert(1)" ||
		acc[3]["status"] != float64(500) {
		t.Errorf("500 line %v", acc[3])
	}
	for _, f := range []string{"access-2026-11-13.log", "error-2026-11-13.log"} {
		for _, ln := range strings.Split(e.read(t, f), "\n") {
			if strings.HasPrefix(ln, `{"forged"`) || strings.Contains(ln, "\r") {
				t.Errorf("%s: forged line %q", f, ln)
			}
		}
	}
}

// The file changes at LOCAL midnight (UTC+8 here), not at UTC midnight.
func TestLogFilesLocalMidnight(t *testing.T) {
	e := newLogEnv(t, false, local("2026-11-13", "23:59:59"), nil)
	get := func(at time.Time) {
		e.clock.Set(at)
		if resp, _ := do(t, e.ts, "GET", "www.nday.land", "/about"); resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
	}
	get(local("2026-11-13", "23:59:59"))
	get(local("2026-11-14", "00:00:01"))
	// UTC midnight is 08:00 local: both requests stay in the 2026-11-14 file.
	get(at("2026-11-13T23:59:59Z")) // 07:59:59 local on the 14th
	get(at("2026-11-14T00:00:01Z")) // 08:00:01 local on the 14th
	a := lines(t, e.read(t, "access-2026-11-13.log"))
	b := lines(t, e.read(t, "access-2026-11-14.log"))
	if len(a) != 1 || a[0]["time"] != "2026-11-13T23:59:59.000+08:00" {
		t.Errorf("13th: %v", a)
	}
	if len(b) != 3 || b[0]["time"] != "2026-11-14T00:00:01.000+08:00" || b[1]["time"] != "2026-11-14T07:59:59.000+08:00" ||
		b[2]["time"] != "2026-11-14T08:00:01.000+08:00" {
		t.Errorf("14th: %v", b)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "access-2026-11-15.log")); err == nil {
		t.Error("a file was opened for the UTC date")
	}
	if !strings.HasSuffix(e.logs.Access.Name(), "access-2026-11-14.log") {
		t.Errorf("current %s", e.logs.Access.Name())
	}
}

// Concurrent requests across the rollover lose no line (run with -race).
func TestLogFilesConcurrentRollover(t *testing.T) {
	e := newLogEnv(t, false, local("2026-11-13", "23:59:59"), nil)
	const n = 200
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16) // stay under the macOS listen backlog
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if i == n/2 {
				e.clock.Set(local("2026-11-14", "00:00:00"))
			}
			resp, err := http.Get(e.ts.URL + fmt.Sprintf("/about?i=%d", i))
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}
	wg.Wait()
	a := lines(t, e.read(t, "access-2026-11-13.log"))
	b := lines(t, e.read(t, "access-2026-11-14.log"))
	seen := map[string]bool{}
	for _, m := range append(a, b...) {
		seen[fmt.Sprint(m["uri"])] = true
	}
	if len(a)+len(b) != n || len(seen) != n {
		t.Errorf("lines %d + %d, distinct %d, want %d", len(a), len(b), len(seen), n)
	}
	for _, m := range a {
		if !strings.HasPrefix(fmt.Sprint(m["time"]), "2026-11-13T") {
			t.Errorf("13th file has %v", m["time"])
		}
	}
	for _, m := range b {
		if !strings.HasPrefix(fmt.Sprint(m["time"]), "2026-11-14T") {
			t.Errorf("14th file has %v", m["time"])
		}
	}
}

// nday never deletes anything in the log directory.
func TestLogFilesKeepOldFiles(t *testing.T) {
	old := map[string]string{"access-2020-01-01.log": "old access\n", "error-2019-12-31.log": "old error\n",
		"access-2026-11-13.log": "earlier today\n"}
	e := newLogEnv(t, false, local("2026-11-13", "23:59:00"), func(dir string) {
		for n, c := range old {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o640); err != nil {
				t.Fatal(err)
			}
		}
	})
	check := func(when string) {
		t.Helper()
		for n, c := range old {
			b, err := os.ReadFile(filepath.Join(e.dir, n))
			if err != nil || !strings.HasPrefix(string(b), c) {
				t.Errorf("%s: %s changed: %q %v", when, n, b, err)
			}
		}
	}
	check("startup")
	do(t, e.ts, "GET", "www.nday.land", "/about")
	e.clock.Set(local("2026-11-14", "00:00:05"))
	do(t, e.ts, "GET", "www.nday.land", "/about")
	check("rollover")
	// A restart on the same day appended to that day's file.
	if got := e.read(t, "access-2026-11-13.log"); !strings.HasPrefix(got, "earlier today\n{") {
		t.Errorf("same-day file %q", got)
	}
}

// If the new day's file cannot be opened, lines keep going to the old one
// and the failure is reported on stderr once, not per request.
func TestLogFilesFailedRollover(t *testing.T) {
	e := newLogEnv(t, false, local("2026-11-13", "23:59:00"), nil)
	e.logs.Access.SetOpenFunc(func(string, int, os.FileMode) (*os.File, error) { return nil, errors.New("disk full (test)") })
	e.clock.Set(local("2026-11-14", "00:00:05"))
	for i := 0; i < 3; i++ {
		do(t, e.ts, "GET", "www.nday.land", "/about")
	}
	if n := len(lines(t, e.read(t, "access-2026-11-13.log"))); n != 3 {
		t.Errorf("old file lines %d", n)
	}
	if strings.Count(e.stderr.String(), "log rollover failed") != 1 {
		t.Errorf("stderr:\n%s", e.stderr.String())
	}
	e.logs.Access.SetOpenFunc(os.OpenFile)
	do(t, e.ts, "GET", "www.nday.land", "/about")
	if n := len(lines(t, e.read(t, "access-2026-11-14.log"))); n != 1 {
		t.Errorf("new file lines %d", n)
	}
}

func TestOpenLogFilesErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	_ = os.WriteFile(file, nil, 0o640)
	now := func() time.Time { return local("2026-11-13", "12:00:00") }
	blocked := t.TempDir()
	_ = os.Mkdir(filepath.Join(blocked, "error-2026-11-13.log"), 0o750) // today's error file cannot be opened
	for d, want := range map[string]string{
		filepath.Join(dir, "missing"): "does not exist",
		"relative/log":                "absolute path",
		file:                          "not a directory",
		blocked:                       "error-2026-11-13.log",
	} {
		_, err := web.OpenLogFiles(web.LogOptions{Dir: d, Now: now, Location: loc8})
		if err == nil || !strings.Contains(err.Error(), want) || !strings.HasPrefix(err.Error(), "NDAY_LOG_DIR") {
			t.Errorf("%s: %v", d, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); err == nil {
		t.Error("directory was created")
	}
	// The access file opened before the failure is closed again (no leak
	// to check portably); nothing else is created in the missing case.
}

// Without NDAY_LOG_DIR (Config.Logs nil) access lines stay on the logger.
func TestNoLogDirUnchanged(t *testing.T) {
	e := newEnv(t, nil)
	e.get(t, "/api/stats?x=1")
	if !strings.Contains(e.logs.String(), "msg=http method=GET path=/api/stats status=400") {
		t.Errorf("logs:\n%s", e.logs.String())
	}
}

// Keys always present, in the documented order, with the documented types.
func TestAccessLineFormat(t *testing.T) {
	e := newLogEnv(t, false, local("2026-11-13", "10:00:00"), nil)
	do(t, e.ts, "GET", "www.nday.land", "/about")
	first := strings.SplitN(e.read(t, "access-2026-11-13.log"), "\n", 2)[0]
	dec := json.NewDecoder(strings.NewReader(first))
	dec.UseNumber()
	if tok, _ := dec.Token(); tok != json.Delim('{') {
		t.Fatal(first)
	}
	var keys []string
	types := map[string]string{}
	for dec.More() {
		k, _ := dec.Token()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k.(string))
		types[k.(string)] = fmt.Sprintf("%T", v)
	}
	want := "time client_ip remote_addr domain host method uri status referer http_x_forwarded_for server_port " +
		"request_length request_time ssl_protocol ssl_cipher bytes_sent proto user_agent cf_ray country"
	if strings.Join(keys, " ") != want {
		t.Errorf("keys %v", keys)
	}
	for _, k := range []string{"status", "server_port", "request_length", "request_time", "bytes_sent"} {
		if types[k] != "json.Number" {
			t.Errorf("%s is %s", k, types[k])
		}
	}
	for _, k := range []string{"time", "client_ip", "domain", "referer", "ssl_protocol", "cf_ray"} {
		if types[k] != "string" {
			t.Errorf("%s is %s", k, types[k])
		}
	}
}

// request_length: request line + headers (Host included) + blank line +
// body, for a hand-written HTTP/1.1 request.
func TestAccessRequestLength(t *testing.T) {
	e := newLogEnv(t, false, local("2026-11-13", "10:00:00"), nil)
	raw := "POST /echo?a=1 HTTP/1.1\r\nHost: www.nday.land\r\nContent-Length: 11\r\nX-Test: abc\r\n" +
		"Connection: close\r\n\r\nhello world"
	c, err := net.Dial("tcp", e.ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, raw)
	b, _ := io.ReadAll(c)
	c.Close()
	if !strings.HasSuffix(string(b), "hello world") {
		t.Fatalf("response %q", b)
	}
	m := lines(t, e.read(t, "access-2026-11-13.log"))[0]
	if m["request_length"] != float64(len(raw)) || m["method"] != "POST" || m["uri"] != "/echo?a=1" {
		t.Errorf("request_length %v want %d (%v)", m["request_length"], len(raw), m)
	}
}

// TLS fields come from the connection that reached the server.
func TestAccessTLSFields(t *testing.T) {
	e := newLogEnv(t, false, local("2026-11-13", "10:00:00"), nil)
	ts := httptest.NewTLSServer(e.ts.Config.Handler)
	defer ts.Close()
	resp, err := ts.Client().Get(ts.URL + "/about")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	m := lines(t, e.read(t, "access-2026-11-13.log"))[0]
	port := float64(ts.Listener.Addr().(*net.TCPAddr).Port)
	if m["ssl_protocol"] != "TLSv1.3" || m["ssl_cipher"] == "" || !strings.HasPrefix(m["ssl_cipher"].(string), "TLS_") ||
		m["server_port"] != port {
		t.Errorf("tls line %v", m)
	}
	// Hand-built TLS 1.2 state.
	r := httptest.NewRequest("GET", "https://www.nday.land/about", nil)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	e.ts.Config.Handler.ServeHTTP(httptest.NewRecorder(), r)
	m = lines(t, e.read(t, "access-2026-11-13.log"))[1]
	if m["ssl_protocol"] != "TLSv1.2" || m["ssl_cipher"] != "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" || m["server_port"] != float64(0) {
		t.Errorf("tls1.2 line %v", m)
	}
}
