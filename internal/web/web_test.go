package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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
	"nday.land/nday/internal/web/webtest"
)

// counting wraps a ConnSource and counts WithConn calls (= query batches).
type counting struct {
	site.ConnSource
	n atomic.Int64
}

func (c *counting) WithConn(ctx context.Context, fn func(*pgx.Conn) error) error {
	c.n.Add(1)
	return c.ConnSource.WithConn(ctx, fn)
}

type env struct {
	ts   *httptest.Server
	srv  *web.Server
	src  *counting
	logs *syncBuf
	db   *testutil.TestDB // seeded with sitetest.Seed
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newEnv(t *testing.T, register func(*web.Server)) *env {
	t.Helper()
	return newEnvCfg(t, web.Config{}, register)
}

// newEnvCfg is newEnv with extra server configuration (Store and Logger are
// filled in).
func newEnvCfg(t *testing.T, wc web.Config, register func(*web.Server)) *env {
	t.Helper()
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 3, Dial: testutil.Dial(cfg)})
	t.Cleanup(pool.Close)
	src := &counting{ConnSource: pool}
	logs := &syncBuf{}
	store := site.New(src).WithClock(func() time.Time { return sitetest.Now })
	wc.Store, wc.Logger = store, slog.New(slog.NewTextHandler(logs, nil))
	srv := web.New(wc)
	srv.SetAPIAuth(webtest.BearerAuth{})
	if register != nil {
		register(srv)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &env{ts: ts, srv: srv, src: src, logs: logs, db: d}
}

// get sends the test API token unless hdr sets Authorization itself (an
// empty value sends none).
func (e *env) get(t *testing.T, path string, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+webtest.TestAPIToken)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
		if hdr[i] == "Authorization" && hdr[i+1] == "" {
			req.Header.Del("Authorization")
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return m
}

func TestHotEndpointAndCaching(t *testing.T) {
	e := newEnv(t, nil)
	resp, b := e.get(t, "/api/hot?since=30d&min_stage=patch&limit=2")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "private, max-age=60" ||
		resp.Header.Get("Vary") != "Authorization" ||
		resp.Header.Get("Content-Type") != "application/json; charset=utf-8" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, b)
	}
	m := decode(t, b)
	rows := m["rows"].([]any)
	if len(rows) != 2 || m["next_cursor"] == nil || m["min_stage"] != "patch_released" || m["since"] != "30d" {
		t.Errorf("%s", b)
	}
	r0 := rows[0].(map[string]any)
	if r0["cve_id"] != "CVE-2026-1001" || r0["title"] != nil || r0["disclosed_at"] != nil {
		t.Errorf("row %v", r0)
	}
	tr := r0["transition"].(map[string]any)
	if tr["code"] != "KEV" || tr["precision"] != "day" || !strings.HasSuffix(tr["at"].(string), "T00:00:00Z") {
		t.Errorf("transition %v", tr)
	}
	slots := r0["slots"].([]any)
	if len(slots) != 6 || slots[4].(map[string]any)["state"] != "implied" || slots[5].(map[string]any)["latest"] != true {
		t.Errorf("slots %v", slots)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" || resp.Header.Get("X-Nday-Cache") != "miss" {
		t.Errorf("etag %q cache %q", etag, resp.Header.Get("X-Nday-Cache"))
	}
	// Same request: in-process cache hit, no DB; conditional request -> 304.
	before := e.src.n.Load()
	resp, b = e.get(t, "/api/hot?limit=2&min_stage=patch_released&since=30d", "If-None-Match", etag)
	if resp.StatusCode != http.StatusNotModified || len(b) != 0 || resp.Header.Get("X-Nday-Cache") != "hit" || e.src.n.Load() != before {
		t.Errorf("conditional: %d %q db=%d->%d", resp.StatusCode, resp.Header.Get("X-Nday-Cache"), before, e.src.n.Load())
	}
	// Next page via cursor.
	resp, b = e.get(t, "/api/hot?since=30d&min_stage=patch&limit=2&cursor="+m["next_cursor"].(string))
	if resp.StatusCode != 200 || decode(t, b)["rows"].([]any)[0].(map[string]any)["cve_id"] != "CVE-2026-1003" {
		t.Errorf("page 2: %s", b)
	}
}

func TestBurstOfIdenticalRequestsHitsDatabaseOnce(t *testing.T) {
	e := newEnv(t, nil)
	before := e.src.n.Load()
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/hot?since=7d&min_stage=kev", nil)
			req.Header.Set("Authorization", "Bearer "+webtest.TestAPIToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil || resp.StatusCode != 200 {
				bad.Add(1)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if bad.Load() != 0 || e.src.n.Load()-before != 1 {
		t.Errorf("errors %d, db calls %d", bad.Load(), e.src.n.Load()-before)
	}
}

func TestBadRequests(t *testing.T) {
	e := newEnv(t, nil)
	for path, param := range map[string]string{
		"/api/hot?since=5m":                         "since",
		"/api/hot?since=999d":                       "since",
		"/api/hot?min_stage=zzz":                    "min_stage",
		"/api/hot?limit=0":                          "limit",
		"/api/hot?limit=201":                        "limit",
		"/api/hot?limit=x":                          "limit",
		"/api/hot?offset=-1":                        "offset",
		"/api/hot?cursor=bogus":                     "cursor",
		"/api/hot?include_rejected=maybe":           "include_rejected",
		"/api/hot?foo=1":                            "foo",
		"/api/hot?since=7d&since=30d":               "since",
		"/api/vuln/CVE-26-1":                        "cve",
		"/api/vuln/CVE-2026-1?x=1":                  "x",
		"/api/search?q=" + strings.Repeat("a", 101): "q",
		"/api/search?q=abc&limit=51":                "limit",
		"/raw/nosuch/CVE-2026-1.json":               "source",
		"/raw/kev/..%2Fetc.json":                    "key",
	} {
		resp, b := e.get(t, path)
		if resp.StatusCode != 400 || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %s", path, resp.StatusCode, b)
			continue
		}
		er := decode(t, b)["error"].(map[string]any)
		if er["param"] != param || er["code"] != "bad_request" || er["status"].(float64) != 400 {
			t.Errorf("%s: %s", path, b)
		}
	}
}

func TestVulnEndpoint(t *testing.T) {
	e := newEnv(t, nil)
	resp, b := e.get(t, "/api/vuln/cve-2026-102895")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "private, max-age=60" {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	m := decode(t, b)
	if m["cve_id"] != "CVE-2026-102895" || len(m["events"].([]any)) != 6 || m["kev"].(map[string]any)["due_date"] != "2026-11-12" {
		t.Errorf("%s", b)
	}
	ev := m["events"].([]any)[0].(map[string]any)
	for _, k := range []string{"type", "source", "url", "occurred_at", "observed_at", "is_backfill", "precision", "dedupe_key", "detail"} {
		if _, ok := ev[k]; !ok {
			t.Errorf("event lacks %s", k)
		}
	}
	resp, b = e.get(t, "/api/vuln/CVE-1999-0001")
	if resp.StatusCode != 404 || decode(t, b)["error"].(map[string]any)["code"] != "not_found" {
		t.Errorf("404: %d %s", resp.StatusCode, b)
	}
}

func TestOtherEndpoints(t *testing.T) {
	e := newEnv(t, nil)
	for path, check := range map[string]func(map[string]any) bool{
		"/api/sources": func(m map[string]any) bool {
			return len(m["collectors"].([]any)) == 9 && m["cvelist_backfill_backlog"].(float64) == 10
		},
		"/api/stats":                func(m map[string]any) bool { return len(m["by_stage"].([]any)) == 6 },
		"/api/search?q=barracuda":   func(m map[string]any) bool { return m["kind"] == "text" && len(m["rows"].([]any)) == 1 },
		"/api/search?q=2026-1028":   func(m map[string]any) bool { return m["kind"] == "cve_id" && len(m["rows"].([]any)) == 1 },
		"/api/search?q=a&limit=5":   func(m map[string]any) bool { return m["kind"] == "too_short" },
		"/api/search?q=100%25_safe": func(m map[string]any) bool { return len(m["rows"].([]any)) == 0 },
		"/healthz":                  func(m map[string]any) bool { return m["status"] == "ok" && m["db"] == "ok" },
		"/api/vuln/CVE-2026-1010":   func(m map[string]any) bool { return m["state"] == nil && m["stage"] == nil },
	} {
		resp, b := e.get(t, path)
		if resp.StatusCode != 200 || !check(decode(t, b)) {
			t.Errorf("%s: %d %s", path, resp.StatusCode, b)
		}
		want := "private, max-age=60"
		if path == "/healthz" {
			want = "no-store"
		}
		if resp.Header.Get("Cache-Control") != want {
			t.Errorf("%s: cache-control %q", path, resp.Header.Get("Cache-Control"))
		}
	}
}

func TestRawEndpoint(t *testing.T) {
	e := newEnv(t, nil)
	resp, b := e.get(t, "/raw/kev/CVE-2026-102895.json")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "private, max-age=3600" || resp.Header.Get("ETag") != `"h-kev-new"` ||
		resp.Header.Get("Last-Modified") == "" || !json.Valid(b) || !strings.Contains(string(b), `"v": 2`) {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, b)
	}
	resp, _ = e.get(t, "/raw/kev/CVE-2026-102895.json", "If-None-Match", `"h-kev-new"`)
	if resp.StatusCode != 304 {
		t.Errorf("304: %d", resp.StatusCode)
	}
	if resp, b := e.get(t, "/raw/metasploit/exploit/linux/http/gpustack_rce.json"); resp.StatusCode != 200 || !strings.Contains(string(b), "gpustack_rce") {
		t.Errorf("slash key %d", resp.StatusCode)
	}
	for _, p := range []string{"/raw/kev/CVE-1999-0001.json", "/raw/kev/CVE-2026-102895", "/raw/kev"} {
		if resp, b := e.get(t, p); resp.StatusCode != 404 || !json.Valid(b) {
			t.Errorf("%s: %d %s", p, resp.StatusCode, b)
		}
	}
}

func TestMethodsNotFoundPanicAndLogging(t *testing.T) {
	e := newEnv(t, func(s *web.Server) {
		s.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("kaboom") })
		s.HandleFunc("GET /page/{x}", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<p>" + r.PathValue("x")))
		})
	})
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(m, e.ts.URL+"/api/hot", strings.NewReader("x")) // 405 before any authentication
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, HEAD" || !json.Valid(b) {
			t.Errorf("%s: %d %s", m, resp.StatusCode, b)
		}
	}
	req, _ := http.NewRequest(http.MethodHead, e.ts.URL+"/api/stats", nil)
	req.Header.Set("Authorization", "Bearer "+webtest.TestAPIToken)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Errorf("HEAD %v", err)
	}
	for _, p := range []string{"/nope", "/api/nope", "/api/vuln/"} {
		if resp, b := e.get(t, p); resp.StatusCode != 404 || !json.Valid(b) {
			t.Errorf("%s: %d %s", p, resp.StatusCode, b)
		}
	}
	resp, b := e.get(t, "/boom", "CF-Connecting-IP", "203.0.113.7", "User-Agent", "secret-agent-header")
	if resp.StatusCode != 500 || decode(t, b)["error"].(map[string]any)["code"] != "internal" {
		t.Errorf("panic: %d %s", resp.StatusCode, b)
	}
	if resp, b := e.get(t, "/page/abc"); resp.StatusCode != 200 || string(b) != "<p>abc" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("html route %d %s", resp.StatusCode, b)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "msg=panic") || !strings.Contains(logs, "cf_ip=203.0.113.7") ||
		!strings.Contains(logs, "path=/boom status=500") || strings.Contains(logs, "secret-agent-header") {
		t.Errorf("logs:\n%s", logs)
	}
	if !strings.Contains(logs, "method=GET path=/page/abc status=200") || !strings.Contains(logs, "dur_ms=") {
		t.Errorf("access log:\n%s", logs)
	}
}

func TestCacheSingleflightTTLAndErrors(t *testing.T) {
	t.Parallel()
	c := web.NewCache(3, time.Second)
	var calls atomic.Int32
	slow := func(ctx context.Context) (any, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return "v", nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, _, err := c.Get(context.Background(), "k", time.Minute, slow); err != nil || v != "v" {
				t.Error(v, err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Errorf("calls %d", calls.Load())
	}
	// Errors are not cached.
	fail := func(context.Context) (any, error) { calls.Add(1); return nil, errors.New("x") }
	_, _, err1 := c.Get(context.Background(), "e", time.Minute, fail)
	_, _, err2 := c.Get(context.Background(), "e", time.Minute, fail)
	if err1 == nil || err2 == nil || calls.Load() != 3 {
		t.Errorf("errors cached? %v %v %d", err1, err2, calls.Load())
	}
	// A cancelled waiter does not cancel the shared computation.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	if _, _, err := c.Get(ctx, "s", time.Minute, slow); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, hit, _ := c.Get(context.Background(), "s", time.Minute, slow); !hit {
		t.Error("computation abandoned")
	}
	// Bounded size.
	for _, k := range []string{"a", "b", "c", "d", "e2"} {
		_, _, _ = c.Get(context.Background(), k, time.Minute, func(context.Context) (any, error) { return 1, nil })
	}
	if _, _, size := c.Stats(); size > 3 {
		t.Errorf("size %d", size)
	}
	// Panics become errors.
	if _, _, err := c.Get(context.Background(), "p", time.Minute, func(context.Context) (any, error) { panic("p") }); err == nil {
		t.Error("panic swallowed")
	}
}

func TestServeGracefulShutdown(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("done"))
	})
	ctx, cancel := context.WithCancel(context.Background())
	addrc := make(chan net.Addr, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- web.Serve(ctx, "127.0.0.1:0", h, slog.New(slog.NewTextHandler(io.Discard, nil)), func(a net.Addr) { addrc <- a })
	}()
	addr := <-addrc
	got := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + addr.String() + "/")
		if err != nil {
			got <- err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		got <- string(b)
	}()
	<-started
	cancel() // like SIGTERM
	if s := <-got; s != "done" {
		t.Errorf("in-flight request: %q", s)
	}
	if err := <-errc; err != nil {
		t.Errorf("serve: %v", err)
	}
	if _, err := net.DialTimeout("tcp", addr.String(), 200*time.Millisecond); err == nil {
		t.Error("still listening")
	}
	srv := web.NewHTTPServer(":0", h, slog.Default())
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 || srv.MaxHeaderBytes != 32<<10 {
		t.Errorf("timeouts %+v", srv)
	}
}

func TestVulnByGHSA(t *testing.T) {
	e := newEnv(t, nil)
	noFollow := func(path string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+webtest.TestAPIToken)
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	resp := noFollow("/api/vuln/ghsa-GJ9M-f8ph-pmhr")
	if resp.StatusCode != 307 || resp.Header.Get("Location") != "/api/vuln/"+sitetest.GPU ||
		resp.Header.Get("Cache-Control") != "private, max-age=60" {
		t.Errorf("one match: %d %v", resp.StatusCode, resp.Header)
	}
	resp, b := e.get(t, "/api/vuln/GHSA-2222-3333-4444")
	if resp.StatusCode != 404 || decode(t, b)["error"].(map[string]any)["code"] != "not_found" {
		t.Errorf("no match: %d %s", resp.StatusCode, b)
	}
	for _, bad := range []string{"GHSA-gj9m-f8ph", "GHSA-aaaa-bbbb-cccc"} {
		resp, b = e.get(t, "/api/vuln/"+bad)
		if resp.StatusCode != 400 || decode(t, b)["error"].(map[string]any)["param"] != "cve" {
			t.Errorf("malformed %s: %d %s", bad, resp.StatusCode, b)
		}
	}
	resp, _ = e.get(t, "/api/vuln/GHSA-gj9m-f8ph-pmhr?x=1")
	if resp.StatusCode != 400 {
		t.Errorf("unknown param: %d", resp.StatusCode)
	}
}

// A vulnerability keyed by a GHSA id is served like a CVE (cve_id holds the
// GHSA id); a GHSA id that became an alias still redirects; lists, cursors,
// the year filter and the search treat the row like any other.
func TestVulnKeyedByGHSA(t *testing.T) {
	e := newEnv(t, nil)
	sitetest.SeedGHSA(t, e.db.Conn)
	for _, p := range []string{"/api/vuln/" + sitetest.GHSA, "/api/vuln/ghsa-GPWC-27cw-rh9r"} {
		resp, b := e.get(t, p)
		if resp.StatusCode != 200 || decode(t, b)["cve_id"] != sitetest.GHSA {
			t.Errorf("%s: %d %.200s", p, resp.StatusCode, b)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/vuln/"+sitetest.GHSAAlias, nil)
	req.Header.Set("Authorization", "Bearer "+webtest.TestAPIToken)
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 307 || resp.Header.Get("Location") != "/api/vuln/CVE-2026-1004" {
		t.Errorf("alias: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	inRows := func(b []byte) bool {
		rows, _ := decode(t, b)["rows"].([]any)
		for _, r := range rows {
			if r.(map[string]any)["cve_id"] == sitetest.GHSA {
				return true
			}
		}
		return false
	}
	if _, b := e.get(t, "/api/hot"); !inRows(b) {
		t.Errorf("hot: %.300s", b)
	}
	if _, b := e.get(t, "/api/vulns?limit=200"); !inRows(b) {
		t.Errorf("vulns: %.300s", b)
	}
	if resp, b := e.get(t, "/api/vulns?year=2026&limit=200"); resp.StatusCode != 200 || inRows(b) {
		t.Errorf("vulns year: %d %.300s", resp.StatusCode, b)
	}
	resp, b := e.get(t, "/api/search?q=ghsa-gpwc-27cw-rh9r")
	if m := decode(t, b); resp.StatusCode != 200 || m["kind"] != "alias" || m["query"] != sitetest.GHSA || !inRows(b) {
		t.Errorf("search: %d %s", resp.StatusCode, b)
	}
	// a cursor ending on the GHSA row: the walk goes on past it
	seen, next := false, "/api/hot?since=30d&limit=1"
	for i := 0; next != "" && i < 50; i++ {
		resp, b := e.get(t, next)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", next, resp.StatusCode, b)
		}
		seen = seen || inRows(b)
		next = ""
		if c, ok := decode(t, b)["next_cursor"].(string); ok {
			next = "/api/hot?since=30d&limit=1&cursor=" + c
		}
	}
	if !seen {
		t.Error("hot walk never saw the GHSA row")
	}
}
