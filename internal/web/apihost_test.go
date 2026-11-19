package web_test

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

const (
	testPublic = "https://www.nday.land"
	testAPI    = "https://api.nday.land"
	apiHost    = "api.nday.land"
)

func TestParseOrigin(t *testing.T) {
	cases := map[string]string{
		"":                            "",
		"https://www.nday.land":       "https://www.nday.land",
		" https://www.nday.land/ ":    "https://www.nday.land",
		"http://127.0.0.1:8080":       "http://127.0.0.1:8080",
		"https://api.nday.land":       "https://api.nday.land",
		"www.nday.land":               "!",
		"javascript:alert(1)":         "!",
		"https://user:pw@nday.land":   "!",
		"https://nday.land/path":      "!",
		"https://nday.land/v1":        "!",
		"https://nday.land?x=1":       "!",
		"https://nday.land/#frag":     "!",
		"ftp://nday.land":             "!",
		"https://":                    "!",
		"https://nday.land'><script>": "!",
		"https://nday.land%2Fevil":    "!",
		"https://evil.example\\@x":    "!",
	}
	for in, want := range cases {
		got, err := web.ParseOrigin(in)
		if want == "!" {
			if err == nil || got != "" {
				t.Errorf("ParseOrigin(%q) = %q, %v; want error", in, got, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("ParseOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"https://api.nday.land", "https://API.nday.land:443", true},
		{"http://localhost", "http://localhost:80", true},
		{"https://api.nday.land", "http://api.nday.land", false},
		{"https://api.nday.land", "https://www.nday.land", false},
		{"https://api.nday.land:8443", "https://api.nday.land", false},
		{"", "", false},
	} {
		if got := web.SameOrigin(c.a, c.b); got != c.want {
			t.Errorf("SameOrigin(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestIsAPIHost(t *testing.T) {
	two := web.New(web.Config{PublicURL: testPublic, APIURL: testAPI})
	for host, want := range map[string]bool{
		"api.nday.land":       true,
		"API.Nday.LAND":       true,
		"api.nday.land:443":   true,
		"api.nday.land:":      true,
		"api.nday.land:80":    false,
		"api.nday.land:8443":  false,
		"www.nday.land":       false,
		"evil.api.nday.land":  false,
		"api.nday.land.evil":  false,
		"":                    false,
		"api.nday.land\r\nx:": false,
	} {
		if got := two.IsAPIHost(host); got != want {
			t.Errorf("IsAPIHost(%q) = %v, want %v", host, got, want)
		}
	}
	if web.New(web.Config{}).IsAPIHost("api.nday.land") {
		t.Error("single-host server has an API host")
	}
	if got := web.New(web.Config{APIURL: "http://api.nday.localhost:8080"}); !got.IsAPIHost("API.nday.localhost:8080") || got.IsAPIHost("api.nday.localhost") {
		t.Error("non-default port")
	}
}

// twoEnv runs a single-host and a two-host server over the same store.
type twoEnv struct {
	single, two *httptest.Server
}

func newTwoEnv(t *testing.T) *twoEnv {
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
	store := site.New(pool).WithClock(func() time.Time { return sitetest.Now })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	single := web.New(web.Config{Store: store, Logger: log})
	two := web.New(web.Config{Store: store, Logger: log, PublicURL: testPublic, APIURL: testAPI})
	for _, s := range []*web.Server{single, two} {
		s.SetAPIAuth(webtest.BearerAuth{})
		registerFakeSite(s)
	}
	e := &twoEnv{single: httptest.NewServer(single.Handler()), two: httptest.NewServer(two.Handler())}
	t.Cleanup(e.single.Close)
	t.Cleanup(e.two.Close)
	return e
}

// registerFakeSite mounts stand-ins for what internal/auth and internal/webui
// register (same patterns); each sets a cookie so a leak would show.
func registerFakeSite(s *web.Server) {
	fake := func(kind string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "nday_session", Value: "x"})
			if kind == "html" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = io.WriteString(w, "<!doctype html><p>page</p>")
				return
			}
			_, _ = io.WriteString(w, kind)
		})
	}
	s.Handle("/auth/", fake("auth"))
	s.Handle("/account/", fake("account"))
	s.Handle("/api/me", fake("me"))
	s.Handle("/static/", fake("static"))
	s.Handle("GET /{$}", fake("html"))
	s.Handle("GET /about", fake("html"))
}

// gated installs the test authenticator (webtest.BearerAuth) on s.
func gated(s *web.Server) *web.Server {
	s.SetAPIAuth(webtest.BearerAuth{})
	return s
}

func do(t *testing.T, ts *httptest.Server, method, host, path string, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	// the test API token unless hdr sets Authorization (an empty value: none)
	req.Header.Set("Authorization", "Bearer "+webtest.TestAPIToken)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
		if hdr[i] == "Authorization" && hdr[i+1] == "" {
			req.Header.Del("Authorization")
		}
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func checkCORS(t *testing.T, what string, resp *http.Response) {
	t.Helper()
	h := resp.Header
	if h.Get("Access-Control-Allow-Origin") != "*" || h.Get("Access-Control-Allow-Credentials") != "" ||
		h.Get("Cross-Origin-Resource-Policy") != "cross-origin" || h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" ||
		h.Get("Access-Control-Expose-Headers") != "ETag, Retry-After, WWW-Authenticate" || len(h.Values("Set-Cookie")) != 0 {
		t.Errorf("%s: headers %v", what, h)
	}
}

// Every /v1 route on the API host answers exactly what its /api (or /raw)
// counterpart answers in single-host mode.
func TestAPIHostSameBodies(t *testing.T) {
	e := newTwoEnv(t)
	pairs := map[string]string{
		"/api/hot?since=30d&min_stage=patch&limit=2":           "/v1/hot?since=30d&min_stage=patch&limit=2",
		"/api/hot?since=5m":                                    "/v1/hot?since=5m",
		"/api/vuln/cve-2026-102895":                            "/v1/vuln/cve-2026-102895",
		"/api/vuln/CVE-1999-0001":                              "/v1/vuln/CVE-1999-0001",
		"/api/sources":                                         "/v1/sources",
		"/api/stats":                                           "/v1/stats",
		"/api/search?q=barracuda":                              "/v1/search?q=barracuda",
		"/api/search?q=abc&limit=51":                           "/v1/search?q=abc&limit=51",
		"/raw/kev/CVE-2026-102895.json":                        "/v1/raw/kev/CVE-2026-102895.json",
		"/raw/metasploit/exploit/linux/http/gpustack_rce.json": "/v1/raw/metasploit/exploit/linux/http/gpustack_rce.json",
		"/raw/kev/..%2Fetc.json":                               "/v1/raw/kev/..%2Fetc.json",
		"/healthz":                                             "/healthz",
	}
	for old, v1 := range pairs {
		r1, b1 := do(t, e.single, "GET", "", old)
		r2, b2 := do(t, e.two, "GET", apiHost, v1)
		if r1.StatusCode != r2.StatusCode || string(b1) != string(b2) || r1.Header.Get("ETag") != r2.Header.Get("ETag") ||
			r1.Header.Get("Cache-Control") != r2.Header.Get("Cache-Control") || r1.Header.Get("Content-Type") != r2.Header.Get("Content-Type") {
			t.Errorf("%s vs %s: %d %q %s\n  vs %d %q %s", old, v1, r1.StatusCode, r1.Header.Get("ETag"), b1,
				r2.StatusCode, r2.Header.Get("ETag"), b2)
		}
		if strings.HasPrefix(old, "/healthz") {
			continue
		}
		checkCORS(t, v1, r2)
		if r1.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("single-host %s has CORS", old)
		}
	}
	// /raw/... on the API host is an alias of /v1/raw/... (raw_records[].path
	// resolves against the API origin).
	for _, p := range []string{"/raw/kev/CVE-2026-102895.json", "/raw/metasploit/exploit/linux/http/gpustack_rce.json",
		"/raw/kev/CVE-1999-0001.json"} {
		r1, b1 := do(t, e.single, "GET", "", p)
		r2, b2 := do(t, e.two, "GET", apiHost, p)
		r3, b3 := do(t, e.two, "GET", apiHost, "/v1"+p)
		if r1.StatusCode != r2.StatusCode || string(b1) != string(b2) || string(b2) != string(b3) ||
			r2.Header.Get("ETag") != r3.Header.Get("ETag") {
			t.Errorf("raw alias %s: %d %d %d", p, r1.StatusCode, r2.StatusCode, r3.StatusCode)
		}
		checkCORS(t, "alias "+p, r2)
	}
	// conditional request from the API host
	r, _ := do(t, e.two, "GET", apiHost, "/v1/stats")
	if r2, b := do(t, e.two, "GET", apiHost, "/v1/stats", "If-None-Match", r.Header.Get("ETag")); r2.StatusCode != 304 || len(b) != 0 {
		t.Errorf("304: %d %s", r2.StatusCode, b)
	}
	// HEAD
	if r, b := do(t, e.two, "HEAD", "API.NDAY.LAND:443", "/v1/stats"); r.StatusCode != 200 || len(b) != 0 {
		t.Errorf("HEAD: %d", r.StatusCode)
	}
}

func TestAPIHostOnlyServesAPI(t *testing.T) {
	e := newTwoEnv(t)
	for _, host := range []string{apiHost, "API.nday.land", "api.nday.land:443"} {
		for _, p := range []string{"/auth/github/start", "/auth/", "/account/", "/account/sessions", "/api/me", "/api/hot",
			"/api/stats", "/raw/", "/static/app.css", "/about", "/zh-hans/", "/feed.xml",
			"/nope", "/v1/", "/v1/nope", "/v1/hot/x", "/v2/hot", "/favicon.ico", "/sitemap.xml", "/sitemap/pages.xml"} {
			resp, b := do(t, e.two, "GET", host, p)
			var m struct {
				Error web.APIError `json:"error"`
			}
			if resp.StatusCode != 404 || json.Unmarshal(b, &m) != nil || m.Error.Code != "not_found" ||
				resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
				t.Errorf("%s%s: %d %s", host, p, resp.StatusCode, b)
			}
			checkCORS(t, host+p, resp)
		}
	}
	// The same paths on the site host still reach the site handlers.
	for _, p := range []string{"/auth/github/start", "/api/me", "/static/app.css", "/"} {
		resp, _ := do(t, e.two, "GET", "www.nday.land", p)
		if resp.StatusCode != 200 || len(resp.Header.Values("Set-Cookie")) == 0 {
			t.Errorf("site %s: %d", p, resp.StatusCode)
		}
	}
	// Index: JSON, not HTML.
	for _, p := range []string{"/", "/v1"} {
		resp, b := do(t, e.two, "GET", apiHost, p, "Authorization", "") // public
		var idx struct {
			Name      string   `json:"name"`
			Docs      string   `json:"docs"`
			Endpoints []string `json:"endpoints"`
		}
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json; charset=utf-8" ||
			json.Unmarshal(b, &idx) != nil || idx.Docs != "https://www.nday.land/account#api" ||
			!strings.Contains(string(b), `"auth":{"scheme":"Bearer","header":"Authorization","token_url":"https://www.nday.land/account#api"}`) ||
			strings.Join(idx.Endpoints, " ") != "/v1/hot /v1/vulns /v1/discussed /v1/vuln/{cve} /v1/search /v1/tags /v1/affected/suggest /v1/sources /v1/stats /v1/raw/{source}/{key}.json /healthz" {
			t.Errorf("index %s: %d %s", p, resp.StatusCode, b)
		}
		checkCORS(t, p, resp)
	}
	resp, b := do(t, e.two, "GET", apiHost, "/robots.txt", "Authorization", "")
	if resp.StatusCode != 200 || string(b) != "User-agent: *\nDisallow: /\n" {
		t.Errorf("robots: %d %q", resp.StatusCode, b)
	}
	// Methods.
	resp, b = do(t, e.two, "POST", apiHost, "/v1/hot")
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, HEAD, OPTIONS" || !json.Valid(b) {
		t.Errorf("POST: %d %v %s", resp.StatusCode, resp.Header, b)
	}
	checkCORS(t, "POST", resp)
	// a preflight never carries credentials and needs none
	resp, b = do(t, e.two, "OPTIONS", apiHost, "/v1/hot", "Origin", "https://example.org", "Authorization", "",
		"Access-Control-Request-Method", "GET", "Access-Control-Request-Headers", "authorization, if-none-match")
	if resp.StatusCode != 204 || len(b) != 0 || resp.Header.Get("Access-Control-Allow-Methods") != "GET, HEAD, OPTIONS" ||
		resp.Header.Get("Access-Control-Allow-Headers") != "Accept, Authorization, If-None-Match" ||
		resp.Header.Get("Access-Control-Max-Age") != "86400" {
		t.Errorf("preflight: %d %v", resp.StatusCode, resp.Header)
	}
	checkCORS(t, "OPTIONS", resp)
}

// APIHeaders strips a cookie even if a handler behind it sets one.
func TestAPIHeadersStripsCookies(t *testing.T) {
	h := web.APIHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "b"})
		if r.URL.Path == "/write" {
			_, _ = w.Write([]byte("x"))
			return
		}
		w.WriteHeader(404)
	}))
	for _, p := range []string{"/write", "/status"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if len(rec.Result().Header.Values("Set-Cookie")) != 0 {
			t.Errorf("%s: cookie leaked", p)
		}
	}
}

func TestSiteHostRedirectsToAPI(t *testing.T) {
	e := newTwoEnv(t)
	cases := map[string]string{
		"/api/hot?since=7d&min_stage=patch":                            testAPI + "/v1/hot?since=7d&min_stage=patch",
		"/api/hot?min_stage=patch&since=7d&x=%2F%2F&y=a+b&z=%E4%B8%AD": testAPI + "/v1/hot?min_stage=patch&since=7d&x=%2F%2F&y=a+b&z=%E4%B8%AD",
		"/api/hot":                  testAPI + "/v1/hot",
		"/api/hot?":                 testAPI + "/v1/hot",
		"/api/vuln/CVE-2026-102895": testAPI + "/v1/vuln/CVE-2026-102895",
		"/api/sources":              testAPI + "/v1/sources",
		"/api/stats":                testAPI + "/v1/stats",
		"/api/search?q=100%25_safe": testAPI + "/v1/search?q=100%25_safe",
	}
	// "" sends the test server's own loopback Host (served); "evil.example" is
	// a foreign host, which the host gate sends to the public origin instead
	// (foreign_test.go): the API redirect is only for the public host.
	for _, host := range []string{"www.nday.land", ""} {
		for in, want := range cases {
			resp, _ := do(t, e.two, "GET", host, in)
			if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want ||
				len(resp.Header.Values("Set-Cookie")) != 0 {
				t.Errorf("%s%s: %d %q", host, in, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
	}
	// /raw/... is served on the site host itself (signed-in readers open
	// raw-record links from vulnerability pages), with credentials.
	for _, p := range []string{"/raw/kev/CVE-2026-102895.json", "/raw/metasploit/exploit/linux/http/gpustack_rce.json"} {
		if resp, b := do(t, e.two, "GET", "www.nday.land", p); resp.StatusCode != 200 || !json.Valid(b) {
			t.Errorf("site %s: %d %s", p, resp.StatusCode, b)
		}
		if resp, _ := do(t, e.two, "GET", "www.nday.land", p, "Authorization", ""); resp.StatusCode != 401 {
			t.Errorf("site %s without credentials: %d", p, resp.StatusCode)
		}
	}
	// The redirects need no credentials.
	if resp, _ := do(t, e.two, "GET", "www.nday.land", "/api/hot", "Authorization", ""); resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("redirect without token: %d", resp.StatusCode)
	}
	// Unknown /api/* stays a JSON 404; /healthz stays on the site host.
	for _, p := range []string{"/api/nope", "/api/vuln/", "/raw/"} {
		if resp, b := do(t, e.two, "GET", "www.nday.land", p); resp.StatusCode != 404 || !json.Valid(b) {
			t.Errorf("%s: %d %s", p, resp.StatusCode, b)
		}
	}
	if resp, _ := do(t, e.two, "GET", "www.nday.land", "/healthz"); resp.StatusCode != 200 {
		t.Errorf("site healthz %d", resp.StatusCode)
	}
	// /api/me is not redirected.
	if resp, b := do(t, e.two, "GET", "www.nday.land", "/api/me"); resp.StatusCode != 200 || string(b) != "me" {
		t.Errorf("/api/me: %d %s", resp.StatusCode, b)
	}
	// Non-GET stays 405 on the site host.
	if resp, _ := do(t, e.two, "POST", "www.nday.land", "/api/hot"); resp.StatusCode != 405 {
		t.Errorf("POST redirect: %d", resp.StatusCode)
	}
	// Single-host mode is unchanged: no redirect, no /v1.
	if resp, _ := do(t, e.single, "GET", "", "/api/stats"); resp.StatusCode != 200 {
		t.Errorf("single /api/stats %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.single, "GET", apiHost, "/api/stats"); resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("single api host /api/stats %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.single, "GET", apiHost, "/v1/stats"); resp.StatusCode != 404 {
		t.Errorf("single /v1/stats %d", resp.StatusCode)
	}
}

// rawRequest sends request bytes exactly as given and parses the response.
func rawRequest(t *testing.T, ts *httptest.Server, reqLine, host string) *http.Response {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, reqLine+"\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%q: %v", reqLine, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// A crafted path or query can neither move the redirect off the API origin
// (or, for a foreign host, off the public origin) nor inject a header.
func TestRedirectSafety(t *testing.T) {
	e := newTwoEnv(t)
	for _, target := range []string{
		"//evil.example/api/hot",
		"//evil.example",
		"/api//evil.example",
		"/raw//evil.example/x.json",
		"/raw/kev/%2F%2Fevil.example",
		"/raw/kev/%2f%2fevil.example/x.json",
		"/api/vuln/%5C%5Cevil.example",
		"/api/vuln/%5c%5cevil.example",
		`/api/vuln/\\evil.example`,
		`/raw/kev/\evil.example\x.json`,
		"/api/vuln/a%0D%0AX-Injected:%201",
		"/api/vuln/a%0d%0aX-Injected:%201",
		"/api/hot?x=%0D%0AX-Injected:%201",
		"/api/hot?next=//evil.example",
		"/api/hot?@evil.example",
		"/api/hot?x=\\evil.example",
		"/raw/kev/..%2F..%2F..%2Fevil.example",
		"/raw/kev/%2E%2E/%2E%2E/x",
		"/api/vuln/@evil.example",
		"/api/vuln/%40evil.example",
		"/api/vuln/CVE-1%23@evil.example",
		"/api/hot#@evil.example",
		"/api/hot?x#@evil.example",
	} {
		for _, host := range []string{"www.nday.land", "evil.example"} {
			resp := rawRequest(t, e.two, "GET "+target+" HTTP/1.1", host)
			if resp.Header.Get("X-Injected") != "" {
				t.Errorf("%q: header injected", target)
			}
			loc := resp.Header.Get("Location")
			t.Logf("%s %s -> %d %q", host, target, resp.StatusCode, loc)
			if loc == "" {
				if resp.StatusCode/100 == 3 {
					t.Errorf("%q: %d without Location", target, resp.StatusCode)
				}
				continue
			}
			// A backslash may only appear in the (verbatim) query, where it
			// cannot change the origin or path.
			beforeQuery, _, _ := strings.Cut(loc, "?")
			if strings.ContainsAny(loc, "\r\n") || strings.Contains(beforeQuery, "\\") {
				t.Errorf("%q: Location %q", target, loc)
			}
			u, err := url.Parse(loc)
			if err != nil {
				t.Errorf("%q: Location %q: %v", target, loc, err)
				continue
			}
			switch {
			case u.IsAbs() && host == "evil.example":
				// foreign host: sent to the public origin (foreign.go), same path
				if u.Scheme != "https" || u.Host != "www.nday.land" || u.User != nil || u.Fragment != "" ||
					!strings.HasPrefix(loc, testPublic+"/") || resp.StatusCode != http.StatusPermanentRedirect {
					t.Errorf("%q: %d Location %q", target, resp.StatusCode, loc)
				}
			case u.IsAbs():
				if u.Scheme != "https" || u.Host != apiHost || u.User != nil || !strings.HasPrefix(u.EscapedPath(), "/v1/") ||
					resp.StatusCode != http.StatusPermanentRedirect {
					t.Errorf("%q: %d Location %q", target, resp.StatusCode, loc)
				}
			default: // ServeMux's own path-cleaning redirect: must stay on this host
				if u.Host != "" || strings.HasPrefix(loc, "//") || !strings.HasPrefix(loc, "/") {
					t.Errorf("%q: relative Location %q", target, loc)
				}
			}
		}
	}
}
