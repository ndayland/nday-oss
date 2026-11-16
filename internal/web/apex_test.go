package web_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nday.land/nday/internal/web"
)

// apexServer is a server whose only page answers "site <host>".
func apexServer(t *testing.T, public, api string) *httptest.Server {
	t.Helper()
	srv := web.New(web.Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), PublicURL: public, APIURL: api})
	srv.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "site "+r.Method+" "+r.Host)
	}))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func apexDo(t *testing.T, ts *httptest.Server, method, host, target string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestApexRedirect(t *testing.T) {
	ts := apexServer(t, testPublic, testAPI)
	for _, c := range []struct {
		method, host, target string
		want                 string // Location; "" = served by the site
		status               int
	}{
		{"GET", "nday.land", "/vuln/CVE-2026-1?q=a%20b&x=1", testPublic + "/vuln/CVE-2026-1?q=a%20b&x=1", 308},
		{"HEAD", "nday.land", "/", testPublic + "/", 308},
		{"GET", "NDAY.Land", "/about", testPublic + "/about", 308},
		{"GET", "nday.land:443", "/src", testPublic + "/src", 308},
		{"GET", "nday.land:", "/src", testPublic + "/src", 308},
		{"GET", "nday.land", "/zh-hans/login?return=%2Faccount", testPublic + "/zh-hans/login?return=%2Faccount", 308},
		{"GET", "nday.land", "/a%2F%2Fb", testPublic + "/a%2F%2Fb", 308},
		{"GET", "nday.land", "//evil.example/x", "", 400},
		{"GET", "nday.land", "/x\\evil", testPublic + "/x%5Cevil", 308}, // the client sends %5C
		{"POST", "nday.land", "/auth/signout", "", 200},                 // only GET/HEAD
		{"OPTIONS", "nday.land", "/", "", 200},                          // only GET/HEAD
		{"GET", "www.nday.land", "/", "", 200},                          // the public host itself
		// Every other host is foreign (foreign.go): it is not served but sent to the
		// public origin, like the apex. Another port is another host.
		{"GET", "nday.land:8443", "/", testPublic + "/", 308},
		{"GET", "other.example", "/", testPublic + "/", 308},
		{"GET", "evil.nday.land", "/", testPublic + "/", 308},
		{"GET", "wwwnday.land", "/", testPublic + "/", 308},
		{"POST", "other.example", "/", "", 421}, // not redirected: 421 wrong_host
	} {
		resp, body := apexDo(t, ts, c.method, c.host, c.target)
		if resp.StatusCode != c.status {
			t.Errorf("%s %s%s: status %d want %d (%s)", c.method, c.host, c.target, resp.StatusCode, c.status, body)
			continue
		}
		if got := resp.Header.Get("Location"); got != c.want {
			t.Errorf("%s %s%s: Location %q want %q", c.method, c.host, c.target, got, c.want)
		}
		if c.status == 421 && !strings.Contains(body, `"wrong_host"`) {
			t.Errorf("%s %s%s: body %q", c.method, c.host, c.target, body)
		}
		// the apex redirect is cacheable, the one for a foreign host is not
		cache := "no-store"
		if h := strings.ToLower(c.host); h == "nday.land" || h == "nday.land:443" || h == "nday.land:" {
			cache = "public, max-age=3600"
		}
		if c.status == 308 && (resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Cache-Control") != cache) {
			t.Errorf("%s %s%s: headers %v", c.method, c.host, c.target, resp.Header)
		}
		if c.status == 200 && !strings.HasPrefix(body, "site "+c.method) {
			t.Errorf("%s %s%s: not served by the site: %q", c.method, c.host, c.target, body)
		}
	}
	// The API host keeps its own mux.
	resp, body := apexDo(t, ts, "GET", apiHost, "/v1")
	if resp.StatusCode != 200 || !strings.Contains(body, `"endpoints"`) {
		t.Errorf("api host: %d %s", resp.StatusCode, body)
	}
}

func TestApexRedirectOnlyForWWW(t *testing.T) {
	// Without a www. public host there is no apex: the bare domain is either the
	// public host itself (served), or just another foreign host, which is sent to
	// the public origin by the foreign-host rule (foreign.go), not by the apex
	// rule; with no public origin nothing is redirected.
	for _, c := range []struct {
		public, host, loc string // loc "" = served
	}{
		{"https://nday.land", "nday.land", ""},
		{"https://nday.land", "localhost:8080", ""},
		{"https://nday.land", "land", "https://nday.land/x"},
		{"", "nday.land", ""},
		{"", "localhost:8080", ""},
		{"", "land", ""},
		{"https://api.nday.land", "nday.land", "https://api.nday.land/x"},
		{"https://api.nday.land", "localhost:8080", ""},
		{"https://api.nday.land", "land", "https://api.nday.land/x"},
		{"http://localhost:8080", "nday.land", "http://localhost:8080/x"},
		{"http://localhost:8080", "localhost:8080", ""},
		{"http://localhost:8080", "land", "http://localhost:8080/x"},
	} {
		ts := apexServer(t, c.public, "")
		resp, body := apexDo(t, ts, "GET", c.host, "/x")
		want := 200
		if c.loc != "" {
			want = 308
		}
		if resp.StatusCode != want || resp.Header.Get("Location") != c.loc {
			t.Errorf("public %q, host %s: %d %q %s", c.public, c.host, resp.StatusCode, resp.Header.Get("Location"), body)
		}
	}
	// http origin: the default port is :80.
	ts := apexServer(t, "http://www.example.test", "")
	resp, _ := apexDo(t, ts, "GET", "example.test:80", "/p?a=1")
	if resp.StatusCode != 308 || resp.Header.Get("Location") != "http://www.example.test/p?a=1" {
		t.Errorf("http apex: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// An API host equal to the apex keeps the API.
	ts = apexServer(t, "https://www.example.test", "https://example.test")
	resp, body := apexDo(t, ts, "GET", "example.test", "/v1")
	if resp.StatusCode != 200 || !strings.Contains(body, `"endpoints"`) {
		t.Errorf("api on apex: %d %s", resp.StatusCode, body)
	}
}
