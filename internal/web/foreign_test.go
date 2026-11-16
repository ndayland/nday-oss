package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	fgPublic = "https://www.nday.land"
	fgAPI    = "https://api.nday.land"
)

// foreignServer answers "site <method> <host>" on every page.
func foreignServer(t *testing.T, public, api string) *httptest.Server {
	t.Helper()
	srv := New(Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), PublicURL: public, APIURL: api})
	srv.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "site "+r.Method+" "+r.Host)
	}))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func foreignDo(t *testing.T, ts *httptest.Server, method, host, target string) (*http.Response, string) {
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

func TestForeignHostRedirect(t *testing.T) {
	ts := foreignServer(t, fgPublic, fgAPI)
	for _, c := range []struct{ method, host, target, loc string }{
		{"GET", "evil.example", "/", fgPublic + "/"},
		{"GET", "evil.example", "/vuln/CVE-2026-1?q=a%20b&x=1", fgPublic + "/vuln/CVE-2026-1?q=a%20b&x=1"},
		{"GET", "evil.example", "/a%2Fb%20c/%E4%B8%AD?next=%2F%2Fevil.example", fgPublic + "/a%2Fb%20c/%E4%B8%AD?next=%2F%2Fevil.example"},
		{"GET", "evil.example:8443", "/x", fgPublic + "/x"},
		{"GET", "EVIL.Example", "/x", fgPublic + "/x"},
		{"HEAD", "evil.example", "/vuln/CVE-2026-1?q=1", fgPublic + "/vuln/CVE-2026-1?q=1"},
		{"GET", "www.nday.land:8443", "/x", fgPublic + "/x"}, // another port is another host
		{"GET", "www.nday.land.evil.example", "/x", fgPublic + "/x"},
	} {
		resp, body := foreignDo(t, ts, c.method, c.host, c.target)
		if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != c.loc {
			t.Errorf("%s %s%s: %d %q, want 308 %q", c.method, c.host, c.target, resp.StatusCode, resp.Header.Get("Location"), c.loc)
		}
		if resp.Header.Get("Cache-Control") != "no-store" || len(resp.Header.Values("Set-Cookie")) != 0 ||
			strings.HasPrefix(body, "site ") {
			t.Errorf("%s %s%s: headers %v body %q", c.method, c.host, c.target, resp.Header, body)
		}
	}
	// A target that cannot be redirected safely is a 400, never a page.
	if resp, body := foreignDo(t, ts, "GET", "evil.example", "//evil.example/x"); resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Errorf("// path: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
}

func TestForeignHostOtherMethods(t *testing.T) {
	ts := foreignServer(t, fgPublic, fgAPI)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		resp, body := foreignDo(t, ts, m, "evil.example", "/auth/signout?x=1")
		if resp.StatusCode != http.StatusMisdirectedRequest || !strings.Contains(body, `"wrong_host"`) ||
			resp.Header.Get("Location") != "" || resp.Header.Get("Cache-Control") != "no-store" ||
			!strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %v %s", m, resp.StatusCode, resp.Header, body)
		}
	}
}

func TestForeignHostServedHosts(t *testing.T) {
	ts := foreignServer(t, fgPublic, fgAPI)
	for _, host := range []string{
		"www.nday.land", "WWW.NDAY.LAND", "www.nday.land:443", "www.nday.land:",
		"localhost:8080", "localhost", "127.0.0.1:8080", "127.0.0.1", "[::1]:8080", "[::1]", "foo.localhost", "foo.localhost:8080",
		"127.1.2.3:9",
	} {
		for _, m := range []string{"GET", "POST"} {
			resp, body := foreignDo(t, ts, m, host, "/x")
			if resp.StatusCode != 200 || !strings.HasPrefix(body, "site "+m+" ") {
				t.Errorf("%s %s: %d %q", m, host, resp.StatusCode, body)
			}
		}
	}
	// The API host keeps its own mux, not the site's.
	for _, host := range []string{"api.nday.land", "API.nday.land:443"} {
		if resp, body := foreignDo(t, ts, "GET", host, "/v1"); resp.StatusCode != 200 || !strings.Contains(body, `"endpoints"`) {
			t.Errorf("api host %s: %d %s", host, resp.StatusCode, body)
		}
	}
	// Lookalikes of loopback names are foreign.
	for _, host := range []string{"localhost.evil.example", "127.0.0.1.evil.example", "evil.localhost.example",
		"localhostevil", "10.0.0.1", "192.0.2.1:8080", "[2001:db8::1]:8080"} {
		if resp, _ := foreignDo(t, ts, "GET", host, "/x"); resp.StatusCode != 308 {
			t.Errorf("host %q: %d", host, resp.StatusCode)
		}
	}
}

func TestForeignHostApexStillRedirects(t *testing.T) {
	ts := foreignServer(t, fgPublic, fgAPI)
	resp, _ := foreignDo(t, ts, "GET", "nday.land", "/about?a=1")
	if resp.StatusCode != 308 || resp.Header.Get("Location") != fgPublic+"/about?a=1" {
		t.Errorf("apex GET: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The apex is not foreign for other methods: the apex rule leaves them to the site.
	if resp, body := foreignDo(t, ts, "POST", "nday.land", "/x"); resp.StatusCode != 200 || !strings.HasPrefix(body, "site POST") {
		t.Errorf("apex POST: %d %s", resp.StatusCode, body)
	}
}

func TestForeignHostNoGateWithoutPublicURL(t *testing.T) {
	for _, api := range []string{"", fgAPI} {
		ts := foreignServer(t, "", api)
		for _, host := range []string{"evil.example", "www.nday.land", "localhost:8080", "nday.land"} {
			for _, m := range []string{"GET", "HEAD", "POST"} {
				if resp, _ := foreignDo(t, ts, m, host, "/x"); resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
					t.Errorf("api %q: %s %s: %d %q", api, m, host, resp.StatusCode, resp.Header.Get("Location"))
				}
			}
		}
	}
}

func TestLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":               true,
		"localhost:8080":          true,
		"foo.localhost":           true,
		"a.b.localhost:3000":      true,
		"127.0.0.1":               true,
		"127.0.0.1:8080":          true,
		"127.1.2.3":               true,
		"::1":                     true,
		"[::1]":                   true,
		"[::1]:8080":              true,
		"localhost.evil.example":  false,
		"127.0.0.1.evil.example":  false,
		"evil.localhost.example":  false,
		"evil-localhost":          false,
		"xlocalhost":              false,
		".localhost.evil":         false,
		"":                        false,
		"[]":                      false,
		":8080":                   false,
		"0.0.0.0":                 false,
		"10.0.0.1":                false,
		"192.0.2.1:80":            false,
		"[2001:db8::1]:80":        false,
		"::ffff:127.0.0.1":        true, // 4-in-6 loopback is still loopback
		"127.0.0.1@evil.example":  false,
		"localhost@evil.example":  false,
		"evil.example#localhost":  false,
		"127.0.0.1\r\nHost: evil": false,
		"www.nday.land":           false,
		"localhost.":              false, // no trailing-dot form is accepted
	} {
		if got := loopbackHost(host); got != want {
			t.Errorf("loopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
