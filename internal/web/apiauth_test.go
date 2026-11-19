package web_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nday.land/nday/internal/web"
	"nday.land/nday/internal/web/webtest"
)

func TestPrivateCache(t *testing.T) {
	for in, want := range map[string]string{
		"public, max-age=60":               "private, max-age=60",
		"public, max-age=3600":             "private, max-age=3600",
		"max-age=60":                       "private, max-age=60",
		"no-store":                         "no-store",
		"private, no-store":                "private, no-store",
		"":                                 "private, no-cache",
		"Public, max-age=5, s-maxage=600":  "private, max-age=5",
		`private="Set-Cookie", max-age=60`: "private, max-age=60",
		`public, private="x"`:              "private",
		"PRIVATE, max-age=1":               "PRIVATE, max-age=1",
	} {
		if got := web.PrivateCache(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// Without an authenticator (accounts disabled) every gated route is closed;
// the rest of the server is not.
func TestGateWithoutAuthenticator(t *testing.T) {
	srv := web.New(web.Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv.Handle("GET /feed.xml", srv.Gate(web.AuthSession|web.AuthFeedKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("gated handler ran")
	})))
	h := srv.Handler()
	for _, p := range []string{"/api/hot", "/api/vuln/CVE-2026-1", "/raw/kev/CVE-2026-1.json", "/api/affected/suggest?q=ab", "/feed.xml?key=x"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer "+webtest.TestAPIToken)
		h.ServeHTTP(rec, req)
		if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") != `Bearer realm="nday"` ||
			rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), `"code":"token_required"`) {
			t.Errorf("%s: %d %v %s", p, rec.Code, rec.Header(), rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/feed.xml", nil))
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("feed Referrer-Policy %q", rec.Header().Get("Referrer-Policy"))
	}
}

func TestRedactQueryCredentials(t *testing.T) {
	for _, c := range []struct{ path, in, want string }{
		{"/feed.xml", "key=u.mac&tag=kev", "key=REDACTED&tag=kev"},
		{"/zh-hans/feed.xml", "tag=a&KEY=x", "tag=a&KEY=REDACTED"},
		{"/feed.xml", "k%65y=x", "k%65y=REDACTED"},
		{"/api/hot", "since=7d&access_token=abc&token=d&api_key=e&apikey=f", "since=7d&access_token=REDACTED&token=REDACTED&api_key=REDACTED&apikey=REDACTED"},
		{"/api/search", "q=nday_" + strings.Repeat("A", 43), "q=REDACTED"},
		{"/api/search", "q=%6Eday_x", "q=REDACTED"},
		{"/api/search", "q=%zz", "q=REDACTED"},
		{"/api/search", "q=barracuda&limit=5", "q=barracuda&limit=5"},
		{"/auth/github/callback", "code=c&state=s&return=/x", "code=REDACTED&state=REDACTED&return=/x"},
	} {
		if got := web.RedactQuery(c.path, c.in); got != c.want {
			t.Errorf("%s?%s -> %q, want %q", c.path, c.in, got, c.want)
		}
	}
}

// Neither the API token (Authorization) nor a feed key or a token put in
// the query string reaches the access or error log.
func TestLogsHoldNoCredentials(t *testing.T) {
	e := newLogEnv(t, true, local("2026-11-13", "15:30:00.123"), nil)
	const feedKey = "0f0f0f0f-0000-4000-8000-000000000000.SECRETFEEDKEYMAC123456"
	urlToken := "nday_" + strings.Repeat("U", 43)
	for _, r := range []struct{ host, path string }{
		{apiHost, "/v1/stats?key=" + feedKey},
		{apiHost, "/v1/hot?access_token=" + urlToken},
		{"www.nday.land", "/feed.xml?key=" + feedKey},
		{"www.nday.land", "/raw/kev/CVE-2026-102895.json"},
		{"www.nday.land", "/boom?key=" + feedKey},
	} {
		for _, ref := range []string{"https://www.nday.land/feed.xml?key=" + feedKey,
			"https://www.nday.land/%zz?key=" + feedKey,                           // ours, but does not parse
			"https://evil.example/x?a=1&key=" + feedKey + "#frag",                // a foreign host
			"https://evil.example/q?access_token=" + urlToken + "&b=" + urlToken, // token-looking values
			"not a url ?key=" + feedKey} {
			do(t, e.ts, "GET", r.host, r.path, "Referer", ref)
		}
		do(t, e.ts, "GET", r.host, r.path, "Authorization", "")
	}
	all := e.read(t, "access-2026-11-13.log") + e.read(t, "error-2026-11-13.log") + e.stderr.String()
	for _, s := range []string{webtest.TestAPIToken, "SECRETFEEDKEYMAC", urlToken} {
		if strings.Contains(all, s) {
			t.Errorf("logs contain %.12s…:\n%s", s, all)
		}
	}
	if !strings.Contains(all, "key=REDACTED") || !strings.Contains(all, "access_token=REDACTED") ||
		!strings.Contains(all, `"referer":"https://evil.example/x?a=1&key=REDACTED#frag"`) && !strings.Contains(all, `"referer":"https://evil.example/x?a=1&key=REDACTED#frag"`) ||
		!strings.Contains(all, "https://www.nday.land/%zz?key=REDACTED") {
		t.Errorf("no redacted query in the logs:\n%s", all)
	}
}
