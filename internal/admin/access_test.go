package admin_test

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestAccessMatrix: every page and endpoint for every kind of visitor, on
// the public host, plus the API host and a foreign host. The table printed
// with -v is the access matrix of docs/admin.md.
func TestAccessMatrix(t *testing.T) {
	h := newHarness(t, hopt{})
	anon := h.browser()
	user := h.user("pat", "user")
	smod := h.user("sam", "moderator")
	h.suspend(smod.id)
	sadm := h.user("sue", "admin")
	h.suspend(sadm.id)
	mod := h.user("mia", "moderator")
	adm := h.user("boss", "admin")
	target := h.user("tom", "user")

	pages := []string{"/admin", "/admin/moderation", "/admin/corrections", "/admin/users", "/admin/users/" + target.id, "/admin/system", "/admin/audit"}
	type cell struct {
		status int
		loc    string
	}
	want := map[string]map[string]cell{}
	for _, p := range pages {
		want[p] = map[string]cell{"signed out": {302, "/login?return=" + url.QueryEscape(p)}, "user": {404, ""},
			"suspended moderator": {404, ""}, "suspended admin": {404, ""}, "admin": {200, ""}}
		switch p {
		case "/admin":
			want[p]["moderator"] = cell{302, "/admin/moderation"}
		case "/admin/moderation", "/admin/corrections", "/admin/users/" + target.id:
			want[p]["moderator"] = cell{200, ""}
		default:
			want[p]["moderator"] = cell{404, ""}
		}
	}
	who := []struct {
		name string
		b    *browser
	}{{"signed out", anon}, {"user", user}, {"suspended moderator", smod}, {"suspended admin", sadm}, {"moderator", mod}, {"admin", adm}}
	rows := map[string][]string{}
	for _, p := range pages {
		for _, w := range who {
			resp, body := w.b.do("GET", p, "")
			c := want[p][w.name]
			got := fmt.Sprint(resp.StatusCode)
			if resp.StatusCode == 302 {
				got += " → " + resp.Header.Get("Location")
			}
			rows[p] = append(rows[p], got)
			if resp.StatusCode != c.status || (c.loc != "" && resp.Header.Get("Location") != c.loc) {
				t.Errorf("%s as %s: %s, want %d %s", p, w.name, got, c.status, c.loc)
			}
			if resp.StatusCode == 404 {
				// the ordinary 404 page: nothing of the back office in it
				s := string(body)
				if !strings.Contains(s, `<html lang="en">`) || strings.Contains(s, "admin.js") || strings.Contains(s, "adm-nav") ||
					!strings.Contains(s, "No such page") {
					t.Errorf("%s as %s: 404 page is not the ordinary one", p, w.name)
				}
			}
			if resp.StatusCode == 200 && !strings.Contains(string(body), `<meta name="robots" content="noindex"/>`) {
				t.Errorf("%s as %s: no robots meta", p, w.name)
			}
		}
	}
	// localized: the same rules under a locale prefix
	if resp, _ := anon.do("GET", "/zh-hans/admin/users", ""); resp.StatusCode != 302 ||
		resp.Header.Get("Location") != "/zh-hans/login?return="+url.QueryEscape("/zh-hans/admin/users") {
		t.Errorf("zh-hans signed out: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := mod.do("GET", "/zh-hans/admin", ""); resp.StatusCode != 302 || resp.Header.Get("Location") != "/zh-hans/admin/moderation" {
		t.Errorf("zh-hans moderator: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := adm.do("GET", "/zh-hans/admin/system", ""); resp.StatusCode != 200 || !strings.Contains(string(body), `<html lang="zh-Hans">`) {
		t.Errorf("zh-hans admin: %d", resp.StatusCode)
	}
	// a query string is kept in the return target (and HEAD works like GET)
	if resp, _ := anon.do("GET", "/admin?days=30", ""); resp.Header.Get("Location") != "/login?return="+url.QueryEscape("/admin?days=30") {
		t.Errorf("return with query: %s", resp.Header.Get("Location"))
	}
	if resp, _ := adm.do("HEAD", "/admin/system", ""); resp.StatusCode != 200 {
		t.Errorf("HEAD: %d", resp.StatusCode)
	}
	// conditional requests never get a 304
	if resp, _ := adm.do("GET", "/admin/system", "", "If-None-Match", "*"); resp.StatusCode != 200 {
		t.Errorf("If-None-Match: %d", resp.StatusCode)
	}
	// other methods on a page
	if resp, _ := adm.do("POST", "/admin/users", ""); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST page: %d", resp.StatusCode)
	}

	// API: every endpoint for every visitor (admin last, in an order that succeeds)
	api := []struct{ path, body string }{
		{"/api/admin/users/" + target.id + "/suspend", `{"reason":"spam wave","duration":"7d"}`},
		{"/api/admin/users/" + target.id + "/unsuspend", ``},
		{"/api/admin/users/" + target.id + "/role", `{"role":"moderator"}`},
		{"/api/admin/users/" + target.id + "/signout-all", ``},
	}
	wantAPI := map[string]struct {
		status int
		code   string
	}{"signed out": {401, "not_signed_in"}, "user": {404, "not_found"}, "suspended moderator": {404, "not_found"},
		"suspended admin": {404, "not_found"}, "moderator": {403, "forbidden"}, "admin": {200, ""}}
	for _, a := range api {
		for _, w := range who {
			resp, body := w.b.post(a.path, a.body)
			e := wantAPI[w.name]
			rows[a.path] = append(rows[a.path], fmt.Sprintf("%d %s", resp.StatusCode, errCode(body)))
			expect(t, a.path+" as "+w.name, resp, body, e.status, e.code)
		}
	}
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != 4 {
		t.Errorf("audit rows after the admin's 4 actions: %d", n)
	}

	// host, method, CSRF, cross-site, content type, stale sign-in
	p := "/api/admin/users/" + target.id + "/unsuspend"
	h.sql(`UPDATE users SET status = 'suspended' WHERE id = $1`, target.id)
	check(t, "API host POST", 405, "method_not_allowed")(adm.do("POST", p, "", "Host", apiHost, "Origin", origin, "X-CSRF-Token", adm.csrf))
	check(t, "API host GET", 404, "not_found")(adm.do("GET", p, "", "Host", apiHost))
	// a foreign host never reaches the back office: web.Server answers it
	resp, body := adm.do("POST", p, "", "Host", "evil.example", "Origin", origin, "X-CSRF-Token", adm.csrf)
	checkForeignHost(t, "wrong host", "POST", p, resp, body)
	resp, body = adm.do("GET", "/admin/users", "", "Host", "evil.example")
	checkForeignHost(t, "page on a foreign host", "GET", "/admin/users", resp, body)
	if resp, body := adm.do("GET", "/admin/users", "", "Host", apiHost); resp.StatusCode != 404 || !strings.Contains(string(body), `"not_found"`) {
		t.Errorf("page on the API host: %d %s", resp.StatusCode, body)
	}
	check(t, "GET endpoint", 405, "method_not_allowed")(adm.do("GET", p, ""))
	check(t, "no CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", ""))
	check(t, "bad CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", flip(adm.csrf)))
	check(t, "other user's CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", mod.csrf))
	check(t, "cross-site", 403, "cross_site")(adm.post(p, "", "Sec-Fetch-Site", "cross-site"))
	check(t, "foreign origin", 403, "cross_site")(adm.post(p, "", "Origin", "https://evil.example", "Sec-Fetch-Site", ""))
	check(t, "no origin evidence", 403, "cross_site")(adm.post(p, "", "Origin", "", "Sec-Fetch-Site", ""))
	check(t, "form post", 415, "bad_request")(adm.post("/api/admin/users/"+target.id+"/suspend", "reason=x&duration=1d",
		"Content-Type", "application/x-www-form-urlencoded"))
	check(t, "unknown field", 400, "bad_request")(adm.post("/api/admin/users/"+target.id+"/suspend", `{"reason":"x","duration":"1d","until":"2099"}`))
	check(t, "body on a no-body endpoint", 400, "bad_request")(adm.post(p, `{"x":1}`))
	check(t, "unknown endpoint", 404, "not_found")(adm.post("/api/admin/users/"+target.id+"/delete", ""))
	check(t, "unknown subtree", 404, "not_found")(adm.post("/api/admin/x", ""))
	before := h.count(`SELECT count(*) FROM admin_audit`)
	h.clock.Advance(16 * time.Minute) // past the 15-minute window
	check(t, "stale session", 403, "reauth_required")(adm.post(p, ""))
	if resp, _ := adm.do("GET", "/admin/users", ""); resp.StatusCode != 200 {
		t.Errorf("pages need no recent sign-in: %d", resp.StatusCode)
	}
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != before {
		t.Errorf("refused requests wrote audit rows: %d -> %d", before, n)
	}
	if h.count(`SELECT count(*) FROM users WHERE id = $1 AND status = 'suspended'`, target.id) != 1 {
		t.Error("a refused request changed the target")
	}

	// the table for docs/admin.md
	var b strings.Builder
	b.WriteString("\n| route |")
	for _, w := range who {
		b.WriteString(" " + w.name + " |")
	}
	b.WriteString("\n|---|" + strings.Repeat("---|", len(who)) + "\n")
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("| `" + strings.ReplaceAll(k, target.id, "{id}") + "` | " + strings.Join(rows[k], " | ") + " |\n")
	}
	t.Log(b.String())
}

// check returns an expectation to apply to a (response, body) pair.
func check(t *testing.T, what string, status int, code string) func(*http.Response, []byte) {
	t.Helper()
	return func(resp *http.Response, body []byte) { t.Helper(); expect(t, what, resp, body, status, code) }
}

// TestNotInPageCache: back-office pages never go through the server's
// shared cache (a public page does, to compare).
func TestNotInPageCache(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("boss", "admin")
	_, _, before := h.srv.Cache.Stats()
	for _, p := range []string{"/admin", "/admin/moderation", "/admin/users", "/admin/users/" + adm.id, "/admin/system", "/admin/audit"} {
		if resp, _ := adm.do("GET", p, ""); resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	if _, _, after := h.srv.Cache.Stats(); after != before {
		t.Errorf("admin pages added %d entries to the shared cache", after-before)
	}
	adm.do("GET", "/src", "")
	if _, _, after := h.srv.Cache.Stats(); after == before {
		t.Error("control: a public page did not use the cache")
	}
}

// flip changes the first character of a token (always a different token).
func flip(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}
