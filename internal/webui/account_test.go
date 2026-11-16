package webui_test

import (
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
	"nday.land/nday/internal/webui/i18n"
)

var allAccounts = &webui.Accounts{Providers: []string{"google", "apple", "github", "x"}, Passkeys: true,
	PasskeySignup: true, MaxPasskeys: 20}

func newAccountsEnv(t *testing.T, a *webui.Accounts) *tenv {
	return newEnvWith(t, webui.Options{Accounts: a})
}

var switcherRe = regexp.MustCompile(`(?s)<details class="langs">.*?</details>|<link rel="alternate"[^>]*>|<select .*?</select>`)

var providerRe = regexp.MustCompile(`<a class="btn acct-btn" href="([^"]+)" data-provider="([a-z]+)">`)

// TestLoginShowsConfiguredMethods: /login lists exactly the enabled
// providers, the passkey button only with passkeys, the sign-up form only
// with passkey sign-up; start links carry a safe return target.
func TestLoginShowsConfiguredMethods(t *testing.T) {
	cases := []struct {
		name string
		a    *webui.Accounts
		want []string
	}{
		{"all", allAccounts, []string{"google", "apple", "github", "x"}},
		{"github only", &webui.Accounts{Providers: []string{"github"}}, []string{"github"}},
		{"passkeys only", &webui.Accounts{Passkeys: true}, nil},
		{"two, passkeys, no signup", &webui.Accounts{Providers: []string{"google", "x"}, Passkeys: true}, []string{"google", "x"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			e := newAccountsEnv(t, c.a)
			resp, body := e.get(t, "/login")
			if resp.StatusCode != 200 {
				t.Fatalf("/login %d", resp.StatusCode)
			}
			var got []string
			for _, m := range providerRe.FindAllStringSubmatch(body, -1) {
				got = append(got, m[2])
				if want := "/auth/" + m[2] + "/start?return=%2F"; htmlUnescape(m[1]) != want {
					t.Errorf("start link %q, want %q", htmlUnescape(m[1]), want)
				}
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("providers %v, want %v", got, c.want)
			}
			for _, p := range []string{"google", "apple", "github", "x"} {
				in := strings.Contains(body, `data-provider="`+p+`"`)
				if in != contains(c.want, p) {
					t.Errorf("provider %s present=%v", p, in)
				}
			}
			if has := strings.Contains(body, `id="pk-login"`); has != c.a.Passkeys {
				t.Errorf("passkey button present=%v, passkeys=%v", has, c.a.Passkeys)
			}
			if has := strings.Contains(body, `id="f-signup"`); has != c.a.PasskeySignup {
				t.Errorf("signup form present=%v, signup=%v", has, c.a.PasskeySignup)
			}
		})
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestLoginReturnTargets: the return parameter is kept only when it is a
// safe site path (auth.SafeReturnPath, which accepts the account page of
// every locale directly); hostile values fall back to home.
func TestLoginReturnTargets(t *testing.T) {
	e := newAccountsEnv(t, &webui.Accounts{Providers: []string{"github"}})
	for ret, want := range map[string]string{
		"/vuln/CVE-2026-102895":     "/vuln/CVE-2026-102895",
		"/vuln?q=a+b":               "/vuln?q=a+b",
		"/zh-hans/account":          "/zh-hans/account",
		"/account":                  "/account",
		"/account?x=1":              "/account?x=1",
		"//evil.example/":           "/",
		"https://evil.example/":     "/",
		"/\\evil.example":           "/",
		"/auth/github/start":        "/",
		"/account/delete":           "/",
		"/login?return=/x":          "/",
		"/a/../b":                   "/",
		"javascript:alert(1)":       "/",
		"/x?q=%0d%0aSet-Cookie:a=b": "/",
	} {
		_, body := e.get(t, "/login?return="+url.QueryEscape(ret))
		m := providerRe.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("return %q: no provider link", ret)
		}
		u, err := url.Parse(htmlUnescape(m[1]))
		if err != nil || u.Path != "/auth/github/start" {
			t.Fatalf("return %q: start link %q", ret, m[1])
		}
		if got := u.Query().Get("return"); got != want {
			t.Errorf("return %q: flow return %q, want %q", ret, got, want)
		}
		// (the language switcher keeps the query, escaped, like on every page)
		if strings.Contains(switcherRe.ReplaceAllString(body, ""), "evil.example") {
			t.Errorf("return %q echoed into the page", ret)
		}
	}
	// No page carries a navigation target for ?auth= results any more.
	for _, p := range []string{"/login?return=%2Faccount", "/login?return=%2F%2Fevil.example", "/account?auth=ok"} {
		if _, body := e.get(t, p); strings.Contains(body, "data-bounce") {
			t.Errorf("%s: data-bounce", p)
		}
	}
	// The zh-hans sign-in page builds localized flows.
	_, body := e.get(t, "/zh-hans/login?return=%2Fzh-hans%2Faccount")
	if !strings.Contains(body, `/auth/github/start?return=%2Fzh-hans%2Faccount`) {
		t.Error("zh-hans account return")
	}
}

// TestAccountsDisabled: no slot, no script, no messages; /login and /account
// are ordinary 404 pages; robots.txt is unchanged.
func TestAccountsDisabled(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/login", "/account", "/zh-hans/login", "/ja/account", "/login?return=%2F"} {
		resp, body := e.get(t, p)
		if resp.StatusCode != 404 || !strings.Contains(body, "HTTP 404") {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	for _, p := range []string{"/", "/vuln/" + sitetest.GPU, "/zh-hans/about", "/no/such"} {
		_, body := e.get(t, p)
		for _, bad := range []string{`id="acct"`, "acct-msgs", "account.", "/login", `name="robots"`} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: accounts disabled but page contains %q", p, bad)
			}
		}
	}
	if _, body := e.get(t, "/robots.txt"); body != "User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /raw/\nSitemap: https://nday.land/sitemap.xml\n" {
		t.Errorf("robots %q", body)
	}
}

var slotRe = regexp.MustCompile(`<a class="acct" id="acct" href="([^"]+)" data-login="([^"]+)" data-account="([^"]+)"`)

// TestAccountSlot: with accounts enabled every page has the plain sign-in
// link (returning to the page, without ?auth=) and the banner words, but no
// account.js; the sign-in pages load account.js and are noindex.
func TestAccountSlot(t *testing.T) {
	e := newAccountsEnv(t, allAccounts)
	for p, want := range map[string]string{
		"/":                                  "/login?return=%2F",
		"/vuln/" + sitetest.GPU + "?auth=ok": "/login?return=%2Fvuln%2F" + sitetest.GPU,
		"/zh-hans/vuln?q=a&auth=denied":      "/zh-hans/login?return=%2Fzh-hans%2Fvuln%3Fq%3Da",
		"/account":                           "/login?return=%2Faccount",
		"/login?return=%2Fsrc":               "/login",
		"/no/such/page":                      "/login?return=%2Fno%2Fsuch%2Fpage",
	} {
		resp, body := e.get(t, p)
		m := slotRe.FindStringSubmatch(body)
		if m == nil {
			t.Errorf("%s (%d): no account slot", p, resp.StatusCode)
			continue
		}
		if htmlUnescape(m[1]) != want {
			t.Errorf("%s: slot href %q, want %q", p, htmlUnescape(m[1]), want)
		}
		l := e.localeOf(p)
		if m[2] != l.Path("/login") || m[3] != l.Path("/account") {
			t.Errorf("%s: slot paths %q %q", p, m[2], m[3])
		}
		for _, k := range []string{"acct.banner.ok", "acct.banner.signed_in_as_other", "acct.role.badge#admin", "acct.banner.dismiss"} {
			if !strings.Contains(body, `data-k="`+k+`"`) {
				t.Errorf("%s: no message %s", p, k)
			}
		}
		n, _ := url.Parse(p)
		sign := neutral(l, n.Path) == "/login" || neutral(l, n.Path) == "/account"
		if strings.Contains(body, "/static/account.") != sign {
			t.Errorf("%s: account.js loaded=%v", p, !sign)
		}
		if strings.Contains(body, `<meta name="robots" content="noindex"/>`) != sign || (resp.Header.Get("X-Robots-Tag") == "noindex") != sign {
			t.Errorf("%s: noindex should be %v", p, sign)
		}
		if strings.Contains(body, `data-k="acct.err.csrf"`) != sign {
			t.Errorf("%s: page messages should be present=%v", p, sign)
		}
	}
}

// TestAccountPagesAllLocales: /login and /account exist in every enabled
// locale and render without missing messages; en and zh-Hans are native,
// the pending locales show English marked lang="en"; no inline script or
// style, the CSP, cacheable, every link resolves.
func TestAccountPagesAllLocales(t *testing.T) {
	e := newAccountsEnv(t, allAccounts)
	set := e.ui.Locales()
	if len(set.Enabled) != 7 {
		t.Fatalf("%d locales enabled, want 7", len(set.Enabled))
	}
	native := map[string]string{"en": "sign in with GitHub", "zh-Hans": "使用 GitHub 登录"}
	for _, l := range set.Enabled {
		for _, page := range []string{"/login", "/account", "/welcome", "/welcome?next=%2Fvuln%2F" + sitetest.GPU} {
			p := l.Path(page)
			resp, body := e.get(t, p)
			if resp.StatusCode != 200 {
				t.Errorf("%s: %d", p, resp.StatusCode)
				continue
			}
			if resp.Header.Get("Content-Security-Policy") != webui.CSP || resp.Header.Get("Cache-Control") != "public, max-age=60" ||
				resp.Header.Get("ETag") == "" || resp.Header.Get("X-Robots-Tag") != "noindex" {
				t.Errorf("%s: headers %v", p, resp.Header)
			}
			links, problems := CheckHTML(body)
			for _, pr := range problems {
				t.Errorf("%s: %s", p, pr)
			}
			if strings.Contains(body, i18n.MissingOpen) || !strings.Contains(body, `<html lang="`+l.Tag+`">`) {
				t.Errorf("%s: missing message or lang", p)
			}
			own := switcherRe.ReplaceAllString(body, "")
			fallback := strings.Contains(own, `<span lang="en">`) || regexp.MustCompile(`data-k="[^"]+" lang="en"`).MatchString(own)
			switch l.Tag {
			case "en", "zh-Hans":
				if fallback {
					t.Errorf("%s: English fallback in a complete locale", p)
				}
				if page == "/login" && !strings.Contains(body, native[l.Tag]) {
					t.Errorf("%s: missing %q", p, native[l.Tag])
				}
			default:
				if !fallback || len(set.PendingKeys(l)) == 0 {
					t.Errorf("%s: pending locale without marked English fallback", p)
				}
			}
			for _, lk := range links {
				if strings.HasPrefix(lk, "/auth/") {
					continue // the sign-in flow itself (internal/auth)
				}
				if r, _ := e.get(t, lk); r.StatusCode != 200 {
					t.Errorf("%s: link %s -> %d", p, lk, r.StatusCode)
				}
			}
		}
	}
	// English pages carry no CJK outside the language switcher and the
	// language <select> (native names).
	strip := regexp.MustCompile(`(?s)<details class="langs">.*?</details>|<select .*?</select>`)
	for _, p := range []string{"/login", "/account", "/welcome", "/"} {
		_, body := e.get(t, p)
		for _, r := range strip.ReplaceAllString(body, "") {
			if i18n.IsWide(r) {
				t.Errorf("%s: CJK %q on an English page", p, string(r))
				break
			}
		}
	}
}

// TestAccountPagesNotPersonal: the pages never read the session: the same
// bytes and cache headers with and without session cookies, no Set-Cookie,
// no Vary: Cookie (the public pages keep their caching).
func TestAccountPagesNotPersonal(t *testing.T) {
	e := newAccountsEnv(t, allAccounts)
	for _, p := range []string{"/", "/login", "/account", "/zh-hans/account", "/login?return=%2Faccount", "/vuln/" + sitetest.GPU,
		"/welcome", "/zh-hans/welcome?next=%2Fzh-hans%2Fsrc"} {
		r1, b1 := e.get(t, p)
		r2, b2 := e.get(t, p, "Cookie", "__Host-nday_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; other=1")
		if b1 != b2 {
			t.Errorf("%s: body differs with a session cookie", p)
		}
		for _, h := range []string{"Cache-Control", "ETag", "Vary", "Set-Cookie", "X-Robots-Tag"} {
			if r1.Header.Get(h) != r2.Header.Get(h) {
				t.Errorf("%s: %s %q vs %q", p, h, r1.Header.Get(h), r2.Header.Get(h))
			}
		}
		if len(r2.Header.Values("Set-Cookie")) != 0 || strings.Contains(strings.Join(r2.Header.Values("Vary"), ","), "Cookie") ||
			r2.Header.Get("Cache-Control") != "public, max-age=60" {
			t.Errorf("%s: personal headers %v", p, r2.Header)
		}
	}
}

func TestAccountRobots(t *testing.T) {
	e := newAccountsEnv(t, allAccounts)
	_, body := e.get(t, "/robots.txt")
	for _, want := range []string{"Disallow: /api/\n", "Disallow: /auth/\n", "Disallow: /login\n", "Disallow: /account\n",
		"Disallow: /zh-hans/login\n", "Disallow: /zh-hans/account\n", "Disallow: /fr/account\n", "Disallow: /welcome\n",
		"Disallow: /zh-hans/welcome\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("robots.txt missing %q:\n%s", want, body)
		}
	}
}

// TestAccountPagesTwoHost: in two-host mode the sign-in pages stay on the
// site host (never the API host) and /api/me stays a site path for the
// script (it is registered by internal/auth, not redirected here).
func TestAccountPagesTwoHost(t *testing.T) {
	e := newEnvFull(t, web.Config{PublicURL: "https://www.nday.land", APIURL: "https://api.nday.land"},
		webui.Options{Accounts: allAccounts})
	resp, _ := e.get(t, "/login")
	if resp.StatusCode != 200 {
		t.Errorf("/login %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/login", nil)
	req.Host = "api.nday.land"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("/login on the API host: %d", resp.StatusCode)
	}
}

// TestScriptsAreSafe: the account and discussion scripts never build HTML
// from strings (DOMParser and range fragments count), never evaluate code,
// keep the CSRF token out of storage, and talk only to their own origin.
func TestScriptsAreSafe(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile("static/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	sinks := []string{"innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "eval(", "new Function",
		"setTimeout('", "setTimeout(\"", "srcdoc", "javascript:", "DOMParser", "createContextualFragment", "parseFromString",
		"setHTML", "parseHTMLUnsafe"}
	acct := read("account.js")
	disc := read("discuss.js")
	for name, src := range map[string]string{"account.js": acct, "discuss.js": disc} {
		for _, bad := range append(append([]string(nil), sinks...), "localStorage", "sessionStorage", "document.cookie",
			"indexedDB", "postMessage", "http://", "https://", "XMLHttpRequest", ".href =", "location.href", "location.replace",
			"window.open") {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
	app := read("app.js")
	// app.js never navigates on its own (the ?auth= result only shows a banner).
	for _, bad := range []string{"location.replace", "location.assign", "data-bounce"} {
		if strings.Contains(app, bad) {
			t.Errorf("app.js contains %q", bad)
		}
	}
	for _, bad := range append(sinks, "document.cookie", "http://", "https://") {
		if strings.Contains(app, bad) {
			t.Errorf("app.js contains %q", bad)
		}
	}
	// Every fetch is same-origin with credentials: same-origin, and every
	// POST carries the JSON content type and the CSRF header.
	for name, src := range map[string]string{"account.js": acct, "app.js": app, "discuss.js": disc} {
		calls := regexp.MustCompile(`fetch\(([^,]+),`).FindAllStringSubmatch(src, -1)
		if len(calls) == 0 {
			t.Errorf("%s: no fetch", name)
		}
		for _, c := range calls {
			if a := strings.TrimSpace(c[1]); a != "path" && a != "'/api/me'" {
				t.Errorf("%s: fetch(%s) — only fixed paths", name, a)
			}
		}
		if strings.Count(src, "credentials: 'same-origin'") < len(calls) {
			t.Errorf("%s: a fetch without credentials: 'same-origin'", name)
		}
	}
	for _, want := range []string{"method: 'POST'", "'Content-Type': 'application/json'", "headers['X-CSRF-Token'] = csrf",
		"!url.startsWith('/auth/')", "url.startsWith('//')", "(page ? !pagePath.test(url) : !url.startsWith('/auth/'))",
		"const pagePath = /^\\/[A-Za-z0-9._~\\-\\/]*(\\?[A-Za-z0-9._~\\-=&+%]*)?$/;"} {
		if !strings.Contains(acct, want) {
			t.Errorf("account.js: missing %q", want)
		}
	}
	for _, want := range []string{"method: 'POST'", "'Content-Type': 'application/json'", "headers['X-CSRF-Token'] = csrf",
		"let p = window.location.pathname;", "if (!p.startsWith('/') || p.startsWith('//')) p = '/';",
		"const ok = typeof id === 'string' && UUID.test(id);", "if (ok) q.set('c', id);", "const q = new URLSearchParams();"} {
		if !strings.Contains(disc, want) {
			t.Errorf("discuss.js: missing %q", want)
		}
	}
	// discuss.js navigates once (reload), to the page's own path with only
	// ?c=<uuid>&fresh=<n> and a #c-<uuid> (or ?fresh=<n>#discussion); the
	// CSRF token is only ever a header.
	if n := strings.Count(disc, "location.assign("); n != 1 ||
		!strings.Contains(disc, "window.location.assign(p + '?' + q.toString() + (ok ? '#c-' + id : '#discussion'));") {
		t.Errorf("discuss.js: %d location.assign calls, want the one in reload()", n)
	}
	rest := disc
	for _, ok := range []string{"let csrf = '';", "if (csrf) headers['X-CSRF-Token'] = csrf;", "e.code !== 'csrf'",
		"csrf = (me && me.signed_in && me.csrf_token) || '';", "csrf = me.csrf_token || '';", "'csrf'", "a csrf error"} {
		rest = strings.ReplaceAll(rest, ok, "")
	}
	if m := regexp.MustCompile(`.*\bcsrf\b.*`).FindString(rest); m != "" {
		t.Errorf("discuss.js: the CSRF token is used for something else than the header: %s", m)
	}
	// no markup in any string literal of discuss.js
	if m := regexp.MustCompile(`'[^'\n]*<[a-zA-Z/!][^'\n]*'`).FindString(disc); m != "" {
		t.Errorf("discuss.js: markup in a string literal: %s", m)
	}
	// Removing a follow on the account page saves the list as it is at
	// click time and never runs two removals at once (no lost update).
	for _, want := range []string{"const latest = (me && me.user && me.user.follows) || [];",
		"if (followBusy) return;", "followBusy = true;", "followBusy = false;"} {
		if !strings.Contains(acct, want) {
			t.Errorf("account.js: missing %q", want)
		}
	}
	// window.location is assigned only in go() (start_url) and the
	// result forwarding of app.js (a server-validated data-bounce path).
	if n := strings.Count(acct, "location.assign("); n != 1 {
		t.Errorf("account.js: %d location.assign calls, want 1 (go)", n)
	}
	if strings.Contains(acct, "location.href") || strings.Contains(acct, "location.replace") {
		t.Error("account.js: other navigation")
	}
	// All API paths used by the scripts are the documented endpoints.
	paths := regexp.MustCompile(`'(/(?:auth|account|api)/[^']*)'`).FindAllStringSubmatch(acct+app+disc, -1)
	var seen []string
	for _, p := range paths {
		seen = append(seen, p[1])
	}
	sort.Strings(seen)
	allowed := regexp.MustCompile(`^/(api/me|api/affected/suggest|api/posts/|api/discuss/|api/discuss/comment/|api/mod/comment/|auth/(signout|signout-all|passkey/(login|signup|register)/(begin|finish))|auth/|account/|account/(handle|locale|delete|accept-terms|passkeys/|follows|follows/match))$`)
	for _, p := range seen {
		if !allowed.MatchString(p) {
			t.Errorf("script uses undocumented path %s", p)
		}
	}
}
