package webui_test

import (
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/webui"
	"nday.land/nday/internal/webui/i18n"
)

var (
	destRe   = regexp.MustCompile(`<main class="main acctpage wel" id="main" data-page="welcome" data-dest="([^"]*)">`)
	skipRe   = regexp.MustCompile(`<a class="wel-skip" href="([^"]*)">`)
	presetRe = regexp.MustCompile(`<button type="button" class="btn wel-chip" aria-pressed="false" data-term="([^"]*)" data-label="([^"]*)">`)
)

// TestWelcomePage: /welcome exists only with accounts, loads account.js,
// keeps a safe ?next= as where "done" and "skip" go (else the locale's
// home), renders the presets from the Go list, shows the rules section only
// with a terms version, and its signed-out sample carries no sample words.
func TestWelcomePage(t *testing.T) {
	a := *allAccounts
	a.TermsVersion = "2026-11-01"
	e := newAccountsEnv(t, &a)
	for p, dest := range map[string]string{
		"/welcome": "/",
		"/welcome?next=%2Fvuln%2F" + sitetest.GPU:     "/vuln/" + sitetest.GPU,
		"/welcome?next=%2Fvuln%3Fq%3Da%2Bb":           "/vuln?q=a+b",
		"/welcome?next=%2Faccount":                    "/account",
		"/welcome?next=%2F%2Fevil.example":            "/",
		"/welcome?next=https%3A%2F%2Fevil.example%2F": "/",
		"/welcome?next=%2Fwelcome%3Fnext%3D%252Fsrc":  "/",
		"/welcome?next=%2Fzh-hans%2Fwelcome":          "/",
		"/welcome?next=%2Flogin":                      "/",
		"/welcome?next=%2Fwelcome%2F":                 "/",
		"/welcome?next=%2Fzh-hans%2F%2Fwelcome":       "/",
		"/welcome?next=%2Fvuln%2F%2FCVE-2026-1":       "/",
		"/welcome?next=%2Fzh-hans%2F":                 "/zh-hans/",
		"/welcome?next=%2Fsrc%2F":                     "/src/",
		"/welcome?next=%2Faccount%2Fdelete":           "/",
		"/zh-hans/welcome":                            "/zh-hans/",
		"/zh-hans/welcome?next=%2Fzh-hans%2Fsrc":      "/zh-hans/src",
	} {
		resp, body := e.get(t, p)
		if resp.StatusCode != 200 || resp.Header.Get("X-Robots-Tag") != "noindex" {
			t.Errorf("%s: %d", p, resp.StatusCode)
			continue
		}
		m, s := destRe.FindStringSubmatch(body), skipRe.FindStringSubmatch(body)
		if m == nil || s == nil || htmlUnescape(m[1]) != dest || htmlUnescape(s[1]) != dest {
			t.Errorf("%s: dest %v skip %v, want %q", p, m, s, dest)
		}
		// (the sign-in link of the top bar keeps the page's query, escaped,
		// as its return path, like on every page)
		if regexp.MustCompile(`="(//|https?://|/\\)evil\.example`).MatchString(switcherRe.ReplaceAllString(body, "")) {
			t.Errorf("%s: off-site target in the page", p)
		}
		if !strings.Contains(body, "/static/account.") || !strings.Contains(body, `data-k="acct.welcome.handle_ok"`) ||
			!strings.Contains(body, `data-k="acct.err.too_many_follows"`) {
			t.Errorf("%s: account.js or its messages missing", p)
		}
		if !strings.Contains(body, `<span>~/welcome</span>`) {
			t.Errorf("%s: status bar path", p)
		}
	}
	_, body := e.get(t, "/welcome")
	var got []webui.FollowPreset
	for _, m := range presetRe.FindAllStringSubmatch(body, -1) {
		got = append(got, webui.FollowPreset{Label: htmlUnescape(m[2]), Term: htmlUnescape(m[1])})
	}
	want := webui.FollowPresets()
	if len(got) != len(want) {
		t.Fatalf("presets %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("preset %d: %v, want %v", i, got[i], want[i])
		}
	}
	if !strings.Contains(body, `id="w-rules"`) || !strings.Contains(body, `id="w-accept"`) {
		t.Error("rules section missing with a terms version")
	}
	// the discussion comparison is off (WelcomeData.DiscussDemo) until posts
	// are shown to signed-in users
	if strings.Contains(body, "wel-side") || strings.Contains(body, "wel-scrib") {
		t.Error("discussion comparison rendered while DiscussDemo is off")
	}
	// the account page links here to add follows, returning to the account page
	if _, b := e.get(t, "/zh-hans/account"); !strings.Contains(b, `href="/zh-hans/welcome?next=%2Fzh-hans%2Faccount"`) {
		t.Error("account page: no link to the welcome page")
	}
	// zh-Hans is native
	if _, b := e.get(t, "/zh-hans/welcome"); !strings.Contains(b, "账号已创建") || !strings.Contains(b, "关注的厂商和产品") ||
		!strings.Contains(b, "关注对象的漏洞进入新阶段时，会在首页置顶。只对当前这一页的结果生效。") {
		t.Error("zh-hans welcome text")
	}
	// the handle field is never filled from a provider by itself: a hidden
	// button offers the username, and only a click puts it in the field
	if !strings.Contains(body, `<input class="acct-in" id="w-handle" type="text"`) || strings.Contains(body, `id="w-handle" type="text" value=`) ||
		!strings.Contains(body, `<button type="button" class="btn wel-use" id="w-handle-use" hidden=""></button>`) {
		t.Error("handle field / use button markup")
	}
	js, err := os.ReadFile("static/account.js")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), "hIn.value = id.handle") || !strings.Contains(string(js), "use.dataset.handle = id.handle;") ||
		!strings.Contains(string(js), "hIn.value = use.dataset.handle || '';") || !strings.Contains(string(js), "if (h && h !== current) {") {
		t.Error("account.js: the provider username must only be offered, and an empty field must not be sent")
	}
}

// TestFollowPresets: each preset is saved as typed (NormalizeFollow keeps
// it), its term is its lower case, and terms are unique.
func TestFollowPresets(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range webui.FollowPresets() {
		n, err := auth.NormalizeFollow(p.Label)
		if err != nil || n != p.Label || p.Term != strings.ToLower(p.Label) || seen[p.Term] {
			t.Errorf("preset %+v: %q %v", p, n, err)
		}
		seen[p.Term] = true
	}
	if len(seen) == 0 || len(seen) > auth.MaxFollows {
		t.Errorf("%d presets", len(seen))
	}
}

// TestWelcomeLocalePrefixes: auth.LocalePrefixes (where the OAuth callback
// keeps the locale of the welcome page) equals the prefixes of locales.json.
func TestWelcomeLocalePrefixes(t *testing.T) {
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	var have []string
	for _, l := range set.All {
		if l.Prefix != "" {
			have = append(have, l.Prefix)
		}
	}
	if strings.Join(have, ",") != strings.Join(auth.LocalePrefixes, ",") {
		t.Errorf("locales.json prefixes %v, auth.LocalePrefixes %v", have, auth.LocalePrefixes)
	}
	// every welcome target the callback can produce is a page here
	e := newAccountsEnv(t, allAccounts)
	for _, ret := range []string{"/", "/vuln/" + sitetest.GPU, "/zh-hans/src", "/fr/", "/ja"} {
		w := auth.WelcomeReturn(ret)
		if r, _ := e.get(t, w); r.StatusCode != 200 {
			t.Errorf("WelcomeReturn(%q) = %q -> %d", ret, w, r.StatusCode)
		}
	}
}

// TestLoginWelcomeTarget: the sign-in page tells account.js where a passkey
// sign-up continues: the welcome page of its locale with the return path.
func TestLoginWelcomeTarget(t *testing.T) {
	e := newAccountsEnv(t, allAccounts)
	re := regexp.MustCompile(`data-page="login" data-welcome="([^"]*)"`)
	for p, want := range map[string]string{
		"/login": "/welcome",
		"/login?return=" + url.QueryEscape("/vuln/"+sitetest.GPU): "/welcome?next=" + url.QueryEscape("/vuln/"+sitetest.GPU),
		"/zh-hans/login?return=%2Fzh-hans%2F":                     "/zh-hans/welcome",
		"/zh-hans/login?return=%2Fzh-hans%2Fsrc":                  "/zh-hans/welcome?next=%2Fzh-hans%2Fsrc",
		"/zh-hans/login?return=%2Fvuln%3Fq%3D1%26auth%3Dok":       "/welcome?next=%2Fvuln%3Fq%3D1", // the return path's locale, like the callback
		"/login?return=%2Fwelcome%3Fnext%3D%252Fsrc":              "/welcome?next=%2Fsrc",
		"/login?return=%2F%2Fevil.example":                        "/welcome",
	} {
		_, body := e.get(t, p)
		m := re.FindStringSubmatch(body)
		u, _ := url.Parse(p)
		ret := u.Query().Get("return")
		if ret == "" || auth.SafeReturnPath(ret) != ret {
			ret = e.localeOf(p).Home()
		}
		if same := auth.WelcomeReturn(ret); same != want {
			t.Errorf("%s: test expectation %q differs from auth.WelcomeReturn %q", p, want, same)
		}
		if m == nil || htmlUnescape(m[1]) != want {
			t.Errorf("%s: %v, want %q", p, m, want)
		}
	}
}

// TestHotPinMarker: with accounts the hot table carries the words of the
// pinned group header for app.js; without accounts nothing changes.
func TestHotPinMarker(t *testing.T) {
	e := newAccountsEnv(t, allAccounts)
	for p, want := range map[string]string{"/": `data-pin="following"`, "/zh-hans/": `data-pin="关注"`,
		"/fr/": `data-pin="following" data-pin-lang="en"`} {
		if _, b := e.get(t, p); !strings.Contains(b, `<div class="tbl-in" role="table" `+want+`>`) {
			t.Errorf("%s: no %s", p, want)
		}
	}
}

// TestWelcomeVariants: without accounts there is no /welcome and no pin
// marker; without a terms version there is no rules section.
func TestWelcomeVariants(t *testing.T) {
	t.Run("accounts off", func(t *testing.T) {
		e := newEnv(t)
		if r, _ := e.get(t, "/welcome"); r.StatusCode != 404 {
			t.Errorf("/welcome %d", r.StatusCode)
		}
		if _, b := e.get(t, "/"); strings.Contains(b, "data-pin") {
			t.Error("data-pin without accounts")
		}
	})
	t.Run("no terms", func(t *testing.T) {
		if _, b := newAccountsEnv(t, allAccounts).get(t, "/welcome"); strings.Contains(b, `id="w-rules"`) {
			t.Error("rules section without a terms version")
		}
	})
}
