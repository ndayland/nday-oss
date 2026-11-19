package webui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestAdminScriptIsSafe: static/admin.js follows the rules of the account
// and discussion scripts: no HTML from strings, no code evaluation, no
// storage, same-origin requests to fixed documented paths only, the CSRF
// token only as a header, and navigation only to a reload or a sign-in
// start_url.
func TestAdminScriptIsSafe(t *testing.T) {
	b, err := os.ReadFile("static/admin.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	// one narrow exception to "no storage": the drafts page keeps each
	// draft's posting form under the key prefix FKEY, through store() only
	if strings.Count(src, "localStorage") != 1 || !strings.Contains(src, "const store = () => window.localStorage; // only ever for FKEY entries") ||
		!strings.Contains(src, "const FKEY = 'nday.xdform.';") {
		t.Error("admin.js: localStorage outside the posting-form helper")
	}
	for _, l := range strings.Split(src, "\n") {
		if strings.Contains(l, "store().") && !strings.Contains(l, "FKEY") && !strings.Contains(l, "store().length") && !strings.Contains(l, "store().key(i)") {
			t.Errorf("admin.js: storage use without the FKEY prefix: %s", strings.TrimSpace(l))
		}
	}
	src = strings.Replace(src, "const store = () => window.localStorage;", "", 1)
	for _, bad := range []string{"innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "eval(", "new Function",
		"setTimeout('", "setTimeout(\"", "srcdoc", "javascript:", "DOMParser", "createContextualFragment", "parseFromString",
		"setHTML", "parseHTMLUnsafe", "localStorage", "sessionStorage", "document.cookie", "indexedDB", "postMessage",
		"http://", "https://", "XMLHttpRequest", ".href =", "location.href", "location.replace", "window.open"} {
		if strings.Contains(src, bad) {
			t.Errorf("admin.js contains %q", bad)
		}
	}
	// two fetch calls: api(path) and the drafts page's share card GET for
	// "copy image", only for a path that matches CARD (same origin, no
	// query but the address card's)
	calls := regexp.MustCompile(`fetch\(([^,]+),`).FindAllStringSubmatch(src, -1)
	if len(calls) != 2 || strings.TrimSpace(calls[0][1]) != "path" || strings.TrimSpace(calls[1][1]) != "card" {
		t.Errorf("admin.js fetch calls: %v", calls)
	}
	for _, want := range []string{"const CARD = /^\\/og\\/vuln\\/(CVE-[0-9]{4}-[0-9]{4,19}|GHSA(-[0-9a-z]{4}){3})\\.png\\?addr=1$/;",
		"if (!canCopyImg || !CARD.test(card)) return;", "window.fetch(card, { credentials: 'same-origin', redirect: 'error' })"} {
		if !strings.Contains(src, want) {
			t.Errorf("admin.js: missing %q", want)
		}
	}
	for _, want := range []string{"method: 'POST', credentials: 'same-origin'", "'Content-Type': 'application/json'",
		"if (csrf) headers['X-CSRF-Token'] = csrf;", "!url.startsWith('/auth/')", "url.startsWith('//')",
		"if (!UUID.test(v)) throw { code: 'not_found' };", "if (!XID.test(v)) throw { code: 'not_found' };",
		"if (!DID.test(v)) throw { code: 'not_found' };", "if (!SKEY.test(v)) throw { code: 'not_found' };",
		"const SKEY = /^NDAY_[A-Z0-9_]{1,60}$/;", "if (!RID.test(v)) throw { code: 'not_found' };", "const RID = /^[1-9][0-9]{0,17}$/;",
		"if (!VID.test(v)) throw { code: 'not_found' };", "const VID = /^(CVE-[0-9]{4}-[0-9]{4,19}|GHSA(-[0-9a-z]{4}){3})$/;"} {
		if !strings.Contains(src, want) {
			t.Errorf("admin.js: missing %q", want)
		}
	}
	if n := strings.Count(src, "location.assign("); n != 1 {
		t.Errorf("admin.js: %d location.assign calls, want 1 (go)", n)
	}
	if n := strings.Count(src, "location.reload("); n != 1 {
		t.Errorf("admin.js: %d location.reload calls, want 1 (after a success)", n)
	}
	// the CSRF token is only ever the header
	rest := src
	for _, ok := range []string{"let csrf = '';", "if (csrf) headers['X-CSRF-Token'] = csrf;",
		"csrf = (me && me.signed_in && me.csrf_token) || '';", "csrf = (m && m.signed_in && m.csrf_token) || '';",
		"e.code === 'csrf'", "'csrf'", "the CSRF token"} {
		rest = strings.ReplaceAll(rest, ok, "")
	}
	if m := regexp.MustCompile(`.*\bcsrf\b.*`).FindString(rest); m != "" {
		t.Errorf("admin.js: the CSRF token is used for something else than the header: %s", m)
	}
	if m := regexp.MustCompile(`'[^'\n]*<[a-zA-Z/!][^'\n]*'`).FindString(src); m != "" {
		t.Errorf("admin.js: markup in a string literal: %s", m)
	}
	// every path is one of the documented endpoints
	allowed := regexp.MustCompile(`^/(api/admin/users/|api/admin/x/(settings|accounts|accounts/|accounts/profiles|import|drafts/|candidates/|candidates/batch|drafts/batch)|api/admin/github/repos/(batch)?|api/admin/github/owners/?|api/admin/settings(/secret|/secret/clear)?|api/admin/titles/|api/discuss/comment/|api/mod/reports/|api/corrections/item/|auth/|auth/passkey/login/(begin|finish))$`)
	for _, p := range regexp.MustCompile(`'(/(?:auth|account|api)/[^']*)'`).FindAllStringSubmatch(src, -1) {
		if !allowed.MatchString(p[1]) {
			t.Errorf("admin.js uses undocumented path %s", p[1])
		}
	}
	// the visitor map tooltip: text from the data-tip attribute, through textContent only
	for _, want := range []string{"tip.textContent = el.getAttribute('data-tip') || '';", "document.getElementById('map-cc')",
		"svg.querySelectorAll('[data-tip] > title').forEach((t) => t.remove());"} {
		if !strings.Contains(src, want) {
			t.Errorf("admin.js: missing %q", want)
		}
	}
	for _, sfx := range []string{"'/hide'", "'/unhide'", "'/resolve'", "'suspend'", "'unsuspend'", "'role'", "'signout-all'",
		"'/update'", "'/enable'", "'/disable'", "'save'", "'posted'", "'discard'", "'restore'",
		"xcadd: '/add'", "xcdismiss: '/dismiss'", "xcrestore: '/restore'",
		"ghtrust: '/trust'", "ghreject: '/reject'", "ghreset: '/reset'", "'/set'", "'/clear'"} {
		if !strings.Contains(src, sfx) {
			t.Errorf("admin.js: no %s", sfx)
		}
	}
}

// TestAdminScriptSettingsNotApplied: a 500 not_applied answer (stored, not
// in force) still updates the settings shown, empties the secret input,
// and lets an unchanged save through (the server applies again). Static:
// there is no DOM to run the script in.
func TestAdminScriptSettingsNotApplied(t *testing.T) {
	b, err := os.ReadFile("static/admin.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if n := strings.Count(src, "if (notApplied(e)) {"); n != 3 {
		t.Errorf("not_applied handled in %d settings calls, want 3 (save, secret, clear)", n)
	}
	if n := strings.Count(src, "showSettings(e.settings);"); n != 3 {
		t.Errorf("not_applied state shown in %d places, want 3", n)
	}
	for _, want := range []string{
		"const notApplied = (e) => !!(e && e.code === 'not_applied');",
		"if (notApplied(e)) { // stored: never keep the value in the page\n            inp.value = '';",
		"if (!Object.keys(set).length && !unset.length && main.dataset.notApplied !== '1') {",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("admin.js: missing %q", want)
		}
	}
}
