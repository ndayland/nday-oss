package webui_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
)

var (
	landingBodyRe = regexp.MustCompile(`<body class="landing"[ >]`)
	topmRe        = regexp.MustCompile(`<details class="topm" open="">\n<summary><span class="sr">([^<]+)</span><span class="topm-g" aria-hidden="true">&gt;</span></summary>`)
	inlineRe      = regexp.MustCompile(`(?i)<[^>]*\s(on[a-z]+|style)\s*=|<style[\s>]|<script>`)
)

// TestLandingChrome: the /vuln landing (and only it) is marked for the
// stylesheet (body.landing: full-screen search, no bottom status bar), puts
// the header menus in a disclosure with a named ">" toggle (every locale),
// and leaves the header search box out; no inline script, handler or
// style. Every other page keeps the header as it was: no class, no
// disclosure, the header search box.
func TestLandingChrome(t *testing.T) {
	e := newEnv(t)
	for loc, name := range map[string]string{"": "menu", "/zh-Hans": "菜单", "/zh-Hant": "選單", "/ja": "メニュー", "/ko": "메뉴", "/es": "menú", "/fr": "menu"} {
		_, b := e.get(t, loc+"/vuln", "Authorization", "")
		if !landingBodyRe.MatchString(b) {
			t.Errorf("%s/vuln: no landing class", loc)
		}
		m := topmRe.FindStringSubmatch(b)
		if m == nil || m[1] != name {
			t.Errorf("%s/vuln: menu toggle %q, want %q", loc, m, name)
		}
		top := b[strings.Index(b, `<header class="top">`):strings.Index(b, `</header>`)]
		// the menu holds the page links and the right-hand links, and the header has no search box
		if i, j, k := strings.Index(top, `<details class="topm"`), strings.Index(top, `<nav class="nav"`), strings.Index(top, `<div class="toplinks">`); i < 0 || j < i || k < j ||
			!strings.HasSuffix(strings.TrimSpace(top), "</details>\n</div>") || strings.Contains(top, `<form class="search"`) || strings.Contains(b, `id="q"`) {
			t.Errorf("%s/vuln: header\n%s", loc, top)
		}
		if !strings.Contains(b, `id="cat-q"`) || !strings.Contains(b, `<footer class="sbar">`) {
			t.Errorf("%s/vuln: the page's own search box or the (hidden by CSS) status bar is missing", loc)
		}
		if x := inlineRe.FindString(b); x != "" {
			t.Errorf("%s/vuln: inline script or style %q", loc, x)
		}
	}
	for _, p := range []string{"/vuln?browse=1", "/vuln?q=gpu", "/", "/discussed", "/about", "/src", "/vuln/" + sitetest.GPU, "/ja/vuln?browse=1"} {
		_, b := e.get(t, p, "Authorization", "")
		if strings.Contains(b, `class="landing"`) || strings.Contains(b, "topm") || !strings.Contains(b, `<form class="search" action=`) ||
			!strings.Contains(b, "<body data-") && !strings.Contains(b, "<body>") {
			t.Errorf("%s: header or body changed", p)
		}
	}
	// the stylesheet keys everything on the server's class (no script sniffs the URL)
	css, err := os.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{".landing .sbar { display: none; }", ".landing .chero > .cbg { position: fixed;", "body.landing { min-height: 100vh; min-height: 100dvh; }"} {
		if !strings.Contains(string(css), w) {
			t.Errorf("app.css lacks %q", w)
		}
	}
}
