package webui_test

import (
	"image/png"
	"net/url"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/webui/i18n"
)

// TestGHSAKeyedPage: a vulnerability keyed by its GHSA id (an advisory
// without a CVE) is a full page in every locale, linked from the lists and
// the search like a CVE, with its own share card.
func TestGHSAKeyedPage(t *testing.T) {
	e := newEnv(t)
	path := "/vuln/" + sitetest.GHSA
	for _, l := range e.ui.Locales().Enabled {
		resp, body := e.get(t, l.Path(path))
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d", l.Path(path), resp.StatusCode)
			continue
		}
		for _, want := range []string{
			`<span class="id">` + sitetest.GHSA + `</span>`,
			`data-copy="` + sitetest.GHSA + `"`,
			`<link rel="canonical" href="https://nday.land` + l.Path(path) + `"/>`,
			`href="https://github.com/advisories/` + sitetest.GHSA + `"`,
			`href="/raw/ghsa/` + sitetest.GHSA + `.json"`,
			"qzfinder",
			"qzmerge",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q", l.Path(path), want)
			}
		}
		if strings.Contains(body, i18n.MissingOpen) {
			t.Errorf("%s: a message is missing", l.Path(path))
		}
	}
	// non-canonical spelling: the canonical 301, like a CVE id
	if resp := e.noRedirect(t, "/vuln/ghsa-GPWC-27cw-rh9r"); resp.StatusCode != 301 || resp.Header.Get("Location") != path {
		t.Errorf("non-canonical: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// the exact id in the search goes straight to the page
	if resp := e.noRedirect(t, "/vuln?q="+url.QueryEscape("ghsa-gpwc-27cw-rh9r")); resp.StatusCode != 302 || resp.Header.Get("Location") != path {
		t.Errorf("search: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := e.noRedirect(t, "/zh-hans/vuln?q="+sitetest.GHSA); resp.StatusCode != 302 || resp.Header.Get("Location") != "/zh-hans"+path {
		t.Errorf("zh-hans search: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// lists link it
	link := `href="` + path + `"`
	for _, p := range []string{"/", "/vuln?browse=1", "/vuln?q=qzmerge", "/vuln?stage=patch", "/zh-hans/vuln?stage=patch"} {
		if resp, body := e.get(t, p); resp.StatusCode != 200 || !strings.Contains(body, `href="`+e.localeOf(p).Path(path)+`"`) {
			t.Errorf("%s: %d, no link to the GHSA page", p, resp.StatusCode)
		}
	}
	// the year filter has no year for it
	if resp, body := e.get(t, "/vuln?year=2026"); resp.StatusCode != 200 || strings.Contains(body, link) {
		t.Errorf("/vuln?year=2026: %d, lists the GHSA row", resp.StatusCode)
	}
	// share card
	card := ogImage(t, e, path)
	cardPath := strings.TrimPrefix(card, "https://nday.land")
	if !strings.HasPrefix(cardPath, "/og/vuln/"+sitetest.GHSA+".png?v=") {
		t.Fatalf("og:image %q", card)
	}
	resp, body := e.get(t, cardPath)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("%s: %d", cardPath, resp.StatusCode)
	}
	if img, err := png.Decode(strings.NewReader(body)); err != nil || img.Bounds().Dx() != 1200 {
		t.Errorf("card: %v", err)
	}
	if resp := e.noRedirect(t, "/og/vuln/ghsa-gpwc-27cw-rh9r.png"); resp.StatusCode != 301 || resp.Header.Get("Location") != "/og/vuln/"+sitetest.GHSA+".png" {
		t.Errorf("card non-canonical: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, p := range []string{"/og/vuln/" + sitetest.GHSAAlias + ".png", "/og/vuln/GHSA-aaaa-27cw-rh9r.png"} {
		if resp, body := e.get(t, p); resp.StatusCode != 404 {
			t.Errorf("%s: %d %.300s", p, resp.StatusCode, body)
		}
	}
	// the alias left behind by a merge still redirects to its CVE
	if resp := e.noRedirect(t, "/vuln/"+sitetest.GHSAAlias); resp.StatusCode != 302 || resp.Header.Get("Location") != "/vuln/CVE-2026-1004" {
		t.Errorf("alias: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// TestGHSAKeyedMemberRoutes: with accounts on, a GHSA-keyed page carries the
// discussion and corrections sections under its own id, and the
// researcher-posts endpoint answers for it; for a GHSA id that is only an
// alias the endpoint is the not-found error, not a 500.
func TestGHSAKeyedMemberRoutes(t *testing.T) {
	e, _ := newMemberEnv(t, false)
	resp, page := e.fetch(t, wwwHost, "/vuln/"+sitetest.GHSA, nil)
	if resp.StatusCode != 200 || !strings.Contains(page, `id="discussion"`) || !strings.Contains(page, `data-cve="`+sitetest.GHSA+`"`) ||
		!strings.Contains(page, `id="correction"`) {
		t.Errorf("page: %d", resp.StatusCode)
	}
	if strings.Contains(page, `id="research"`) {
		t.Error("an advisory without a CVE has no X posts, yet the research section is shown")
	}
	resp, body := e.fetch(t, wwwHost, "/api/posts/"+sitetest.GHSA, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `"cve":"`+sitetest.GHSA+`"`) {
		t.Errorf("posts: %d %s", resp.StatusCode, body)
	}
	for p, want := range map[string]int{"/api/posts/" + sitetest.GHSAAlias: 404, "/api/posts/GHSA-aaaa-27cw-rh9r": 400,
		"/api/discuss/" + sitetest.GHSAAlias: 404, "/api/discuss/" + sitetest.GHSA: 200} {
		if resp, body := e.fetch(t, wwwHost, p, nil); resp.StatusCode != want {
			t.Errorf("%s: %d, want %d: %s", p, resp.StatusCode, want, body)
		}
	}
}
