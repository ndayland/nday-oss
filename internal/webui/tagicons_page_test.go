package webui_test

import (
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/webui"
)

// iconPat is the pattern of the icon markup of symbol id in the rendering
// the site uses (webui.TagIconMode).
func iconPat(id string) string {
	if webui.TagIconMode == webui.TagIconMask {
		return `<span class="tgi" data-i="` + id + `" aria-hidden="true"></span>`
	}
	return `<svg class="tgi" aria-hidden="true" focusable="false"><use href="/static/tagicons\.[0-9a-f]{12}\.svg#` + id + `"/></svg>`
}

// chipRe matches the chip of slug (link to href) with the icon id in front
// of its name.
func chipRe(slug, href, id, name string) *regexp.Regexp {
	return regexp.MustCompile(`<a class="tg" href="` + regexp.QuoteMeta(href) + `"( title="[^"]*")?>` + iconPat(id) + regexp.QuoteMeta(name) + `</a>`)
}

// Product and ecosystem tags carry their mark wherever a chip is drawn: the
// vulnerability page block and "why these tags", /tags, the tag page
// heading, the filter chips of the hot list, the catalogue and search. A
// product tag without an icon and tags of other dimensions render as
// before. Pages stay polyglot and the same for every visitor.
func TestTagIconsOnPages(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/vuln/CVE-2026-1002")
	block := section(body, `<div class="vtags">`, `<dl class="facts">`)
	fortios := chipRe("fortios", "/tag/fortios", "fortinet", "FortiOS")
	if n := len(fortios.FindAllString(block, -1)); n != 2 { // the block and "why these tags"
		t.Errorf("vulnerability page: %d FortiOS chips with the mark\n%s", n, block)
	}
	// product types, access and type tags: no icon
	if strings.Count(block, `class="tgi"`) != 2 {
		t.Errorf("icons on other tags\n%s", block)
	}
	if _, p := CheckHTML(body); len(p) != 0 {
		t.Errorf("vulnerability page: %v", p)
	}
	// /tags: with icon, product without one, ecosystem, other dimensions
	_, tagsPage := e.get(t, "/tags")
	for _, c := range []*regexp.Regexp{chipRe("fortios", "/tag/fortios", "fortinet", "FortiOS"), chipRe("php", "/tag/php", "php", "PHP"),
		chipRe("cisco-asa", "/tag/cisco-asa", "cisco", "Cisco ASA"), chipRe("npm", "/tag/npm", "npm", "npm"),
		chipRe("github-actions", "/tag/github-actions", "githubactions", "GitHub Actions")} {
		if !c.MatchString(tagsPage) {
			t.Errorf("/tags: %s missing", c)
		}
	}
	for _, want := range []string{`<a class="tg" href="/tag/windows">Windows</a>`, `<a class="tg" href="/tag/composer">Composer</a>`,
		`<a class="tg" href="/tag/operating-system">operating system</a>`, `<a class="tg tg-s" href="/tag/remote-unauth">remote, unauthenticated</a>`} {
		if !strings.Contains(tagsPage, want) {
			t.Errorf("/tags: %q missing (a tag without an icon renders as before)", want)
		}
	}
	if _, p := CheckHTML(tagsPage); len(p) != 0 {
		t.Errorf("/tags: %v", p)
	}

	// tag page heading: mark and name kept together; no icon: as before
	_, tp := e.get(t, "/tag/fortios")
	if !regexp.MustCompile(`<h1 class="h1"><span class="h" aria-hidden="true"># </span><span class="tgh">` + iconPat("fortinet") + `<span>FortiOS</span></span></h1>`).MatchString(tp) {
		t.Error("/tag/fortios heading")
	}
	_, tw := e.get(t, "/tag/windows")
	if !strings.Contains(tw, `<h1 class="h1"><span class="h" aria-hidden="true"># </span>Windows</h1>`) || strings.Contains(tw, `class="tgi"`) {
		t.Error("/tag/windows heading")
	}

	// filter chips: hot list, catalogue, search
	for _, p := range []string{"/?tag=fortios", "/vuln?tag=fortios", "/vuln?q=fortios&tag=fortios"} {
		_, b := e.get(t, p)
		if !regexp.MustCompile(`<span class="tfc"><a class="tg" href="/tag/fortios" title="[^"]*">` + iconPat("fortinet") + `FortiOS</a>`).MatchString(b) {
			t.Errorf("%s: filter chip without the mark", p)
		}
		if _, pr := CheckHTML(b); len(pr) != 0 {
			t.Errorf("%s: %v", p, pr)
		}
	}

	// the referenced sprite is served like every static file
	if webui.TagIconMode == webui.TagIconUse {
		ref := regexp.MustCompile(`<use href="(/static/tagicons\.[0-9a-f]{12}\.svg)#`).FindStringSubmatch(tagsPage)
		if ref == nil {
			t.Fatal("no sprite reference")
		}
		resp, sprite := e.get(t, ref[1])
		h := resp.Header
		if resp.StatusCode != 200 || h.Get("Content-Type") != "image/svg+xml" || h.Get("Cache-Control") != "public, max-age=31536000, immutable" ||
			h.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(sprite, `<symbol id="fortinet" viewBox="0 0 24 24"><path d="M`) {
			t.Errorf("sprite: %d %v", resp.StatusCode, h)
		}
		if strings.Contains(tagsPage, "tagicons.") && strings.Contains(tagsPage, `rel="stylesheet" href="/static/tagicons.`) {
			t.Error("mask stylesheet linked in the sprite rendering")
		}
	}

	// the same bytes for a signed-in reader (publicly cacheable pages)
	me, _ := newMemberEnv(t, false)
	cookies, _ := me.signIn(t, "9311", "tagiconreader")
	for _, p := range []string{"/tags", "/tag/fortios"} {
		_, anon := me.fetch(t, wwwHost, p, nil)
		if _, in := me.fetch(t, wwwHost, p, cookies); in != anon || !strings.Contains(in, `class="tgi"`) {
			t.Errorf("%s differs for a signed-in reader (or has no icon)", p)
		}
	}
}
