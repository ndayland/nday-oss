package webui

import (
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/webui/i18n"
)

// The mapping and the generated files agree: every mapping target is a
// symbol of the sprite and a rule of the mask stylesheet, and every symbol
// is used. The sprite holds only <symbol viewBox><path d/></symbol>
// elements, and its path data only path-data characters.
func TestTagIconsMatchSprite(t *testing.T) {
	used := map[string]bool{}
	for slug, id := range tags.Icons {
		used[id] = true
		if !tagIconSymbols[id] {
			t.Errorf("%s: icon %q is not in static/tagicons.svg (run tools/tagicons)", slug, id)
		}
		if tagIcon(slug) != id {
			t.Errorf("%s: tagIcon %q, want %q", slug, tagIcon(slug), id)
		}
	}
	for id := range tagIconSymbols {
		if !used[id] {
			t.Errorf("symbol %q is not used by any tag (run tools/tagicons)", id)
		}
	}
	if len(tagIconSymbols) == 0 {
		t.Fatal("no symbols")
	}
	svg, err := staticFS.ReadFile("static/tagicons.svg")
	if err != nil {
		t.Fatal(err)
	}
	dec := xml.NewDecoder(bytes.NewReader(svg))
	dec.Strict = true
	pathRe := regexp.MustCompile(`^[MmZzLlHhVvCcSsQqTtAa0-9.,+\-eE ]+$`)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("sprite: %v", err)
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var attrs []string
		for _, a := range el.Attr {
			attrs = append(attrs, a.Name.Local)
			if a.Name.Local == "d" && !pathRe.MatchString(a.Value) {
				t.Errorf("path data %q", a.Value)
			}
		}
		if got := el.Name.Local + " " + strings.Join(attrs, " "); got != "svg xmlns" && got != "symbol id viewBox" && got != "path d" {
			t.Errorf("sprite element %q", got)
		}
	}
	css, err := staticFS.ReadFile("static/tagicons.css")
	if err != nil {
		t.Fatal(err)
	}
	rules := regexp.MustCompile(`(?m)^\.tgi\[data-i="([a-z0-9]+)"\]\{-webkit-mask-image:url\("data:image/svg\+xml,[A-Za-z0-9.,\-+=/:'%]+"\);mask-image:url\("data:image/svg\+xml,[A-Za-z0-9.,\-+=/:'%]+"\)\}$`).FindAllSubmatch(css, -1)
	if len(rules) != len(tagIconSymbols) {
		t.Errorf("tagicons.css: %d rules for %d symbols", len(rules), len(tagIconSymbols))
	}
	for _, r := range rules {
		if !tagIconSymbols[string(r[1])] {
			t.Errorf("tagicons.css: rule for %s, not in the sprite", r[1])
		}
	}
}

// Only product and ecosystem tags get an icon; unknown slugs none.
func TestTagIconDimensions(t *testing.T) {
	for _, tg := range tags.Vocabulary {
		id := tagIcon(tg.Slug)
		if id != "" && tg.Dim != tags.DimProduct && tg.Dim != tags.DimEcosystem {
			t.Errorf("%s (%s) has icon %s", tg.Slug, tg.Dim, id)
		}
	}
	for _, s := range []string{"", "nope", "xss", "remote-unauth", "operating-system", "<script>"} {
		if tagIcon(s) != "" {
			t.Errorf("%q has an icon", s)
		}
	}
	if tagIcon("php") != "php" || tagIcon("fortios") != "fortinet" || tagIcon("npm") != "npm" || tagIcon("windows") != "" {
		t.Error("sample icons")
	}
}

// Both renderings, through the page templates (/tags lists every tag): the
// sprite reference by default, the mask span plus its stylesheet in the
// fallback. Either is well-formed, decorative and absent for tags without
// an icon.
func TestTagIconRenderings(t *testing.T) {
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	assets, err := loadAssets("")
	if err != nil {
		t.Fatal(err)
	}
	l := set.Primary()
	rep := &site.TagsReport{}
	for _, tg := range tags.Vocabulary {
		rep.Tags = append(rep.Tags, site.TagInfo{Slug: tg.Slug, Dimension: tg.Dim, Count: 1})
	}
	page := &Page{Title: "t", Data: BuildTagsPage(l, rep, API{}), L: l, Lang: "en"}
	sprite, maskCSS := assets.URL("tagicons.svg"), assets.URL("tagicons.css")
	for _, mode := range []string{TagIconUse, TagIconMask} {
		r, err := newRendererIcons(assets, set, mode)
		if err != nil {
			t.Fatal(err)
		}
		out, err := r.render(l, "tags", page)
		if err != nil {
			t.Fatal(err)
		}
		body := string(out)
		var php, eco, stylesheet string
		switch mode {
		case TagIconUse:
			php = `<a class="tg" href="/tag/php"><svg class="tgi" aria-hidden="true" focusable="false"><use href="` + sprite + `#php"/></svg>PHP</a>`
			eco = `<a class="tg" href="/tag/crates-io"><svg class="tgi" aria-hidden="true" focusable="false"><use href="` + sprite + `#rust"/></svg>crates.io</a>`
			if strings.Contains(body, maskCSS) || strings.Contains(body, "data-i=") {
				t.Errorf("%s: mask markup", mode)
			}
		case TagIconMask:
			php = `<a class="tg" href="/tag/php"><span class="tgi" data-i="php" aria-hidden="true"></span>PHP</a>`
			eco = `<a class="tg" href="/tag/crates-io"><span class="tgi" data-i="rust" aria-hidden="true"></span>crates.io</a>`
			stylesheet = `<link rel="stylesheet" href="` + maskCSS + `"/>`
			if strings.Contains(body, sprite) || strings.Contains(body, "<use") {
				t.Errorf("%s: sprite markup", mode)
			}
		}
		for _, want := range []string{php, eco, `<a class="tg" href="/tag/windows">Windows</a>`, `<a class="tg tg-c-web" href="/tag/xss">`, stylesheet} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q", mode, want)
			}
		}
		if n, want := strings.Count(body, `class="tgi"`), len(tags.Icons); n != want {
			t.Errorf("%s: %d icons, want one per mapped tag (%d)", mode, n, want)
		}
		dec := xml.NewDecoder(bytes.NewReader(out))
		dec.Strict, dec.Entity = true, xml.HTMLEntity
		for {
			if _, err := dec.Token(); err == io.EOF {
				break
			} else if err != nil {
				t.Errorf("%s: not well-formed: %v", mode, err)
				break
			}
		}
	}
}
