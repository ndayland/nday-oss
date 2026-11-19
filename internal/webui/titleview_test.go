package webui

import (
	"strings"
	"testing"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/titles"
)

func composedInfo(p titles.Parts) site.TitleInfo {
	en := titles.English(p, tags.TypeLabel)
	o := titles.OriginComposed
	return site.TitleInfo{EffectiveTitle: &en, TitleOrigin: &o, Composed: &p}
}

// The English catalog's joining patterns are the ones the API, feed, card
// and search use (titles.EnglishPattern); every locale renders the Oracle
// example; the excerpt is the record's English text in every locale.
func TestComposedTitleLocales(t *testing.T) {
	oracle := titles.Parts{Form: titles.FormFull, Product: "Java SE", Weakness: "buffer-overflow", Component: "Compiler"}
	want := map[string]string{
		"en":      "Java SE: buffer overflow / out-of-bounds write in Compiler",
		"zh-Hans": "Java SE：Compiler 中的 buffer overflow / out-of-bounds write",
	}
	for _, tag := range []string{"en", "zh-Hans", "zh-Hant", "ja", "ko", "es", "fr"} {
		l := loc(t, tag)
		got, lang := composedTitle(l, composedInfo(oracle))
		if w, ok := want[tag]; (ok && got != w) || lang != "" || !strings.Contains(got, "Java SE") || !strings.Contains(got, "Compiler") {
			t.Errorf("%s: %q lang %q", tag, got, lang)
		}
		ex, lang := composedTitle(l, composedInfo(titles.Parts{Form: titles.FormExcerpt, Excerpt: "Acme Widget allows bypass"}))
		if ex != "Acme Widget allows bypass" || lang != upstreamLang(l) {
			t.Errorf("%s excerpt: %q %q", tag, ex, lang)
		}
	}
	en := loc(t, "en")
	for _, f := range []string{titles.FormFull, titles.FormWeakness, titles.FormComponent} {
		p := titles.Parts{Form: f, Product: "P", Weakness: "xss", Component: "C"}
		if got, _ := composedTitle(en, composedInfo(p)); got != titles.English(p, tags.TypeLabel) {
			t.Errorf("%s: catalog %q, rule %q", f, got, titles.English(p, tags.TypeLabel))
		}
	}
}

// The row title: staff before everything, the record's (or title_zh) next,
// the composed one before the placeholder; the marker only for staff and
// composed titles.
func TestRowTitleOrigins(t *testing.T) {
	en, zh := loc(t, "en"), loc(t, "zh-Hans")
	rec, zhT := "Record", "记录"
	staff, so := "Staff", titles.OriginStaff
	staffInfo := site.TitleInfo{EffectiveTitle: &staff, TitleOrigin: &so}
	comp := composedInfo(titles.Parts{Form: titles.FormWeakness, Product: "P", Weakness: "xss"})
	for _, c := range []struct {
		name      string
		origin    string
		missing   bool
		zh, en    *string
		ti        site.TitleInfo
		wantTitle string
	}{
		{name: "staff over record", ti: staffInfo, en: &rec, wantTitle: "Staff", origin: "staff"},
		{name: "staff over title_zh", ti: staffInfo, zh: &zhT, en: &rec, wantTitle: "Staff", origin: "staff"},
		{name: "record", en: &rec, wantTitle: "Record"},
		{name: "composed", ti: comp, wantTitle: "P: XSS", origin: "composed"},
		{name: "untitled", wantTitle: "untitled: the CVE record gives no title", missing: true},
	} {
		got, missing, _, mark := rowTitle(en, c.zh, c.en, c.ti, recordPresent)
		origin := ""
		if mark != nil {
			origin = mark.Origin
		}
		if got != c.wantTitle || missing != c.missing || origin != c.origin {
			t.Errorf("%s: %q %v %q", c.name, got, missing, origin)
		}
	}
	if got, _, _, mark := rowTitle(zh, &zhT, &rec, site.TitleInfo{}, recordPresent); got != zhT || mark != nil {
		t.Errorf("zh: %q %v", got, mark)
	}
}

// The share card carries the effective English title (composed or staff),
// never the placeholder.
func TestCardEffectiveTitle(t *testing.T) {
	v := &site.VulnDetail{CVEID: "CVE-2026-7001", TitleInfo: composedInfo(titles.Parts{Form: titles.FormComponent, Product: "Java SE", Component: "Compiler"})}
	if c := cardFor(v); c.Title != "Java SE: vulnerability in Compiler" {
		t.Errorf("composed card %q", c.Title)
	}
	if c := cardFor(&site.VulnDetail{CVEID: "CVE-2026-7003"}); c.Title != "" {
		t.Errorf("untitled card %q", c.Title)
	}
}
