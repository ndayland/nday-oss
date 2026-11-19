package webui

import (
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/titles"
	"nday.land/nday/internal/webui/i18n"
)

// Titles nday composed or staff set (docs/titles.md; site.TitleInfo). Such
// a title is shown like any title, followed by one small marker (parts.tmpl
// "titlemark") whose tooltip and accessible name tell its origin; the
// record's own title has none, and a vulnerability that stays untitled
// keeps its placeholder.

// TitleMark is the origin marker after a title (nil: the record's own).
type TitleMark struct {
	Origin string // composed | staff
	Text   string // tooltip and accessible name
}

// titleMark is the marker of origin ("" and record: none).
func titleMark(l *i18n.Locale, origin string) *TitleMark {
	switch origin {
	case titles.OriginComposed:
		return &TitleMark{Origin: origin, Text: l.Text("title.origin_composed")}
	case titles.OriginStaff:
		return &TitleMark{Origin: origin, Text: l.Text("title.origin_staff")}
	}
	return nil
}

// composedTitle renders a composed title in l: the locale's joining
// pattern (title.composed, by form) around the product and component as
// the record names them and the weakness's localised tag name; the
// excerpt form is the record's own English text. lang is the lang
// attribute the text needs ("" = the page's).
func composedTitle(l *i18n.Locale, ti site.TitleInfo) (title, lang string) {
	p := ti.Composed
	switch {
	case p == nil:
		if ti.EffectiveTitle == nil {
			return "", ""
		}
		return *ti.EffectiveTitle, upstreamLang(l)
	case p.Form == titles.FormExcerpt:
		return p.Excerpt, upstreamLang(l)
	}
	w := ""
	if p.Weakness != "" {
		w = tagNameText(l, p.Weakness)
	}
	return l.Text("title.composed", "form", p.Form, "product", i18n.Upstream(p.Product), "weakness", w,
		"component", i18n.Upstream(p.Component)), ""
}
