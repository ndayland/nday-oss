package webui

import (
	"net/url"
	"strings"
	"time"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
	"nday.land/nday/internal/xdraft"
)

// The share control of a vulnerability page (vuln.tmpl "share"): a link to
// X's compose window and a copy button, both with the text an X draft would
// have (xdraft.Share: same composer, English on every locale) plus the
// page's canonical URL in the page's language. Built from public data only
// (the vulnerability record and its events), never from X posts, so the
// page stays the same for every visitor.

// ShareView is what the control needs.
type ShareView struct {
	Compose string // X's compose intent with Text
	Text    string // body + "\n" + link (the copy button)
}

// shareStages: the draft stages, most advanced first.
var shareStages = []string{model.EventKevAdded, model.EventExploitedInWild, model.EventPocPublished}

// shareInput is the draft input of v for its most advanced reached draft
// stage, read the way the draft generator reads it (xdraft loadInput): the
// effective title (staff, record, composed in English), the affected pairs
// first reported first, the source of the stage's first event (lowest id)
// and site.CalendarDays from the first disclosure to the stage's first
// effective time. No stage reached, or a rejected record: Stage "".
func shareInput(v *site.VulnDetail) xdraft.Input {
	in := xdraft.Input{CVE: v.CVEID}
	if v.EffectiveTitle != nil {
		in.Title = *v.EffectiveTitle
	}
	for _, p := range v.Products {
		in.Products = append(in.Products, xdraft.Product{Vendor: p.Vendor, Product: p.Product})
	}
	if v.IsRejected { // the generator skips rejected records too: no stage
		return in
	}
	for _, st := range shareStages {
		var first *site.Event
		var at *time.Time
		for i := range v.Events {
			e := &v.Events[i]
			if e.Type != st {
				continue
			}
			if first == nil || e.ID < first.ID {
				first = e
			}
			if e.EffectiveAt != nil && (at == nil || e.EffectiveAt.Before(*at)) {
				at = e.EffectiveAt
			}
		}
		if first == nil {
			continue
		}
		in.Stage, in.Source = st, first.Source
		in.Days = site.CalendarDays(v.DisclosedAt, at)
		break
	}
	return in
}

// canonURL is the absolute canonical URL of a locale-neutral site path in
// locale l: what page() puts in <link rel="canonical"> and the hreflang
// alternates.
func (u *UI) canonURL(l *i18n.Locale, path string) string {
	return u.opts.BaseURL + l.Path(path)
}

// shareView is the share control of v's page in locale l.
func (u *UI) shareView(l *i18n.Locale, v *site.VulnDetail) *ShareView {
	body := xdraft.Share(shareInput(v))
	link := u.canonURL(l, "/vuln/"+v.CVEID)
	return &ShareView{Compose: xdraft.ComposeURL(body, link), Text: xdraft.ComposeText(body, link)}
}

// cardAddress is what the address card of id prints: the public host
// without "www." and the English page's path ("nday.land/vuln/CVE-…").
func (u *UI) cardAddress(id string) string {
	h := ""
	if p, err := url.Parse(u.opts.BaseURL); err == nil {
		h = strings.TrimPrefix(strings.ToLower(p.Host), "www.")
	}
	return h + u.locales.Primary().Path("/vuln/"+id)
}
