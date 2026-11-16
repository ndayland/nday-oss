package webui

import (
	"context"
	"net/http"
	"net/url"

	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// Readers' corrections on vulnerability pages (docs/corrections.md).
//
// The page is the same for every visitor (publicly cacheable; nothing here
// reads a cookie). It holds:
//
//   - the revision log: the ACCEPTED corrections only (site.Store.
//     Corrections), each with when it was accepted, its category, the note
//     an editor wrote and the submitter's public handle. The section is
//     absent when there is none. Pending and rejected corrections and the
//     submitters' own texts are never on the page.
//   - with accounts, the entry: a short explanation, the sign-in call and a
//     form shell, all hidden but the explanation; static/corrections.js
//     shows the part that fits the visitor (/api/me), sends the form to
//     POST /api/corrections/{cve} and lists the visitor's own corrections of
//     this vulnerability with their status (GET /api/corrections/mine).
//
// Accepting a correction does not change the vulnerability data, and the
// words of the section say so.
//
// Caching: the log is cached in the server cache for CacheTTL like the
// other sections, so an accepted correction shows up at most that late
// (plus the page's own Cache-Control max-age).

// corrKeys are the messages corrections.js needs (rendered into the page's
// <template id="acct-msgs"> with the discussion ones).
var corrKeys = []string{"corr.busy", "corr.done", "corr.category", "corr.status", "corr.mine.at", "corr.mine.note",
	"corr.err.not_signed_in", "corr.err.suspended", "corr.err.handle_required", "corr.err.terms_required",
	"corr.err.csrf", "corr.err.cross_site", "corr.err.bad_category", "corr.err.invalid_body", "corr.err.bad_url",
	"corr.err.too_many_open", "corr.err.queue_full", "corr.err.daily_limit", "corr.err.rate_limited",
	"corr.err.not_found", "corr.err.too_large", "corr.err.network", "corr.err.empty", "corr.err.too_long",
	"corr.err.generic"}

// CorrView is the corrections part of a vulnerability page.
type CorrView struct {
	CVE        string
	Log        []CorrEntry // accepted corrections, most recent first
	Failed     bool        // the log could not be loaded
	Write      bool        // accounts are on: the entry and corrections.js
	Login      string      // localized /login?return=<page>?correction
	Account    string      // localized /account
	Rules      string      // localized /rules
	Categories []string
	MaxBody    int
	MaxURL     int
}

// CorrEntry is one accepted correction of the revision log.
type CorrEntry struct {
	At       Stamp
	Category string
	Note     string // plain text (escaped by the template)
	Handle   string // "" = no name shown
	Deleted  bool   // no name because the account was deleted ("reported by a deleted account")
}

// BuildCorrView turns the accepted corrections into the view (nil list:
// the log could not be loaded).
func BuildCorrView(cve string, log []site.PublicCorrection, failed bool) *CorrView {
	v := &CorrView{CVE: cve, Failed: failed, Categories: corrections.Categories, MaxBody: corrections.MaxBodyChars,
		MaxURL: corrections.MaxURLBytes}
	for _, c := range log {
		e := CorrEntry{At: instant(c.AcceptedAt, stampLong), Category: c.Category, Note: plain(c.Note)}
		if c.Handle != nil {
			e.Handle = plain(*c.Handle)
		}
		e.Deleted = c.Deleted
		v.Log = append(v.Log, e)
	}
	return v
}

// corrections builds the part of a vulnerability page (a failure leaves the
// rest of the page intact and hides the log).
func (u *UI) corrections(r *http.Request, loc *i18n.Locale, cve string) *CorrView {
	v, err := u.cached(r.Context(), "corr|"+cve, func(ctx context.Context) (any, error) {
		return u.srv.Store.Corrections(ctx, cve)
	})
	var list []site.PublicCorrection
	if err != nil {
		u.srv.Log.Warn("corrections unavailable", "cve", cve, "err", err)
	} else {
		list = v.([]site.PublicCorrection)
	}
	cv := BuildCorrView(cve, list, err != nil)
	if u.opts.Accounts != nil {
		cv.Write = true
		cv.Login = loc.Path("/login") + "?return=" + url.QueryEscape(loc.Path("/vuln/"+cve)+"?correction")
		cv.Account = loc.Path("/account")
		cv.Rules = loc.Path("/rules")
	}
	return cv
}
