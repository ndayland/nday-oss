package webui

import (
	"net/http"
	"net/url"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/webui/i18n"
)

// /admin/corrections (docs/corrections.md): readers' corrections of
// vulnerability pages. Staff (moderators and admins), like the moderation
// page. Two lists: the open queue (oldest first) and the decided ones
// (most recently decided first, ?state=decided), 30 per page with a cursor.
// The submission, the evidence link and the notes are user or staff input:
// escaped text, the link only through ExtLink (absolute http/https).
// Accepting needs a public note; static/admin.js calls
// POST /api/corrections/item/{id}/accept|reject and reloads the page.

// AdminCorrItem is one correction as the staff page shows it.
type AdminCorrItem struct {
	ID            string
	CVE           string
	VulnHref      string
	Category      string
	Status        string
	Body          string
	Evidence      *Link // nil: none
	At            Stamp
	Submitter     string
	SubmitterHref string // the user page ("" when the account is gone)
	Decided       bool
	DecidedAt     Stamp
	Decider       string
	DeciderHref   string
	PublicNote    string
	InternalNote  string
}

// AdminCorrView is the corrections page.
type AdminCorrView struct {
	State       string // pending | decided
	Filters     []AdminFilter
	Items       []AdminCorrItem
	Next, First string
	Pending     int
	MaxPublic   int
	MaxInternal int
}

func (u *UI) adminCorrections(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	q := r.URL.Query()
	base := loc.Path("/admin/corrections")
	state := q.Get("state")
	if state != "decided" {
		state = "pending"
	}
	after := admin.DecodeCursor(q.Get("c"))
	list, next, pending, err := a.Corrections(r.Context(), state == "decided", after)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminCorrView{State: state, Pending: pending, MaxPublic: corrections.MaxPublicNote, MaxInternal: corrections.MaxInternalNote}
	keep := func(extra url.Values) string {
		vs := url.Values{}
		if state == "decided" {
			vs.Set("state", state)
		}
		for k, x := range extra {
			vs[k] = x
		}
		if len(vs) == 0 {
			return base
		}
		return base + "?" + vs.Encode()
	}
	for _, s := range []string{"pending", "decided"} {
		href := base
		if s == "decided" {
			href += "?state=decided"
		}
		v.Filters = append(v.Filters, AdminFilter{Value: s, Href: href, Current: s == state})
	}
	if next != nil {
		v.Next = keep(url.Values{"c": {admin.EncodeCursor(next)}})
	}
	if after != nil {
		v.First = keep(nil)
	}
	for _, c := range list {
		it := AdminCorrItem{ID: c.ID, CVE: c.CVE, VulnHref: loc.Path("/vuln/" + c.CVE), Category: c.Category, Status: c.Status,
			Body: plain(c.Body), At: instant(c.CreatedAt, stampLong)}
		if c.EvidenceURL != nil {
			l := ExtLink(plain(*c.EvidenceURL), *c.EvidenceURL)
			it.Evidence = &l
		}
		if c.SubmitterID != nil {
			it.SubmitterHref = loc.Path("/admin/users/" + *c.SubmitterID)
			if c.Submitter != nil {
				it.Submitter = plain(*c.Submitter)
			}
		}
		if c.DecidedAt != nil {
			it.Decided, it.DecidedAt = true, instant(*c.DecidedAt, stampLong)
		}
		if c.DeciderID != nil {
			it.DeciderHref = loc.Path("/admin/users/" + *c.DeciderID)
			if c.Decider != nil {
				it.Decider = plain(*c.Decider)
			}
		}
		if c.PublicNote != nil {
			it.PublicNote = plain(*c.PublicNote)
		}
		if c.InternalNote != nil {
			it.InternalNote = plain(*c.InternalNote)
		}
		v.Items = append(v.Items, it)
	}
	u.adminRender(w, r, loc, me, "corrections", "admin_corr", loc.Text("admin.nav", "tab", "corrections"), v)
}
