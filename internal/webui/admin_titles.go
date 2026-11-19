package webui

import (
	"net/http"
	"strings"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/titles"
	"nday.land/nday/internal/webui/i18n"
)

// /admin/titles: staff titles of vulnerabilities (docs/titles.md,
// docs/admin.md). Admin only. A queue of the vulnerabilities researchers
// discuss (most researchers in the last 7 days first, then most posts),
// by default those whose record has no title (?f=all: every one), 10 per
// page (?p=), plus a lookup of any vulnerability id (?cve=). A row's
// "edit" opens its detail row: the staff title's input with the composed
// and record titles and the description's start for reference; save, and
// clear when a staff title exists (two steps). static/admin.js posts to
// /api/admin/titles/{id}/set|clear (internal/admin titles.go).

// AdminTitleRow is one vulnerability of the page.
type AdminTitleRow struct {
	CVE         string
	Href        string // the public page (this locale)
	Detail      string // id of the detail row
	Title       string // the effective title as the public page shows it
	TitleLang   string
	Missing     bool
	Mark        *TitleMark
	Origin      string // staff | record | composed | "" (untitled)
	Researchers int
	Posts       int
	Stage       string // stage code, "—" when none
	StageClass  string
	Version     int
	Staff       string // the staff title ("" = none)
	Composed    string // the composed title in English ("" = none)
	Record      string // the record's title ("" = none)
	Desc        string // the description's first 300 characters
	Max         int    // the staff title's maximum length
}

// AdminTitlesView is the page.
type AdminTitlesView struct {
	All       bool
	Filters   []AdminFilter // "" (no record title) | "all"
	Rows      []AdminTitleRow
	Total     int
	Pager     *Pager
	Lookup    string         // the id looked up (as typed, trimmed)
	Found     *AdminTitleRow // the vulnerability looked up (nil: none or unknown)
	NotFound  bool
	Providers []ProviderLink
	Passkeys2 bool
}

func (u *UI) adminTitleRow(loc *i18n.Locale, x site.TitleQueueRow, pfx string) AdminTitleRow {
	recState := recordUnknown
	row := AdminTitleRow{CVE: x.CVEID, Href: loc.Path("/vuln/" + x.CVEID), Detail: "dt-" + pfx + "-" + x.CVEID,
		Origin: x.Origin(), Researchers: x.Researchers, Posts: x.Posts, Stage: "—", StageClass: "weak", Version: x.StaffVersion,
		Desc: plain(x.Description), Max: titles.MaxStaff}
	row.Title, row.Missing, row.TitleLang, row.Mark = rowTitle(loc, nil, x.Record, x.TitleInfo, recState)
	if x.Stage != nil {
		code := site.StageCode(*x.Stage)
		row.Stage, row.StageClass = code, StageClass(code)
	}
	if x.Staff != nil {
		row.Staff = plain(*x.Staff)
	}
	if x.ComposedEN != nil {
		row.Composed = plain(*x.ComposedEN)
	}
	if x.Record != nil {
		row.Record = plain(strings.TrimSpace(*x.Record))
	}
	return row
}

func (u *UI) adminTitles(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	q := r.URL.Query()
	all := q.Get("f") == "all"
	rows, win, err := a.TitleQueue(r.Context(), all, pageParam(q, "p"))
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminTitlesView{All: all, Total: win.Total}
	links := newAdminLinks(loc.Path("/admin/titles"), q, "p")
	if all {
		links.set("f", "all")
	}
	for _, f := range []string{"", "all"} {
		v.Filters = append(v.Filters, AdminFilter{Value: f, Href: links.href("", "f", f, "p", ""), Current: (f == "all") == all})
	}
	for _, x := range rows {
		v.Rows = append(v.Rows, u.adminTitleRow(loc, x, "q"))
	}
	v.Pager = links.numbered(loc, win, "p", "r-titles")
	if id := strings.TrimSpace(cutRunes(q.Get("cve"), 40)); id != "" {
		v.Lookup = id
		x, err := a.TitleLookup(r.Context(), id)
		if err != nil {
			u.adminFail(w, r, loc, err)
			return
		}
		if x == nil {
			v.NotFound = true
		} else {
			row := u.adminTitleRow(loc, *x, "l")
			v.Found = &row
		}
	}
	if acc := u.opts.Accounts.Current(); acc != nil {
		for _, p := range acc.Providers {
			v.Providers = append(v.Providers, ProviderLink{ID: p, Name: providerNames[p]})
		}
		v.Passkeys2 = acc.Passkeys
	}
	u.adminRender(w, r, loc, me, "titles", "admin_titles", loc.Text("admin.nav", "tab", "titles"), v)
}
