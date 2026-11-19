package webui

import (
	"net/http"
	"net/url"
	"strconv"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
	"nday.land/nday/internal/xconfig"
)

// /admin/github (admins only; docs/github.md, docs/admin.md): the GitHub
// repositories to review, in three lists by status (admin.GitHubReview),
// and the trusted accounts whose repositories need no review
// (admin.GitHubOwners), each optionally linked to an allow-listed X account.
// Names and descriptions are third-party text: escaped by the template, the
// name linked to GitHub only when it is a valid full name.

// adminGHCVEs is how many associated CVEs a row lists ("+N" for the rest).
const adminGHCVEs = 5

// ghFlagSep joins a row's flags and its origins (the template's separator;
// the flags and found-by orders sort by that text).
const ghFlagSep = " · "

// adminGHDesc is the length (runes) a description is cut to.
const adminGHDesc = 160

// AdminGHCVE is one associated CVE of a row.
type AdminGHCVE struct {
	ID, Href string // Href "" when the id is not a canonical vulnerability id (CVE or GHSA)
}

// AdminGHRepo is one repository row.
type AdminGHRepo struct {
	ID       string
	Detail   string // id of its detail row (the row pattern)
	FullName string
	Href     string // https://github.com/<full name>, "" when not a valid full name
	Desc     string // one line, cut to adminGHDesc
	Stars    string
	Created  string // UTC date, "" = unknown
	CVEs     []AdminGHCVE
	More     int      // associated CVEs not listed
	Flags    []string // fork | archived | collection | predates | owner (trusted because of its owner)
	Sources  []string // ghrepo.ReviewOrigins: search, xposts (one line, joined by ghFlagSep)
	// Owner: its owner is a trusted account, enabled ("on") or disabled
	// ("off"), or none (""); AddOwner: the owner is known and not listed,
	// so the row offers to list it.
	Owner    string
	AddOwner bool
}

// AdminGHTable is one list: its status decides the actions (per row and
// for the selected rows: Bulk).
type AdminGHTable struct {
	Rows   []AdminGHRepo
	Status string // ghrepo.StatusUnverified, StatusTrusted, StatusRejected
	Region string // r-gh-<status>
	Pager  *Pager
	Bulk   *BulkBar
	// the sortable columns' header links
	Stars, Flags, Found AdminGHSort
}

// AdminGHSort is the header of a sortable column (Col: its admin.gh.col
// key; Right: right-aligned): Href the list in the next order of the
// column (ghSortNext), Aria its aria-sort now (ascending, descending, none).
type AdminGHSort struct {
	Col, Href, Aria string
	Right           bool
}

// ghSortNext is the order a click on the header of column key gives when
// the list is in order cur: stars most first, the text columns A to Z; a
// second click reverses; a third is the default order again.
func ghSortNext(key string, cur ghrepo.ReviewSort) string {
	first := ghrepo.ReviewSort{By: key, Desc: key == ghrepo.SortStars}
	switch {
	case cur.By != key:
		return first.String()
	case cur.Desc == first.Desc:
		return ghrepo.ReviewSort{By: key, Desc: !first.Desc}.String()
	}
	return ""
}

// ghAria is the aria-sort of column key in order cur.
func ghAria(key string, cur ghrepo.ReviewSort) string {
	switch {
	case cur.By != key:
		return "none"
	case cur.Desc:
		return "descending"
	}
	return "ascending"
}

// ghSortParams are each list's page and sort parameters.
var ghSortParams = map[string][2]string{ghrepo.StatusUnverified: {"up", "us"}, ghrepo.StatusTrusted: {"tp", "ts"},
	ghrepo.StatusRejected: {"rjp", "rjs"}}

// AdminGitHubView is /admin/github.
type AdminGitHubView struct {
	Unverified, Trusted, Rejected    AdminGHTable
	UnverifiedN, TrustedN, RejectedN int
	TrustedOpen, RejectedOpen        bool // the toggle is open (its pager was used)
	Owners                           AdminGHOwners
	Providers                        []ProviderLink // re-verification panel
	Passkeys2                        bool
}

// AdminGHOwners is the list of trusted accounts (admin.GitHubOwners).
type AdminGHOwners struct {
	Rows     []AdminGHOwner
	Total    int
	Pager    *Pager
	MaxNote  int
	From, To int
}

// AdminGHOwner is one trusted account. Login is an admin's or GitHub's
// text (ghrepo.ValidLogin); the X handle is checked before it is shown.
type AdminGHOwner struct {
	ID      string
	Detail  string // id of its detail row (the row pattern)
	Login   string
	Href    string // https://github.com/<login>
	Note    string
	XHandle string // the linked X account, "" = none
	XHref   string // that account on /admin/x
	Repos   string
	Trusted string
	Enabled bool
	Pending bool   // no owner id yet: trusts nothing
	State   string // on | off
	Created Stamp
}

// ghOwnerRows builds the rows of the trusted accounts.
func ghOwnerRows(loc *i18n.Locale, os []ghrepo.Owner) []AdminGHOwner {
	var out []AdminGHOwner
	for _, o := range os {
		id := strconv.FormatInt(o.ID, 10)
		row := AdminGHOwner{ID: id, Detail: "dt-gho-" + id, Login: plain(o.Login), Note: plain(o.Note),
			Repos: num(loc, int64(o.Repos)), Trusted: num(loc, int64(o.Trusted)), Enabled: o.Enabled, State: "off", Pending: o.OwnerID == 0,
			Created: instant(o.Created, stampShort)}
		if ghrepo.ValidLogin(o.Login) {
			row.Href = "https://github.com/" + o.Login
		}
		if o.Enabled {
			row.State = "on"
		}
		if xconfig.ValidHandle(o.XHandle) {
			row.XHandle = o.XHandle
			row.XHref = loc.Path("/admin/x") + "?q=" + url.QueryEscape(o.XHandle) + "#r-accounts"
		}
		out = append(out, row)
	}
	return out
}

func ghRows(loc *i18n.Locale, items []ghrepo.ReviewItem) []AdminGHRepo {
	var out []AdminGHRepo
	for _, it := range items {
		row := AdminGHRepo{ID: strconv.FormatInt(it.ID, 10), Detail: "dt-gh-" + strconv.FormatInt(it.ID, 10), FullName: plain(it.FullName), Desc: plain(audit.Excerpt(it.Description, adminGHDesc)),
			Stars: num(loc, int64(it.Stars))}
		if ghrepo.ValidFullName(it.FullName) {
			row.Href = "https://github.com/" + it.FullName
		}
		if it.Created != nil {
			row.Created = it.Created.UTC().Format(layoutDate)
		}
		for i, c := range it.CVEs {
			if i == adminGHCVEs {
				break
			}
			x := AdminGHCVE{ID: plain(c.CVE)}
			if id, ok := site.ParseVulnID(c.CVE); ok && id == c.CVE {
				x.Href = loc.Path("/vuln/" + id)
			}
			row.CVEs = append(row.CVEs, x)
		}
		row.More = max(it.CVECount, len(it.CVEs)) - len(row.CVEs)
		for _, f := range []struct {
			on   bool
			name string
		}{{it.IsFork, "fork"}, {it.IsArchived, "archived"}, {it.Collection, "collection"}, {it.Predates, "predates"},
			{it.StatusBy == ghrepo.StatusByOwner, "owner"}} {
			if f.on {
				row.Flags = append(row.Flags, f.name)
			}
		}
		row.Sources = ghrepo.ReviewOrigins(it)
		row.Owner = it.Owner
		row.AddOwner = it.Owner == "" && ghrepo.ValidLogin(it.OwnerLogin)
		out = append(out, row)
	}
	return out
}

// ghActs are each list's decisions, per row and for the selected rows:
// the primary decision first, the destructive one (reject) last.
var ghActs = map[string][]string{ghrepo.StatusUnverified: {"trust", "reject"}, ghrepo.StatusTrusted: {"reset", "reject"},
	ghrepo.StatusRejected: {"trust", "reset"}}

func (u *UI) adminGitHub(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	q := r.URL.Query()
	// three numbered lists: ?up= unverified, ?tp= trusted, ?rjp= rejected;
	// each sorted by ?us=, ?ts=, ?rjs= (ghrepo.ParseReviewSort: anything
	// else is the default order, and is not kept in the links)
	sorts := map[string]ghrepo.ReviewSort{}
	links := newAdminLinks(loc.Path("/admin/github"), q, "up", "tp", "rjp", "us", "ts", "rjs", "op")
	for st, p := range ghSortParams {
		sorts[st] = ghrepo.ParseReviewSort(q.Get(p[1]))
		links.set(p[1], sorts[st].String())
	}
	flag := func(f string) string { return loc.Text("admin.gh.flag", "f", f) }
	src := func(f string) string { return loc.Text("admin.gh.source", "s", f) }
	l, err := u.opts.Admin.GitHubReview(r.Context(), admin.GitHubPages{Unverified: pageParam(q, "up"), Trusted: pageParam(q, "tp"),
		Rejected: pageParam(q, "rjp"), UnverifiedSort: sorts[ghrepo.StatusUnverified], TrustedSort: sorts[ghrepo.StatusTrusted],
		RejectedSort: sorts[ghrepo.StatusRejected],
		Labels: ghrepo.ReviewLabels{Fork: flag("fork"), Archived: flag("archived"), Collection: flag("collection"),
			Predates: flag("predates"), Owner: flag("owner"), Sep: ghFlagSep, Search: src(ghrepo.SearchSource), Post: src(ghrepo.Source)}})
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	owners, err := u.opts.Admin.GitHubOwners(r.Context(), pageParam(q, "op"))
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	table := func(rows []ghrepo.ReviewItem, status, param string, win admin.Window) AdminGHTable {
		t := AdminGHTable{Rows: ghRows(loc, rows), Status: status, Region: "r-gh-" + status}
		t.Pager = links.numbered(loc, win, param, t.Region)
		// a new order starts the list at page 1
		cur, sp := sorts[status], ghSortParams[status][1]
		head := func(key, col string) AdminGHSort {
			return AdminGHSort{Col: col, Href: links.href(t.Region, sp, ghSortNext(key, cur), param, ""), Aria: ghAria(key, cur),
				Right: key == ghrepo.SortStars}
		}
		t.Stars, t.Flags, t.Found = head(ghrepo.SortStars, "stars"), head(ghrepo.SortFlags, "flags"), head(ghrepo.SortFound, "source")
		var acts []BulkAction
		for _, a := range ghActs[status] {
			acts = append(acts, BulkAction{Act: a, Label: loc.Text("admin.gh.act", "a", a), Danger: a == "reject"})
		}
		t.Bulk = newBulkBar("gh", acts)
		return t
	}
	v := AdminGitHubView{
		Unverified:  table(l.Unverified, ghrepo.StatusUnverified, "up", l.UnverifiedW),
		Trusted:     table(l.Trusted, ghrepo.StatusTrusted, "tp", l.TrustedW),
		Rejected:    table(l.Rejected, ghrepo.StatusRejected, "rjp", l.RejectedW),
		UnverifiedN: l.UnverifiedN, TrustedN: l.TrustedN, RejectedN: l.RejectedN,
	}
	v.Owners = AdminGHOwners{Rows: ghOwnerRows(loc, owners.Owners), Total: owners.Total, MaxNote: ghrepo.MaxOwnerNote,
		Pager: links.numbered(loc, owners.W, "op", "r-gh-owners")}
	if n := len(v.Owners.Rows); n > 0 {
		v.Owners.From = owners.W.Offset() + 1
		v.Owners.To = v.Owners.From + n - 1
	}
	// a list opened through its pager or its sort links stays open
	v.TrustedOpen, v.RejectedOpen = q.Get("tp") != "" || q.Has("ts"), q.Get("rjp") != "" || q.Has("rjs")
	if acc := u.opts.Accounts.Current(); acc != nil {
		for _, p := range acc.Providers {
			v.Providers = append(v.Providers, ProviderLink{ID: p, Name: providerNames[p]})
		}
		v.Passkeys2 = acc.Passkeys
	}
	u.adminRender(w, r, loc, me, "github", "admin_github", loc.Text("admin.nav", "tab", "github"), v)
}
