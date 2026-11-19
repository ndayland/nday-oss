package webui

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/discuss/md"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/stats"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui/i18n"
)

// The staff back office (docs/admin.md): server-rendered pages under
// /admin for every locale prefix. Unlike every other page these are
// personal: they are rendered for the signed-in staff member, so they go
// through admin.Service.Page (session loaded, response forced to no-store
// and noindex, conditional requests ignored), never through the server's
// shared cache, and are written without validators (writePersonal).
//
// Access (admin.Service.Decide): signed out -> 302 to the localized sign-in
// page with return=<this page>; not staff, suspended staff, another host
// -> the ordinary 404 page; moderators get the moderation module and the
// limited user view only (a moderator asking for /admin lands on
// /admin/moderation).
//
// Everything user-derived is escaped text (handles, display names,
// reasons, notes, earlier comment versions, search terms, referrer hosts,
// 404 paths, log records); the only HTML inserted as is is the discussion
// renderer's output (package discuss/md, allowlisted).
//
// Actions are made by static/admin.js against /api/admin/* and the
// discussion moderation endpoints; after a success it reloads the page.

// adminKeys are the messages admin.js needs.
var adminKeys = []string{"acct.busy", "acct.reauth.done", "acct.err.webauthn_cancelled",
	"admin.msg.done", "admin.msg.reason_needed",
	"admin.err.reauth_required", "admin.err.self", "admin.err.protected", "admin.err.no_change", "admin.err.not_found",
	"admin.err.forbidden", "admin.err.bad_reason", "admin.err.bad_duration", "admin.err.bad_role", "admin.err.rate_limited",
	"admin.err.csrf", "admin.err.cross_site", "admin.err.not_signed_in", "admin.err.wrong_status", "admin.err.suspended",
	"admin.err.network", "admin.err.generic", "admin.err.exists", "admin.err.bad_user_id", "admin.err.bad_handle",
	"admin.err.bad_note", "admin.err.bad_setting", "admin.err.bad_import", "admin.err.too_large",
	"admin.err.stale_version", "admin.err.too_long", "admin.err.bad_body", "admin.err.bad_post_url",
	"admin.err.x_lookup_off", "admin.err.x_not_found", "admin.err.x_unavailable", "admin.err.x_rate_limited", "admin.err.x_auth",
	"admin.err.x_upstream", "admin.err.no_handle", "admin.x.add_done", "admin.x.add_renamed", "admin.x.import_found",
	"admin.x.worst_posts", "admin.x.field_err", "admin.x.import_line", "admin.x.import_preview", "admin.xd.length",
	"admin.err.settings_off", "admin.err.no_master_key", "admin.err.unknown_setting", "admin.err.secret_setting",
	"admin.err.not_secret", "admin.err.bad_secret", "admin.err.invalid_config", "admin.err.sign_in_off", "admin.err.not_applied",
	"admin.set.source", "admin.set.secret_state", "admin.set.secret_set_hint", "admin.set.saved", "admin.set.saved_restart",
	"admin.set.unchanged", "admin.set.secret_empty", "admin.set.field_err",
	"admin.corr.note_needed", "admin.err.too_many", "admin.err.duplicate",
	"admin.bulk.selected", "admin.bulk.result", "admin.bulk.result_failed", "admin.x.profiles_done", "admin.err.bad_title",
	"admin.xd.length_alone", "admin.xd.copied", "admin.xd.copy_failed", "admin.err.bad_form",
	"admin.err.link_too_long", "admin.xd.over_link", "admin.xd.body_label", "admin.xd.body_label_alone",
	"admin.err.bad_login", "admin.err.no_owner", "admin.err.x_not_listed", "admin.err.owner_exists", "admin.err.github_not_found"}

// AdminTab is one entry of the back office navigation.
type AdminTab struct {
	Key     string // stats | moderation | corrections | titles | users | system | settings | xgh | audit; in SubTabs x | xdrafts | github
	Href    string
	Current bool
}

// adminGroups are the menu items that stand for several pages: the item
// links to the first page, is current on each of them, and those pages
// show the group's pages as a second-level menu (AdminView.SubTabs).
var adminGroups = map[string][]string{"xgh": {"x", "xdrafts", "github"}}

// AdminView is the frame every admin page shares.
type AdminView struct {
	Title   string // h1
	Tab     string
	Tabs    []AdminTab
	SubTabs []AdminTab // the current page's group, nil outside a group
	Handle  string     // the signed-in staff member
	Role    string
	IsAdmin bool
	Actions bool // moderation actions are available (discussions on)
	Body    any
}

// adminRoutes registers the pages of one locale. admin.Service.Page is the
// outermost wrapper, so even a 405 carries the back office's headers.
func (u *UI) adminRoutes(p string, loc *i18n.Locale) {
	a := u.opts.Admin
	h := func(pattern string, lvl admin.Level, f adminFunc) {
		gate := u.adminGate(lvl, f)
		u.srv.Handle(pattern, a.Page(web.GetOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gate(w, r, loc) }))))
	}
	h(p+"/admin", admin.AdminOnly, u.adminStats)
	h(p+"/admin/moderation", admin.Staff, u.adminModeration)
	h(p+"/admin/corrections", admin.Staff, u.adminCorrections)
	h(p+"/admin/users", admin.AdminOnly, u.adminUsers)
	h(p+"/admin/users/{id}", admin.Staff, u.adminUser)
	h(p+"/admin/system", admin.AdminOnly, u.adminSystem)
	h(p+"/admin/settings", admin.AdminOnly, u.adminSettings)
	h(p+"/admin/x", admin.AdminOnly, u.adminX)
	h(p+"/admin/x/drafts", admin.AdminOnly, u.adminXDrafts)
	h(p+"/admin/github", admin.AdminOnly, u.adminGitHub)
	h(p+"/admin/audit", admin.AdminOnly, u.adminAudit)
	h(p+"/admin/titles", admin.AdminOnly, u.adminTitles)
}

type adminFunc func(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User)

// adminGate is the access check of every admin page (see the file comment);
// the request has been through admin.Service.Page.
func (u *UI) adminGate(lvl admin.Level, f adminFunc) pageFunc {
	a := u.opts.Admin
	return func(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
		{
			dec, me := a.Decide(r, lvl)
			switch {
			case dec == admin.SignIn:
				ret := u.cleanReturn(r.URL.Path)
				if q := r.URL.Query(); len(q) > 0 {
					if full := u.cleanReturn(r.URL.Path + "?" + q.Encode()); full != "" {
						ret = full
					}
				}
				to := loc.Path("/login")
				if ret != "" {
					to += "?return=" + url.QueryEscape(ret)
				}
				http.Redirect(w, r, to, http.StatusFound)
			case dec == admin.Hidden && a.IsStaff(me) && neutralPath(loc, r.URL.Path) == "/admin":
				http.Redirect(w, r, loc.Path("/admin/moderation"), http.StatusFound)
			case dec != admin.Allow:
				u.notFound(w, r, loc)
			case !a.PageAllowed(me):
				w.Header().Set("Retry-After", "1")
				u.errorPage(w, r, loc, http.StatusTooManyRequests, ErrorView{Heading: loc.Text("admin.err.rate_limited"),
					Message: loc.HTML("admin.err.rate_limited")}, "")
			default:
				f(w, r, loc, me)
			}
		}
	}
}

// adminRender renders an admin page.
func (u *UI) adminRender(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User, tab, name, title string, body any) {
	a := u.opts.Admin
	v := AdminView{Title: title, Tab: tab, Role: me.Role, IsAdmin: a.IsAdmin(me), Actions: a.Discussions(), Body: body}
	if me.Handle != nil {
		v.Handle = *me.Handle
	}
	pages := map[string]struct {
		path  string
		admin bool
	}{"stats": {"/admin", true}, "moderation": {"/admin/moderation", false}, "corrections": {"/admin/corrections", false},
		"users": {"/admin/users", true}, "system": {"/admin/system", true}, "settings": {"/admin/settings", true},
		"x": {"/admin/x", true}, "xdrafts": {"/admin/x/drafts", true}, "github": {"/admin/github", true}, "audit": {"/admin/audit", true},
		"titles": {"/admin/titles", true}}
	visible := func(key string) bool { return !pages[key].admin || v.IsAdmin }
	for _, key := range []string{"stats", "moderation", "corrections", "titles", "users", "system", "settings", "xgh", "audit"} {
		members, group := adminGroups[key]
		if !group {
			if visible(key) {
				v.Tabs = append(v.Tabs, AdminTab{Key: key, Href: loc.Path(pages[key].path), Current: key == tab})
			}
			continue
		}
		var subs []AdminTab
		current := false
		for _, m := range members {
			if visible(m) {
				subs = append(subs, AdminTab{Key: m, Href: loc.Path(pages[m].path), Current: m == tab})
				current = current || m == tab
			}
		}
		if len(subs) == 0 {
			continue // the group disappears when none of its pages is visible
		}
		v.Tabs = append(v.Tabs, AdminTab{Key: key, Href: subs[0].Href, Current: current})
		if current {
			v.SubTabs = subs
		}
	}
	p := &Page{Title: loc.Text("admin.page_title", "section", title), Description: loc.Text("admin.description"),
		Path: "~" + neutralPath(loc, r.URL.Path), Hints: helpHints(loc), NoIndex: true, Personal: true, AdminScript: true, Data: v}
	u.page(w, r, loc, http.StatusOK, name, p)
}

func (u *UI) adminFail(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, err error) {
	u.srv.Log.Error("admin page failed", "path", r.URL.Path, "err", err)
	u.errorPage(w, r, loc, http.StatusInternalServerError, ErrorView{Heading: loc.Text("err.internal.heading"),
		Message: loc.HTML("err.internal.message")}, "")
}

// num is an integer in the locale's grouping.
func num(l *i18n.Locale, n int64) string { return l.Int(n) }

// ================================================================ /admin

// AdminCard is one headline number.
type AdminCard struct {
	Key          string // admin.stats.card.<Key>
	Range, Today string
	HumanRange   string // "" when not applicable
	HumanToday   string
}

// ChartBar is one drawn bar (SVG user units: each day is 10 wide, the plot
// 100 high).
type ChartBar struct {
	X, Y, W, H string
	Class      string
	Title      string
}

// ChartLegend is one legend entry.
type ChartLegend struct{ Class, Key string }

// DayChart is one per-day bar chart.
type DayChart struct {
	ID      string
	Key     string // admin.stats.chart.<Key>
	Width   string // viewBox width
	Bars    []ChartBar
	Gaps    []ChartBar
	Legend  []ChartLegend
	Max     string
	First   string // first day label
	Last    string
	Empty   bool // every value is 0
	Aria    string
	HasGaps bool
}

// TopRow is one row of a top list.
type TopRow struct {
	Key   string // shown as text
	Href  string // set only for a vulnerability id
	Lang  string // lang attribute of Key ("" none)
	Value string
}

// TopTable is one top list, paged in memory (?<Param>=).
type TopTable struct {
	ID, Key, Col string // admin.stats.top.<Key>, admin.stats.col.<Col>
	Rows         []TopRow
	Region       string // r-<ID>
	Pager        *Pager
}

// AdminStatsView is the statistics page.
type AdminStatsView struct {
	Days       int
	Ranges     []AdminRange
	HasStats   bool
	LastRollup template.HTML
	RolledDays int
	Zone       string
	Cards      []AdminCard
	Charts     []DayChart
	Tables     []TopTable
	Map        WorldMap // page views by people per country
	BotShare   string
	Bots, Reqs string
}

// AdminRange is one choice of the range selector.
type AdminRange struct {
	Days    int
	Href    string
	Current bool
}

func (u *UI) adminStats(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	d, err := a.Dashboard(r.Context(), days)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminStatsView{Days: d.Days, HasStats: d.HasStats, RolledDays: d.RolledDays, Zone: a.Location().String()}
	if v.Zone == "Local" {
		_, off := a.Now().In(a.Location()).Zone()
		v.Zone = utcOffset(off)
	}
	for _, n := range admin.Ranges {
		v.Ranges = append(v.Ranges, AdminRange{Days: n, Href: loc.Path("/admin") + "?days=" + strconv.Itoa(n), Current: n == d.Days})
	}
	if d.LastRollup != nil {
		v.LastRollup = instant(*d.LastRollup, stampLong).HTML()
	}
	pair := func(key string, rg, td, hr, ht int64, human bool) AdminCard {
		c := AdminCard{Key: key, Range: num(loc, rg), Today: num(loc, td)}
		if human {
			c.HumanRange, c.HumanToday = num(loc, hr), num(loc, ht)
		}
		return c
	}
	v.Cards = []AdminCard{
		pair("page_views", d.Range.PageViews, d.Today.PageViews, d.Range.HumanPageViews, d.Today.HumanPageViews, true),
		pair("visitors", d.Range.Visitors, d.Today.Visitors, d.Range.HumanVisitors, d.Today.HumanVisitors, true),
		pair("api", d.Range.APIRequests, d.Today.APIRequests, 0, 0, false),
		pair("accounts", d.Range.NewAccounts, d.Today.NewAccounts, 0, 0, false),
		pair("comments", d.Range.Comments, d.Today.Comments, 0, 0, false),
		{Key: "reports_open", Range: num(loc, d.OpenReports), Today: num(loc, d.OpenReports)},
	}
	type ser struct {
		class, key string
		v          []admin.DayValue
	}
	chart := func(id, key string, stacked bool, ss ...ser) DayChart {
		return buildDayChart(loc, id, key, stacked, ss2(ss, func(s ser) chartSeries { return chartSeries{s.class, s.key, s.v} }))
	}
	status := []ser{}
	for i, c := range admin.StatusClasses {
		status = append(status, ser{"s" + strconv.Itoa(i+1), "status_" + c, d.Status[c]})
	}
	v.Charts = []DayChart{
		chart("ch-pv", "page_views", false, ser{"s1", "all", d.PageViews}, ser{"s2", "human", d.HumanPageViews}),
		chart("ch-uv", "visitors", false, ser{"s1", "all", d.Visitors}, ser{"s2", "human", d.HumanVisitors}),
		chart("ch-api", "api", false, ser{"s1", "api", d.APIRequests}),
		chart("ch-st", "status", true, status...),
		chart("ch-acc", "accounts", false, ser{"s2", "accounts", d.NewAccounts}),
		chart("ch-cm", "comments", false, ser{"s1", "comments", d.Comments}, ser{"s4", "reports", d.Reports}),
	}
	top := func(id, key, col string, es []stats.TopEntry, row func(e stats.TopEntry) TopRow) TopTable {
		t := TopTable{ID: id, Key: key, Col: col}
		for _, e := range es {
			tr := TopRow{Key: plain(e.Key)}
			if row != nil {
				tr = row(e)
			}
			tr.Value = num(loc, e.Value)
			t.Rows = append(t.Rows, tr)
		}
		return t
	}
	v.Tables = []TopTable{
		top("t-vuln", "vulns", "vuln", d.TopVulns, func(e stats.TopEntry) TopRow {
			if id, ok := site.ParseVulnID(e.Key); ok && id == e.Key {
				return TopRow{Key: e.Key, Href: loc.Path("/vuln/" + id)}
			}
			return TopRow{Key: plain(e.Key)}
		}),
		top("t-ref", "referrers", "host", d.Referrers, nil),
		top("t-cc", "countries", "country", d.Countries, nil),
		top("t-q", "searches", "term", d.Searches, nil),
		top("t-404", "not_found", "path", d.NotFound, nil),
		top("t-loc", "locales", "language", d.Locales, func(e stats.TopEntry) TopRow {
			if l := u.locales.ByTag(admin.LocaleTag(e.Key)); l != nil && l.NativeName != "" {
				return TopRow{Key: l.NativeName, Lang: l.Tag}
			}
			return TopRow{Key: plain(e.Key)}
		}),
		top("t-ep", "endpoints", "endpoint", d.Endpoints, nil),
		top("t-bot", "bots", "agent", d.BotUA, nil),
	}
	// each top list pages on its own parameter: the table id without "-" (tvuln, tref …)
	q := r.URL.Query()
	keys := []string{"days"}
	for _, t := range v.Tables {
		keys = append(keys, strings.ReplaceAll(t.ID, "-", ""))
	}
	links := newAdminLinks(loc.Path("/admin"), q, keys...)
	if d.Days > 0 {
		links.set("days", strconv.Itoa(d.Days))
	}
	for i := range v.Tables {
		t := &v.Tables[i]
		param := strings.ReplaceAll(t.ID, "-", "")
		var w admin.Window
		t.Rows, w = memPage(t.Rows, pageParam(q, param))
		t.Region = "r-" + t.ID
		t.Pager = links.numbered(loc, w, param, t.Region)
	}
	v.Map = BuildWorldMap(loc, d.CountriesHuman)
	v.Reqs, v.Bots = num(loc, d.Requests), num(loc, d.BotRequests)
	if d.Requests > 0 {
		v.BotShare = strconv.FormatFloat(float64(d.BotRequests)*100/float64(d.Requests), 'f', 1, 64) + "%"
	}
	u.adminRender(w, r, loc, me, "stats", "admin_stats", loc.Text("admin.nav", "tab", "stats"), v)
}

func ss2[T any](in []T, f func(T) chartSeries) []chartSeries {
	out := make([]chartSeries, len(in))
	for i, x := range in {
		out[i] = f(x)
	}
	return out
}

// utcOffset is "UTC+08:00".
func utcOffset(sec int) string {
	sign := "+"
	if sec < 0 {
		sign, sec = "-", -sec
	}
	return "UTC" + sign + pad2(sec/3600) + ":" + pad2(sec%3600/60)
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

type chartSeries struct {
	class, key string
	v          []admin.DayValue
}

// buildDayChart lays out per-day bars: side by side, or stacked. Days
// without statistics (Gap) get a full-height background mark.
func buildDayChart(l *i18n.Locale, id, key string, stacked bool, ss []chartSeries) DayChart {
	c := DayChart{ID: id, Key: key, Empty: true}
	if len(ss) == 0 || len(ss[0].v) == 0 {
		return c
	}
	n := len(ss[0].v)
	c.Width = strconv.Itoa(n * 10)
	var max int64
	for i := 0; i < n; i++ {
		var stack int64
		for _, s := range ss {
			if i >= len(s.v) {
				continue
			}
			if s.v[i].V > 0 {
				c.Empty = false
			}
			if stacked {
				stack += s.v[i].V
			} else if s.v[i].V > max {
				max = s.v[i].V
			}
		}
		if stack > max {
			max = stack
		}
	}
	f := func(x float64) string { return strconv.FormatFloat(x, 'f', 2, 64) }
	for i := 0; i < n; i++ {
		day := ss[0].v[i].Day.Format("2006-01-02")
		if ss[0].v[i].Gap {
			c.HasGaps = true
			c.Gaps = append(c.Gaps, ChartBar{X: f(float64(i * 10)), Y: "0", W: "10", H: "100", Class: "gap",
				Title: l.Text("admin.stats.gap_day", "day", day)})
		}
		var base float64
		for k, s := range ss {
			if i >= len(s.v) || s.v[i].V == 0 || max == 0 {
				continue
			}
			h := float64(s.v[i].V) / float64(max) * 96
			if h < 0.8 {
				h = 0.8
			}
			x, w := float64(i*10)+1, 8.0
			y := 100 - h
			if stacked {
				y = 100 - base - h
				base += h
			} else if len(ss) > 1 {
				w = 8.0 / float64(len(ss))
				x += float64(k) * w
			}
			c.Bars = append(c.Bars, ChartBar{X: f(x), Y: f(y), W: f(w), H: f(h), Class: s.class,
				Title: l.Text("admin.stats.bar", "day", day, "series", l.Text("admin.stats.series", "series", s.key), "n", s.v[i].V)})
		}
	}
	for _, s := range ss {
		c.Legend = append(c.Legend, ChartLegend{Class: s.class, Key: s.key})
	}
	c.Max = num(l, max)
	c.First = ss[0].v[0].Day.Format("01-02")
	c.Last = ss[0].v[n-1].Day.Format("01-02")
	c.Aria = l.Text("admin.stats.chart_aria", "chart", l.Text("admin.stats.chart", "chart", key), "max", max)
	return c
}

// ============================================================ moderation

// ModReport is one open report as shown.
type ModReport struct {
	ID     string
	Reason string // code
	Note   string
	At     Stamp
}

// ModRevision is an earlier body (plain text).
type ModRevision struct {
	Body string
	At   Stamp
}

// ModItem is one comment of the moderation pages.
type ModItem struct {
	ID         string
	CVE        string
	VulnHref   string
	Permalink  string
	Handle     string
	AuthorHref string // the user page ("" without an author)
	Gone       bool   // the author deleted the account
	Role       string // moderator | admin | ""
	Status     string
	At         Stamp
	EditedAt   Stamp
	Edited     bool
	Body       template.HTML
	Hidden     template.HTML // hide reason (isolated text)
	HiddenBy   template.HTML
	Revisions  int
	History    []ModRevision
	// report groups only
	Reports   []ModReport
	ReportIDs string // space-separated open report ids (resolve all)
	Total     int
	Reporters int
	Reasons   []ReasonCount
	OpenRep   int
	Act       bool   // moderation actions are available
	Pfx       string // the list's prefix of the item's ids inside its region (q, r, u)
}

// ReasonCount is a report reason with its count.
type ReasonCount struct {
	Reason string
	N      int
}

// AdminModView is the moderation page.
type AdminModView struct {
	Queue       []ModItem
	QueueTotal  int
	QueuePager  *Pager
	Recent      []ModItem
	RecentPager *Pager
	Status      string
	Filters     []AdminFilter
	MaxReason   int
}

// AdminFilter is one choice of the status filter.
type AdminFilter struct {
	Value   string // "" = all
	Href    string
	Current bool
}

func (u *UI) modItem(loc *i18n.Locale, c *admin.Comment, history []admin.Revision) ModItem {
	link := func(cve string) string { return loc.Path("/vuln/" + cve) }
	m := ModItem{ID: c.ID, CVE: c.CVE, VulnHref: link(c.CVE), Status: c.Status, At: instant(c.CreatedAt, stampLong),
		Permalink: link(c.CVE) + "?" + discComment1 + "=" + c.ID + "#c-" + c.ID, Revisions: c.Revisions, OpenRep: c.OpenReports,
		Act: u.opts.Admin.Discussions()}
	// the renderer's output is allowlisted (package md); <br> becomes <br/>
	// as on the vulnerability pages; off-site links open in a new tab
	m.Body = template.HTML(strings.ReplaceAll(md.Render(c.Body, md.Options{Links: c.Links, CVELink: link, NewTab: u.offSite}), "<br>", "<br/>"))
	if c.AuthorID != nil {
		m.AuthorHref = loc.Path("/admin/users/" + *c.AuthorID)
		if c.Handle != nil {
			m.Handle = *c.Handle
		}
		if c.Role != nil && (*c.Role == auth.RoleModerator || *c.Role == auth.RoleAdmin) {
			m.Role = *c.Role
		}
	} else {
		m.Gone = true
	}
	if c.EditedAt != nil {
		m.Edited, m.EditedAt = true, instant(*c.EditedAt, stampLong)
	}
	if c.HiddenReason != nil {
		m.Hidden = isolate(*c.HiddenReason)
	}
	if c.HiddenBy != nil {
		m.HiddenBy = isolate(*c.HiddenBy)
	}
	for _, h := range history {
		m.History = append(m.History, ModRevision{Body: plain(h.Body), At: instant(h.ReplacedAt, stampLong)})
	}
	return m
}

func (u *UI) adminModeration(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	q := r.URL.Query()
	base := loc.Path("/admin/moderation")
	v := AdminModView{MaxReason: 200}
	status := q.Get("status")
	known := status == ""
	for _, s := range admin.CommentStatuses {
		known = known || s == status
	}
	if !known {
		status = ""
	}
	v.Status = status
	// the queue is numbered (?qp=), the patrol list keyset (?rc= older, ?rb= newer, ?rp= its page number)
	links := newAdminLinks(base, q, "qp", "rp")
	links.set("status", status)
	pos := admin.Keyset[admin.Cursor]{Older: admin.DecodeCursor(q.Get("rc")), Newer: admin.DecodeCursor(q.Get("rb"))}
	links.set("rc", admin.EncodeCursor(pos.Older)) // a position that does not decode is dropped
	links.set("rb", admin.EncodeCursor(pos.Newer))
	groups, qw, err := a.ReportQueue(r.Context(), pageParam(q, "qp"))
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	for _, g := range groups {
		m := u.modItem(loc, g.Comment, g.History)
		m.Total, m.Reporters = g.Total, g.Reporters
		var ids []string
		for _, rp := range g.Reports {
			note := ""
			if rp.Note != nil {
				note = plain(*rp.Note)
			}
			m.Reports = append(m.Reports, ModReport{ID: rp.ID, Reason: rp.Reason, Note: note, At: instant(rp.CreatedAt, stampLong)})
			ids = append(ids, rp.ID)
		}
		m.ReportIDs = strings.Join(ids, " ")
		for _, reason := range reportReasons {
			if n := g.Reasons[reason]; n > 0 {
				m.Reasons = append(m.Reasons, ReasonCount{reason, n})
			}
		}
		m.Pfx = "q"
		v.Queue = append(v.Queue, m)
	}
	v.QueueTotal = qw.Total
	v.QueuePager = links.numbered(loc, qw, "qp", "r-queue")
	recent, rprev, rnext, err := a.RecentComments(r.Context(), status, pos)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	recentN, err := a.RecentCommentsCount(r.Context(), status)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	for _, c := range recent {
		var hist []admin.Revision
		if c.Revisions > 0 {
			if hist, err = a.History(r.Context(), c.ID); err != nil {
				u.adminFail(w, r, loc, err)
				return
			}
		}
		m := u.modItem(loc, c, hist)
		m.Pfx = "r"
		v.Recent = append(v.Recent, m)
	}
	v.RecentPager = links.keyset(loc, "r-recent", "rc", "rb", "rp", admin.EncodeCursor(rprev), admin.EncodeCursor(rnext), recentN)
	for _, s := range append([]string{""}, admin.CommentStatuses...) {
		v.Filters = append(v.Filters, AdminFilter{Value: s, Href: links.href("r-recent", "status", s, "rc", "", "rb", "", "rp", ""),
			Current: s == status})
	}
	u.adminRender(w, r, loc, me, "moderation", "admin_mod", loc.Text("admin.nav", "tab", "moderation"), v)
}

// ================================================================ users

// AdminUserRow is one row of the user list.
type AdminUserRow struct {
	ID, Href    string
	Handle      string
	DisplayName string
	Role        string
	Status      string
	Joined      Stamp
	LastSeen    Stamp
	Comments    string
}

// AdminUsersView is the user list.
type AdminUsersView struct {
	Query string
	Rows  []AdminUserRow
	Pager *Pager
}

func (u *UI) adminUsers(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	q := r.URL.Query()
	query := plain(strings.TrimSpace(q.Get("q")))
	if len([]rune(query)) > 64 {
		query = string([]rune(query)[:64])
	}
	// keyset: ?after= older, ?before= newer, ?p= the page number
	pos := admin.Keyset[auth.UserCursor]{Older: admin.DecodeUserCursor(q.Get("after")), Newer: admin.DecodeUserCursor(q.Get("before"))}
	rows, prev, next, err := a.Users(r.Context(), query, pos)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	total, err := a.UsersCount(r.Context(), query)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminUsersView{Query: query}
	for _, x := range rows {
		row := AdminUserRow{ID: x.ID, Href: loc.Path("/admin/users/" + x.ID), Role: x.Role, Status: x.Effective,
			Joined: instant(x.CreatedAt, stampShort), LastSeen: instant(x.LastSeenAt, stampShort), Comments: num(loc, int64(x.Comments))}
		if x.Handle != nil {
			row.Handle = *x.Handle
		}
		if x.DisplayName != nil {
			row.DisplayName = plain(*x.DisplayName)
		}
		v.Rows = append(v.Rows, row)
	}
	links := newAdminLinks(loc.Path("/admin/users"), q, "p")
	links.set("q", query)
	links.set("after", admin.EncodeUserCursor(pos.Older))
	links.set("before", admin.EncodeUserCursor(pos.Newer))
	v.Pager = links.keyset(loc, "r-users", "after", "before", "p", admin.EncodeUserCursor(prev), admin.EncodeUserCursor(next), total)
	u.adminRender(w, r, loc, me, "users", "admin_users", loc.Text("admin.nav", "tab", "users"), v)
}

// AdminIdentity is a linked sign-in method on the user page.
type AdminIdentity struct {
	Provider string // brand name
	Handle   string
	Subject  string // shortened
	Linked   Stamp
	Used     Stamp
}

// AdminReportRow is a report in a user's history.
type AdminReportRow struct {
	Detail    string // id of its detail row (the row pattern)
	At        Stamp
	Reason    string
	Note      string
	State     string // open | hidden | dismissed | actioned
	Excerpt   string
	Permalink string
	CVE       string
}

// AdminAuditRow is one audit entry as shown.
type AdminAuditRow struct {
	Detail     string // id of its detail row (the row pattern)
	At         Stamp
	Actor      string // handle, "" for the CLI
	ActorHref  string
	ActorRole  string // user | moderator | admin | cli
	Action     string // code with "." replaced by "_" (select value)
	TargetType string
	TargetID   string
	TargetHref string
	Label      string
	Reason     string
	Details    string
	Source     string
	Client     string
	Ray        string
}

// AdminUserView is the user page.
type AdminUserView struct {
	ID             string
	Handle         string
	DisplayName    string
	Role           string
	Status         string
	Until          Stamp // suspended until (empty Text: until lifted)
	Reason         string
	Joined         Stamp
	LastSeen       Stamp
	Full           bool
	Identities     []AdminIdentity
	Passkeys       int
	Sessions       int
	CommentCount   int
	Comments       []ModItem
	CommentsPager  *Pager
	ReportsAbout   []AdminReportRow
	AboutPager     *Pager
	ReportsFiled   []AdminReportRow
	FiledPager     *Pager
	Audit          []AdminAuditRow
	AuditPager     *Pager
	Self           bool
	Protected      bool // the target is an admin
	CanAct         bool
	Durations      []string
	Providers      []ProviderLink // re-verification panel
	Passkeys2      bool
	MaxReason      int
	ModeratorLimit bool
}

func reportState(x admin.ReportRow) string {
	if x.ResolvedAt == nil || x.Resolution == nil {
		return "open"
	}
	return *x.Resolution
}

func (u *UI) adminUser(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	id := strings.ToLower(r.PathValue("id"))
	if !admin.ValidID(id) {
		u.notFound(w, r, loc)
		return
	}
	full := a.IsAdmin(me)
	q := r.URL.Query()
	// four numbered lists: comments ?cp=, reports about ?rap=, reports filed ?rfp=, audit ?ap=
	d, err := a.UserDetail(r.Context(), id, full, admin.UserPages{Comments: pageParam(q, "cp"), About: pageParam(q, "rap"),
		Filed: pageParam(q, "rfp"), Audit: pageParam(q, "ap")})
	if errors.Is(err, admin.ErrNoUser) {
		u.notFound(w, r, loc)
		return
	}
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	t := d.User
	v := AdminUserView{ID: t.ID, Role: t.Role, Status: d.Status, Joined: instant(t.CreatedAt, stampLong), Full: full,
		CommentCount: d.CommentCount, Self: strings.EqualFold(t.ID, me.ID), Protected: t.Role == auth.RoleAdmin,
		Durations: admin.DurationOrder, MaxReason: auth.MaxSuspendReason, ModeratorLimit: !full}
	if t.Handle != nil {
		v.Handle = *t.Handle
	}
	if t.DisplayName != nil {
		v.DisplayName = plain(*t.DisplayName)
	}
	if d.Status == auth.StatusSuspended && t.SuspendedUntil != nil {
		v.Until = instant(*t.SuspendedUntil, stampLong)
	}
	if full {
		v.LastSeen = instant(t.LastSeenAt, stampLong)
		if d.Status == auth.StatusSuspended && t.StatusReason != nil {
			v.Reason = plain(*t.StatusReason)
		}
		v.CanAct = !v.Self && !v.Protected
		if acc := u.opts.Accounts.Current(); acc != nil {
			for _, p := range acc.Providers {
				v.Providers = append(v.Providers, ProviderLink{ID: p, Name: providerNames[p]})
			}
			v.Passkeys2 = acc.Passkeys
		}
		if s := d.Summary; s != nil {
			v.Passkeys, v.Sessions = s.Passkeys, s.ActiveSessions
			for _, i := range s.Identities {
				ai := AdminIdentity{Provider: providerNames[i.Provider], Subject: i.SubjectShort,
					Linked: instant(i.LinkedAt, stampShort), Used: instant(i.LastUsedAt, stampShort)}
				if ai.Provider == "" {
					ai.Provider = i.Provider
				}
				if i.Handle != nil {
					ai.Handle = plain(*i.Handle)
				}
				v.Identities = append(v.Identities, ai)
			}
		}
		for _, x := range d.ReportsFiled {
			v.ReportsFiled = append(v.ReportsFiled, u.reportRow(loc, x, "rf"))
		}
		v.Audit = u.auditRows(loc, d.Audit, "ua")
	}
	for _, c := range d.Comments {
		m := u.modItem(loc, c, nil)
		m.Pfx = "u"
		v.Comments = append(v.Comments, m)
	}
	for _, x := range d.ReportsAbout {
		v.ReportsAbout = append(v.ReportsAbout, u.reportRow(loc, x, "ra"))
	}
	links := newAdminLinks(loc.Path("/admin/users/"+t.ID), q, "cp", "rap", "rfp", "ap")
	v.CommentsPager = links.numbered(loc, d.CommentsW, "cp", "r-ucomments")
	v.AboutPager = links.numbered(loc, d.AboutW, "rap", "r-rabout")
	if full {
		v.FiledPager = links.numbered(loc, d.FiledW, "rfp", "r-rfiled")
		v.AuditPager = links.numbered(loc, d.AuditW, "ap", "r-uaudit")
	}
	title := v.Handle
	if title == "" {
		title = loc.Text("admin.user.no_handle")
	}
	tab := "users"
	if !full {
		tab = "moderation"
	}
	u.adminRender(w, r, loc, me, tab, "admin_user", title, v)
}

func (u *UI) reportRow(loc *i18n.Locale, x admin.ReportRow, pfx string) AdminReportRow {
	rr := AdminReportRow{Detail: "dt-" + pfx + "-" + x.ID, At: instant(x.CreatedAt, stampShort), Reason: x.Reason, State: reportState(x), Excerpt: plain(x.Excerpt),
		CVE: x.CVE, Permalink: loc.Path("/vuln/"+x.CVE) + "?" + discComment1 + "=" + x.CommentID + "#c-" + x.CommentID}
	if x.Note != nil {
		rr.Note = plain(*x.Note)
	}
	return rr
}

func (u *UI) auditRows(loc *i18n.Locale, rows []audit.Row, pfx string) []AdminAuditRow {
	var out []AdminAuditRow
	for _, x := range rows {
		ar := AdminAuditRow{Detail: "dt-" + pfx + "-" + strconv.FormatInt(x.ID, 10), At: instant(x.At, stampLong), ActorRole: x.ActorRole, Action: strings.ReplaceAll(x.Action, ".", "_"),
			TargetType: x.TargetType, TargetID: x.TargetID, Source: x.Source}
		if x.ActorHandle != nil {
			ar.Actor = plain(*x.ActorHandle)
		}
		if x.ActorID != nil {
			ar.ActorHref = loc.Path("/admin/users/" + *x.ActorID)
		}
		switch x.TargetType {
		case audit.TargetUser:
			if admin.ValidID(x.TargetID) {
				ar.TargetHref = loc.Path("/admin/users/" + x.TargetID)
			}
		case audit.TargetSetting:
			if _, ok := settings.Lookup(x.TargetID); ok {
				ar.TargetHref = loc.Path("/admin/settings") + "#s-" + x.TargetID
			} else {
				ar.TargetHref = loc.Path("/admin/settings")
			}
		case audit.TargetXAccount:
			// a github.repo.* row is stored under x_account (audit.GitHubRepoTarget)
			if strings.HasPrefix(x.Action, "github.repo.") && strings.HasPrefix(x.TargetID, audit.GitHubRepoTarget) {
				ar.TargetType, ar.TargetHref = "github_repo", loc.Path("/admin/github")
			}
			// and a github.owner.* row (audit.GitHubOwnerTarget)
			if strings.HasPrefix(x.Action, "github.owner.") && strings.HasPrefix(x.TargetID, audit.GitHubOwnerTarget) {
				ar.TargetType, ar.TargetHref = "github_owner", loc.Path("/admin/github")+"#owners"
			}
		case audit.TargetXDraft:
			if admin.ValidDraftID(x.TargetID) {
				ar.TargetHref = loc.Path("/admin/x/drafts") + "#d-" + x.TargetID
			}
		case audit.TargetCorrection:
			if admin.ValidID(x.TargetID) {
				ar.TargetHref = loc.Path("/admin/corrections") + "?state=decided#k-" + x.TargetID
			}
		case audit.TargetVuln:
			if id, ok := site.ParseVulnID(x.TargetID); ok && id == x.TargetID {
				ar.TargetHref = loc.Path("/admin/titles") + "?cve=" + id
			}
		case audit.TargetComment, audit.TargetReport:
			cve, _ := x.Details["cve"].(string)
			cid := x.TargetID
			if x.TargetType == audit.TargetReport {
				cid, _ = x.Details["comment_id"].(string)
			}
			if id, ok := site.ParseVulnID(cve); ok && id == cve && admin.ValidID(cid) {
				ar.TargetHref = loc.Path("/vuln/"+id) + "?" + discComment1 + "=" + cid + "#c-" + cid
			}
		}
		if x.TargetLabel != nil {
			ar.Label = plain(*x.TargetLabel)
		}
		if x.Reason != nil {
			ar.Reason = plain(*x.Reason)
		}
		if len(x.Details) > 0 {
			ar.Details = detailsText(x.Details)
		}
		if x.ClientAddr != nil {
			ar.Client = plain(*x.ClientAddr)
		}
		if x.CFRay != nil {
			ar.Ray = plain(*x.CFRay)
		}
		out = append(out, ar)
	}
	return out
}

// plain makes user-derived text safe to show as text: invalid UTF-8 and
// control characters (C0 except tab and newline, DEL, C1) become U+FFFD.
// html/template escapes markup; these characters are not markup but no page
// text may carry them (they break the pages' XML well-formedness and can
// hide or fake content in a terminal-style view).
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\t' && r != '\n' && unicode.IsControl(r) {
			return '\uFFFD'
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))
}

// isolate is plain text wrapped in <bdi>, for a message placeholder (a
// staff-entered reason may carry bidi controls; the CLI does not clean it).
func isolate(s string) template.HTML {
	return template.HTML("<bdi>" + template.HTMLEscapeString(plain(s)) + "</bdi>")
}

// detailsText renders the details object as key=value pairs (JSON values).
func detailsText(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		switch x := m[k].(type) {
		case nil:
			b.WriteString("null")
		case string:
			b.WriteString(strconv.Quote(x))
		case float64:
			b.WriteString(strconv.FormatFloat(x, 'f', -1, 64))
		case bool:
			b.WriteString(strconv.FormatBool(x))
		default: // a nested object, e.g. {"from": …, "to": …}
			j, err := json.Marshal(x)
			if err != nil || len(j) > 600 {
				b.WriteString("…")
			} else {
				b.WriteString(plain(string(j)))
			}
		}
	}
	return b.String()
}

// =============================================================== system

// AdminCollector is one collector row.
type AdminCollector struct {
	Public              bool // false: hidden from the public site (docs/xposts.md)
	Name, Status, Class string
	LastRun, LastOK     Stamp
	Error               string
	Detail              string // id of its detail row (the row pattern)
}

// AdminJob is one background job row (same columns as AdminCollector,
// plus the backlog).
type AdminJob struct {
	Name, Status, Class string
	LastRun, LastOK     Stamp
	Error               string
	Backlog             string // "" = none shown
	Detail              string // id of its detail row (the row pattern)
}

// AdminTable is one table row.
type AdminTable struct {
	Name, Rows, Size string
	Estimate         bool
}

// AdminLog is one error record.
type AdminLog struct {
	File, Time, Level, Msg, Attrs string
	Detail                        string // id of its detail row (the row pattern)
}

// AdminSystemView is the system page.
type AdminSystemView struct {
	Collectors   []AdminCollector
	Jobs         []AdminJob
	CollPager    *Pager
	TablesPager  *Pager
	LogsPager    *Pager
	LogsN        int // records read in all (every page)
	StateAt      template.HTML
	StateError   string
	Tables       []AdminTable
	DBSize       string
	StatsFiles   int
	StatsLines   string
	StatsBad     string
	StatsLast    template.HTML
	StatsFile    string
	LogsOff      bool
	LogsMissing  bool
	LogFiles     string
	Logs         []AdminLog
	LogsUnread   int
	LogsCut      bool
	Started      Stamp
	GoVersion    string
	BuildPath    string
	BuildVersion string
	Revision     string
	BuildTime    string
	Modified     bool
	Goroutines   string
	Pools        []AdminPool
}

// AdminPool is one pool row.
type AdminPool struct {
	Name, Size, InUse, Idle string
	Known                   bool
}

// bytesText is a byte count in binary units (language-neutral tokens).
func bytesText(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) + " " + string("KMGTPE"[exp]) + "iB"
}

func (u *UI) adminSystem(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	sys, err := u.opts.Admin.System(r.Context())
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminSystemView{DBSize: bytesText(sys.DBSize), StatsFiles: sys.Stats.Files, StatsLines: num(loc, sys.Stats.Lines),
		StatsBad: num(loc, sys.Stats.BadLines), StatsFile: sys.Stats.LastFile, LogsOff: !sys.Logs.Configured,
		LogsMissing: sys.Logs.Missing, LogsUnread: sys.Logs.Unreadable, LogsCut: sys.Logs.Cut,
		Started: instant(sys.Started, stampLong), GoVersion: sys.Build.GoVersion, BuildPath: sys.Build.Path,
		BuildVersion: sys.Build.Version, Revision: sys.Build.Revision, BuildTime: sys.Build.Time, Modified: sys.Build.Modified,
		Goroutines: num(loc, int64(sys.Goroutine))}
	if sys.Stats.LastRollup != nil {
		v.StatsLast = instant(*sys.Stats.LastRollup, stampLong).HTML()
	}
	// every collector, the non-public ones (xposts) included and marked
	for _, c := range sys.Collectors {
		ac := AdminCollector{Name: plain(c.Name), Status: loc.Text("collector.never_run"), Class: "weak",
			LastRun: Stamp{Text: "—"}, LastOK: Stamp{Text: "—"}, Public: c.Public}
		if c.Status != nil {
			ac.Status, ac.Class = plain(*c.Status), "warn"
			switch *c.Status {
			case "ok":
				ac.Class = "ok"
			case "error":
				ac.Class = "bad"
			}
		}
		if c.LastRunAt != nil {
			ac.LastRun = shortStamp(*c.LastRunAt)
		}
		if c.LastSuccessAt != nil {
			ac.LastOK = shortStamp(*c.LastSuccessAt)
		}
		if c.LastError != nil {
			ac.Error = plain(*c.LastError)
		}
		v.Collectors = append(v.Collectors, ac)
	}
	// the other background jobs (job_run): a job with no record yet is
	// neutral, not an error (an empty table right after a deploy)
	for i, j := range sys.Jobs {
		code := strings.ReplaceAll(j.Name, "-", "_")
		aj := AdminJob{Name: loc.Text("admin.sys.job", "job", code), Status: loc.Text("admin.sys.job_status", "status", j.Status),
			Class: "weak", LastRun: Stamp{Text: "—"}, LastOK: Stamp{Text: "—"}, Detail: "dt-j-" + strconv.Itoa(i)}
		switch j.Status {
		case "ok":
			aj.Class = "ok"
		case "error", "unfinished":
			aj.Class = "bad"
		case "stale", "running", "limited":
			aj.Class = "warn"
		}
		if j.StartedAt != nil {
			aj.LastRun = shortStamp(*j.StartedAt)
		}
		if j.LastSuccessAt != nil {
			aj.LastOK = shortStamp(*j.LastSuccessAt)
		}
		if j.Error != nil {
			aj.Error = plain(*j.Error)
		}
		if j.BacklogKind != "" {
			aj.Backlog = loc.Text("admin.sys.backlog", "kind", j.BacklogKind, "n", j.Backlog)
		}
		v.Jobs = append(v.Jobs, aj)
	}
	if src := sys.Sources; src != nil {
		v.StateAt = minuteHTML(src.StateRefreshedAt)
		v.StateError = plain(deref(src.StateError))
	}
	for _, t := range sys.Tables {
		row := AdminTable{Name: t.Name, Size: bytesText(t.Bytes), Estimate: !t.Exact}
		switch {
		case t.Rows < 0:
			row.Rows, row.Estimate = "—", false
		default:
			row.Rows = num(loc, t.Rows)
		}
		v.Tables = append(v.Tables, row)
	}
	v.LogFiles = strings.Join(sys.Logs.Files, ", ")
	for _, rec := range sys.Logs.Records {
		v.Logs = append(v.Logs, AdminLog{File: rec.File, Time: plain(rec.Time), Level: rec.Level, Msg: plain(rec.Msg), Attrs: plain(rec.Attrs)})
	}
	// three lists paged in memory: collectors ?cp=, tables ?tp=, log records ?lp= (pools: a few, never paged)
	q := r.URL.Query()
	links := newAdminLinks(loc.Path("/admin/system"), q, "cp", "tp", "lp")
	var cw, tw, lw admin.Window
	for i := range v.Collectors {
		v.Collectors[i].Detail = "dt-c-" + strconv.Itoa(i)
	}
	for i := range v.Logs {
		v.Logs[i].Detail = "dt-l-" + strconv.Itoa(i)
	}
	v.LogsN = len(v.Logs)
	v.Collectors, cw = memPage(v.Collectors, pageParam(q, "cp"))
	v.Tables, tw = memPage(v.Tables, pageParam(q, "tp"))
	v.Logs, lw = memPage(v.Logs, pageParam(q, "lp"))
	v.CollPager = links.numbered(loc, cw, "cp", "r-coll")
	v.TablesPager = links.numbered(loc, tw, "tp", "r-tables")
	v.LogsPager = links.numbered(loc, lw, "lp", "r-logs")
	for _, p := range sys.Pools {
		v.Pools = append(v.Pools, AdminPool{Name: p.Name, Size: strconv.Itoa(p.Size), InUse: strconv.Itoa(p.InUse),
			Idle: strconv.Itoa(p.Idle), Known: p.Known})
	}
	u.adminRender(w, r, loc, me, "system", "admin_system", loc.Text("admin.nav", "tab", "system"), v)
}

// ================================================================ audit

// AdminAuditView is the audit log page.
type AdminAuditView struct {
	Action, Actor, Target string
	Actions               []string // select values (codes with "_")
	Rows                  []AdminAuditRow
	Pager                 *Pager
}

func (u *UI) adminAudit(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	q := r.URL.Query()
	f := audit.Filter{ActorHandle: plain(strings.TrimSpace(q.Get("actor"))), TargetID: plain(strings.TrimSpace(q.Get("target")))}
	f.ActorHandle, f.TargetID = cutRunes(f.ActorHandle, 64), cutRunes(f.TargetID, 64)
	act := strings.ReplaceAll(q.Get("action"), "_", ".")
	for _, a := range audit.Actions {
		if a == act {
			f.Action = a
		}
	}
	// keyset on the id: ?before= older, ?after= newer, ?p= the page number
	id := func(k string) *int64 {
		n, err := strconv.ParseInt(q.Get(k), 10, 64)
		if err != nil || n <= 0 {
			return nil
		}
		return &n
	}
	rows, prev, next, err := u.opts.Admin.AuditLog(r.Context(), f, admin.Keyset[int64]{Older: id("before"), Newer: id("after")})
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	total, err := u.opts.Admin.AuditCount(r.Context(), f)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminAuditView{Action: strings.ReplaceAll(f.Action, ".", "_"), Actor: f.ActorHandle, Target: f.TargetID,
		Rows: u.auditRows(loc, rows, "a")}
	for _, a := range audit.Actions {
		v.Actions = append(v.Actions, strings.ReplaceAll(a, ".", "_"))
	}
	idText := func(p *int64) string {
		if p == nil {
			return ""
		}
		return strconv.FormatInt(*p, 10)
	}
	links := newAdminLinks(loc.Path("/admin/audit"), q, "p")
	links.set("before", idText(id("before")))
	links.set("after", idText(id("after")))
	links.set("action", v.Action)
	links.set("actor", f.ActorHandle)
	links.set("target", f.TargetID)
	v.Pager = links.keyset(loc, "r-audit", "before", "after", "p", idText(prev), idText(next), total)
	u.adminRender(w, r, loc, me, "audit", "admin_audit", loc.Text("admin.nav", "tab", "audit"), v)
}

// cutRunes returns s as valid UTF-8, at most n runes long. Filters from the
// query string go to PostgreSQL as text: a byte cut could split a character
// and make the query fail (invalid byte sequence).
func cutRunes(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
