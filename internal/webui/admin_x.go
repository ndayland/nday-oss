package webui

import (
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
	"nday.land/nday/internal/xconfig"
)

// /admin/x: the X posts collector (docs/xposts.md, docs/admin.md). Admin
// only, like every page here; posts and the xposts health never reach a
// public page (internal/site/public.go), this page is the staff exception.
// The bearer token is never read here: the page only says whether the
// admin service can look handles up (admin.Service.XLookupAvailable); the
// status comes from the cursor the collector wrote.

// AdminXField is one numeric setting of the form.
type AdminXField struct {
	Name           string // max_posts …
	Value          string // stored value, "" when default
	Default        int
	Min, Max       int
	Effective      int
	UsesDefault    bool
	EffectiveIsSet bool
}

// AdminXAccount is one allowlisted account. The user id is never shown:
// it is in data attributes only, for the actions.
type AdminXAccount struct {
	UserID   string
	Handle   string
	Href     string // https://x.com/<handle> when the handle is valid
	Name     string // the display name on X ("" not known)
	Bio      string // the profile description on X ("" not known or empty)
	Detail   string // id of its detail row (the row pattern)
	Note     string
	Enabled  bool
	State    string // on | off
	Created  Stamp
	Updated  Stamp
	Posts    string
	FormNote string // the note for the edit form
	// GitHub: the trusted GitHub accounts linked to it (admin only; a
	// small marker next to the handle)
	GitHub []AdminXGitHub
}

// AdminXGitHub is a trusted GitHub account linked to an X account.
type AdminXGitHub struct {
	Login, Href string // Href: the trusted accounts on /admin/github
}

// AdminXPost is one collected post.
type AdminXPost struct {
	At       Stamp
	Seen     Stamp
	Handle   string
	Profile  string // https://x.com/<handle> ("" when the handle is not valid)
	Text     string
	Lang     string
	URL      string // the post on X ("" when not of the expected form)
	CVEs     []Link
	AuthorID string
}

// AdminXCandidate is one allowlist candidate (xconfig.Candidate).
type AdminXCandidate struct {
	UserID    string
	Label     string // id of the cell that names the row (its checkbox's label)
	Handle    string // "" when the stored handle is missing or not valid
	Href      string // https://x.com/<handle> when Handle is set
	Referrers string
	Kinds     []string // quoted | replied_to | mentioned
	LastSeen  Stamp
}

// AdminXCandTable is one candidates table: Open (add, dismiss) or the
// dismissed ones (restore).
type AdminXCandTable struct {
	Rows   []AdminXCandidate
	Open   bool
	State  string // the rows' status as rendered (xconfig.CandidatePending, CandidateDismissed)
	Region string // r-xcand, r-xcand-dismissed
	Pager  *Pager
	Bulk   *BulkBar
}

// AdminXCount is posts per author.
type AdminXCount struct {
	AuthorID, Handle, Profile, Posts string
}

// AdminXView is the X page.
type AdminXView struct {
	// status
	Exists                         bool
	Status, StatusClass            string
	LastRun, LastOK                Stamp
	Error                          string
	RunAt                          Stamp
	HasRun                         bool
	Skipped, Mode, Stopped         string
	StopInfo, SinceID              string
	Posts, Kept, KeptNoCVE         string
	DroppedAuthor, Requests        string
	Accounts, Batches, BatchesDone string
	// cost
	Price                       string // $ per post
	LastCost                    string
	WorstPosts                  string
	WorstRun, WorstDay, Worst30 string
	RunsPerDay, PostsPerPage    int
	PriceRaw                    string
	// settings
	Enabled        string // "default" | "on" | "off"
	EnabledEff     bool
	Fields         []AdminXField
	SettingsAt     Stamp
	SettingsStored bool
	Warnings       []string
	// allowlist
	List     []AdminXAccount // the current page
	Total    int             // every account (the status counts)
	EnabledN int             // enabled among every account
	MaxNote  int
	Lookup   bool // handles can be looked up (a token is configured; nothing else about it is known here)
	// allowlist search and paging (?q=&page=)
	Q           string        // the normalised search term ("" = no search)
	QHTML       template.HTML // Q in <bdi>, for messages
	Matched     int           // accounts whose handle contains Q (Total when Q is "")
	Page, Pages int           // 1-based page after clamping; page count (≥ 1)
	From, To    int           // 1-based positions of the first and last row shown
	AccPager    *Pager        // the allowlist's pager (nil on one page)
	AccClear    string        // the page without the search (other filters kept)
	AccKeep     []KV          // hidden inputs of the search form (the other lists' positions, the posts filters)
	// allowlist candidates (numbered, ?cp= open, ?dp= dismissed)
	Cands, CandsDismissed AdminXCandTable
	CandN, CandDismissedN int // totals
	DismissedOpen         bool
	// posts (keyset: ?before= older, ?after= newer, ?pp= its page number)
	Author, CVE string
	PostKeep    []KV // hidden inputs of the posts filter form
	PostList    []AdminXPost
	PostsPager  *Pager
	Chart       DayChart
	PerAccount  []AdminXCount // posts per author, paged in memory (?ap=)
	PerPager    *Pager
	// re-verification panel
	Providers []ProviderLink
	Passkeys2 bool
}

var xLangRe = regexp.MustCompile(`^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})?$`)

var xPostURLRe = regexp.MustCompile(`^https://x\.com/(?:[A-Za-z0-9_]{1,15}|i/web)/status/[0-9]{1,20}$`)

// xProfile is the profile URL of a handle that passes xconfig.ValidHandle
// ("" otherwise: the handle is shown as text only).
func xProfile(handle string) string {
	if !xconfig.ValidHandle(handle) {
		return ""
	}
	return "https://x.com/" + handle
}

// xCandKinds are the reference kinds a candidate row may show (the
// select values of admin.x.cand_kind).
var xCandKinds = map[string]bool{"quoted": true, "replied_to": true, "mentioned": true}

// xCandRows turns candidates into rows: the handle (upstream text) only
// when it passes xconfig.ValidHandle, unknown kinds dropped.
func xCandRows(loc *i18n.Locale, cs []xconfig.Candidate) []AdminXCandidate {
	var out []AdminXCandidate
	for _, c := range cs {
		row := AdminXCandidate{UserID: c.UserID, Referrers: num(loc, int64(c.Referrers)), LastSeen: instant(c.LastSeenAt, stampShort)}
		if c.Handle != nil && xconfig.ValidHandle(*c.Handle) {
			row.Handle, row.Href = *c.Handle, xProfile(*c.Handle)
		}
		for _, k := range c.Kinds {
			if xCandKinds[k] {
				row.Kinds = append(row.Kinds, k)
			}
		}
		out = append(out, row)
	}
	return out
}

// usd formats dollars with cents ("$2.50"; language-neutral token).
func usd(v float64) string { return "$" + strconv.FormatFloat(v, 'f', 2, 64) }

func i64(p *int64) string {
	if p == nil {
		return "—"
	}
	return strconv.FormatInt(*p, 10)
}

// xSearchMax is the longest allowlist search term kept, in characters.
const xSearchMax = 32

// xSearchTerm normalises ?q=: control characters made visible (plain),
// spaces trimmed, one leading '@' dropped, at most xSearchMax characters.
func xSearchTerm(s string) string {
	s = strings.TrimSpace(plain(s))
	s = strings.TrimSpace(strings.TrimPrefix(s, "@"))
	if rs := []rune(s); len(rs) > xSearchMax {
		s = strings.TrimSpace(string(rs[:xSearchMax]))
	}
	return s
}

// xPageParam parses ?page=: anything but a plain number from 1 up to
// 999999 is page 1 (the service clamps it to the last page).
func xPageParam(s string) int {
	if len(s) > 6 {
		return 1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// xParams are the query parameters of /admin/x: the accounts search and
// page, the candidates' pages, the posts filters and position, the
// per-account page.
var xParams = []string{"q", "page", "cp", "dp", "author", "cve", "before", "after", "pp", "ap"}

func (u *UI) adminX(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	ctx := r.Context()
	run, err := a.XStatus(ctx)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	cfg, err := a.XConfig(ctx)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	q := r.URL.Query()
	author := strings.TrimPrefix(plain(strings.TrimSpace(q.Get("author"))), "@")
	if !xconfig.ValidHandle(author) {
		author = "" // an invalid handle matches nothing anyway
	}
	cve := ""
	if id, ok := site.ParseVulnID(strings.TrimSpace(q.Get("cve"))); ok {
		cve = id
	}
	pos := admin.Keyset[admin.Cursor]{Older: admin.DecodeXCursor(q.Get("before")), Newer: admin.DecodeXCursor(q.Get("after"))}
	postsN, err := a.XPostsCount(ctx, author, cve)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	pp := pageIndex(q.Get("pp")) // the posts' page number: labels a position, or picks a first or last page
	if pos.Older == nil && pos.Newer == nil {
		pp = keysetJump(&pos, pp, postsN)
	}
	posts, prev, next, err := a.XPosts(ctx, author, cve, pos)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	daily, per, err := a.XStats(ctx)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	term := xSearchTerm(q.Get("q"))
	accs, err := a.XAccounts(ctx, term, xPageParam(q.Get("page")))
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	cands, err := a.XCandidates(ctx, pageParam(q, "cp"), pageParam(q, "dp"))
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminXView{Exists: run.Exists, Status: loc.Text("collector.never_run"), StatusClass: "weak",
		LastRun: Stamp{Text: "—"}, LastOK: Stamp{Text: "—"}, Error: plain(run.LastError), HasRun: run.HasLastRun,
		Skipped: run.Skipped, Mode: plain(run.Mode), Stopped: plain(run.Stopped), StopInfo: plain(run.StopInfo),
		SinceID: plain(run.SinceID), Posts: i64(run.Posts), Kept: i64(run.Kept), KeptNoCVE: i64(run.KeptNoCVE),
		DroppedAuthor: i64(run.DroppedAuthor), Requests: i64(run.Requests), Accounts: i64(run.Accounts),
		Batches: i64(run.Batches), BatchesDone: i64(run.BatchesDone), MaxNote: xconfig.MaxNoteLen, Lookup: a.XLookupAvailable(),
		RunsPerDay: admin.XRunsPerDay, PostsPerPage: admin.XPostsPerPage, Author: author, CVE: cve,
		Price: "$" + strconv.FormatFloat(admin.XPricePerPostUSD, 'f', -1, 64), PriceRaw: strconv.FormatFloat(admin.XPricePerPostUSD, 'f', -1, 64)}
	if run.Status != "" {
		v.Status, v.StatusClass = plain(run.Status), "warn"
		switch run.Status {
		case "ok":
			v.StatusClass = "ok"
		case "error":
			v.StatusClass = "bad"
		}
	}
	if run.LastRunAt != nil {
		v.LastRun = instant(*run.LastRunAt, stampLong)
	}
	if run.LastSuccessAt != nil {
		v.LastOK = instant(*run.LastSuccessAt, stampLong)
	}
	if t, err := time.Parse(time.RFC3339, run.At); err == nil {
		v.RunAt = instant(t, stampLong)
	} else {
		v.RunAt = Stamp{Text: "—"}
	}
	switch v.Skipped {
	case "", "no_token", "no_accounts", "disabled":
	default:
		v.Skipped = "other"
	}
	// cost (docs/xposts.md: $0.005 per post read)
	if run.Posts != nil {
		v.LastCost = usd(float64(*run.Posts) * admin.XPricePerPostUSD)
	}
	eff := cfg.Effective
	worst := admin.XWorstPostsPerRun(eff)
	v.WorstPosts = num(loc, int64(worst))
	perRun := float64(worst) * admin.XPricePerPostUSD
	v.WorstRun, v.WorstDay, v.Worst30 = usd(perRun), usd(perRun*admin.XRunsPerDay), usd(perRun*admin.XRunsPerDay*30)
	// settings
	st := cfg.Stored
	v.Enabled, v.EnabledEff = "default", eff.Enabled
	if st.Enabled != nil {
		v.Enabled = map[bool]string{true: "on", false: "off"}[*st.Enabled]
	}
	stored := map[string]*int{"max_posts": st.MaxPosts, "max_requests": st.MaxRequests, "bootstrap_days": st.BootstrapDays,
		"max_query_length": st.MaxQueryLength}
	effective := map[string]int{"max_posts": eff.MaxPosts, "max_requests": eff.MaxRequests, "bootstrap_days": eff.BootstrapDays,
		"max_query_length": eff.MaxQueryLength}
	for _, b := range xconfig.Bounds {
		f := AdminXField{Name: b.Name, Default: b.Default, Min: b.Min, Max: b.Max, Effective: effective[b.Name], UsesDefault: true}
		if p := stored[b.Name]; p != nil {
			f.Value, f.UsesDefault = strconv.Itoa(*p), false
		}
		v.Fields = append(v.Fields, f)
	}
	if st.UpdatedAt != nil {
		v.SettingsStored, v.SettingsAt = true, instant(*st.UpdatedAt, stampLong)
	}
	for _, wn := range cfg.Warnings {
		v.Warnings = append(v.Warnings, plain(wn))
	}
	// allowlist
	postsBy := map[string]int64{}
	for _, c := range per {
		postsBy[c.AuthorID] = c.Posts
	}
	v.Total = len(cfg.Accounts) // the status counts every account, whatever page is shown
	for _, x := range cfg.Accounts {
		if x.Enabled {
			v.EnabledN++
		}
	}
	var ids []string
	for _, x := range accs.Accounts {
		ids = append(ids, x.UserID)
	}
	gh, err := a.GitHubOwnersOfX(ctx, ids)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	for _, x := range accs.Accounts {
		row := AdminXAccount{UserID: x.UserID, Handle: plain(x.Handle), Href: xProfile(x.Handle), Note: plain(x.Note),
			Name: plain(deref(x.Name)), Bio: plain(deref(x.Description)), Detail: "dt-xa-" + x.UserID,
			FormNote: plain(x.Note), Enabled: x.Enabled, Created: instant(x.CreatedAt, stampShort), Updated: instant(x.UpdatedAt, stampShort),
			Posts: num(loc, postsBy[x.UserID])}
		row.State = "off"
		if x.Enabled {
			row.State = "on"
		}
		for _, o := range gh[x.UserID] {
			if ghrepo.ValidLogin(o.Login) {
				row.GitHub = append(row.GitHub, AdminXGitHub{Login: o.Login, Href: loc.Path("/admin/github") + "#owners"})
			}
		}
		v.List = append(v.List, row)
	}
	v.Q, v.QHTML, v.Matched, v.Page, v.Pages = term, isolate(term), accs.Matched, accs.Page, accs.Pages
	if len(v.List) > 0 {
		v.From = (accs.Page-1)*admin.XAccountsPage + 1
		v.To = v.From + len(v.List) - 1
	}
	links := newAdminLinks(loc.Path("/admin/x"), q, xParams...)
	links.set("q", term)
	links.set("page", pageStr(v.Page))
	links.set("author", author)
	links.set("cve", cve)
	links.set("before", admin.EncodeXCursor(pos.Older)) // a position that does not decode is dropped
	links.set("after", admin.EncodeXCursor(pos.Newer))
	links.set("pp", pageStr(pp))
	// candidates
	cand := func(rows []xconfig.Candidate, open bool, param, region string, w admin.Window) AdminXCandTable {
		t := AdminXCandTable{Rows: xCandRows(loc, rows), Open: open, State: xconfig.CandidateDismissed, Region: region}
		if open {
			t.State = xconfig.CandidatePending
		}
		for i := range t.Rows {
			t.Rows[i].Label = "lb-" + region + "-" + t.Rows[i].UserID
		}
		t.Pager = links.numbered(loc, w, param, region)
		if open {
			t.Bulk = newBulkBar("xcand", []BulkAction{{Act: "add", Label: loc.Text("admin.x.cand_add")},
				{Act: "dismiss", Label: loc.Text("admin.x.cand_dismiss"), Danger: true}})
		} else {
			t.Bulk = newBulkBar("xcand", []BulkAction{{Act: "restore", Label: loc.Text("admin.x.cand_restore")}})
		}
		return t
	}
	v.Cands = cand(cands.Open, true, "cp", "r-xcand", cands.OpenW)
	v.CandsDismissed = cand(cands.Dismissed, false, "dp", "r-xcand-dismissed", cands.DismissedW)
	v.CandN, v.CandDismissedN = cands.OpenN, cands.DismissedN
	v.DismissedOpen = q.Get("dp") != ""
	// posts
	for _, p := range posts {
		ap := AdminXPost{Seen: instant(p.ObservedAt, stampShort), At: Stamp{Text: "—"}, Handle: plain(p.Handle), Profile: xProfile(p.Handle),
			Text: plain(p.Text), AuthorID: plain(p.AuthorID)}
		if xLangRe.MatchString(p.Lang) {
			ap.Lang = p.Lang
		}
		if p.At != nil {
			ap.At = instant(*p.At, stampLong)
		}
		if xPostURLRe.MatchString(p.URL) {
			ap.URL = p.URL
		}
		for _, c := range p.CVEs {
			if id, ok := site.ParseVulnID(c); ok && id == c {
				ap.CVEs = append(ap.CVEs, Link{Text: id, Href: loc.Path("/vuln/" + id)})
			} else {
				ap.CVEs = append(ap.CVEs, Link{Text: plain(c)})
			}
		}
		v.PostList = append(v.PostList, ap)
	}
	v.PostsPager = links.keyset(loc, "r-posts", "before", "after", "pp", admin.EncodeXCursor(prev), admin.EncodeXCursor(next), postsN)
	v.PostKeep = links.hidden("author", "cve", "before", "after", "pp")
	// accounts pager and the clear link
	v.AccPager = numberedPager(loc, v.Page, v.Pages, func(p int) string { return links.href("r-accounts", "page", pageStr(p)) })
	if term != "" {
		v.AccClear = links.href("r-accounts", "q", "", "page", "")
	}
	v.AccKeep = links.hidden("q", "page")
	v.Chart = buildDayChart(loc, "ch-x", "x_posts", false, []chartSeries{{"s1", "x_posts", daily}})
	for _, c := range per {
		v.PerAccount = append(v.PerAccount, AdminXCount{AuthorID: plain(c.AuthorID), Handle: plain(c.Handle), Profile: xProfile(c.Handle),
			Posts: num(loc, c.Posts)})
	}
	var pw admin.Window
	v.PerAccount, pw = memPage(v.PerAccount, pageParam(q, "ap"))
	v.PerPager = links.numbered(loc, pw, "ap", "r-xper")
	if acc := u.opts.Accounts.Current(); acc != nil {
		for _, p := range acc.Providers {
			v.Providers = append(v.Providers, ProviderLink{ID: p, Name: providerNames[p]})
		}
		v.Passkeys2 = acc.Passkeys
	}
	u.adminRender(w, r, loc, me, "x", "admin_x", loc.Text("admin.nav", "tab", "x"), v)
}
