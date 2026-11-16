package webui

import (
	"net/http"
	"strconv"
	"time"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
	"nday.land/nday/internal/xdraft"
)

// /admin/x/drafts: draft posts for the brand X account (docs/admin.md,
// docs/xposts.md). Admin only. The drafts are never public: no public
// page, feed, sitemap or API reads x_draft (TestPostsNotPublic stores some).
// Publishing is the admin's own click on a plain link to X's web compose
// intent (xdraft.ComposeURL, new tab); the server never calls X.

// AdminXDraft is one draft.
type AdminXDraft struct {
	ID          string
	Version     int
	Code        string // POC | ITW | KEV
	CodeClass   string
	CVE         string
	CVEHref     string // the public detail page (this locale)
	Created     Stamp
	Body        string
	Length      int // weighted, with the link
	Over        bool
	Compose     string // X's compose intent with body + "\n" + the absolute detail URL
	Status      string // posted | discarded (history)
	PostURL     string
	By          string // handle ("" when the account has none)
	ByHref      string // the decider's user page ("" when the account is gone)
	Decided     Stamp
	Discarded   bool
	PostedNoURL bool
}

// AdminXDraftsView is the drafts page.
type AdminXDraftsView struct {
	Pending   []AdminXDraft
	Total     int
	Capped    bool
	History   []AdminXDraft
	HistTotal int    // decided drafts in all
	Page      int    // 1-based history page after clamping
	Pages     int    // history pages (≥ 1)
	HistPrev  string // pager links ("" when there is none)
	HistNext  string
	Max       int // X's weighted maximum
	LinkCost  int // "\n" + a link
	HasRun    bool
	RunAt     Stamp
	Created   int64
	Cands     int64
	Carried   int64
	SkipCap   int64 // dropped for good: over the cap in a bulk change
	SkipOld   int64 // dropped for good: older than xdraft.MaxEventAge
	Deferred  bool  // a later pass found the event table busy
	DeferAt   Stamp
	Providers []ProviderLink
	Passkeys2 bool
}

func (u *UI) adminXDrafts(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	// ?page=N pages the history; anything that is not a positive number is page 1
	hpage, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pending, total, history, run, err := a.XDraftList(r.Context(), hpage)
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminXDraftsView{Total: total, Capped: total > len(pending), Max: xdraft.MaxWeighted, LinkCost: xdraft.LinkCost}
	row := func(d admin.XDraft) AdminXDraft {
		code := site.StageCode(d.Stage)
		x := AdminXDraft{ID: strconv.FormatInt(d.ID, 10), Version: d.Version, Code: code, CodeClass: StageClass(code),
			CVE: d.CVE, Created: instant(d.CreatedAt, stampLong), Body: plain(d.Body), Status: d.Status, By: plain(d.DecidedBy)}
		if id, ok := site.ParseCVEID(d.CVE); ok && id == d.CVE {
			x.CVEHref = loc.Path("/vuln/" + id)
			// the post links the English page (the root path)
			link := u.opts.BaseURL + u.locales.Primary().Path("/vuln/"+id)
			x.Compose = xdraft.ComposeURL(d.Body, link)
		}
		x.Length = xdraft.WeightedLength(d.Body) + xdraft.LinkCost
		x.Over = x.Length > xdraft.MaxWeighted
		if n, ok := xdraft.NormalizePostURL(d.PostURL); ok && n == d.PostURL {
			x.PostURL = n
		}
		if d.DecidedUID != "" && admin.ValidID(d.DecidedUID) {
			x.ByHref = loc.Path("/admin/users/" + d.DecidedUID)
		}
		if d.DecidedAt != nil {
			x.Decided = instant(*d.DecidedAt, stampLong)
		}
		x.Discarded = d.Status == admin.DraftDiscarded
		x.PostedNoURL = d.Status == admin.DraftPosted && x.PostURL == ""
		return x
	}
	for _, d := range pending {
		v.Pending = append(v.Pending, row(d))
	}
	for _, d := range history.Rows {
		v.History = append(v.History, row(d))
	}
	v.HistTotal, v.Page, v.Pages = history.Total, history.Page, history.Pages
	histHref := func(p int) string {
		h := loc.Path("/admin/x/drafts")
		if p > 1 {
			h += "?page=" + strconv.Itoa(p)
		}
		return h + "#history"
	}
	if v.Page > 1 {
		v.HistPrev = histHref(v.Page - 1)
	}
	if v.Page < v.Pages {
		v.HistNext = histHref(v.Page + 1)
	}
	if run.LastRunAt != nil {
		v.HasRun, v.RunAt = true, instant(*run.LastRunAt, stampLong)
		num := func(k string) int64 {
			f, _ := run.Summary[k].(float64)
			return int64(f)
		}
		v.Created, v.Cands = num("created"), num("candidates")
		v.Carried, v.SkipCap, v.SkipOld = num("carried"), num("skipped_cap"), num("skipped_old")
	}
	if at, ok := run.Summary["deferred_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, at); err == nil {
			v.Deferred, v.DeferAt = true, instant(t, stampLong)
		}
	}
	if acc := u.opts.Accounts.Current(); acc != nil {
		for _, p := range acc.Providers {
			v.Providers = append(v.Providers, ProviderLink{ID: p, Name: providerNames[p]})
		}
		v.Passkeys2 = acc.Passkeys
	}
	u.adminRender(w, r, loc, me, "xdrafts", "admin_xdrafts", loc.Text("admin.nav", "tab", "xdrafts"), v)
}
