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
	ID        string
	Label     string // id of the element that names the draft (its checkbox's label)
	Version   int
	Code      string // POC | ITW | KEV
	CodeClass string
	CVE       string
	CVEHref   string // the public detail page (this locale)
	Created   Stamp
	Body      string
	Length    int // weighted, with the link
	Over      bool
	Compose   string // X's compose intent with body + "\n" + the absolute detail URL
	// the image forms (docs/xposts.md "Forms"): the compose intent with the
	// body alone, its weighted length (no link), the address card and its
	// download name, and the link for the reply
	ComposeAlone string
	LengthAlone  int
	OverAlone    bool
	Card         string
	CardName     string
	Link         string
	Form         string // posted drafts: the form used ("" = not recorded)
	Status       string // posted | discarded (history)
	PostURL      string
	By           string // handle ("" when the account has none)
	ByHref       string // the decider's user page ("" when the account is gone)
	Decided      Stamp
	Discarded    bool
	PostedNoURL  bool
}

// AdminXDraftsView is the drafts page.
type AdminXDraftsView struct {
	Pending   []AdminXDraft
	Total     int    // pending drafts in all
	PendPager *Pager // pending drafts: numbered, ?dp=
	Bulk      *BulkBar
	History   []AdminXDraft
	HistTotal int    // decided drafts in all
	Page      int    // 1-based history page after clamping
	Pages     int    // history pages (≥ 1)
	HistPager *Pager // nil on one page
	Max       int    // X's weighted maximum
	LinkCost  int    // "\n" + a link
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
	// two numbered lists: ?dp= the pending drafts, ?page= the history
	q := r.URL.Query()
	pending, pw, history, run, err := a.XDraftList(r.Context(), pageParam(q, "dp"), pageParam(q, "page"))
	if err != nil {
		u.adminFail(w, r, loc, err)
		return
	}
	v := AdminXDraftsView{Total: pw.Total, Max: xdraft.MaxWeighted, LinkCost: xdraft.LinkCost,
		Bulk: newBulkBar("xd", []BulkAction{{Act: "discard", Label: loc.Text("admin.xd.discard"), Danger: true}})}
	row := func(d admin.XDraft) AdminXDraft {
		code := site.StageCode(d.Stage)
		x := AdminXDraft{ID: strconv.FormatInt(d.ID, 10), Version: d.Version, Code: code, CodeClass: StageClass(code),
			CVE: d.CVE, Created: instant(d.CreatedAt, stampLong), Body: plain(d.Body), Status: d.Status, By: plain(d.DecidedBy)}
		if id, ok := site.ParseVulnID(d.CVE); ok && id == d.CVE {
			x.CVEHref = loc.Path("/vuln/" + id)
			// the post links the English page (the root path)
			link := stageLink(u.canonURL(u.locales.Primary(), "/vuln/"+id), d.Stage)
			x.Compose = xdraft.ComposeURL(d.Body, link)
			x.ComposeAlone = xdraft.ComposeTextURL(d.Body)
			x.Card, x.CardName, x.Link = addrCardPath(id), id+"-nday.png", link
		}
		x.Length = xdraft.WeightedLength(d.Body) + xdraft.LinkCost
		x.Over = x.Length > xdraft.MaxWeighted
		x.LengthAlone = xdraft.WeightedLength(d.Body)
		x.OverAlone = !xdraft.FitsAlone(d.Body)
		if xdraft.ValidForm(d.Form) {
			x.Form = d.Form
		}
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
		x := row(d)
		x.Label = "lb-xd-" + x.ID
		v.Pending = append(v.Pending, x)
	}
	for _, d := range history.Rows {
		v.History = append(v.History, row(d))
	}
	v.HistTotal, v.Page, v.Pages = history.Total, history.Page, history.Pages
	links := newAdminLinks(loc.Path("/admin/x/drafts"), q, "dp", "page")
	v.PendPager = links.numbered(loc, pw, "dp", "r-xdpending")
	v.HistPager = links.numbered(loc, admin.Window{Page: v.Page, Pages: v.Pages, Total: v.HistTotal}, "page", "r-xdhistory")
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
