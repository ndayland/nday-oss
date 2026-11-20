package webui

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// Discussions on vulnerability pages (docs/discuss.md section 9).
//
// The page is the same for every visitor (publicly cacheable; nothing here
// reads a cookie) and holds NO comment content: only the outline
// (discuss.Service.Outline: how many comments, and per comment of the
// first page its status and a coarse size class), drawn as "tadpole
// script" speckle (static/app.js; data-size only).
//
// Signed-out reading (discuss.Service.GuestRead, NDAY_DISCUSS_GUEST_READ,
// on by default) only changes what the page says under the outline, the
// same for every visitor: on, the outline is a placeholder while
// static/discuss.js loads the comments for everyone, signed in or not;
// off, it carries a call to sign in and only signed-in visitors get the
// comments. Either way discuss.js asks GET /api/discuss/{cve} (no-store)
// and renders the comments in place of the outline (DOM methods only, from
// body_nodes), with the writing controls the caller may use.
//
// Caching: the outline is cached in the server cache under a key that holds
// Version(cve). Version is itself memoised per CVE for discVersionTTL, so a
// visitor sees a change at most discVersionTTL late (plus the page's own
// Cache-Control max-age in browsers and shared caches). After a write the
// script reloads the page with ?fresh=…, which looks Version up again at
// most once per CVE per discFreshEvery.

// Discussions is what the pages use of discuss.Service.
type Discussions interface {
	Outline(ctx context.Context, cve string) (*discuss.Outline, error)
	// OutlinePage is the outline of numbered page page (clamped); Locate
	// says where a visible comment is (Position.Index): ?c= picks the page.
	OutlinePage(ctx context.Context, cve string, page, per int) (*discuss.Outline, error)
	Locate(ctx context.Context, cve, id string) (*discuss.Position, error)
	Version(ctx context.Context, cve string) (string, error)
	// GuestRead: signed-out visitors may read the comments (the API gives
	// them the comments, not only the outline).
	GuestRead() bool
}

// DiscussionsOf returns s as Discussions (nil service: nil, discussions off).
func DiscussionsOf(s *discuss.Service) Discussions {
	if s == nil {
		return nil
	}
	return s
}

const (
	discVersionTTL = 10 * time.Second // worst-case staleness of the outline on the server
	discFreshEvery = time.Second      // ?fresh= looks Version up at most this often per CVE
	discFreshParam = "fresh"          // throw-away parameter of discuss.js after a write
	discComment1   = "c"              // permalink of one comment (?c=<id>#c-<id>; discuss.js shows its page)
)

// reportReasons are the report reasons of POST /api/discuss/comment/{id}/report.
var reportReasons = []string{"spam", "abuse", "off_topic", "misinformation", "malicious_link", "illegal", "other"}

// mdSyntax is the Markdown cheat-sheet (docs/discuss.md section 6): the
// syntax shown (language-neutral) and the key that explains it.
var mdSyntax = []Hint{
	{"↵↵", "disc.md.paragraph"}, {"↵", "disc.md.break"},
	{"*…*", "disc.md.em"}, {"**…**", "disc.md.strong"}, {"`…`", "disc.md.code"},
	{"```", "disc.md.fence"}, {"> …", "disc.md.quote"}, {"- …", "disc.md.list"}, {"1. …", "disc.md.olist"},
	{"[…](https://…)", "disc.md.link"}, {"https://…", "disc.md.autolink"}, {"CVE-2026-1234", "disc.md.cve"},
	{"\\*", "disc.md.escape"},
}

// discKeys are the messages discuss.js needs (rendered into the page's
// <template id="acct-msgs"> next to the account messages).
var discKeys = []string{"disc.busy", "disc.delete_confirm", "disc.hidden_reason", "disc.mod.source", "disc.mod.revisions", "disc.mod.revision_at",
	"disc.terms.needed", "disc.terms.updated", "disc.report.done", "disc.report.already",
	"disc.err.not_signed_in", "disc.err.cross_site", "disc.err.csrf", "disc.err.suspended", "disc.err.handle_required",
	"disc.err.terms_required", "disc.err.forbidden", "disc.err.not_author", "disc.err.own_comment", "disc.err.wrong_status",
	"disc.err.not_found", "disc.err.bad_cve", "disc.err.bad_parent", "disc.err.thread_full", "disc.err.duplicate",
	"disc.err.invalid_body", "disc.err.bad_lang", "disc.err.bad_purpose", "disc.err.bad_reason", "disc.err.bad_note", "disc.err.bad_resolution",
	"disc.err.bad_cursor", "disc.err.bad_request", "disc.err.too_large", "disc.err.rate_limited",
	"disc.err.rate_limited_later", "disc.err.daily_limit", "disc.err.busy", "disc.err.wrong_host", "disc.err.internal",
	"disc.err.network", "disc.err.terms_version_mismatch", "disc.err.empty", "disc.err.too_long",
	"disc.err.terms_unchecked", "disc.err.generic",
	// rendering the comments of a signed-in visitor
	"disc.empty", "disc.unavailable", "disc.more", "disc.first", "disc.more_replies", "disc.replies_label",
	"disc.comment.deleted_account", "disc.comment.permalink", "disc.comment.edited", "disc.comment.lang",
	"disc.comment.hidden", "disc.comment.deleted",
	// purposes of top-level comments (select messages: every variant)
	"disc.purpose", "disc.purpose_hint"}

// discPurposes are the purposes a top-level comment may declare
// (discuss.Purposes), in the order of the drop-down.
var discPurposes = discuss.Purposes

// rschKeys are the messages discuss.js needs for the researcher section.
var rschKeys = []string{"rsch.more", "rsch.view_on_x", "rsch.failed", "rsch.empty", "rsch.expand", "rsch.collapse"}

// DiscView is the discussion section of a vulnerability page.
type DiscView struct {
	CVE     string
	Locale  string // page locale tag (the lang of new comments)
	Count   int    // visible comments of the vulnerability (all pages)
	Failed  bool   // the outline could not be loaded
	Threads []DiscShape
	More    bool   // threads beyond the outline exist
	Page    int    // number of the page shown (discuss.js loads the same one)
	Pager   *Pager // nil: one page
	Write   bool   // accounts are on: sign-in call, compose shell, templates, discuss.js
	// Guest: signed-out visitors may read the comments (discuss.js loads
	// them for everyone; the outline is only a placeholder). Same for every
	// visitor: a site setting, not a property of the request.
	Guest    bool
	Purposes []string // purposes of top-level comments (drop-down)
	MaxBody  int
	MaxNote  int
	MaxHide  int
	Login    string // localized /login?return=<page>?discussion
	Account  string // localized /account
	Rules    string // localized /rules
	Reasons  []string
	Markdown []Hint // syntax -> explanation
}

// DiscShape is one comment of the outline: drawn as speckle (static/app.js,
// "tadpole script") from its size class alone.
type DiscShape struct {
	Status      string // visible | hidden | deleted
	Size        string // s | m | l (visible only)
	Login       string // sign-in link the speckle leads to ("" without accounts)
	Replies     []DiscShape
	MoreReplies int
}

// BuildDiscView turns an outline into the section's view.
func BuildDiscView(l *i18n.Locale, cve string, o *discuss.Outline) *DiscView {
	v := &DiscView{CVE: cve, Locale: l.Tag, MaxBody: discuss.MaxBodyChars, MaxNote: discuss.MaxNoteChars,
		MaxHide: discuss.MaxReasonChars, Reasons: reportReasons, Markdown: mdSyntax, Purposes: discPurposes}
	if o == nil {
		v.Failed = true
		return v
	}
	v.Count, v.More = o.Count, o.More
	shape := func(c discuss.OutlineComment) DiscShape {
		return DiscShape{Status: c.Status, Size: c.Size, MoreReplies: c.MoreReplies}
	}
	for _, t := range o.Threads {
		d := shape(t)
		for _, r := range t.Replies {
			d.Replies = append(d.Replies, shape(r))
		}
		v.Threads = append(v.Threads, d)
	}
	return v
}

// discVersion is Version(cve) memoised for discVersionTTL (fresh: for
// discFreshEvery, in its own per-second bucket) through the server cache.
func (u *UI) discVersion(ctx context.Context, cve string, fresh bool) (string, error) {
	key, ttl := "discver|"+cve, discVersionTTL
	if fresh {
		key, ttl = "discver1|"+cve+"|"+strconv.FormatInt(time.Now().Unix(), 10), discFreshEvery
	}
	v, _, err := u.srv.Cache.Get(ctx, "html|"+key, ttl, func(ctx context.Context) (any, error) {
		return u.opts.Discussions.Version(ctx, cve)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// discussion builds the section of a vulnerability page (nil when
// discussions are off). A failure leaves the rest of the page intact. The
// query is read for the page of threads (?cmp=, or the page of the comment
// ?c= names) and ?fresh= for the cache; the URL is the page's whole cache
// key, so the HTML is the same for every visitor of one URL.
func (u *UI) discussion(r *http.Request, loc *i18n.Locale, cve string) *DiscView {
	if u.opts.Discussions == nil {
		return nil
	}
	base := loc.Path("/vuln/" + cve)
	q := r.URL.Query()
	// the page: ?cmp=, else the page that holds the comment ?c= names
	page := 1
	if s := q.Get(DiscPageParam); s != "" {
		page = pocPage(s)
	} else if c := strings.ToLower(q.Get(discComment1)); discuss.ValidID(c) {
		if pos, err := u.opts.Discussions.Locate(r.Context(), cve, c); err == nil {
			page = pos.Index/DiscPageSize + 1
		}
	}
	var o *discuss.Outline
	ver, err := u.discVersion(r.Context(), cve, q.Has(discFreshParam))
	if err == nil {
		// page 1 first: it says how many pages there are, so the cache holds
		// no entry for a page that does not exist
		get := func(n int) (*discuss.Outline, error) {
			v, err := u.cached(r.Context(), "disc|o|"+cve+"|"+ver+"|"+strconv.Itoa(n), func(ctx context.Context) (any, error) {
				return u.opts.Discussions.OutlinePage(ctx, cve, n, DiscPageSize)
			})
			if err != nil {
				return nil, err
			}
			return v.(*discuss.Outline), nil
		}
		o, err = get(1)
		if err == nil && page > 1 && o.Pages > 1 {
			o, err = get(min(page, o.Pages))
		}
	}
	if err != nil {
		u.srv.Log.Warn("discussion unavailable", "cve", cve, "err", err)
	}
	dv := BuildDiscView(loc, cve, o)
	if o != nil {
		dv.Page = o.Page
		dv.Pager = numberedPager(loc, o.Page, o.Pages, discHref(loc, cve, q))
	}
	if u.opts.Accounts != nil {
		dv.Write = true
		dv.Login = loc.Path("/login") + "?return=" + url.QueryEscape(base+"?discussion")
		dv.Account = loc.Path("/account")
		dv.Rules = loc.Path("/rules")
		dv.Guest = u.opts.Discussions.GuestRead()
		if dv.Guest { // the speckle is a placeholder, not a call to sign in
			return dv
		}
		for i := range dv.Threads {
			dv.Threads[i].Login = dv.Login
			for k := range dv.Threads[i].Replies {
				dv.Threads[i].Replies[k].Login = dv.Login
			}
		}
	}
	return dv
}

// ResearchView is the researcher section of a vulnerability page: the
// public count and outline (site.ResearcherOutline: author, day, size
// class per post; the body is speckle); the posts themselves come from
// GET /api/posts/{cve} for signed-in visitors.
type ResearchView struct {
	CVE         string
	Researchers int             // distinct researchers, last 7 days
	Entries     []ResearchShape // the page shown (Page); Total counts all
	Total       int             // all posts of the outline
	Offset      int             // index of Entries[0] among all (discuss.js shows the same posts)
	Pager       *Pager          // nil: the outline fits one page
	Failed      bool
	Accounts    bool   // sign-in exists: call to sign in, discuss.js loads the posts
	Login       string // localized /login?return=<page>?research
}

// ResearchShape is one post of the public outline: the author's public
// name and profile link (public since 2026-11-14), the UTC date and the
// size class (the body is speckle drawn from the size class alone).
type ResearchShape struct {
	Author    string // @username, "" = not a valid handle (a neutral name is shown)
	AuthorURL string // https://x.com/<Author>, "" with Author
	Name      string // X display name (cleaned upstream text), "" = show only @Author
	Avatar    string // same-origin avatar path (/avatar/<hash>), "" = the monogram
	Initial   string // monogram: first letter of Author, upper case ("" without one)
	Day       string // YYYY-MM-DD (UTC)
	Size      string // s | m | l
}

// monogram is the letter of the avatar fallback: the handle's first
// character, upper case (handles are ASCII letters, digits and "_").
func monogram(handle string) string {
	if handle == "" {
		return ""
	}
	return strings.ToUpper(handle[:1])
}

// BuildResearchView turns the public outline into the section's view.
func BuildResearchView(cve string, o *site.ResearcherOutline) *ResearchView {
	v := &ResearchView{CVE: cve}
	if o == nil {
		v.Failed = true
		return v
	}
	v.Researchers = o.Researchers
	for _, e := range o.Entries {
		r := ResearchShape{Author: e.Author, Day: e.Day, Size: e.Size, Name: e.AuthorName, Avatar: e.AuthorAvatar,
			Initial: monogram(e.Author)}
		if e.AuthorURL != nil && e.Author != "" {
			r.AuthorURL = *e.AuthorURL
		}
		v.Entries = append(v.Entries, r)
	}
	v.Total = len(v.Entries)
	return v
}

// research builds the researcher section (always present; a failure
// leaves the rest of the page intact).
func (u *UI) research(r *http.Request, loc *i18n.Locale, cve string) *ResearchView {
	v, err := u.cached(r.Context(), "rsch|"+cve, func(ctx context.Context) (any, error) {
		return u.srv.Store.ResearcherOutline(ctx, cve)
	})
	var o *site.ResearcherOutline
	if err != nil {
		u.srv.Log.Warn("researcher posts unavailable", "cve", cve, "err", err)
	} else {
		o = v.(*site.ResearcherOutline)
	}
	rv := BuildResearchView(cve, o)
	if u.opts.Accounts != nil {
		rv.Accounts = true
		rv.Login = loc.Path("/login") + "?return=" + url.QueryEscape(loc.Path("/vuln/"+cve)+"?research")
	}
	return rv
}

// RulesData is the community rules page's data.
type RulesData struct {
	Version string // configured terms version ("" = none: no version line)
	Rules   []Hint // title key, body key
}

// communityRules are the rules in order (one key per title and body, so an
// edit of one rule stays local to its keys).
var communityRules = []Hint{
	{"rules.r1.title", "rules.r1.body"}, {"rules.r2.title", "rules.r2.body"}, {"rules.r3.title", "rules.r3.body"},
	{"rules.r4.title", "rules.r4.body"}, {"rules.r5.title", "rules.r5.body"}, {"rules.r6.title", "rules.r6.body"},
	{"rules.r7.title", "rules.r7.body"}, {"rules.r8.title", "rules.r8.body"},
}

func (u *UI) rules(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	d := RulesData{Rules: communityRules}
	if a := u.opts.Accounts.Current(); a != nil {
		d.Version = a.TermsVersion
	}
	u.page(w, r, loc, http.StatusOK, "rules", &Page{Title: loc.Text("rules.page_title"),
		Description: loc.Text("rules.description"), Path: "~/rules", Hints: helpHints(loc), Data: d})
}
