// Package webui is the HTML website of nday: server-rendered pages over
// internal/site, registered on the internal/web server (same middleware as
// the JSON API). No front-end framework; templates, CSS, JS, fonts and the
// favicon are embedded in the binary.
//
// Routes (GET/HEAD), for every enabled locale under its prefix ("" for
// English, "/zh-hans", "/ja", ... — see internal/webui/i18n/locales.json):
//
//	/  (alias /hot)       hot list: ?since=24h|7d|30d&min_stage=patch|poc|exploited&include_rejected=1&cursor=
//	                      &tag=<slug> (repeatable, AND; unknown slugs ignored; docs/tags.md); &before= pages
//	                      back, &p= is the display-only page number of a later page (pager.go)
//	/discussed            CVEs ranked by researchers posting about them on X (last 7 days): ?offset=
//	/vuln                 catalogue of every vulnerability (catalogue.go): ?stage=&year=&include_rejected=1
//	                      &tag=<slug> (repeatable, AND)&cursor= (&before=, &p= as on /); with ?q= (&tag=)
//	                      the search results
//	/tags                 the tag vocabulary with counts
//	/tag/{slug}           the hot list scoped to one tag (same parameters as /)
//	/vuln/{cve}           vulnerability page (400 malformed id, 404 unknown); {cve} is a
//	                      CVE id or the GHSA id of an advisory without a CVE; a GHSA id
//	                      that is only an alias redirects (302) to its CVE, or to the
//	                      search if several
//	/src                  data sources and how to read the data
//	/stats                stage counts
//	/about                what nday is, keys
//	/feed.xml             Atom feed of the latest transitions (min stage patch); needs a
//	                      session, an API token or the private feed key (?key=)
//	/rules                community rules of the discussions (version line from
//	                      the configured terms version, Accounts.TermsVersion)
//	/login, /account      sign-in and account pages, only with Options.Accounts
//	                      (noindex; the same bytes for every visitor, see account.go)
//	/welcome              first-sign-in page (?next=), only with Options.Accounts
//	                      (noindex, the same bytes for every visitor, see welcome.go)
//	/admin[/moderation|/users[/{id}]|/system|/settings|/audit]
//	                      the staff back office, only with Options.Admin (personal,
//	                      no-store, server-rendered for staff; see admin.go)
//
// Language-neutral, unprefixed: /robots.txt, /sitemap.xml and its shards
// /sitemap/*.xml (sitemap.go), /favicon.ico, /static/<hashed name> (and
// the JSON API /api/, /raw/, /healthz of internal/web; with an API host
// configured, curl lines and raw JSON links point there instead, see API).
// "/zh-hans"
// redirects to "/zh-hans/"; a prefix whose catalog is missing or invalid is
// a 404. With Options.I18nDebug, /__i18n/<tag> renders a whole catalog with
// example values (for catalog writers; never enabled in production).
//
// Unknown query parameters are ignored on HTML pages (unlike the API).
// Security: every HTML response carries CSP (see CSP); templates contain no
// inline style or script; all upstream data is escaped by html/template and
// upstream URLs become links only when SafeURL accepts them.
package webui

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui/i18n"
)

// Options configure the UI.
type Options struct {
	// BaseURL is the public origin used in the feed and canonical links
	// (and curl lines in single-host mode). Default: the server's PublicURL,
	// else web.DefaultPublicURL.
	BaseURL string
	// APIURL is the API host origin for curl lines and raw JSON links.
	// Default: the server's APIOrigin ("" = single-host mode).
	APIURL string
	// CacheTTL of query results in the server's shared cache (default 30s).
	CacheTTL time.Duration
	// Now is the clock (tests).
	Now func() time.Time
	// I18nDebug serves /__i18n/<tag> (catalog preview for writers).
	I18nDebug bool
	// Locales overrides the embedded locale set (tests).
	Locales *i18n.Set
	// Accounts describes sign-in (AccountsOf); nil = accounts disabled: no
	// top-bar slot, and /login and /account are 404 like any unknown path.
	Accounts *Accounts
	// Discussions (DiscussionsOf) adds the discussion section to every
	// vulnerability page; nil = discussions off (no section). Writing
	// controls need Accounts too (see discussion.go).
	Discussions Discussions
	// Admin (with Accounts) serves the staff back office under /admin
	// (admin.go); nil = no back office: /admin is the ordinary 404.
	Admin *admin.Service
}

// UI serves the pages.
type UI struct {
	srv     *web.Server
	opts    Options
	assets  *Assets
	tmpl    *renderer
	locales *i18n.Set
	api     API
}

// Register adds the HTML routes to srv with default options; accounts (nil
// = disabled) are the sign-in configuration (AccountsOf), discussions (nil =
// off) the discussion service (DiscussionsOf), adm (nil = none) the staff
// back office. The nday binary calls it from cli.ServeHook.
//
// The public origin (NDAY_PUBLIC_URL) and the API origin (NDAY_API_URL) come
// from the server's configuration (`nday serve` reads and validates both with
// web.ParseOrigin), so a typo cannot put a broken or hostile URL into every
// page. NDAY_I18N_DEBUG=1 enables the catalog preview pages.
func Register(srv *web.Server, accounts *Accounts, discussions Discussions, adm *admin.Service) {
	opts := Options{I18nDebug: os.Getenv("NDAY_I18N_DEBUG") == "1", Accounts: accounts, Discussions: discussions, Admin: adm}
	if _, err := New(srv, opts); err != nil {
		panic(err) // embedded templates/assets/catalogs are broken: a build defect caught by tests
	}
}

// pageFunc is a page handler for one locale.
type pageFunc func(w http.ResponseWriter, r *http.Request, loc *i18n.Locale)

// New builds the UI and registers its routes on srv.
func New(srv *web.Server, opts Options) (*UI, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = srv.PublicURL()
	}
	if opts.BaseURL == "" {
		opts.BaseURL = web.DefaultPublicURL
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	if opts.APIURL == "" {
		opts.APIURL = srv.APIOrigin()
	}
	if opts.CacheTTL == 0 {
		opts.CacheTTL = 30 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	set := opts.Locales
	if set == nil {
		var err error
		if set, err = i18n.Default(); err != nil {
			return nil, err
		}
	}
	for _, l := range set.All {
		if !l.Enabled() && srv.Log != nil {
			srv.Log.Info("locale disabled", "locale", l.Tag, "problems", len(l.Problems()))
		}
	}
	assets, err := loadAssets(i18n.FontCSS(set))
	if err != nil {
		return nil, err
	}
	tmpl, err := newRenderer(assets, set)
	if err != nil {
		return nil, err
	}
	u := &UI{srv: srv, opts: opts, assets: assets, tmpl: tmpl, locales: set, api: NewAPI(opts.BaseURL, opts.APIURL)}
	get := func(pattern string, h http.HandlerFunc) { srv.Handle(pattern, web.GetOnly(h)) }
	for _, loc := range set.Enabled {
		loc := loc
		h := func(f pageFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { f(w, r, loc) }
		}
		p := ""
		if loc.Prefix != "" {
			p = "/" + loc.Prefix
		}
		get(p+"/{$}", h(u.hot))
		get(p+"/hot", h(u.hot))
		get(p+"/discussed", h(u.discussed))
		get(p+"/vuln", h(u.vulnIndex))
		get(p+"/vuln/{$}", redirect(loc.Path("/vuln")))
		get(p+"/vuln/{cve}", h(u.vuln))
		get(p+"/src", h(u.sources))
		get(p+"/stats", h(u.stats))
		get(p+"/about", h(u.about))
		get(p+"/rules", h(u.rules))
		get(p+"/tags", h(u.tagsPage))
		get(p+"/tag/{slug}", h(u.tagPage))
		// the feed needs a signed-in session, an API token or the reader's
		// private feed key (?key=); see feed.go
		get(p+"/feed.xml", u.srv.Gate(web.AuthSession|web.AuthFeedKey, h(u.feed)).ServeHTTP)
		if opts.Accounts != nil {
			get(p+"/login", h(u.login))
			get(p+"/account", h(u.account))
			get(p+"/welcome", h(u.welcome))
		}
		if opts.Accounts != nil && opts.Admin != nil {
			u.adminRoutes(p, loc)
		}
		if p != "" {
			get(p, redirect(p+"/"))   // "/zh-hans" -> "/zh-hans/"
			get(p+"/", h(u.notFound)) // catch-all inside the locale
		}
	}
	get("/robots.txt", u.robots)
	get("/sitemap.xml", u.sitemapIndex)    // sitemap.go
	get("/sitemap/{file}", u.sitemapShard) // locale-independent like robots.txt
	get("/favicon.ico", u.favicon)
	get("/og/vuln/{file}", u.ogVuln)     // share cards: locale-independent (ogcard.go)
	get(iconPrefix+"{host}", u.siteIcon) // site icons of outbound links: locale-independent (siteicons.go)
	srv.Handle("/static/", web.GetOnly(assets))
	if opts.I18nDebug {
		get("/__i18n/{$}", u.i18nIndex)
		get("/__i18n/{tag}", u.i18nDebug)
	}
	// catch-all: styled 404 (the API keeps its JSON 404s under /api/ and /raw/)
	get("/", u.rootNotFound)
	return u, nil
}

// Assets exposes the static files (tests, size report).
func (u *UI) Assets() *Assets { return u.assets }

// Locales is the locale set the UI serves.
func (u *UI) Locales() *i18n.Set { return u.locales }

// redirect answers 301 to a fixed path, keeping the query string.
func redirect(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t := to
		if r.URL.RawQuery != "" {
			t += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, t, http.StatusMovedPermanently)
	}
}

// cached runs fn through the server's shared TTL cache + request
// coalescing, under keys that cannot collide with the API's.
func (u *UI) cached(ctx context.Context, key string, fn func(context.Context) (any, error)) (any, error) {
	v, _, err := u.srv.Cache.Get(ctx, "html|"+key, u.opts.CacheTTL, fn)
	return v, err
}

func (u *UI) sourcesReport(ctx context.Context) (*site.SourcesReport, error) {
	v, err := u.cached(ctx, "sources", func(ctx context.Context) (any, error) { return u.srv.Store.Sources(ctx) })
	if err != nil {
		return nil, err
	}
	return v.(*site.SourcesReport), nil
}

func (u *UI) statsReport(ctx context.Context) (*site.Stats, error) {
	v, err := u.cached(ctx, "stats", func(ctx context.Context) (any, error) { return u.srv.Store.Stats(ctx) })
	if err != nil {
		return nil, err
	}
	return v.(*site.Stats), nil
}

// neutralPath strips the locale prefix: "/zh-hans/vuln/X" -> "/vuln/X".
func neutralPath(loc *i18n.Locale, p string) string {
	if loc.Prefix == "" {
		return p
	}
	rest := strings.TrimPrefix(p, "/"+loc.Prefix)
	if rest == "" || rest[0] != '/' {
		return "/" + rest
	}
	return rest
}

// page fills the locale fields of p, renders and writes a page.
//
// Canonical (set by handlers) is the locale-neutral canonical path+query
// ("/?since=30d", "/vuln"); when empty on a 200 page it is the request path.
// The page then links its own locale's version as canonical and every
// enabled locale (plus x-default = English) as hreflang alternates. The
// language switcher links to the same path AND query in each locale.
func (u *UI) page(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, status int, name string, p *Page) {
	p.L = loc
	p.Lang = loc.Tag
	if p.OGImage == "" || status != http.StatusOK {
		p.OGImage = u.opts.BaseURL + u.assets.URL("og.png")
	}
	rel := neutralPath(loc, r.URL.Path)
	if status == http.StatusOK && !p.Personal {
		canon := p.Canonical
		if canon == "" {
			canon = rel
		}
		p.Canonical = u.canonURL(loc, canon)
		for _, l := range u.locales.Enabled {
			p.Alternates = append(p.Alternates, Alternate{Tag: l.Tag, Href: u.canonURL(l, canon)})
		}
		p.XDefault = u.canonURL(u.locales.Primary(), canon)
	} else {
		p.Canonical = ""
	}
	for _, l := range u.locales.Enabled {
		href := l.Path(rel)
		if r.URL.RawQuery != "" {
			href += "?" + r.URL.RawQuery
		}
		p.Switch = append(p.Switch, LangLink{Tag: l.Tag, Name: l.NativeName, Href: href, Current: l == loc,
			Hint: l.Text("lang.hint"), Dismiss: l.Text("lang.hint_dismiss"), Match: strings.Join(l.Match, " ")})
	}
	if p.Up == "" {
		p.Up = loc.Home()
	}
	p.Acct = u.acctView(r, loc, p.AcctScript, p.DiscScript, p.AdminScript)
	body, err := u.tmpl.render(loc, name, p)
	if err != nil {
		u.srv.Log.Error("render failed", "page", name, "locale", loc.Tag, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if p.siteIcons {
		body = u.withSiteIcons(r.Context(), body)
	}
	if p.Personal {
		writePersonal(w, r, status, body)
		return
	}
	writeHTML(w, r, status, body)
}

// ErrorView is the error page.
type ErrorView struct {
	Status  int
	Code    string // "404"
	Heading string
	Message template.HTML
	Detail  template.HTML
	Search  bool // show a search box
}

func (u *UI) errorPage(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, status int, ev ErrorView, query string) {
	ev.Status = status
	ev.Code = strconv.Itoa(status)
	u.page(w, r, loc, status, "error", &Page{Title: loc.Text("page.error.title", "heading", ev.Heading),
		Description: plainOf(ev.Message), Path: "~" + truncRunes(r.URL.Path, 80), Pos: ev.Code, Hints: helpHints(loc),
		Data: ev, Query: query})
}

// plainOf strips the few tags Go puts into messages, for meta descriptions.
func plainOf(h template.HTML) string {
	s := string(h)
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return htmlUnescape(b.String())
}

// fail maps a query-layer error to an error page.
func (u *UI) fail(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, err error) {
	var ie *site.InputError
	switch {
	case errors.As(err, &ie):
		u.errorPage(w, r, loc, http.StatusBadRequest, ErrorView{Heading: loc.Text("err.bad_param.heading"),
			Message: loc.HTML("err.bad_param.message"),
			Detail:  loc.HTML("err.bad_param.detail", "detail", codeHTML(ie.Error()))}, "")
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		u.srv.Log.Warn("page timed out", "path", r.URL.Path, "err", err)
		u.errorPage(w, r, loc, http.StatusServiceUnavailable, ErrorView{Heading: loc.Text("err.timeout.heading"),
			Message: loc.HTML("err.timeout.message")}, "")
	default:
		u.srv.Log.Error("page failed", "path", r.URL.Path, "err", err)
		u.errorPage(w, r, loc, http.StatusInternalServerError, ErrorView{Heading: loc.Text("err.internal.heading"),
			Message: loc.HTML("err.internal.message")}, "")
	}
}

func (u *UI) notFound(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	u.errorPage(w, r, loc, http.StatusNotFound, ErrorView{Heading: loc.Text("err.not_found.heading"),
		Message: loc.HTML("err.not_found.message"), Search: true}, "")
}

// rootNotFound is the catch-all of the primary locale. A known locale prefix
// in the wrong case ("/zh-Hans/...") is redirected to the lower-case one.
func (u *UI) rootNotFound(w http.ResponseWriter, r *http.Request) {
	seg, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if low := strings.ToLower(seg); low != seg {
		if l := u.locales.ByPrefix(low); l != nil && l.Prefix != "" {
			to := "/" + low + "/" + rest
			if r.URL.RawQuery != "" {
				to += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, to, http.StatusMovedPermanently)
			return
		}
	}
	u.notFound(w, r, u.locales.Primary())
}

// helpHints is the bottom status bar's only key hint: "?" opens the
// keyboard help, which lists every shortcut of every page.
func helpHints(l *i18n.Locale) []Hint {
	return []Hint{{"?", l.Text("hint.help")}}
}

// parseHotFilters reads the hot-list parameters; unknown parameters are
// ignored, bad values of known ones are an *InputError (400 page).
func parseHotFilters(q url.Values) (HotFilters, error) {
	f := HotFilters{Since: defaultSince, MinStage: defaultMinStage}
	var err error
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		if f.Since, err = site.ParseSince(v); err != nil {
			return f, err
		}
	}
	if v := strings.TrimSpace(q.Get("min_stage")); v != "" {
		if f.MinStage, err = site.ParseStage(v); err != nil {
			return f, err
		}
	}
	if q.Has("include_rejected") {
		switch strings.ToLower(strings.TrimSpace(q.Get("include_rejected"))) {
		case "", "1", "true", "yes", "on":
			f.IncludeRejected = true
		case "0", "false", "no", "off":
		default:
			return f, &site.InputError{Param: "include_rejected", Msg: "expected true or false"}
		}
	}
	f.Cursor, f.Before = q.Get("cursor"), q.Get("before")
	if f.Cursor != "" || f.Before != "" {
		f.Page = pageIndex(q.Get("p"))
	}
	f.Tags, _ = tags.ParseFilter(q["tag"]) // unknown slugs are ignored and dropped from links
	return f, nil
}

// HomeData is the hot page's template data.
type HomeData struct {
	Hot        HotView
	Bars       []Bar
	Collectors []CollectorView
	Backlog    string
	BacklogN   int64
}

func (u *UI) hot(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	f, err := parseHotFilters(r.URL.Query())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	u.hotList(w, r, loc, f, nil)
}

// hotList renders the hot list for f: the home page, or a tag page (head
// set, f.Fixed its tag).
func (u *UI) hotList(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, f HotFilters, head *TagHead) {
	p, err := site.HotParams{Since: f.Since, MinStage: f.MinStage, IncludeRejected: f.IncludeRejected,
		Limit: hotPageSize, Cursor: f.Cursor, Before: f.Before, Tags: f.AllTags()}.Normalize()
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	v, err := u.cached(r.Context(), "hot|"+u.srv.Store.HotCacheKey(p), func(ctx context.Context) (any, error) { return u.srv.Store.Hot(ctx, p) })
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	page := v.(*site.HotPage)
	src, err := u.sourcesReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	st, err := u.statsReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	// the list's length, per filter combination (not per position); nil
	// when not counted (a broad tag, site.TagCountMax)
	n, err := u.cached(r.Context(), u.srv.Store.HotCountKey(p), func(ctx context.Context) (any, error) {
		t, ok, err := u.srv.Store.HotCount(ctx, p)
		if !ok {
			return (*site.HotTotal)(nil), err
		}
		return &t, err
	})
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	hv := BuildHotView(loc, f, page, n.(*site.HotTotal), u.api)
	hv.Tag = head
	data := HomeData{Hot: hv, Bars: StageBars(loc, st.ByStage, true), Collectors: BuildCollectors(loc, src),
		Backlog: loc.Int(src.CvelistBackfillBacklog), BacklogN: src.CvelistBackfillBacklog}
	pos := "0/0"
	if n := len(hv.Rows); n > 0 {
		pos = "1/" + strconv.Itoa(n)
	}
	// A filtered list is a view of the home page (or of a tag page), not a
	// page of its own; an unfiltered /tag/<slug> page is indexed.
	noIndex := f.Query(false) != ""
	if noIndex {
		w.Header().Set("X-Robots-Tag", "noindex")
	}
	pg := &Page{
		Title:       loc.Text("page.hot.title"),
		Description: loc.Text("page.hot.description"),
		Nav:         "hot", Path: "~/hot", Pos: pos, PosID: true, Hints: helpHints(loc), Status: BuildStatusLine(loc, src),
		AutoSelect: true, Canonical: f.Href(false), NoIndex: noIndex, Data: data}
	if head != nil {
		pg.Title = loc.Text("tag.one.title", "tag", tagNameText(loc, head.Slug))
		pg.Description = truncRunes(tagDescText(loc, head.Slug), 200)
		pg.Nav, pg.Path = "", "~/tag/"+head.Slug
	}
	u.page(w, r, loc, http.StatusOK, "hot", pg)
}

// tagLabels joins the labels of slugs (plain text, the locale's list).
func tagLabels(l *i18n.Locale, slugs []string) string {
	ls := make([]string, len(slugs))
	for i, s := range slugs {
		ls[i] = tagNameText(l, s)
	}
	return l.List(i18n.ListAnd, ls)
}

func (u *UI) vuln(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	raw := r.PathValue("cve")
	id, ok := site.ParseVulnID(raw)
	if !ok {
		u.errorPage(w, r, loc, http.StatusBadRequest, ErrorView{Heading: loc.Text("err.bad_cve.heading"),
			Message: loc.HTML("err.bad_cve.message", "example", codeHTML("CVE-2026-102895")),
			Detail:  loc.HTML("err.bad_cve.detail", "got", codeHTML(truncRunes(raw, 80))),
			Search:  true}, "")
		return
	}
	if raw != id {
		http.Redirect(w, r, loc.Path("/vuln/"+id), http.StatusMovedPermanently)
		return
	}
	v, found, err := u.vulnDetail(r.Context(), id)
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	if !found {
		if site.IsGHSAID(id) {
			u.vulnByGHSA(w, r, loc, id) // an alias of a CVE, or unknown
			return
		}
		u.errorPage(w, r, loc, http.StatusNotFound, ErrorView{Heading: loc.Text("err.unknown_cve.heading", "id", id),
			Message: loc.HTML("err.unknown_cve.message"), Search: true}, id)
		return
	}
	vv := BuildVulnView(loc, v, u.opts.Now(), u.api)
	vv.Share = u.shareView(loc, v) // public data only: the page is the same for everyone
	vv.Discussion = u.discussion(r, loc, id)
	vv.Research = u.research(r, loc, id)
	if site.IsGHSAID(id) && vv.Research != nil && len(vv.Research.Entries) == 0 {
		// X posts are collected by the CVE ids they name, so an advisory
		// without a CVE has none: leave out a section that could only say
		// "nothing mentions this CVE"
		vv.Research = nil
	}
	vv.Resources = u.resources(r, id)
	if items := ChartItems(vv.Resources, vv.Research); len(items) > 0 { // dots on the lifecycle chart (chartdots.go)
		vv.Chart = BuildChart(loc, v, u.opts.Now(), items...)
	}
	// after the chart took its items: the PoC list and the unreviewed list
	// show one page each (?pocp=, ?pocu=; the URL is the page's whole cache
	// key, the server cache holds the unpaged resources). ?pocu= also opens
	// the unreviewed list, so its pages work without script.
	q := r.URL.Query()
	vv.Resources.PagePoC(loc, pocPage(q.Get(PoCPageParam)), pocHref(loc, id, q))
	vv.Resources.PageUnreviewed(loc, pocPage(q.Get(UnreviewedPageParam)), q.Has(UnreviewedPageParam), unreviewedHref(loc, id, q))
	vv.Corrections = u.corrections(r, loc, id)
	desc := loc.Text("page.vuln.description", "id", id, "title", i18n.Upstream(vv.Title), "sentence", vv.Sentence)
	title := loc.Text("page.vuln.title", "id", id, "title", i18n.Upstream(truncRunes(vv.Title, 60)))
	if vv.TitleMissing {
		desc = loc.Text("page.vuln.description_untitled", "id", id, "sentence", vv.Sentence)
		title = loc.Text("page.vuln.title_untitled", "id", id)
	}
	u.page(w, r, loc, http.StatusOK, "vuln", &Page{
		Title:       title,
		Description: truncRunes(desc, 200),
		Nav:         "vuln", Path: "~/vuln/" + id, Pos: loc.Text("sbar.events", "n", vv.EventCount), Hints: helpHints(loc),
		CopyID: id, DiscScript: u.opts.Accounts != nil, Data: vv,
		OGImage: u.opts.BaseURL + cardPath(cardFor(v)), siteIcons: true})
}

// vulnByGHSA answers /vuln/{GHSA id} when no vulnerability is keyed by the
// GHSA id: the one CVE the advisory is an alias of gets a temporary redirect
// (the alias comes from upstream and can change; an advisory keyed by its
// GHSA id also ends up here once it gets a CVE), several go to the search
// for the advisory, none is the unknown-id page.
func (u *UI) vulnByGHSA(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, ghsa string) {
	got, err := u.cached(r.Context(), "ghsa|"+ghsa, func(ctx context.Context) (any, error) {
		return u.srv.Store.VulnsByGHSA(ctx, ghsa)
	})
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	switch cves := got.([]string); len(cves) {
	case 0:
		u.errorPage(w, r, loc, http.StatusNotFound, ErrorView{Heading: loc.Text("err.unknown_cve.heading", "id", ghsa),
			Message: loc.HTML("err.unknown_cve.message"), Search: true}, ghsa)
	case 1:
		http.Redirect(w, r, loc.Path("/vuln/"+cves[0]), http.StatusFound)
	default:
		http.Redirect(w, r, loc.Path("/vuln?q="+url.QueryEscape(ghsa)), http.StatusFound)
	}
}

// vulnDetail is the detail of one canonical vulnerability id through the
// shared cache; found=false is the unknown id the detail page answers 404 for.
// The share card (ogVuln) uses the same lookup, so it exists exactly when
// the page does.
func (u *UI) vulnDetail(ctx context.Context, id string) (*site.VulnDetail, bool, error) {
	type res struct {
		v     *site.VulnDetail
		found bool
	}
	got, err := u.cached(ctx, "vuln|"+id, func(ctx context.Context) (any, error) {
		v, found, err := u.srv.Store.Vuln(ctx, id)
		return res{v, found}, err
	})
	if err != nil {
		return nil, false, err
	}
	rv := got.(res)
	return rv.v, rv.found, nil
}

func (u *UI) search(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	rawQ := r.URL.Query().Get("q")
	q, err := site.NormalizeQuery(rawQ)
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	ts, _ := tags.ParseFilter(r.URL.Query()["tag"]) // unknown slugs are ignored
	const limit = 50
	var res *site.SearchResult
	if q != "" || len(ts) > 0 {
		v, err := u.cached(r.Context(), "search|"+strings.Join(ts, ",")+"|"+q, func(ctx context.Context) (any, error) {
			return u.srv.Store.SearchTagged(ctx, q, ts, limit)
		})
		if err != nil {
			u.fail(w, r, loc, err)
			return
		}
		res = v.(*site.SearchResult)
		// A complete vulnerability id that exists goes straight to its page
		// (one keyed by a GHSA id sorts before the CVEs that alias it).
		if id, ok := site.ParseVulnID(q); ok && len(res.Rows) > 0 && res.Rows[0].CVEID == id {
			http.Redirect(w, r, loc.Path("/vuln/"+id), http.StatusFound)
			return
		}
	}
	sv := BuildSearchView(loc, q, res, limit, u.api)
	addSearchTags(loc, &sv, q, ts, res, u.api)
	pos := "0/0"
	if n := len(sv.Rows); n > 0 {
		pos = "1/" + strconv.Itoa(n)
	}
	title := loc.Text("page.search.title_query", "query", q) // vulnIndex: q is never empty here
	p := &Page{Title: title, Description: loc.Text("page.search.description"),
		Nav: "vuln", Path: "~/vuln", Pos: pos, PosID: true, Hints: helpHints(loc), Query: q, AutoSelect: true,
		Canonical: "/vuln", Data: sv, SearchTags: ts}
	u.page(w, r, loc, http.StatusOK, "search", p)
}

// SourcesData is the sources page's data.
type SourcesData struct {
	Collectors []CollectorView
	Status     *StatusLine
	Backlog    string
	BacklogN   int64
	StateAt    template.HTML // convertible <time>, "" when unknown
	StateError string
}

func (u *UI) sources(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	src, err := u.sourcesReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	full := BuildStatusLine(loc, src)
	if full != nil {
		full.Full = true
	}
	d := SourcesData{Collectors: BuildCollectors(loc, src), Status: full,
		Backlog: loc.Int(src.CvelistBackfillBacklog), BacklogN: src.CvelistBackfillBacklog, StateAt: minuteHTML(src.StateRefreshedAt),
		StateError: deref(src.StateError)}
	u.page(w, r, loc, http.StatusOK, "src", &Page{Title: loc.Text("page.src.title"),
		Description: loc.Text("page.src.description"),
		Nav:         "src", Path: "~/src", Pos: loc.Text("sbar.sources", "n", len(d.Collectors)), Hints: helpHints(loc),
		Status: full, Data: d})
}

func (u *UI) stats(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	st, err := u.statsReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	u.page(w, r, loc, http.StatusOK, "stats", &Page{Title: loc.Text("page.stats.title"),
		Description: loc.Text("page.stats.description"),
		Nav:         "stats", Path: "~/stats", Hints: helpHints(loc),
		Data: BuildStatsView(loc, st, u.api)})
}

// AboutData is the about page's data.
type AboutData struct {
	Keys  []Hint
	Rules HotRules
}

// HotRules are the numbers of the about page's section on how the home list
// is ordered and pinned: the page defaults (hotview.go) and the pinning
// settings in force (site.Store.PinConfig), never typed into the catalog.
type HotRules struct {
	Window string // default --since, e.g. "7d"
	Stage  string // default --min-stage as a stage code, e.g. "PAT"
	// Pinning (site/pin.go); PinMax 0 = pinning is off.
	PinMax         int
	PinResearchers int
	PinWindow      string // researcher count window, e.g. "7d"
	PinHours       int    // the latest post at most this many hours old
	PinDays        int    // wave length in days
}

// BuildHotRules fills HotRules from the pinning numbers in force.
func BuildHotRules(c site.PinConfig) HotRules {
	return HotRules{Window: formatSince(defaultSince), Stage: site.StageCode(defaultMinStage),
		PinMax: c.Max, PinResearchers: c.MinResearchers, PinWindow: formatSince(site.ResearcherWindow),
		PinHours: int(c.Recent / time.Hour), PinDays: int(c.Wave / (24 * time.Hour))}
}

func (u *UI) about(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	d := AboutData{
		Keys: []Hint{{"j / k", loc.Text("about.key.jk")}, {"Enter", loc.Text("about.key.enter")},
			{"/", loc.Text("about.key.slash")}, {"y", loc.Text("about.key.y")},
			{"o", loc.Text("about.key.o")}, {"u", loc.Text("about.key.u")}, {"?", loc.Text("about.key.help")}},
		Rules: BuildHotRules(u.srv.Store.PinConfig()),
	}
	u.page(w, r, loc, http.StatusOK, "about", &Page{Title: loc.Text("page.about.title"),
		Description: loc.Text("page.about.description"),
		Nav:         "about", Path: "~/about", Hints: helpHints(loc), Data: d})
}

func (u *UI) robots(w http.ResponseWriter, r *http.Request) {
	body := "User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /raw/\n" + u.robotsAccounts() +
		"Sitemap: " + u.opts.BaseURL + "/sitemap.xml\n"
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(body))
}

func (u *UI) favicon(w http.ResponseWriter, r *http.Request) {
	as := u.assets.byLogical["favicon.svg"]
	u.assets.serve(w, r, as, "public, max-age=86400")
}
