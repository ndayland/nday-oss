package webui

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/webui/i18n"
)

// /vuln without a query is the catalogue: every vulnerability with at least
// one lifecycle event, most recent change first (site.Store.Catalogue), in
// the hot list's rows. ?stage=&year=&tag=&cvss_min=&cvss_max=&include_rejected=&cursor=&before=&p=
// filter and page it; ?q= is the search page (search, webui.go). A URL with only
// tag= (the former "search by tag") is the catalogue filtered by those tags.
//
// A bare /vuln (no query, no filter, no position, no browse=) is the landing:
// only the search box, its examples and a "browse all" link. It runs no list
// and no count query. ?browse=1 is the same full list the bare URL used to
// be; every link that means "the whole list" points there (CatFilters.Href).

// catBrowseParam asks for the full list with no filter (the landing's link).
const catBrowseParam = "browse"

// catBrowseHref is the locale-neutral URL of the unfiltered full list.
const catBrowseHref = "/vuln?" + catBrowseParam + "=1"

// catPageSize is the catalogue's page length (the API's default).
const catPageSize = site.DefaultCatalogueLimit

// catQuickYears is how many years before the current one get a link of
// their own; the others are in the "earlier" select.
const catQuickYears = 5

// CatFilters is the canonical catalogue selection as the page sees it.
type CatFilters struct {
	Stage           string // current stage (event type); "" = every stage
	Year            int    // CVE id year; 0 = every year
	IncludeRejected bool
	// Tags: ?tag= filters (vocabulary slugs, canonical order; unknown slugs
	// are dropped as on the hot list).
	Tags []string
	// CVSSMin/CVSSMax: ?cvss_min=&cvss_max=, the displayed CVSS score's
	// inclusive bounds (site.NormalizeCVSS, canonical); "" = no bound.
	CVSSMin, CVSSMax string
	Cursor           string
	Before           string // ?before=: a page's previous-page position
	// Page: ?p=, the page number of a later page (pageIndex). Next to a
	// position it only labels the page; alone it picks one of the first or
	// last pages (jumpTo).
	Page int
}

// parseCatFilters reads the catalogue parameters; unknown parameters are
// ignored, empty ones mean "not set" (the year form sends an empty year for
// every year), bad values of known ones are an *InputError (400 page).
func parseCatFilters(q url.Values) (CatFilters, error) {
	var f CatFilters
	var err error
	if v := strings.TrimSpace(q.Get("stage")); v != "" {
		if f.Stage, err = site.ParseStage(v); err != nil {
			return f, err
		}
	}
	if v := strings.TrimSpace(q.Get("year")); v != "" {
		y, err := strconv.Atoi(v)
		if err != nil || y == 0 {
			y = -1 // out of range: site.CatalogueParams.Normalize names the range
		}
		f.Year = y
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
	if f.CVSSMin, f.CVSSMax, err = parseCVSSFilter(q); err != nil {
		return f, err
	}
	f.Cursor, f.Before = q.Get("cursor"), q.Get("before")
	f.Page = pageIndex(q.Get("p"))
	f.Tags, _ = tags.ParseFilter(q["tag"])
	return f, nil
}

// parseCVSSFilter reads ?cvss_min=&cvss_max= (the catalogue and the search
// page): empty means no bound, a bad value is an *InputError (400 page).
func parseCVSSFilter(q url.Values) (min, max string, err error) {
	return site.NormalizeCVSS(strings.TrimSpace(q.Get("cvss_min")), strings.TrimSpace(q.Get("cvss_max")))
}

// cvssQuery is the score filter as query parameters ("" without one).
func cvssQuery(min, max string) string {
	var parts []string
	if min != "" {
		parts = append(parts, "cvss_min="+url.QueryEscape(min))
	}
	if max != "" {
		parts = append(parts, "cvss_max="+url.QueryEscape(max))
	}
	return strings.Join(parts, "&")
}

// cvssHidden is the score filter as hidden form fields (the search forms
// keep it, like the tag filter).
func cvssHidden(min, max string) []HiddenField {
	var h []HiddenField
	if min != "" {
		h = append(h, HiddenField{"cvss_min", min})
	}
	if max != "" {
		h = append(h, HiddenField{"cvss_max", max})
	}
	return h
}

// cvssLabel is the active score filter as shown ("" without one): "9–10",
// "≥ 7", "≤ 3.9", or the single score of an exact match.
func cvssLabel(min, max string) string {
	switch {
	case min == "" && max == "":
		return ""
	case min == max:
		return min
	case max == "":
		return "≥ " + min
	case min == "":
		return "≤ " + max
	}
	return min + "–" + max
}

// cvssOpts is the score filter row: "all", then the severity bands
// (site.CVSSBands), each a link from href with that range; a range that is
// not a band is appended as the active entry.
func cvssOpts(l *i18n.Locale, min, max string, href func(min, max string) string) []FilterOpt {
	opts := []FilterOpt{{Label: l.Text("cat.all"), Href: href("", ""), Active: min == "" && max == ""}}
	band := false
	for _, b := range site.CVSSBands {
		on := b.Min == min && b.Max == max
		band = band || on
		opts = append(opts, FilterOpt{Label: cvssLabel(b.Min, b.Max), Href: href(b.Min, b.Max), Active: on})
	}
	if !band && (min != "" || max != "") {
		opts = append(opts, FilterOpt{Label: cvssLabel(min, max), Href: href(min, max), Active: true})
	}
	return opts
}

// Params are the store parameters of f (not yet normalized).
func (f CatFilters) Params() site.CatalogueParams {
	return site.CatalogueParams{Stage: f.Stage, Year: f.Year, Tags: f.Tags, IncludeRejected: f.IncludeRejected,
		CVSSMin: f.CVSSMin, CVSSMax: f.CVSSMax, Limit: catPageSize, Cursor: f.Cursor, Before: f.Before}
}

// Query renders f as page query parameters, unset ones omitted; withCursor
// adds the page position (cursor or before, and p).
func (f CatFilters) Query(withCursor bool) string {
	var parts []string
	if f.Stage != "" {
		parts = append(parts, "stage="+url.QueryEscape(stageAlias(f.Stage)))
	}
	if f.Year != 0 {
		parts = append(parts, "year="+strconv.Itoa(f.Year))
	}
	if f.IncludeRejected {
		parts = append(parts, "include_rejected=1")
	}
	if len(f.Tags) > 0 {
		parts = append(parts, tagQuery(f.Tags))
	}
	if c := cvssQuery(f.CVSSMin, f.CVSSMax); c != "" {
		parts = append(parts, c)
	}
	if withCursor {
		if f.Cursor != "" {
			parts = append(parts, "cursor="+url.QueryEscape(f.Cursor))
		}
		if f.Before != "" {
			parts = append(parts, "before="+url.QueryEscape(f.Before))
		}
		if f.Page > 1 {
			parts = append(parts, "p="+strconv.Itoa(f.Page))
		}
	}
	return strings.Join(parts, "&")
}

// Href is the locale-neutral page URL for f.
func (f CatFilters) Href(withCursor bool) string {
	q := f.Query(withCursor)
	switch {
	case q == "":
		return catBrowseHref // a bare /vuln is the landing, not the list
	case f.Query(false) == "" && f.Cursor == "" && f.Before == "":
		// a page number alone stays on the full list (isCatLanding)
		return catBrowseHref + "&" + q
	}
	return "/vuln?" + q
}

// isCatLanding reports whether a catalogue request (no search query) is
// the landing: no filter, no page position and no browse=. Unknown
// parameters, empty known ones and a page number alone (?p=) do not count.
func isCatLanding(q url.Values, f CatFilters) bool {
	return f.Query(false) == "" && f.Cursor == "" && f.Before == "" && q.Get(catBrowseParam) == ""
}

// APIPath is the equivalent JSON API path (/vulns, filters only).
func (f CatFilters) APIPath() string {
	var parts []string
	if f.Stage != "" {
		parts = append(parts, "stage="+url.QueryEscape(stageAlias(f.Stage)))
	}
	if f.Year != 0 {
		parts = append(parts, "year="+strconv.Itoa(f.Year))
	}
	if f.IncludeRejected {
		parts = append(parts, "include_rejected=true")
	}
	if len(f.Tags) > 0 {
		parts = append(parts, tagQuery(f.Tags))
	}
	if c := cvssQuery(f.CVSSMin, f.CVSSMax); c != "" {
		parts = append(parts, c)
	}
	if len(parts) == 0 {
		return "/vulns"
	}
	return "/vulns?" + strings.Join(parts, "&")
}

// StageEntry is one item of the catalogue's stage row.
type StageEntry struct {
	Label  string
	Class  string // stage colour (st-dis ..), "" for "all"
	Count  string // whole-database total, formatted
	Href   string // "" when the stage has no vulnerability (not a link)
	Active bool
}

// YearOpt is one option of the "earlier" year select.
type YearOpt struct {
	Value    string
	Selected bool
}

// HiddenField keeps the other filters in the year form.
type HiddenField struct{ Name, Value string }

// CatRow is one catalogue row: a hot-list row and, on the first row of a
// date or of the tail of rows whose change time is unknown, its group
// header.
type CatRow struct {
	Row    HotRowView
	Header string
	NoDate bool // Header is the "time unknown" group
}

// CatalogueView is the catalogue page (catalogue.tmpl).
type CatalogueView struct {
	SearchAction string
	Examples     template.HTML // example search links, " · "-separated
	SearchTags   []string      // tag filters the search form keeps
	SearchCVSS   []HiddenField // the score filter the search form keeps
	Stages       []StageEntry  // "all", then DIS..KEV
	Years        []FilterOpt   // "all", then the current and catQuickYears earlier years
	YearOpts     []YearOpt     // the select: every other accepted year
	YearHidden   []HiddenField
	YearLabel    string // the active year for the filter summary ("" = every year)
	Rejected     FilterOpt
	CVSS         []FilterOpt // the score filter row (cvssOpts)
	CVSSLabel    string      // the active score filter for the summary ("" = none)
	Chips        []TagChip
	TagsHref     string
	Custom       bool // year, score, tags or rejected set: the filters start open on phones
	Rows         []CatRow
	Pager        *Pager // nil when the list fits on one page
	OnCursor     bool   // a page after the first (the hero is compact)
	Filtered     bool   // any filter set
	ClearHref    string // the unfiltered catalogue
	Landing      bool   // only the search box, examples and BrowseHref (nothing below it)
	BrowseHref   string // landing: the full list
}

// searchExamples are the example search links (language-neutral tokens).
func searchExamples(l *i18n.Locale) template.HTML {
	var ex []string
	for _, e := range []string{"barracuda", "CVE-2026-10", "GHSA-gj9m-f8ph-pmhr"} {
		ex = append(ex, string(anchorHTML(l.Path("/vuln?q="+url.QueryEscape(e)), e)))
	}
	return template.HTML(strings.Join(ex, " · "))
}

// BuildLandingView builds the landing: no store data at all.
func BuildLandingView(l *i18n.Locale) CatalogueView {
	return CatalogueView{SearchAction: l.Path("/vuln"), Examples: searchExamples(l), Landing: true,
		BrowseHref: l.Path(catBrowseHref)}
}

// BuildCatalogueView builds the catalogue page. st gives the stage totals
// (whole database, as on /stats); length is the catalogue's length for f
// (< 0 = not known; catalogueTotal); now is the clock (the current year).
func BuildCatalogueView(l *i18n.Locale, f CatFilters, page *site.CataloguePage, st *site.Stats, length int64, api API, now time.Time) CatalogueView {
	cv := CatalogueView{SearchAction: l.Path("/vuln"), Examples: searchExamples(l), SearchTags: f.Tags,
		SearchCVSS: cvssHidden(f.CVSSMin, f.CVSSMax), CVSSLabel: cvssLabel(f.CVSSMin, f.CVSSMax),
		TagsHref: l.Path("/tags"), Custom: f.Year != 0 || f.IncludeRejected || len(f.Tags) > 0 || f.CVSSMin != "" || f.CVSSMax != "",
		ClearHref: l.Path(catBrowseHref)}
	cv.Filtered = cv.Custom || f.Stage != ""
	link := func(g CatFilters) string {
		g.Cursor = ""
		return l.Path(g.Href(false))
	}
	// stage row
	all := f
	all.Stage = ""
	var total int64
	if st != nil {
		total = st.WithEvents
	}
	cv.Stages = append(cv.Stages, StageEntry{Label: l.Text("cat.all"), Count: l.Int(total), Href: link(all), Active: f.Stage == ""})
	for _, info := range site.StageInfos {
		var n int64
		if st != nil {
			for _, c := range st.ByStage {
				if c.Code == info.Code {
					n = c.Count
				}
			}
		}
		e := StageEntry{Label: l.Text("stage.short", "stage", info.Code), Class: StageClass(info.Code), Count: l.Int(n),
			Active: f.Stage == info.Type}
		if n > 0 {
			g := f
			g.Stage = info.Type
			e.Href = link(g)
		}
		cv.Stages = append(cv.Stages, e)
	}
	// years
	cur := now.UTC().Year()
	if max := site.MaxCatalogueYear(); cur > max {
		cur = max
	}
	g := f
	g.Year = 0
	cv.Years = append(cv.Years, FilterOpt{Label: l.Text("cat.all"), Href: link(g), Active: f.Year == 0})
	low := cur - catQuickYears
	if low < site.MinCatalogueYear {
		low = site.MinCatalogueYear
	}
	for y := cur; y >= low; y-- {
		g := f
		g.Year = y
		cv.Years = append(cv.Years, FilterOpt{Label: strconv.Itoa(y), Href: link(g), Active: f.Year == y})
	}
	for y := site.MaxCatalogueYear(); y >= site.MinCatalogueYear; y-- {
		if y >= low && y <= cur {
			continue
		}
		cv.YearOpts = append(cv.YearOpts, YearOpt{Value: strconv.Itoa(y), Selected: f.Year == y})
	}
	if f.Year != 0 {
		cv.YearLabel = strconv.Itoa(f.Year)
	}
	if f.Stage != "" {
		cv.YearHidden = append(cv.YearHidden, HiddenField{"stage", stageAlias(f.Stage)})
	}
	// the year form with "—" must stay on the list, not fall back to the landing
	cv.YearHidden = append(cv.YearHidden, HiddenField{catBrowseParam, "1"})
	if f.IncludeRejected {
		cv.YearHidden = append(cv.YearHidden, HiddenField{"include_rejected", "1"})
	}
	for _, s := range f.Tags {
		cv.YearHidden = append(cv.YearHidden, HiddenField{"tag", s})
	}
	cv.YearHidden = append(cv.YearHidden, cv.SearchCVSS...)
	// score, rejected, tags
	cv.CVSS = cvssOpts(l, f.CVSSMin, f.CVSSMax, func(min, max string) string {
		g := f
		g.CVSSMin, g.CVSSMax = min, max
		return link(g)
	})
	g = f
	g.IncludeRejected = !f.IncludeRejected
	cv.Rejected = FilterOpt{Label: l.Text("hot.filter.rejected"), Href: link(g), Active: f.IncludeRejected}
	for _, s := range f.Tags {
		g := f
		g.Tags = withoutTag(f.Tags, s)
		c := chip(s, l.Path(tagPath(s)))
		c.Remove = link(g)
		cv.Chips = append(cv.Chips, c)
	}
	addTag := func(s string) string {
		g := f
		g.Tags = withTag(f.Tags, s)
		return link(g)
	}
	// rows
	if page != nil {
		lastDate, undated := "", false
		for _, r := range page.Rows {
			row := BuildHotRow(l, r, &lastDate)
			row.Tags = RowChips(r.Tags, addTag)
			cr := CatRow{Row: row, Header: row.DateHeader}
			if r.Transition.At.IsZero() {
				// the change time is unknown: no change to show, one group for them all
				cr.Row.Change, cr.Row.ChangeText, cr.Row.ChangeClass, cr.Row.DateHeader = "", "", "", ""
				cr.Header, cr.NoDate = "", true
				if !undated {
					cr.Header = l.Text("time.unknown")
					undated = true
				}
			}
			cv.Rows = append(cv.Rows, cr)
		}
		cv.Pager = catPager(l, f, page, length)
		cv.OnCursor = f.Cursor != "" || page.PrevCursor != nil
	}
	return cv
}

// catPager is the catalogue's pager (as hotPager: the first page is the
// one without a position, or the one paging back reached); total is the
// catalogue's length for f (< 0 = not known; catalogueTotal).
func catPager(l *i18n.Locale, f CatFilters, page *site.CataloguePage, total int64) *Pager {
	first := f.Cursor == "" && ((f.Before == "" && f.Page <= 1) || page.PrevCursor == nil)
	cur := f.Page
	if first {
		cur = 1
	}
	cur, pages := clampPage(cur, pagesOf(total, catPageSize), first, page.NextCursor != nil)
	at := func(cursor, before string, idx int) string {
		g := f
		g.Cursor, g.Before, g.Page = cursor, before, idx
		return l.Path(g.Href(true))
	}
	firstHref := l.Path(f.Href(false))
	var prev, next string
	if !first {
		prev = firstHref // page 2, or a later page without rows: back to the start
		if page.PrevCursor != nil && cur != 2 {
			prev = at("", *page.PrevCursor, prevIndex(cur))
		}
	}
	if page.NextCursor != nil {
		next = at(*page.NextCursor, "", nextIndex(cur))
	}
	pg := newPager(prev, next)
	from := 0
	if cur > 0 {
		from = (cur-1)*catPageSize + 1
	}
	pg.position(l, cur, pages, from, len(page.Rows), total)
	pg.numbers(l, cur, pages, func(n int) string {
		if n <= 1 {
			return firstHref
		}
		return at("", "", n)
	})
	return pg
}

// catTotal is the length of the catalogue for f when the whole-database
// counts already give it (st, as on /stats; one scan, cached): no year and
// no tag and no score filter. -1 when not known (catalogueTotal counts it then).
func catTotal(f CatFilters, st *site.Stats) int64 {
	if st == nil || f.Year != 0 || len(f.Tags) > 0 || f.CVSSMin != "" || f.CVSSMax != "" {
		return -1
	}
	if f.Stage == "" {
		if f.IncludeRejected {
			return st.WithEvents
		}
		return st.WithEvents - st.Rejected
	}
	for i, info := range site.StageInfos {
		if info.Type != f.Stage || i >= len(st.ByStageLive) {
			continue
		}
		if !f.IncludeRejected {
			return st.ByStageLive[i]
		}
		for _, c := range st.ByStage {
			if c.Stage == f.Stage {
				return c.Count
			}
		}
	}
	return -1
}

// catalogueTotal is the catalogue's length for f (p its normalized
// params): from the whole-database counts when they give it (catTotal),
// else counted per filter combination (site.CatalogueCount, cached for
// twice the list's lifetime); -1 when it is not counted (a broad tag).
func (u *UI) catalogueTotal(ctx context.Context, f CatFilters, p site.CatalogueParams, st *site.Stats) (int64, error) {
	if n := catTotal(f, st); n >= 0 {
		return n, nil
	}
	v, _, err := u.srv.Cache.Get(ctx, "html|catn|"+p.CountKey(), 2*u.opts.CacheTTL, func(ctx context.Context) (any, error) {
		n, ok, err := u.srv.Store.CatalogueCount(ctx, p)
		if !ok {
			n = -1
		}
		return n, err
	})
	if err != nil {
		return -1, err
	}
	return v.(int64), nil
}

// vulnIndex is /vuln: the search page for a query, else the catalogue.
func (u *UI) vulnIndex(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	q, err := site.NormalizeQuery(r.URL.Query().Get("q"))
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	if q != "" {
		u.search(w, r, loc)
		return
	}
	u.catalogue(w, r, loc)
}

// catalogue renders the catalogue page.
func (u *UI) catalogue(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	f, err := parseCatFilters(r.URL.Query())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	if isCatLanding(r.URL.Query(), f) {
		// the cheapest page of the site: nothing is read from the store
		u.page(w, r, loc, http.StatusOK, "catalogue", &Page{Title: loc.Text("page.cat.title"),
			Description: loc.Text("page.cat.description"),
			Nav:         "vuln", Path: "~/vuln", Hints: helpHints(loc), AutoSelect: true,
			Canonical: "/vuln", Data: BuildLandingView(loc), Landing: true})
		return
	}
	p, err := f.Params().Normalize()
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	st, err := u.statsReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	length, err := u.catalogueTotal(r.Context(), f, p, st)
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	if f.Cursor == "" && f.Before == "" && f.Page > 1 {
		// a page number without a position: one of the first or last pages
		// (jumpTo); any other is out of reach
		j, ok := jumpTo(f.Page, length, catPageSize)
		if !ok {
			u.notFound(w, r, loc)
			return
		}
		f.Page, p.Offset, p.Limit, p.FromEnd = j.Page, j.Offset, j.Limit, j.FromEnd
		if f.Page <= 1 {
			f.Page = 0
		}
		if p, err = p.Normalize(); err != nil {
			u.fail(w, r, loc, err)
			return
		}
	}
	v, err := u.cached(r.Context(), "cat|"+p.CacheKey(), func(ctx context.Context) (any, error) { return u.srv.Store.Catalogue(ctx, p) })
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	page := v.(*site.CataloguePage)
	if p.Offset > 0 && len(page.Rows) == 0 {
		// one of the first pages of a list that is shorter (not counted)
		u.notFound(w, r, loc)
		return
	}
	cv := BuildCatalogueView(loc, f, page, st, length, u.api, u.opts.Now())
	pos := "0/0"
	if n := len(cv.Rows); n > 0 {
		pos = "1/" + strconv.Itoa(n)
	}
	// as on the hot list: a filtered catalogue is a view of /vuln, not a
	// page of its own; a cursor page names its first page as canonical
	noIndex := f.Query(false) != ""
	if noIndex {
		w.Header().Set("X-Robots-Tag", "noindex")
	}
	u.page(w, r, loc, http.StatusOK, "catalogue", &Page{Title: loc.Text("page.cat.title"),
		Description: loc.Text("page.cat.description"),
		Nav:         "vuln", Path: "~/vuln", Pos: pos, PosID: true, Hints: helpHints(loc), AutoSelect: true,
		Canonical: f.Href(false), NoIndex: noIndex, Data: cv, SearchTags: f.Tags, SearchCVSS: cv.SearchCVSS})
}
