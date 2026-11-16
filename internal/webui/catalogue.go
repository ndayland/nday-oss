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
// the hot list's rows. ?stage=&year=&tag=&include_rejected=&cursor= filter
// and page it; ?q= is the search page (search, webui.go). A URL with only
// tag= (the former "search by tag") is the catalogue filtered by those tags.

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
	Tags   []string
	Cursor string
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
	f.Cursor = q.Get("cursor")
	f.Tags, _ = tags.ParseFilter(q["tag"])
	return f, nil
}

// Params are the store parameters of f (not yet normalized).
func (f CatFilters) Params() site.CatalogueParams {
	return site.CatalogueParams{Stage: f.Stage, Year: f.Year, Tags: f.Tags, IncludeRejected: f.IncludeRejected,
		Limit: catPageSize, Cursor: f.Cursor}
}

// Query renders f as page query parameters, unset ones omitted.
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
	if withCursor && f.Cursor != "" {
		parts = append(parts, "cursor="+url.QueryEscape(f.Cursor))
	}
	return strings.Join(parts, "&")
}

// Href is the locale-neutral page URL for f.
func (f CatFilters) Href(withCursor bool) string {
	if q := f.Query(withCursor); q != "" {
		return "/vuln?" + q
	}
	return "/vuln"
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
	Stages       []StageEntry  // "all", then DIS..KEV
	Years        []FilterOpt   // "all", then the current and catQuickYears earlier years
	YearOpts     []YearOpt     // the select: every other accepted year
	YearHidden   []HiddenField
	YearLabel    string // the active year for the filter summary ("" = every year)
	Rejected     FilterOpt
	Chips        []TagChip
	TagsHref     string
	Custom       bool // year, tags or rejected set: the filters start open on phones
	Curl         CmdLine
	APIPath      string
	Rows         []CatRow
	NextHref     string
	FirstHref    string
	OnCursor     bool
	Filtered     bool   // any filter set
	ClearHref    string // the unfiltered catalogue
}

// searchExamples are the example search links (language-neutral tokens).
func searchExamples(l *i18n.Locale) template.HTML {
	var ex []string
	for _, e := range []string{"barracuda", "CVE-2026-10", "GHSA-gj9m-f8ph-pmhr"} {
		ex = append(ex, string(anchorHTML(l.Path("/vuln?q="+url.QueryEscape(e)), e)))
	}
	return template.HTML(strings.Join(ex, " · "))
}

// BuildCatalogueView builds the catalogue page. st gives the stage totals
// (whole database, as on /stats); now is the clock (the current year).
func BuildCatalogueView(l *i18n.Locale, f CatFilters, page *site.CataloguePage, st *site.Stats, api API, now time.Time) CatalogueView {
	cv := CatalogueView{SearchAction: l.Path("/vuln"), Examples: searchExamples(l), SearchTags: f.Tags,
		Curl: CurlCmd(api.URL(f.APIPath()), ".rows"), APIPath: api.Href(f.APIPath()),
		TagsHref: l.Path("/tags"), Custom: f.Year != 0 || f.IncludeRejected || len(f.Tags) > 0,
		ClearHref: l.Path("/vuln")}
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
	if f.IncludeRejected {
		cv.YearHidden = append(cv.YearHidden, HiddenField{"include_rejected", "1"})
	}
	for _, s := range f.Tags {
		cv.YearHidden = append(cv.YearHidden, HiddenField{"tag", s})
	}
	// rejected, tags
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
		if page.NextCursor != nil {
			n := f
			n.Cursor = *page.NextCursor
			cv.NextHref = l.Path(n.Href(true))
		}
	}
	if f.Cursor != "" {
		cv.OnCursor = true
		cv.FirstHref = l.Path(f.Href(false))
	}
	return cv
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
	p, err := f.Params().Normalize()
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	v, err := u.cached(r.Context(), "cat|"+p.CacheKey(), func(ctx context.Context) (any, error) { return u.srv.Store.Catalogue(ctx, p) })
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	page := v.(*site.CataloguePage)
	st, err := u.statsReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	cv := BuildCatalogueView(loc, f, page, st, u.api, u.opts.Now())
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
		RawHref: cv.APIPath, Canonical: f.Href(false), NoIndex: noIndex, Data: cv, SearchTags: f.Tags})
}
