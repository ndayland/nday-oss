package webui

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// /discussed: "researchers are discussing" — CVEs ranked by how many
// allow-listed researchers posted about them on X in the last 7 days
// (site.Store.Discussed; counts only, see site/public.go). Offset paging:
// ?offset=N (multiples of the page size; anything else shows the first
// page).

const discussedPageSize = 50

// DiscussedView is the page's data.
type DiscussedView struct {
	Rows      []HotRowView
	Curl      CmdLine
	APIPath   string
	NextHref  string
	FirstHref string // set on a later page
}

// BuildDiscussedRow converts one row: the hot-list row where the CVE has a
// lifecycle state, otherwise a row without a change ("—").
func BuildDiscussedRow(l *i18n.Locale, d site.DiscussedRow) HotRowView {
	h, ok := d.HotRow()
	var v HotRowView
	if ok {
		last := "-"
		v = BuildHotRow(l, h, &last)
	} else {
		v = HotRowView{CVE: d.CVEID, Href: l.Path("/vuln/" + d.CVEID), Rejected: d.IsRejected, Change: "—",
			Time: Stamp{Text: l.Text("value.no_record")}, Strip: BuildStrip(l, d.Slots), TPlus: FormatTPlus(nil),
			TPlusTitle: TPlusTitle(l, nil), Poc: strconv.Itoa(d.PocSources) + "/" + strconv.Itoa(len(site.PocSourceNames)),
			PocZero: d.PocSources == 0}
		v.Title, v.TitleMissing, v.TitleLang = rowTitle(l, d.TitleZh, d.Title, slotsRecord(d.Slots))
		v.Vendor, _ = ProductLine(l, d.Products, d.ProductCount, 2)
		v.Rsch = rschBadge(l, d.Researchers)
	}
	v.DateHeader = "" // ranked, not dated
	return v
}

func (u *UI) discussed(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	off, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
	if err != nil || off < 0 || off > site.MaxHotOffset || off%discussedPageSize != 0 {
		off = 0
	}
	p, err := site.DiscussedParams{Limit: discussedPageSize, Offset: off}.Normalize()
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	v, err := u.cached(r.Context(), "discussed|"+p.CacheKey(), func(ctx context.Context) (any, error) {
		return u.srv.Store.Discussed(ctx, p)
	})
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	page := v.(*site.DiscussedPage)
	src, err := u.sourcesReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	dv := DiscussedView{Curl: CurlCmd(u.api.URL("/discussed"), ".rows"), APIPath: u.api.Href("/discussed")}
	for _, row := range page.Rows {
		dv.Rows = append(dv.Rows, BuildDiscussedRow(loc, row))
	}
	if page.NextOffset != nil {
		dv.NextHref = loc.Path("/discussed") + "?offset=" + strconv.Itoa(*page.NextOffset)
	}
	if off > 0 {
		dv.FirstHref = loc.Path("/discussed")
		w.Header().Set("X-Robots-Tag", "noindex")
	}
	pos := "0/0"
	if n := len(dv.Rows); n > 0 {
		pos = "1/" + strconv.Itoa(n)
	}
	u.page(w, r, loc, http.StatusOK, "discussed", &Page{Title: loc.Text("discussed.title"),
		Description: loc.Text("discussed.description"), Nav: "discussed", Path: "~/discussed", Pos: pos, PosID: true,
		Hints: helpHints(loc), Status: BuildStatusLine(loc, src), AutoSelect: true, RawHref: dv.APIPath,
		Canonical: "/discussed", NoIndex: off > 0, Data: dv})
}
