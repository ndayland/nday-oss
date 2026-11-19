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
	Rows  []HotRowView
	Pager *Pager // nil when the list fits on one page
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
		v.Title, v.TitleMissing, v.TitleLang, v.Mark = rowTitle(l, d.TitleZh, d.Title, d.TitleInfo, slotsRecord(d.Slots))
		v.Vendor, _ = ProductLine(l, d.Products, d.ProductCount, 2)
		v.Rsch = rschBadge(l, d.Researchers)
	}
	v.DateHeader = "" // ranked, not dated
	return v
}

// discussedPager is the pager of the ranking at offset off (a multiple of
// the page size): offset paging, so the page number, the rows' positions
// and the previous page are exact; total is the ranking's length (0 = not
// known).
func discussedPager(l *i18n.Locale, off int, page *site.DiscussedPage, n int) *Pager {
	href := func(o int) string {
		if o <= 0 {
			return l.Path("/discussed")
		}
		return l.Path("/discussed") + "?offset=" + strconv.Itoa(o)
	}
	var first, prev, next string
	if off > 0 {
		first, prev = href(0), href(off-discussedPageSize)
	}
	if page.NextOffset != nil {
		next = href(*page.NextOffset)
	}
	pg := newPager(first, prev, next)
	total := int64(-1)
	if n > 0 {
		total = int64(n)
	}
	cur, pages := clampPage(off/discussedPageSize+1, pagesOf(total, discussedPageSize), off == 0, next != "")
	pg.position(l, cur, pages, off+1, len(page.Rows), total)
	return pg
}

// discussedPage is one page of the ranking for normalized p, cached.
func (u *UI) discussedPage(ctx context.Context, p site.DiscussedParams) (*site.DiscussedPage, error) {
	v, err := u.cached(ctx, "discussed|"+p.CacheKey(), func(ctx context.Context) (any, error) {
		return u.srv.Store.Discussed(ctx, p)
	})
	if err != nil {
		return nil, err
	}
	return v.(*site.DiscussedPage), nil
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
	page, err := u.discussedPage(r.Context(), p)
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	total := page.Total
	if total == 0 && off > 0 {
		// a page past the end has no rows to carry the ranking's length:
		// the first page's (cached) has it
		first, err := u.discussedPage(r.Context(), site.DiscussedParams{Limit: p.Limit})
		if err != nil {
			u.fail(w, r, loc, err)
			return
		}
		total = first.Total
	}
	src, err := u.sourcesReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	dv := DiscussedView{}
	for _, row := range page.Rows {
		dv.Rows = append(dv.Rows, BuildDiscussedRow(loc, row))
	}
	dv.Pager = discussedPager(loc, off, page, total)
	if off > 0 {
		w.Header().Set("X-Robots-Tag", "noindex")
	}
	pos := "0/0"
	if n := len(dv.Rows); n > 0 {
		pos = "1/" + strconv.Itoa(n)
	}
	u.page(w, r, loc, http.StatusOK, "discussed", &Page{Title: loc.Text("discussed.title"),
		Description: loc.Text("discussed.description"), Nav: "discussed", Path: "~/discussed", Pos: pos, PosID: true,
		Hints: helpHints(loc), Status: BuildStatusLine(loc, src), AutoSelect: true,
		Canonical: "/discussed", NoIndex: off > 0, Data: dv})
}
