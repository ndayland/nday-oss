package webui

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// /discussed: "researchers are discussing" — a heat ranking of the CVEs
// allow-listed researchers posted about on X in the last 7 days, most
// researchers first (site.Store.Discussed; counts, per-day counts and the
// outline's avatars only, see site/public.go). Offset paging:
// ?offset=N (multiples of the page size; anything else shows the first
// page).

const discussedPageSize = 50

// DiscussedView is the page's data.
type DiscussedView struct {
	Start int // the first row's rank (the list's start attribute)
	Rows  []HeatRowView
	Pager *Pager // nil when the list fits on one page
}

// HeatRowView is one row of the heat ranking: rank, heat (researchers, a
// bar scaled to the whole ranking's top), the CVE and its title, one stage
// label, at most one flag, a few avatars and a 7-day sparkline. Nothing
// here names a researcher (site/public.go).
type HeatRowView struct {
	Rank         string // 1-based position in the whole ranking, formatted
	CVE          string
	Href         string
	Title        string
	TitleMissing bool
	TitleLang    string
	Mark         *TitleMark
	Rejected     bool
	Heat         string // researcher count, formatted
	Unit         string // "researchers" (discussed.unit)
	HeatText     string // the count in words, for screen readers (rsch.count)
	Bar          int    // heat bar width, 0..heatBarMax (SVG user units)
	Stage        string // current stage code ("" = no lifecycle state)
	StageClass   string
	StageName    string
	Flag         string // the flag's words ("" = none)
	FlagClass    string // dz-new | dz-bare
	Faces        []string
	More         string // "+N": researchers beyond the faces ("" = none)
	Spark        Spark
}

// Spark is a row's 7-day sparkline, drawn by the server as an inline SVG
// polyline (no script, no style attribute).
type Spark struct {
	Points string // polyline points in the 0 0 sparkW sparkH viewBox
	Trend  string // up | flat | down
	Label  string // "7-day trend: rising"
}

// Geometry of the heat bar and the sparkline (viewBox units; the stylesheet
// sets the drawn size).
const (
	heatBarMax = 100
	sparkW     = 60
	sparkH     = 20
	sparkPad   = 2 // keeps the line's stroke inside the box
)

// heatBar is the width of n's bar when the ranking's top count is top:
// proportional, at least 2 so a row with posts never shows an empty bar.
func heatBar(n, top int) int {
	if n <= 0 || top <= 0 {
		return 0
	}
	if n >= top {
		return heatBarMax
	}
	w := (n*heatBarMax + top/2) / top
	if w < 2 {
		w = 2
	}
	return w
}

// sparkTrend compares the posts of the last three days with those of the
// first three (the middle day counts for neither): up, down or flat.
func sparkTrend(days [site.HeatDays]int) string {
	early, late := 0, 0
	for i := 0; i < 3; i++ {
		early += days[i]
		late += days[site.HeatDays-1-i]
	}
	switch {
	case late > early:
		return "up"
	case late < early:
		return "down"
	}
	return "flat"
}

// BuildSpark draws days (oldest first) scaled to the row's own busiest day;
// a week without posts is a flat line at the bottom.
func BuildSpark(l *i18n.Locale, days [site.HeatDays]int) Spark {
	peak := 0
	for _, n := range days {
		peak = max(peak, n)
	}
	pts := make([]string, len(days))
	step := float64(sparkW-2*sparkPad) / float64(len(days)-1)
	for i, n := range days {
		y := float64(sparkH - sparkPad)
		if peak > 0 {
			y -= float64(n) / float64(peak) * float64(sparkH-2*sparkPad)
		}
		pts[i] = strconv.FormatFloat(sparkPad+float64(i)*step, 'f', 1, 64) + "," + strconv.FormatFloat(y, 'f', 1, 64)
	}
	tr := sparkTrend(days)
	return Spark{Points: strings.Join(pts, " "), Trend: tr, Label: l.Text("discussed.trend", "trend", tr)}
}

// slotHas reports whether the row's slot of stage code has an event
// (known, unknown or implied): the same facts the lifecycle strip draws.
func slotHas(slots []site.Slot, code string) bool {
	for _, s := range slots {
		if s.Code == code {
			return s.State != site.SlotNone
		}
	}
	return false
}

// BuildHeatRow converts one row of the ranking; rank is its 1-based
// position in the whole ranking, top the ranking's highest count.
func BuildHeatRow(l *i18n.Locale, d site.DiscussedRow, rank, top int) HeatRowView {
	v := HeatRowView{Rank: l.Int(int64(rank)), CVE: d.CVEID, Href: l.Path("/vuln/" + d.CVEID), Rejected: d.IsRejected,
		Heat: l.Int(int64(d.Researchers)), Unit: l.Text("discussed.unit", "n", d.Researchers),
		HeatText: l.Text("rsch.count", "n", d.Researchers), Bar: heatBar(d.Researchers, top), Spark: BuildSpark(l, d.Days)}
	v.Title, v.TitleMissing, v.TitleLang, v.Mark = rowTitle(l, d.TitleZh, d.Title, d.TitleInfo, slotsRecord(d.Slots))
	if d.StageCode != nil {
		v.Stage, v.StageClass, v.StageName = *d.StageCode, StageClass(*d.StageCode), StageName(l, *d.StageCode)
	}
	switch {
	case d.Fresh:
		v.Flag, v.FlagClass = l.Text("discussed.flag.new"), "dz-new"
	case !d.IsRejected && !slotHas(d.Slots, "POC") && !slotHas(d.Slots, "PAT"):
		// a rejected id isn't waiting for a PoC or a patch
		v.Flag, v.FlagClass = l.Text("discussed.flag.bare"), "dz-bare"
	}
	faces := d.Faces
	if len(faces) > site.MaxFaces {
		faces = faces[:site.MaxFaces]
	}
	// never more faces than the public count, and "+N" is the rest of it
	if len(faces) > d.Researchers {
		faces = faces[:max(d.Researchers, 0)]
	}
	v.Faces = faces
	if more := d.Researchers - len(faces); more > 0 {
		v.More = "+" + l.Int(int64(more))
	}
	return v
}

// discussedPager is the pager of the ranking at offset off (a multiple of
// the page size): offset paging, so the page number, the rows' positions,
// the previous page and every number are exact; total is the ranking's
// length (0 = not known).
func discussedPager(l *i18n.Locale, off int, page *site.DiscussedPage, n int) *Pager {
	href := func(o int) string {
		if o <= 0 {
			return l.Path("/discussed")
		}
		return l.Path("/discussed") + "?offset=" + strconv.Itoa(o)
	}
	var prev, next string
	if off > 0 {
		prev = href(off - discussedPageSize)
	}
	if page.NextOffset != nil {
		next = href(*page.NextOffset)
	}
	pg := newPager(prev, next)
	total := int64(-1)
	if n > 0 {
		total = int64(n)
	}
	cur, pages := clampPage(off/discussedPageSize+1, pagesOf(total, discussedPageSize), off == 0, next != "")
	pg.position(l, cur, pages, off+1, len(page.Rows), total)
	// numbers by offset: the ranking is short (its own window), and an
	// offset past site.MaxHotOffset is the first page anyway
	pg.numbers(l, cur, pages, func(p int) string { return href((p - 1) * discussedPageSize) })
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
	p, err := site.DiscussedParams{Limit: discussedPageSize, Offset: off, Heat: true}.Normalize()
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	page, err := u.discussedPage(r.Context(), p)
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	total, top := page.Total, page.Top
	if off > 0 {
		// later pages scale their bars to the first page's top (one cached
		// lookup), so every page shows the same scale as page 1 even when
		// their cache entries were computed at different moments; a page
		// past the end takes the ranking's length from there too
		first, err := u.discussedPage(r.Context(), site.DiscussedParams{Limit: p.Limit, Heat: true})
		if err != nil {
			u.fail(w, r, loc, err)
			return
		}
		if first.Top > 0 {
			top = first.Top
		}
		if total == 0 {
			total = first.Total
		}
	}
	src, err := u.sourcesReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	dv := DiscussedView{Start: off + 1}
	for i, row := range page.Rows {
		dv.Rows = append(dv.Rows, BuildHeatRow(loc, row, off+i+1, top))
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
