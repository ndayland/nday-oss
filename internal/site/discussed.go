package site

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// "Researchers are discussing" (/discussed, GET /v1/discussed): CVEs ranked
// by the public researcher count (public.go), offset paging like the
// search list. Only the aggregate is used; see public.go for what is public.

// DiscussedParams select a page of the list.
type DiscussedParams struct {
	Limit  int // 1..MaxHotLimit, default DefaultHotLimit
	Offset int // 0..MaxHotOffset
	// Heat asks for the heat ranking's extras (DiscussedRow.Days, Fresh,
	// Faces; DiscussedPage.Top): the /discussed page sets it, the JSON API
	// never does, so the API runs the plain ranking as before.
	Heat bool
}

// Normalize validates p and fills defaults.
func (p DiscussedParams) Normalize() (DiscussedParams, error) {
	if p.Limit == 0 {
		p.Limit = DefaultHotLimit
	}
	if p.Limit < 1 || p.Limit > MaxHotLimit {
		return p, &InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", MaxHotLimit)}
	}
	if p.Offset < 0 || p.Offset > MaxHotOffset {
		return p, &InputError{Param: "offset", Msg: fmt.Sprintf("must be 0..%d", MaxHotOffset)}
	}
	return p, nil
}

// CacheKey is a canonical string for normalized params.
func (p DiscussedParams) CacheKey() string {
	if p.Heat {
		return fmt.Sprintf("discussed|%d|%d|heat", p.Limit, p.Offset)
	}
	return fmt.Sprintf("discussed|%d|%d", p.Limit, p.Offset)
}

// DiscussedRow is one row: the hot-list row data where the CVE has a
// lifecycle state (Stage, StageCode and Transition are null for a CVE known
// only from posts), plus the researcher count.
type DiscussedRow struct {
	CVEID   string  `json:"cve_id"`
	Title   *string `json:"title"`
	TitleZh *string `json:"title_zh"`
	// the effective title and its origin (titles.go)
	TitleInfo
	Products            []Product   `json:"products"`
	ProductCount        int         `json:"product_count"`
	Stage               *string     `json:"stage"`
	StageCode           *string     `json:"stage_code"`
	IsRejected          bool        `json:"is_rejected"`
	Transition          *Transition `json:"transition"`
	Slots               []Slot      `json:"slots"`
	DisclosedAt         *time.Time  `json:"disclosed_at"`
	DaysSinceDisclosure *int        `json:"days_since_disclosure"`
	PocSources          int         `json:"poc_sources"`
	Tags                []string    `json:"tags"`
	// Researchers: distinct allow-listed researchers who posted about the
	// CVE in the last 7 days (the ranking key; always >= 1 here).
	Researchers int `json:"researchers_7d"`
	// The heat ranking's extras (only with DiscussedParams.Heat, never in
	// the JSON; public.go says why each is public):
	// Days: posts per UTC day, oldest first, Days[HeatDays-1] is today.
	Days [HeatDays]int `json:"-"`
	// Fresh: the CVE's first researcher post ever falls on today's or
	// yesterday's UTC date (no post on an earlier day). UTC days only, so
	// it can change only at 00:00 UTC (or when a post arrives).
	Fresh bool `json:"-"`
	// Faces: avatar paths (/avatar/<hash>, "" = no stored picture) of up
	// to MaxFaces listed window authors, newest post first.
	Faces []string `json:"-"`
	total int      // the ranking's length (DiscussedPage.Total)
	top   int      // the ranking's highest researcher count (DiscussedPage.Top)
}

// DiscussedPage is one page of the list.
type DiscussedPage struct {
	Window string         `json:"window"` // "7d"
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
	Rows   []DiscussedRow `json:"rows"`
	// NextOffset is set when more rows follow.
	NextOffset  *int      `json:"next_offset"`
	GeneratedAt time.Time `json:"generated_at"`
	// Total: how many CVEs the whole ranking has (0 when the page has no
	// rows); counted by the same aggregate the ranking sorts, so it costs
	// nothing extra. For the pages' position text; not in the JSON.
	Total int `json:"-"`
	// Top: the highest researcher count of the whole ranking (rank 1's),
	// which the heat bars scale to; 0 when the page has no rows.
	Top int `json:"-"`
}

// discussedSQL ranks the public aggregate and joins the hot-row data of
// the page's rows only. $1/$2 the window, $3 limit, $4 offset. The number
// of ranked CVEs is a window count over the whole ranking, taken before
// LIMIT. With heat it ranks researcherHeatSQL instead (the same ranking
// columns as researcherAggSQL, plus the per-day counts) and adds the
// ranking's top count and, for the page's rows only, the fresh flag: no
// researcher post before $5, the start of yesterday (UTC).
func discussedSQL(heat bool) string {
	agg, extra, cols := researcherAggSQL(""), "", ""
	if heat {
		agg, extra = researcherHeatSQL(), ", max(a.researchers) OVER () AS top"
		cols = `,
       m.top, m.days, NOT EXISTS (SELECT 1 FROM ` + researcherPostFrom + `
                                  WHERE ` + researcherPostWhere + ` AND p.cve_id = m.cve_id AND p.occurred_at < $5)`
	}
	return `
SELECT m.cve_id, m.researchers, v.title, v.title_zh, s.stage, s.stage_rank, COALESCE(s.is_rejected, false),
       s.last_transition_at, s.last_transition_type,
       e.id, e.source, e.occurred_at, e.is_backfill, e.detail->>'precision',
       COALESCE(s.has_disclosed, false), s.disclosed_at, COALESCE(s.has_patch, false), s.patch_at,
       COALESCE(s.has_analysis, false), s.analysis_at, COALESCE(s.has_poc, false), s.poc_at,
       COALESCE(s.has_itw, false), s.itw_at, COALESCE(s.in_kev, false), s.kev_at, COALESCE(s.poc_sources, 0),
       COALESCE(af.n, 0), COALESCE(af.vendors, '{}'), COALESCE(af.products, '{}'), m.total::int` + cols + `, ` + titleCols + `
FROM (SELECT a.*, count(*) OVER () AS total` + extra + ` FROM (` + agg + `) a
      ORDER BY a.researchers DESC, a.last_at DESC, a.cve_id
      LIMIT $3 OFFSET $4) m
JOIN vuln v ON v.cve_id = m.cve_id
LEFT JOIN vuln_state_mat s ON s.cve_id = m.cve_id
LEFT JOIN event e ON e.id = s.last_transition_event_id
LEFT JOIN LATERAL (` + strings.ReplaceAll(productsLateral, "s.cve_id", "m.cve_id") + `) af ON true` + titleJoinM + `
ORDER BY m.researchers DESC, m.last_at DESC, m.cve_id`
}

var (
	discussedSelect     = discussedSQL(false)
	discussedHeatSelect = discussedSQL(true)
)

// freshSince is the start of yesterday (UTC) for now: a CVE whose first
// researcher post is at or after it is Fresh.
func freshSince(now time.Time) time.Time { return utcDayStart(now).AddDate(0, 0, -1) }

// Discussed returns a page of CVEs ranked by researcher count (last 7
// days), ties by most recent post, then CVE id (ascending).
func (s *Store) Discussed(ctx context.Context, p DiscussedParams) (*DiscussedPage, error) {
	p, err := p.Normalize()
	if err != nil {
		return nil, err
	}
	now := s.clock()
	from, to := researcherWindow(now)
	page := &DiscussedPage{Window: FormatSince(ResearcherWindow), Limit: p.Limit, Offset: p.Offset, Rows: []DiscussedRow{}, GeneratedAt: now}
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		var rows pgx.Rows
		var err error
		if p.Heat {
			rows, err = conn.Query(ctx, discussedHeatSelect, from, to, p.Limit+1, p.Offset, freshSince(now))
		} else {
			rows, err = conn.Query(ctx, discussedSelect, from, to, p.Limit+1, p.Offset)
		}
		if err != nil {
			return err
		}
		page.Rows, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (DiscussedRow, error) { return scanDiscussedRow(r, p.Heat) })
		if err != nil {
			return err
		}
		if len(page.Rows) > 0 {
			page.Total, page.Top = page.Rows[0].total, page.Rows[0].top
		}
		if len(page.Rows) > p.Limit {
			page.Rows = page.Rows[:p.Limit]
			n := p.Offset + p.Limit
			if n <= MaxHotOffset {
				page.NextOffset = &n
			}
		}
		ids := make([]string, len(page.Rows))
		for i, r := range page.Rows {
			ids[i] = r.CVEID
		}
		ts, err := rowSlugs(ctx, conn, ids)
		if err != nil {
			return err
		}
		for i := range page.Rows {
			if t := ts[page.Rows[i].CVEID]; t != nil {
				page.Rows[i].Tags = t
			}
		}
		if !p.Heat {
			return nil
		}
		// the avatars: one query for the rows shown
		faces, err := researcherFaces(ctx, conn, now, ids)
		for i := range page.Rows {
			page.Rows[i].Faces = faces[page.Rows[i].CVEID]
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return page, nil
}

func scanDiscussedRow(r pgx.CollectableRow, heat bool) (DiscussedRow, error) {
	var d DiscussedRow
	var days []int32
	var stage, trType *string
	var rank *int
	var trAt *time.Time
	var evID *int64
	var evSource, prec *string
	var occ *time.Time
	var backfill *bool
	var in SlotInput
	var vendors, products []string
	var ts titleScan
	dest := []any{&d.CVEID, &d.Researchers, &d.Title, &d.TitleZh, &stage, &rank, &d.IsRejected,
		&trAt, &trType,
		&evID, &evSource, &occ, &backfill, &prec,
		&in.Exists[0], &in.FirstAt[0], &in.Exists[1], &in.FirstAt[1], &in.Exists[2], &in.FirstAt[2],
		&in.Exists[3], &in.FirstAt[3], &in.Exists[4], &in.FirstAt[4], &in.Exists[5], &in.FirstAt[5],
		&d.PocSources, &d.ProductCount, &vendors, &products, &d.total}
	if heat {
		dest = append(dest, &d.top, &days, &d.Fresh)
	}
	if err := r.Scan(append(dest, ts.dest()...)...); err != nil {
		return d, err
	}
	for i := 0; i < HeatDays && i < len(days); i++ {
		d.Days[i] = int(days[i])
	}
	d.TitleInfo = ts.info(d.Title)
	if stage != nil {
		code := StageCode(*stage)
		d.Stage, d.StageCode = stage, &code
	}
	if trAt != nil && trType != nil {
		t := &Transition{Type: *trType, Code: StageCode(*trType), At: trAt.UTC(), Source: evSource, EventID: evID}
		bf := true
		if backfill != nil {
			bf = *backfill
		}
		t.Precision = EventPrecision(occ, bf, prec)
		if evID == nil {
			t.Precision = PrecisionExact // see scanHotRow
		}
		d.Transition = t
		in.Latest = t.Type
	}
	d.Slots = ComputeSlots(in)
	d.DisclosedAt = utcPtr(in.FirstAt[0])
	if d.Transition != nil {
		d.DaysSinceDisclosure = CalendarDays(d.DisclosedAt, &d.Transition.At)
	}
	d.Tags = []string{}
	d.Products = make([]Product, 0, len(vendors))
	for i := range vendors {
		if i < len(products) {
			d.Products = append(d.Products, Product{Vendor: vendors[i], Product: products[i]})
		}
	}
	return d, nil
}

// HotRow is d as a hot-list row (for shared rendering); ok is false for a
// CVE without a lifecycle state.
func (d DiscussedRow) HotRow() (HotRow, bool) {
	h := HotRow{CVEID: d.CVEID, Title: d.Title, TitleZh: d.TitleZh, TitleInfo: d.TitleInfo, Products: d.Products, ProductCount: d.ProductCount,
		IsRejected: d.IsRejected, Slots: d.Slots, DisclosedAt: d.DisclosedAt, DaysSinceDisclosure: d.DaysSinceDisclosure,
		PocSources: d.PocSources, Tags: d.Tags, Researchers: d.Researchers}
	if d.Stage == nil || d.Transition == nil {
		return h, false
	}
	h.Stage, h.StageCode, h.Transition = *d.Stage, *d.StageCode, *d.Transition
	return h, true
}
