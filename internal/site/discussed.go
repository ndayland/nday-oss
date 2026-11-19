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
func (p DiscussedParams) CacheKey() string { return fmt.Sprintf("discussed|%d|%d", p.Limit, p.Offset) }

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
	total       int // the ranking's length (DiscussedPage.Total)
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
}

// discussedSelect ranks the aggregate (researcherAggSQL) and joins the
// hot-row data of the page's rows only. $3 limit, $4 offset. The last
// column is the number of ranked CVEs (a window count over the aggregate,
// taken before LIMIT).
var discussedSelect = `
SELECT m.cve_id, m.researchers, v.title, v.title_zh, s.stage, s.stage_rank, COALESCE(s.is_rejected, false),
       s.last_transition_at, s.last_transition_type,
       e.id, e.source, e.occurred_at, e.is_backfill, e.detail->>'precision',
       COALESCE(s.has_disclosed, false), s.disclosed_at, COALESCE(s.has_patch, false), s.patch_at,
       COALESCE(s.has_analysis, false), s.analysis_at, COALESCE(s.has_poc, false), s.poc_at,
       COALESCE(s.has_itw, false), s.itw_at, COALESCE(s.in_kev, false), s.kev_at, COALESCE(s.poc_sources, 0),
       COALESCE(af.n, 0), COALESCE(af.vendors, '{}'), COALESCE(af.products, '{}'), m.total::int, ` + titleCols + `
FROM (SELECT a.*, count(*) OVER () AS total FROM (` + researcherAggSQL("") + `) a
      ORDER BY a.researchers DESC, a.last_at DESC, a.cve_id
      LIMIT $3 OFFSET $4) m
JOIN vuln v ON v.cve_id = m.cve_id
LEFT JOIN vuln_state_mat s ON s.cve_id = m.cve_id
LEFT JOIN event e ON e.id = s.last_transition_event_id
LEFT JOIN LATERAL (` + strings.ReplaceAll(productsLateral, "s.cve_id", "m.cve_id") + `) af ON true` + titleJoinM + `
ORDER BY m.researchers DESC, m.last_at DESC, m.cve_id`

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
		rows, err := conn.Query(ctx, discussedSelect, from, to, p.Limit+1, p.Offset)
		if err != nil {
			return err
		}
		page.Rows, err = pgx.CollectRows(rows, scanDiscussedRow)
		if err != nil {
			return err
		}
		if len(page.Rows) > 0 {
			page.Total = page.Rows[0].total
		}
		ids := make([]string, len(page.Rows))
		for i, r := range page.Rows {
			ids[i] = r.CVEID
		}
		ts, err := rowSlugs(ctx, conn, ids)
		for i := range page.Rows {
			if t := ts[page.Rows[i].CVEID]; t != nil {
				page.Rows[i].Tags = t
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(page.Rows) > p.Limit {
		page.Rows = page.Rows[:p.Limit]
		n := p.Offset + p.Limit
		if n <= MaxHotOffset {
			page.NextOffset = &n
		}
	}
	return page, nil
}

func scanDiscussedRow(r pgx.CollectableRow) (DiscussedRow, error) {
	var d DiscussedRow
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
	err := r.Scan(append([]any{&d.CVEID, &d.Researchers, &d.Title, &d.TitleZh, &stage, &rank, &d.IsRejected,
		&trAt, &trType,
		&evID, &evSource, &occ, &backfill, &prec,
		&in.Exists[0], &in.FirstAt[0], &in.Exists[1], &in.FirstAt[1], &in.Exists[2], &in.FirstAt[2],
		&in.Exists[3], &in.FirstAt[3], &in.Exists[4], &in.FirstAt[4], &in.Exists[5], &in.FirstAt[5],
		&d.PocSources, &d.ProductCount, &vendors, &products, &d.total}, ts.dest()...)...)
	if err != nil {
		return d, err
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
