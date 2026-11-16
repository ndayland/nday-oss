package site

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"nday.land/nday/internal/model"
)

// Hot list limits.
const (
	DefaultHotLimit = 50
	MaxHotLimit     = 200
	MaxHotOffset    = 10000
)

// HotParams select the hot list.
type HotParams struct {
	// Since is the window: transitions at or after now-Since (1h..366d).
	Since time.Duration
	// MinStage is an event type (see ParseStage); only transitions to this
	// stage or a later one are listed. "" = patch_released.
	MinStage string
	// IncludeRejected also lists CVEs whose CVE record is REJECTED.
	IncludeRejected bool
	// Limit rows per page (default 50, max 200).
	Limit int
	// Offset skips rows (max 10000). Ignored when Cursor is set.
	Offset int
	// Cursor continues after the last row of a previous page (HotPage.NextCursor).
	Cursor string
	// Tags: only CVEs that have every one of these tags (vocabulary slugs,
	// at most tags.MaxFilterTags; see NormalizeTags).
	Tags []string
	// NoPins: no pinned rows (pin.go); every row in the usual order (the
	// Atom feed).
	NoPins bool
}

// Product is one affected vendor/product pair.
type Product struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// Transition is a vulnerability's most recent arrival of a NEW event type.
type Transition struct {
	Type string `json:"type"`
	Code string `json:"code"`
	// At is the effective time (for day precision: 00:00Z of that date).
	At        time.Time `json:"at"`
	Precision string    `json:"precision"` // day | exact | observed
	Source    *string   `json:"source"`    // collector that reported the defining event
	EventID   *int64    `json:"event_id"`
}

// HotRow is one row of the hot list.
type HotRow struct {
	CVEID   string  `json:"cve_id"`
	Title   *string `json:"title"`
	TitleZh *string `json:"title_zh"`
	// Products: up to 2 vendor/product pairs (deduplicated case-insensitively,
	// first reported first); ProductCount is the total number of pairs.
	Products     []Product  `json:"products"`
	ProductCount int        `json:"product_count"`
	Stage        string     `json:"stage"`
	StageCode    string     `json:"stage_code"`
	IsRejected   bool       `json:"is_rejected"`
	Transition   Transition `json:"transition"`
	// Slots: always 6, in order DIS PAT ANA POC ITW KEV.
	Slots       []Slot     `json:"slots"`
	DisclosedAt *time.Time `json:"disclosed_at"`
	// DaysSinceDisclosure: calendar days (UTC) from disclosure to the
	// transition; nil if either time is unknown.
	DaysSinceDisclosure *int `json:"days_since_disclosure"`
	// PocSources: how many of exploitdb, metasploit, nuclei have a PoC event.
	PocSources int `json:"poc_sources"`
	// Tags: the CVE's tags (slugs, vocabulary order; internal/tags).
	Tags []string `json:"tags"`
	// Researchers: how many distinct allow-listed researchers posted about
	// the CVE on X in the last 7 days (public aggregate; public.go).
	Researchers int `json:"researchers_7d"`
	// Pinned: researchers are discussing the CVE right now, so it is shown
	// first (only on the first page; pin.go has the rule). A pinned CVE is
	// left out of the ordinary rows of every page.
	Pinned bool `json:"pinned"`
	// PinReason: why a pinned row is pinned — PinRule ("rule") or
	// PinDiscussed ("discussed": filled from the discussed ranking); empty
	// (omitted) on ordinary rows.
	PinReason string `json:"pin_reason,omitempty"`
}

// HotPage is one page of the hot list.
type HotPage struct {
	Since           string    `json:"since"`       // canonical window, e.g. "30d"
	SinceStart      time.Time `json:"since_start"` // window start instant
	MinStage        string    `json:"min_stage"`
	MinStageCode    string    `json:"min_stage_code"`
	IncludeRejected bool      `json:"include_rejected"`
	Limit           int       `json:"limit"`
	Offset          int       `json:"offset"`
	Tags            []string  `json:"tags"` // the tag filter (AND)
	Rows            []HotRow  `json:"rows"`
	// NextCursor is set when more rows follow; pass it as HotParams.Cursor.
	NextCursor  *string   `json:"next_cursor"`
	GeneratedAt time.Time `json:"generated_at"`
}

// Normalize validates p and fills defaults; the result is canonical (two
// equal canonical params give the same page), suitable as a cache key.
func (p HotParams) Normalize() (HotParams, error) {
	if p.Since == 0 {
		p.Since = 7 * 24 * time.Hour
	}
	if p.Since < MinSince || p.Since > MaxSince {
		return p, &InputError{Param: "since", Msg: "out of range (1h to 366d)"}
	}
	if p.MinStage == "" {
		p.MinStage = model.EventPatchReleased
	}
	st, err := ParseStage(p.MinStage)
	if err != nil {
		return p, err
	}
	p.MinStage = st
	if p.Limit == 0 {
		p.Limit = DefaultHotLimit
	}
	if p.Limit < 1 || p.Limit > MaxHotLimit {
		return p, &InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", MaxHotLimit)}
	}
	if p.Offset < 0 || p.Offset > MaxHotOffset {
		return p, &InputError{Param: "offset", Msg: fmt.Sprintf("must be 0..%d", MaxHotOffset)}
	}
	if p.Cursor != "" {
		if _, err := decodeCursor(p.Cursor); err != nil {
			return p, err
		}
		p.Offset = 0
	}
	if p.Tags, err = NormalizeTags(p.Tags); err != nil {
		return p, err
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}
	return p, nil
}

// CacheKey is a canonical string for normalized params.
func (p HotParams) CacheKey() string {
	return fmt.Sprintf("hot|%d|%s|%t|%d|%d|%s|%s|%t", p.Since, p.MinStage, p.IncludeRejected, p.Limit, p.Offset, p.Cursor,
		strings.Join(p.Tags, ","), p.NoPins)
}

type cursor struct {
	at   time.Time
	rank int
	cve  string
}

func encodeCursor(c cursor) string {
	s := strconv.FormatInt(c.at.UnixMicro(), 10) + "|" + strconv.Itoa(c.rank) + "|" + c.cve
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func decodeCursor(s string) (cursor, error) {
	bad := &InputError{Param: "cursor", Msg: "invalid cursor"}
	if len(s) > 100 {
		return cursor{}, bad
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, bad
	}
	parts := strings.Split(string(b), "|")
	if len(parts) != 3 {
		return cursor{}, bad
	}
	us, err1 := strconv.ParseInt(parts[0], 10, 64)
	rank, err2 := strconv.Atoi(parts[1])
	cve, ok := ParseCVEID(parts[2])
	if err1 != nil || err2 != nil || !ok || rank < 1 || rank > 6 {
		return cursor{}, bad
	}
	return cursor{at: time.UnixMicro(us).UTC(), rank: rank, cve: cve}, nil
}

// hotCols and hotJoins are the hot-row columns (scanHotRow) of the rows s
// of vuln_state_mat.
const hotCols = `
SELECT s.cve_id, v.title, v.title_zh, s.stage, s.stage_rank, s.is_rejected,
       s.last_transition_at, s.last_transition_type,
       e.id, e.source, e.occurred_at, e.is_backfill, e.detail->>'precision',
       s.has_disclosed, s.disclosed_at, s.has_patch, s.patch_at, s.has_analysis, s.analysis_at,
       s.has_poc, s.poc_at, s.has_itw, s.itw_at, s.in_kev, s.kev_at, s.poc_sources,
       COALESCE(af.n, 0), COALESCE(af.vendors, '{}'), COALESCE(af.products, '{}')`

const hotJoins = `
JOIN vuln v USING (cve_id)
LEFT JOIN event e ON e.id = s.last_transition_event_id
LEFT JOIN LATERAL (` + productsLateral + `) af ON true`

// hotSelect is shared by the first page and the keyset continuation. The
// inner query walks vuln_state_mat_hot_idx backwards and stops after
// LIMIT+1 rows; joins and the affected lateral run only for those rows.
const hotSelect = hotCols + `
FROM (SELECT m.*
      FROM vuln_state_mat m
      WHERE m.last_transition_at >= $1
        AND m.last_transition_type = ANY($2)
        AND ($3 OR NOT m.is_rejected)
        %s
      ORDER BY m.last_transition_at DESC, m.stage_rank DESC, m.cve_id DESC
      LIMIT $4 OFFSET $5) s` + hotJoins + `
ORDER BY s.last_transition_at DESC, s.stage_rank DESC, s.cve_id DESC`

// pinnedSelect fetches the pinned rows by id ($1). No list filter: the ids
// come from pinnedIDs, which applied the filters each kind of pin needs (a
// fill row may lie outside the window or below the minimum stage, and may
// have no known transition time).
const pinnedSelect = hotCols + `
FROM vuln_state_mat s` + hotJoins + `
WHERE s.cve_id = ANY($1)`

// productsLateral: distinct (case-insensitive) vendor/product pairs of
// s.cve_id, first reported first; total count and the first two.
const productsLateral = `
    SELECT count(*)::int AS n,
           (array_agg(d.vendor ORDER BY d.first_id))[1:2] AS vendors,
           (array_agg(d.product ORDER BY d.first_id))[1:2] AS products
    FROM (SELECT DISTINCT ON (lower(a.vendor), lower(a.product))
                 a.vendor, a.product, a.id AS first_id
          FROM affected a WHERE a.cve_id = s.cve_id
          ORDER BY lower(a.vendor), lower(a.product), a.id) d`

// Hot returns vulnerabilities whose most recent transition falls in the
// window, newest first (transition time desc, stage rank desc, CVE id desc).
//
// Unless p.NoPins, the first page (no cursor, offset 0) starts with up to
// PinConfig().Max pinned rows (Pinned and PinReason set; pin.go: the
// rule's, then the fill from the discussed ranking) followed by up to
// p.Limit ordinary rows, so it may hold p.Limit+Max rows. Every page
// leaves the pinned CVEs out of its ordinary rows; NextCursor, Offset and
// Limit concern the ordinary rows only.
func (s *Store) Hot(ctx context.Context, p HotParams) (*HotPage, error) {
	p, err := p.Normalize()
	if err != nil {
		return nil, err
	}
	now := s.clock()
	start := now.Add(-p.Since)
	idx := stageIndex(p.MinStage)
	types := make([]string, 0, 6)
	for _, st := range StageInfos[idx:] {
		types = append(types, st.Type)
	}
	page := &HotPage{
		Since: FormatSince(p.Since), SinceStart: start, MinStage: p.MinStage, MinStageCode: StageCode(p.MinStage),
		IncludeRejected: p.IncludeRejected, Limit: p.Limit, Offset: p.Offset, Tags: p.Tags, Rows: []HotRow{}, GeneratedAt: now,
	}
	pcfg := s.PinConfig()
	if p.NoPins {
		pcfg.Max = 0
	}
	first := p.Cursor == "" && p.Offset == 0
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		var pinned []HotRow
		pinIDs, err := pinnedIDs(ctx, conn, pcfg, now, start, types, p.IncludeRejected, p.Tags)
		if err != nil {
			return err
		}
		// pins: the ids, each once (pinSQL already keeps the rule's and the
		// fill's apart; the first occurrence wins).
		pins := make([]string, 0, len(pinIDs))
		reason := make(map[string]string, len(pinIDs))
		for _, pi := range pinIDs {
			if _, dup := reason[pi.ID]; !dup {
				reason[pi.ID] = pi.Reason
				pins = append(pins, pi.ID)
			}
		}
		args := []any{start, types, p.IncludeRejected, p.Limit + 1, p.Offset}
		extra := ""
		if p.Cursor != "" {
			c, _ := decodeCursor(p.Cursor)
			extra = "AND (m.last_transition_at, m.stage_rank, m.cve_id) < ($6, $7, $8)"
			args = append(args, c.at, c.rank, c.cve)
		}
		if len(pins) > 0 {
			args = append(args, pins)
			extra += fmt.Sprintf("\n        AND m.cve_id <> ALL($%d)", len(args))
		}
		tf, targs := tagFilterSQL("m.cve_id", p.Tags, len(args)+1)
		rows, err := conn.Query(ctx, fmt.Sprintf(hotSelect, extra+tf), append(args, targs...)...)
		if err != nil {
			return err
		}
		page.Rows, err = pgx.CollectRows(rows, scanHotRow)
		if err != nil {
			return err
		}
		if first && len(pins) > 0 {
			// The pinned rows themselves, in pin order.
			rows, err := conn.Query(ctx, pinnedSelect, pins)
			if err != nil {
				return err
			}
			got, err := pgx.CollectRows(rows, scanHotRow)
			if err != nil {
				return err
			}
			byID := make(map[string]HotRow, len(got))
			for _, r := range got {
				r.Pinned, r.PinReason = true, reason[r.CVEID]
				byID[r.CVEID] = r
			}
			for _, id := range pins {
				if r, ok := byID[id]; ok {
					pinned = append(pinned, r)
				}
			}
		}
		if len(page.Rows) > p.Limit {
			page.Rows = page.Rows[:p.Limit]
			last := page.Rows[p.Limit-1]
			// The keyset is (last_transition_at, stage_rank, cve_id), and
			// stage_rank is the CURRENT stage's rank (last.Stage), which
			// can exceed the last transition type's (a KEV listing older
			// than a later patch).
			c := encodeCursor(cursor{at: last.Transition.At, rank: stageIndex(last.Stage) + 1, cve: last.CVEID})
			page.NextCursor = &c
		}
		if len(pinned) > 0 {
			page.Rows = append(pinned, page.Rows...)
		}
		ids := make([]string, len(page.Rows))
		for i, r := range page.Rows {
			ids[i] = r.CVEID
		}
		ts, err := rowSlugs(ctx, conn, ids)
		if err != nil {
			return err
		}
		rc, err := researcherCounts(ctx, conn, now, ids)
		for i := range page.Rows {
			if t := ts[page.Rows[i].CVEID]; t != nil {
				page.Rows[i].Tags = t
			}
			page.Rows[i].Researchers = rc[page.Rows[i].CVEID]
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return page, nil
}

func scanHotRow(r pgx.CollectableRow) (HotRow, error) {
	var h HotRow
	var rank int
	var evID *int64
	var evSource, prec *string
	var occ *time.Time
	var backfill *bool
	var in SlotInput
	var vendors, products []string
	// trAt/trType are NULL only for a catalogue row whose stage events all
	// have unknown times (catalogue.go); the hot list never selects one.
	var trAt *time.Time
	var trType *string
	err := r.Scan(&h.CVEID, &h.Title, &h.TitleZh, &h.Stage, &rank, &h.IsRejected,
		&trAt, &trType,
		&evID, &evSource, &occ, &backfill, &prec,
		&in.Exists[0], &in.FirstAt[0], &in.Exists[1], &in.FirstAt[1], &in.Exists[2], &in.FirstAt[2],
		&in.Exists[3], &in.FirstAt[3], &in.Exists[4], &in.FirstAt[4], &in.Exists[5], &in.FirstAt[5],
		&h.PocSources, &h.ProductCount, &vendors, &products)
	if err != nil {
		return h, err
	}
	h.StageCode = StageCode(h.Stage)
	if trAt == nil || trType == nil {
		return finishNoTransition(h, in, vendors, products), nil
	}
	h.Transition.At, h.Transition.Type = trAt.UTC(), *trType
	h.Transition.Code = StageCode(h.Transition.Type)
	h.Transition.EventID = evID
	h.Transition.Source = evSource
	bf := true
	if backfill != nil {
		bf = *backfill
	}
	h.Transition.Precision = EventPrecision(occ, bf, prec)
	if evID == nil {
		// Event id missing only if the materialized row predates a change to
		// its events; the time itself is still effective, so it is not
		// "unknown" — report it as observed/exact conservatively.
		h.Transition.Precision = PrecisionExact
	}
	in.Latest = h.Transition.Type
	h.Slots = ComputeSlots(in)
	h.DisclosedAt = utcPtr(in.FirstAt[0])
	h.DaysSinceDisclosure = CalendarDays(h.DisclosedAt, &h.Transition.At)
	fillProducts(&h, vendors, products)
	return h, nil
}

// finishNoTransition completes a row without a known transition: no
// transition time or type (Transition.At zero, marshalled as null), no
// latest slot, no T+ days.
func finishNoTransition(h HotRow, in SlotInput, vendors, products []string) HotRow {
	h.Transition = Transition{Precision: PrecisionUnknown}
	h.Slots = ComputeSlots(in)
	h.DisclosedAt = utcPtr(in.FirstAt[0])
	fillProducts(&h, vendors, products)
	return h
}

func fillProducts(h *HotRow, vendors, products []string) {
	h.Tags = []string{}
	h.Products = make([]Product, 0, len(vendors))
	for i := range vendors {
		if i < len(products) {
			h.Products = append(h.Products, Product{Vendor: vendors[i], Product: products[i]})
		}
	}
}
