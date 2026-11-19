package site

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The catalogue: every vulnerability of vuln_state_mat (every CVE with at
// least one lifecycle event), most recent change first, filterable by
// current stage, CVE id year and tags. Unlike the hot list it has no time
// window, no minimum stage and no pinned rows, and it pages by cursor only.
//
// Order: last_transition_at DESC NULLS LAST, stage_rank DESC, cve_id DESC.
// A CVE whose stage events all have unknown times has no
// last_transition_at; those rows form a tail after every dated row, ordered
// by stage_rank DESC, cve_id DESC.
//
// Plans (migrations/0021_catalogue_indexes.sql): the query is the dated part
// UNION ALL the undated tail, each an index walk in the order above that
// stops after LIMIT+1 rows; the tail is not read while the dated part fills
// the page. Stage and year are inlined as literals (validated integers) so
// the planner sees the actual value instead of a generic parameter.
//
//	no stage, no year  vuln_state_mat_hot_idx           (at, rank, cve)
//	stage              vuln_state_mat_stage_idx         (rank, at, cve)
//	year               vuln_state_mat_year_idx          (year, at, rank, cve)
//	stage + year       vuln_state_mat_stage_year_idx    (rank, year, at, cve)
//
// each walked backwards. Tags are EXISTS filters as on the hot list.

// Catalogue limits.
const (
	DefaultCatalogueLimit = 50
	MaxCatalogueLimit     = 200
	// MinCatalogueYear is the first CVE id year.
	MinCatalogueYear = 1999
)

// CatalogueParams select a catalogue page. The zero value is the first page
// of everything (rejected CVEs left out).
type CatalogueParams struct {
	// Stage: only CVEs whose CURRENT stage is exactly this one (ParseStage
	// vocabulary: disclosed, patch, analysis, poc, exploited, kev, a code or
	// the full event type). "" = every stage.
	Stage string
	// Year: only CVE ids CVE-<Year>-…; 0 = every year
	// (MinCatalogueYear..current UTC year + 1). A vulnerability keyed by a
	// GHSA id has no year and is left out whenever Year is set.
	Year int
	// Tags: only CVEs that have every one of these tags (as HotParams.Tags).
	Tags []string
	// IncludeRejected also lists CVEs whose CVE record is REJECTED.
	IncludeRejected bool
	// Limit rows per page (default 50, max 200).
	Limit int
	// Cursor continues after the last row of a previous page
	// (CataloguePage.NextCursor, opaque).
	Cursor string
	// Before pages backwards: the Limit rows just before a position
	// (CataloguePage.PrevCursor), in the usual order. When no row comes
	// before those, the page is the first page exactly as without Before.
	// Not combined with Cursor.
	Before string
}

// CataloguePage is one catalogue page. Rows are hot-list rows (Pinned is
// always false); a row without a known transition has transition.at null,
// transition.type and code "" and precision "unknown".
type CataloguePage struct {
	// Stage/StageCode: the stage filter (event type / three-letter code);
	// nil when not filtering by stage.
	Stage     *string `json:"stage"`
	StageCode *string `json:"stage_code"`
	// Year: the CVE id year filter; nil when not filtering by year.
	Year            *int     `json:"year"`
	Tags            []string `json:"tags"` // the tag filter (AND), canonical
	IncludeRejected bool     `json:"include_rejected"`
	Limit           int      `json:"limit"`
	Rows            []HotRow `json:"rows"`
	// NextCursor is set when more rows follow; pass it as CatalogueParams.Cursor.
	NextCursor *string `json:"next_cursor"`
	// PrevCursor is set when rows come before this page (any page but the
	// first); pass it as CatalogueParams.Before.
	PrevCursor  *string   `json:"prev_cursor"`
	GeneratedAt time.Time `json:"generated_at"`
}

// MaxCatalogueYear is the last accepted Year (next year: ids are reserved
// ahead).
func MaxCatalogueYear() int { return time.Now().UTC().Year() + 1 }

// Normalize validates p and fills defaults; the result is canonical (two
// equal canonical params give the same page), suitable as a cache key.
func (p CatalogueParams) Normalize() (CatalogueParams, error) {
	if p.Stage != "" {
		st, err := ParseStage(p.Stage)
		if err != nil {
			return p, &InputError{Param: "stage", Msg: fmt.Sprintf("unknown stage %q (use disclosed, patch, analysis, poc, exploited, kev or the full event type)", truncParam(p.Stage))}
		}
		p.Stage = st
	}
	if p.Year != 0 && (p.Year < MinCatalogueYear || p.Year > MaxCatalogueYear()) {
		return p, &InputError{Param: "year", Msg: fmt.Sprintf("must be %d..%d", MinCatalogueYear, MaxCatalogueYear())}
	}
	if p.Limit == 0 {
		p.Limit = DefaultCatalogueLimit
	}
	if p.Limit < 1 || p.Limit > MaxCatalogueLimit {
		return p, &InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", MaxCatalogueLimit)}
	}
	if p.Cursor != "" {
		if _, err := decodeCatCursor(p.Cursor); err != nil {
			return p, err
		}
	}
	if p.Before != "" {
		if p.Cursor != "" {
			return p, &InputError{Param: "before", Msg: "not combined with cursor"}
		}
		if _, err := decodeCatCursor(p.Before); err != nil {
			return p, &InputError{Param: "before", Msg: "invalid cursor"}
		}
	}
	var err error
	if p.Tags, err = NormalizeTags(p.Tags); err != nil {
		return p, err
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}
	return p, nil
}

// CacheKey is a canonical string for normalized params.
func (p CatalogueParams) CacheKey() string {
	k := fmt.Sprintf("vulns|%s|%d|%t|%d|%s|%s", p.Stage, p.Year, p.IncludeRejected, p.Limit, p.Cursor,
		strings.Join(p.Tags, ","))
	if p.Before != "" {
		k += "|before=" + p.Before
	}
	return k
}

// catCursor is the position after a row: its transition time (nil for the
// undated tail), stage rank and CVE id.
type catCursor struct {
	at   *time.Time
	rank int
	cve  string
}

// Catalogue cursors are "v|<unix µs or empty>|<rank>|<cve>", base64url.
func encodeCatCursor(c catCursor) string {
	at := ""
	if c.at != nil {
		at = strconv.FormatInt(c.at.UnixMicro(), 10)
	}
	return base64.RawURLEncoding.EncodeToString([]byte("v|" + at + "|" + strconv.Itoa(c.rank) + "|" + c.cve))
}

func decodeCatCursor(s string) (catCursor, error) {
	bad := &InputError{Param: "cursor", Msg: "invalid cursor"}
	if len(s) > 100 {
		return catCursor{}, bad
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return catCursor{}, bad
	}
	parts := strings.Split(string(b), "|")
	if len(parts) != 4 || parts[0] != "v" {
		return catCursor{}, bad
	}
	var c catCursor
	if parts[1] != "" {
		us, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return catCursor{}, bad
		}
		t := time.UnixMicro(us).UTC()
		c.at = &t
	}
	rank, err := strconv.Atoi(parts[2])
	cve, ok := ParseVulnID(parts[3])
	if err != nil || !ok || rank < 1 || rank > len(StageInfos) || cve != parts[3] {
		return catCursor{}, bad
	}
	c.rank, c.cve = rank, cve
	return c, nil
}

// catalogueSelect: %s is the inner row source (catalogueRows), which
// yields at most LIMIT+1 vuln_state_mat rows in catalogue order.
const catalogueSelect = `
SELECT s.cve_id, v.title, v.title_zh, s.stage, s.stage_rank, s.is_rejected,
       s.last_transition_at, s.last_transition_type,
       e.id, e.source, e.occurred_at, e.is_backfill, e.detail->>'precision',
       s.has_disclosed, s.disclosed_at, s.has_patch, s.patch_at, s.has_analysis, s.analysis_at,
       s.has_poc, s.poc_at, s.has_itw, s.itw_at, s.in_kev, s.kev_at, s.poc_sources,
       COALESCE(af.n, 0), COALESCE(af.vendors, '{}'), COALESCE(af.products, '{}'), ` + titleCols + `
FROM (%s) s
JOIN vuln v USING (cve_id)
LEFT JOIN event e ON e.id = s.last_transition_event_id
LEFT JOIN LATERAL (` + productsLateral + `) af ON true` + titleJoinS + `
ORDER BY s.last_transition_at DESC NULLS LAST, s.stage_rank DESC, s.cve_id DESC`

// catalogueBranch is one ordered index walk (%s: the conditions, then the
// order). Both parts order by the hot index order (at DESC, rank DESC, cve
// DESC; at is constant within each part), so each part is a backward walk
// of the chosen index; a Before page walks it forwards (catUp) from its
// position.
const catalogueBranch = `(SELECT m.*
      FROM vuln_state_mat m
      WHERE %s
      ORDER BY %s
      LIMIT $1)`

const (
	catDown = "m.last_transition_at DESC, m.stage_rank DESC, m.cve_id DESC"
	catUp   = "m.last_transition_at, m.stage_rank, m.cve_id"
)

// catalogueRows builds the inner row source for normalized p and returns
// it with its arguments ($1 = LIMIT+1, then the cursor and tag values).
// For p.Before it yields the at most LIMIT+1 rows nearest before that
// position (catalogueRowsBefore).
func catalogueRows(p CatalogueParams) (string, []any) {
	if p.Before != "" {
		return catalogueRowsBefore(p)
	}
	args := []any{p.Limit + 1}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	common, stageRank := catalogueCommon(p)
	var c *catCursor
	if p.Cursor != "" {
		cc, _ := decodeCatCursor(p.Cursor) // validated by Normalize
		c = &cc
	}
	// dated part
	dated := []string{"m.last_transition_at IS NOT NULL"}
	includeDated := true
	if c != nil {
		switch {
		case c.at == nil:
			includeDated = false // the cursor is in the undated tail
		case stageRank == 0:
			dated = append(dated, fmt.Sprintf("(m.last_transition_at, m.stage_rank, m.cve_id) < (%s, %s, %s)",
				arg(*c.at), arg(c.rank), arg(c.cve)))
		case stageRank == c.rank:
			// stage_rank is fixed: compare (at, cve) so the walk starts at
			// the cursor inside (rank, at, cve)
			dated = append(dated, fmt.Sprintf("(m.last_transition_at, m.cve_id) < (%s, %s)", arg(*c.at), arg(c.cve)))
		case stageRank < c.rank:
			dated = append(dated, "m.last_transition_at <= "+arg(*c.at))
		default:
			dated = append(dated, "m.last_transition_at < "+arg(*c.at))
		}
	}
	// undated tail
	undated := []string{"m.last_transition_at IS NULL"}
	includeUndated := true
	if c != nil && c.at == nil {
		switch {
		case stageRank == 0:
			undated = append(undated, fmt.Sprintf("(m.stage_rank, m.cve_id) < (%s, %s)", arg(c.rank), arg(c.cve)))
		case stageRank == c.rank:
			undated = append(undated, "m.cve_id < "+arg(c.cve))
		case stageRank > c.rank:
			includeUndated = false
		}
	}
	tf, targs := tagFilterSQL("m.cve_id", p.Tags, len(args)+1)
	args = append(args, targs...)
	where := func(own []string) string {
		return strings.Join(append(append([]string{}, own...), common...), "\n        AND ") + tf
	}
	var parts []string
	if includeDated {
		parts = append(parts, fmt.Sprintf(catalogueBranch, where(dated), catDown))
	}
	if includeUndated {
		parts = append(parts, fmt.Sprintf(catalogueBranch, where(undated), catDown))
	}
	switch len(parts) {
	case 0:
		// a stage filter below the rank of an undated cursor: nothing follows
		return "SELECT m.* FROM vuln_state_mat m WHERE false LIMIT $1", args[:1]
	case 1:
		return parts[0], args
	}
	return strings.Join(parts, "\nUNION ALL\n") + "\nLIMIT $1", args
}

// catalogueRowsBefore is catalogueRows for p.Before: the rows before the
// position, nearest first — the undated tail upwards from the position
// when it lies in the tail, then the dated part upwards from its oldest
// row (or from the position when it is dated). Each part is a forward walk
// of the same index; the outer query puts the rows back in list order.
func catalogueRowsBefore(p CatalogueParams) (string, []any) {
	args := []any{p.Limit + 1}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	common, stageRank := catalogueCommon(p)
	c, _ := decodeCatCursor(p.Before) // validated by Normalize
	dated := []string{"m.last_transition_at IS NOT NULL"}
	undated := []string{"m.last_transition_at IS NULL"}
	includeUndated := c.at == nil
	if c.at != nil {
		// before a dated row: dated rows only, the mirror of catalogueRows
		switch {
		case stageRank == 0:
			dated = append(dated, fmt.Sprintf("(m.last_transition_at, m.stage_rank, m.cve_id) > (%s, %s, %s)",
				arg(*c.at), arg(c.rank), arg(c.cve)))
		case stageRank == c.rank:
			dated = append(dated, fmt.Sprintf("(m.last_transition_at, m.cve_id) > (%s, %s)", arg(*c.at), arg(c.cve)))
		case stageRank < c.rank:
			dated = append(dated, "m.last_transition_at > "+arg(*c.at))
		default:
			dated = append(dated, "m.last_transition_at >= "+arg(*c.at))
		}
	} else {
		// before an undated row: the tail rows above it, then every dated row
		switch {
		case stageRank == 0:
			undated = append(undated, fmt.Sprintf("(m.stage_rank, m.cve_id) > (%s, %s)", arg(c.rank), arg(c.cve)))
		case stageRank == c.rank:
			undated = append(undated, "m.cve_id > "+arg(c.cve))
		case stageRank < c.rank:
			includeUndated = false
		}
	}
	tf, targs := tagFilterSQL("m.cve_id", p.Tags, len(args)+1)
	args = append(args, targs...)
	where := func(own []string) string {
		return strings.Join(append(append([]string{}, own...), common...), "\n        AND ") + tf
	}
	d := fmt.Sprintf(catalogueBranch, where(dated), catUp)
	if !includeUndated {
		return d, args
	}
	return fmt.Sprintf(catalogueBranch, where(undated), catUp) + "\nUNION ALL\n" + d + "\nLIMIT $1", args
}

// catalogueCommon is the filter conditions of p that both parts share, and
// the stage filter's rank (0 = every stage).
func catalogueCommon(p CatalogueParams) (common []string, stageRank int) {
	if p.Stage != "" {
		stageRank = stageIndex(p.Stage) + 1
		common = append(common, fmt.Sprintf("m.stage_rank = %d", stageRank))
	}
	if p.Year != 0 {
		// same expression as the year indexes; the literal is a validated
		// year. A GHSA id ("GHSA-xxxx-…") never matches, which is intended.
		common = append(common, fmt.Sprintf("substr(m.cve_id, 5, 4) = '%04d'", p.Year))
	}
	if !p.IncludeRejected {
		common = append(common, "NOT m.is_rejected")
	}
	return common, stageRank
}

// Catalogue returns one page of every vulnerability, most recent change
// first (package comment above). Pinning does not apply.
//
// With p.Before, the page is the p.Limit rows just before that position;
// when no row precedes them, it is the first page itself (computed
// afresh), so paging back always ends on the page a first visit shows.
func (s *Store) Catalogue(ctx context.Context, p CatalogueParams) (*CataloguePage, error) {
	p, err := p.Normalize()
	if err != nil {
		return nil, err
	}
	page, atStart, err := s.catalogue(ctx, p)
	if err == nil && atStart {
		p.Before = ""
		page, _, err = s.catalogue(ctx, p)
	}
	return page, err
}

// catalogue is Catalogue for normalized p; atStart reports a Before page
// that reached the start of the list.
func (s *Store) catalogue(ctx context.Context, p CatalogueParams) (page *CataloguePage, atStart bool, err error) {
	now := s.clock()
	page = &CataloguePage{IncludeRejected: p.IncludeRejected, Limit: p.Limit, Tags: p.Tags, Rows: []HotRow{}, GeneratedAt: now}
	if p.Stage != "" {
		st, code := p.Stage, StageCode(p.Stage)
		page.Stage, page.StageCode = &st, &code
	}
	if p.Year != 0 {
		y := p.Year
		page.Year = &y
	}
	inner, args := catalogueRows(p)
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, fmt.Sprintf(catalogueSelect, inner), args...)
		if err != nil {
			return err
		}
		page.Rows, err = pgx.CollectRows(rows, scanHotRow)
		if err != nil {
			return err
		}
		switch {
		case p.Before != "":
			// in list order; the extra row, if any, is the farthest from
			// the position (the first). Without it nothing precedes these
			// rows: the caller shows the first page instead.
			if len(page.Rows) <= p.Limit {
				atStart = true
				return nil
			}
			page.Rows = page.Rows[1:]
			prev, next := catRowCursor(page.Rows[0]), catRowCursor(page.Rows[len(page.Rows)-1])
			page.PrevCursor, page.NextCursor = &prev, &next
		default:
			if len(page.Rows) > p.Limit {
				page.Rows = page.Rows[:p.Limit]
				c := catRowCursor(page.Rows[p.Limit-1])
				page.NextCursor = &c
			}
			if p.Cursor != "" && len(page.Rows) > 0 {
				c := catRowCursor(page.Rows[0])
				page.PrevCursor = &c
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
		return nil, false, err
	}
	return page, atStart, nil
}

// catRowCursor is the catalogue position of r.
func catRowCursor(r HotRow) string {
	c := catCursor{rank: stageIndex(r.Stage) + 1, cve: r.CVEID}
	if !r.Transition.At.IsZero() {
		at := r.Transition.At
		c.at = &at
	}
	return encodeCatCursor(c)
}

// MarshalJSON writes "at": null for a row without a known transition
// (catalogue rows only; every other Transition has a time and is encoded
// exactly as without this method).
func (t Transition) MarshalJSON() ([]byte, error) {
	type plain Transition
	if !t.At.IsZero() {
		return json.Marshal(plain(t))
	}
	return json.Marshal(struct {
		plain
		At *time.Time `json:"at"`
	}{plain: plain(t)})
}
