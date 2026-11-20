package site

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Lengths of the public lists, for the pager's "page X of Y"
// (docs/pagination.md). Each is a count with exactly the list's filters;
// callers cache it per filter combination (never per position), so it may
// lag the rows by the cache's lifetime.

// HotTotal is the length of a hot list.
type HotTotal struct {
	// Rows: the ordinary rows (the list's filters, pinned CVEs left out
	// exactly as Hot leaves them out), Limit of them per page.
	Rows int64
	// Pins: the pinned rows the first page starts with.
	Pins int
}

// Pages is the number of pages of limit ordinary rows (≥ 1; the first page
// also holds the pinned rows).
func (t HotTotal) Pages(limit int) int {
	if limit < 1 || t.Rows <= int64(limit) {
		return 1
	}
	return int((t.Rows + int64(limit) - 1) / int64(limit))
}

// hotCountSQL counts the hot list's ordinary rows (hotWhere; %s: the
// pinned ids and the tag filters). The window bounds the walk: a bitmap or
// range scan of vuln_state_mat_hot_idx from the window start
// (TestListCountPlans).
const hotCountSQL = `SELECT count(*) FROM vuln_state_mat m
WHERE ` + hotWhere + `%s`

// HotCount is the length of the hot list p selects (its position, limit
// and offset do not matter): the ordinary rows and the pinned ones, the
// pins chosen as Hot chooses them. ok is false when it is not counted (a
// tag filter whose smallest tag is above TagCountMax: nothing else runs).
func (s *Store) HotCount(ctx context.Context, p HotParams) (t HotTotal, ok bool, err error) {
	p, err = p.Normalize()
	if err != nil {
		return HotTotal{}, false, err
	}
	now := s.clock()
	start, types := now.Add(-p.Since), hotTypes(p.MinStage)
	pcfg := s.PinConfig()
	if p.NoPins {
		pcfg.Max = 0
	}
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		if ok, err = tagsCountable(ctx, conn, p.Tags); err != nil || !ok {
			return err
		}
		pinIDs, err := pinnedIDs(ctx, conn, pcfg, now, start, types, p.IncludeRejected, p.Tags)
		if err != nil {
			return err
		}
		pins := make([]string, 0, len(pinIDs))
		seen := map[string]bool{}
		for _, pi := range pinIDs {
			if !seen[pi.ID] {
				seen[pi.ID] = true
				pins = append(pins, pi.ID)
			}
		}
		t.Pins = len(pins)
		sql, args := hotCountQuery(start, types, p.IncludeRejected, pins, p.Tags)
		return conn.QueryRow(ctx, sql, args...).Scan(&t.Rows)
	})
	if err != nil || !ok {
		return HotTotal{}, false, err
	}
	return t, true, nil
}

// hotCountQuery is the count of HotCount with its arguments.
func hotCountQuery(start any, types []string, includeRejected bool, pins, tags []string) (string, []any) {
	args := []any{start, types, includeRejected}
	extra := ""
	if len(pins) > 0 {
		args = append(args, pins)
		extra = fmt.Sprintf("\n        AND m.cve_id <> ALL($%d)", len(args))
	}
	tf, targs := tagFilterSQL("m.cve_id", tags, len(args)+1)
	return fmt.Sprintf(hotCountSQL, extra+tf), append(args, targs...)
}

// HotCountKey is the cache key of HotCount(p) for normalized p: every
// filter and the pinning numbers in force, not the position or the page
// size.
func (s *Store) HotCountKey(p HotParams) string {
	return fmt.Sprintf("hotn|%d|%s|%t|%s|%t|%s", p.Since, p.MinStage, p.IncludeRejected, strings.Join(p.Tags, ","), p.NoPins,
		s.PinConfig().key())
}

// TagCountMax: a list (hot list, catalogue) filtered by tags is counted
// only when its smallest tag has at most this many CVEs (vuln_tag_count).
// Counting a tag reads its entries of vuln_tag_tag_idx and, past a few
// thousand, one pass over vuln_state_mat in a hash semi-join
// (TestListCountPlans); on the hot list a long window with a broad tag
// probes the tag for every row of the window (546 ms on production for
// 366d and network). The broadest tags (network, no-auth, …: 50k+ CVEs)
// are not counted and their pager shows no page count.
const TagCountMax = 50000

// tagsCountable reports whether a list filtered by tags is counted: no
// tags, or the smallest one has at most TagCountMax CVEs (a tag missing
// from vuln_tag_count has none). One primary-key lookup per tag.
func tagsCountable(ctx context.Context, conn *pgx.Conn, tags []string) (bool, error) {
	if len(tags) == 0 {
		return true, nil
	}
	var least *int64
	if err := conn.QueryRow(ctx, `SELECT min(n) FROM vuln_tag_count WHERE tag = ANY($1)`, tags).Scan(&least); err != nil {
		return false, err
	}
	return least == nil || *least <= TagCountMax, nil
}

// catalogueCountSQL counts the catalogue's rows (%s: catalogueCommon and
// the tag filters). A year (with or without a stage) is a bitmap scan of
// vuln_state_mat_year_idx / _stage_year_idx; the planner may read the view
// sequentially for the densest years (TestListCountPlans).
const catalogueCountSQL = `SELECT count(*) FROM vuln_state_mat m
WHERE %s`

// CatalogueCount is the length of the catalogue p selects (its position
// and limit do not matter); ok is false when it is not counted (a tag
// filter whose smallest tag is above TagCountMax).
func (s *Store) CatalogueCount(ctx context.Context, p CatalogueParams) (n int64, ok bool, err error) {
	p, err = p.Normalize()
	if err != nil {
		return 0, false, err
	}
	err = s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		if ok, err = tagsCountable(ctx, conn, p.Tags); err != nil || !ok {
			return err
		}
		sql, args := catalogueCountQuery(p)
		return conn.QueryRow(ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		return 0, false, err
	}
	return n, ok, nil
}

// catalogueCountQuery is the count of CatalogueCount with its arguments.
func catalogueCountQuery(p CatalogueParams) (string, []any) {
	common, _ := catalogueCommon(p)
	if len(common) == 0 {
		common = []string{"true"}
	}
	tf, args := tagFilterSQL("m.cve_id", p.Tags, 1)
	return fmt.Sprintf(catalogueCountSQL, strings.Join(common, "\n        AND ")+tf), args
}

// CountKey is the cache key of CatalogueCount(p) for normalized p:
// every filter, not the position or the page size.
func (p CatalogueParams) CountKey() string {
	return fmt.Sprintf("vulnsn|%s|%d|%t|%s|%s-%s", p.Stage, p.Year, p.IncludeRejected, strings.Join(p.Tags, ","),
		p.CVSSMin, p.CVSSMax)
}
