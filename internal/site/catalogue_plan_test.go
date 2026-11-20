package site

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/state"
	"nday.land/nday/internal/testutil"
)

// The catalogue's filtered queries are index walks, not a sequential scan
// of vuln_state_mat plus a sort, on a synthetic data set shaped like
// production (mostly disclosed, rare patch_released and KEV, recent years
// dense, old years sparse, a small undated tail). 30,000 rows is far
// smaller than production (~426k), so this proves that the indexes serve
// the queries and the planner picks them at this size; the plan at
// production size still has to be confirmed with EXPLAIN there.
func TestCataloguePlans(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	t.Parallel()
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	const n = 30000
	for _, q := range []string{
		// years: 40% 2026, 20% 2025, the rest spread over 1999..2024
		`INSERT INTO vuln (cve_id, first_seen_at)
		 SELECT format('CVE-%s-%s', CASE WHEN i % 10 < 4 THEN 2026 WHEN i % 10 < 6 THEN 2025 ELSE 1999 + (i % 26) END,
		               lpad(i::text, 6, '0')), now()
		 FROM generate_series(1, ` + strconv.Itoa(n) + `) i`,
		// one event each: patch 0.1%, KEV 0.4%, PoC ~7%, else disclosed;
		// 2% without a time (undated tail)
		`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, is_backfill, dedupe_key)
		 SELECT v.cve_id,
		        CASE WHEN i % 1000 = 3 THEN 'patch_released' WHEN i % 250 = 2 THEN 'kev_added'
		             WHEN i % 15 = 1 THEN 'poc_published' ELSE 'disclosed' END,
		        CASE WHEN i % 50 = 7 THEN NULL ELSE timestamptz '2026-11-01' - i * interval '17 minutes' END,
		        timestamptz '2026-11-01', 'synthetic', true, v.cve_id
		 FROM (SELECT cve_id, row_number() OVER (ORDER BY cve_id) AS i FROM vuln) v`,
		// one vuln_title row each, as after `nday titles` (migration 0031)
		`INSERT INTO vuln_title (cve_id, rule_version) SELECT cve_id, 1 FROM vuln`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := state.Refresh(ctx, d.Conn, state.RefreshOptions{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `ANALYZE vuln_state_mat; ANALYZE vuln; ANALYZE event; ANALYZE vuln_title`); err != nil {
		t.Fatal(err)
	}
	// a deep cursor: the 2000th PoC row
	var at time.Time
	var cve string
	if err := d.Conn.QueryRow(ctx, `SELECT last_transition_at, cve_id FROM vuln_state_mat
        WHERE stage_rank = 4 AND last_transition_at IS NOT NULL AND NOT is_rejected
        ORDER BY last_transition_at DESC, cve_id DESC OFFSET 1000 LIMIT 1`).Scan(&at, &cve); err != nil {
		t.Fatal(err)
	}
	deepPoc := encodeCatCursor(catCursor{at: &at, rank: 4, cve: cve})
	var tailCVE string
	if err := d.Conn.QueryRow(ctx, `SELECT cve_id FROM vuln_state_mat WHERE last_transition_at IS NULL
        ORDER BY stage_rank DESC, cve_id DESC OFFSET 100 LIMIT 1`).Scan(&tailCVE); err != nil {
		t.Fatal(err)
	}
	var tailRank int
	_ = d.Conn.QueryRow(ctx, `SELECT stage_rank FROM vuln_state_mat WHERE cve_id = $1`, tailCVE).Scan(&tailRank)
	tail := encodeCatCursor(catCursor{rank: tailRank, cve: tailCVE})

	for _, c := range []struct {
		name string
		p    CatalogueParams
		idx  []string // any of these indexes is acceptable for the walk
	}{
		{"no filter", CatalogueParams{}, []string{"vuln_state_mat_hot_idx"}},
		{"no filter, undated tail", CatalogueParams{Cursor: tail}, []string{"vuln_state_mat_hot_idx"}},
		{"stage patch", CatalogueParams{Stage: "patch"}, []string{"vuln_state_mat_stage_idx"}},
		{"stage kev", CatalogueParams{Stage: "kev"}, []string{"vuln_state_mat_stage_idx"}},
		{"stage poc, deep cursor", CatalogueParams{Stage: "poc", Cursor: deepPoc}, []string{"vuln_state_mat_stage_idx"}},
		{"year 2026", CatalogueParams{Year: 2026}, []string{"vuln_state_mat_year_idx", "vuln_state_mat_hot_idx"}},
		{"year 2014", CatalogueParams{Year: 2014}, []string{"vuln_state_mat_year_idx"}},
		{"kev + 2025", CatalogueParams{Stage: "kev", Year: 2025}, []string{"vuln_state_mat_stage_year_idx"}},
		{"poc + 2014, deep cursor", CatalogueParams{Stage: "poc", Year: 2014, Cursor: deepPoc}, []string{"vuln_state_mat_stage_year_idx"}},
		// backward pages (Before) walk the same indexes forwards from the position
		{"before, no filter", CatalogueParams{Before: deepPoc}, []string{"vuln_state_mat_hot_idx"}},
		{"before, no filter, undated tail", CatalogueParams{Before: tail}, []string{"vuln_state_mat_hot_idx"}},
		{"before, stage poc, deep", CatalogueParams{Stage: "poc", Before: deepPoc}, []string{"vuln_state_mat_stage_idx"}},
		{"before, poc + 2014, deep", CatalogueParams{Stage: "poc", Year: 2014, Before: deepPoc}, []string{"vuln_state_mat_stage_year_idx"}},
	} {
		p, err := c.p.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		inner, args := catalogueRows(p)
		rows, err := d.Conn.Query(ctx, "EXPLAIN "+sprintfSelect(inner), args...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var lines []string
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, l)
		}
		rows.Close()
		plan := strings.Join(lines, "\n")
		// The only sort of view rows allowed is the top one, over the at
		// most LIMIT+1 rows the index walks returned (lines[0] "Sort",
		// lines[1] its key). Every read of vuln_state_mat is a backward
		// index walk under a Limit; the first (the dated part) uses one of
		// c.idx.
		bad := strings.Count(plan, "Sort Key: m.") != 1 || !strings.HasPrefix(lines[0], "Sort ") ||
			!strings.Contains(lines[1], "Sort Key: m.last_transition_at DESC NULLS LAST")
		scan := "Index Scan Backward using "
		if c.p.Before != "" {
			scan = "Index Scan using "
		}
		first := ""
		for i, l := range lines {
			if !strings.Contains(l, " on vuln_state_mat ") {
				continue
			}
			if !strings.Contains(l, scan) || i == 0 || !strings.Contains(lines[i-1], "->  Limit") {
				bad = true
			}
			if first == "" {
				first = l
			}
		}
		found := false
		for _, ix := range c.idx {
			found = found || strings.Contains(first, scan+ix+" on vuln_state_mat")
		}
		if bad || !found {
			t.Errorf("%s: want a walk (%s) of %v without seq scan or sort:\n%s", c.name, scan, c.idx, plan)
		} else {
			t.Logf("%s:\n%s", c.name, plan)
		}
	}
	// the pager's numbered pages (Offset from the start, FromEnd from the
	// end): the same walks under a Limit of at most Offset+Limit+1 rows,
	// then a sort of those few rows; never a scan of the whole view
	for _, c := range []struct {
		name string
		p    CatalogueParams
		scan string
	}{
		{"offset, no filter", CatalogueParams{Offset: 100}, "Index Scan Backward using "},
		{"offset, stage poc", CatalogueParams{Stage: "poc", Offset: 100}, "Index Scan Backward using "},
		{"offset, poc + 2014", CatalogueParams{Stage: "poc", Year: 2014, Offset: 100}, "Index Scan Backward using "},
		{"end, no filter", CatalogueParams{FromEnd: true}, "Index Scan using "},
		{"end + offset, no filter", CatalogueParams{FromEnd: true, Offset: 100}, "Index Scan using "},
		{"end + offset, stage poc", CatalogueParams{Stage: "poc", FromEnd: true, Offset: 100}, "Index Scan using "},
		{"end + offset, year 2014", CatalogueParams{Year: 2014, FromEnd: true, Offset: 100}, "Index Scan using "},
	} {
		p, err := c.p.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		inner, args := catalogueRows(p)
		rows, err := d.Conn.Query(ctx, "EXPLAIN "+sprintfSelect(inner), args...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var lines []string
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, l)
		}
		rows.Close()
		plan := strings.Join(lines, "\n")
		bad := strings.Contains(plan, "Seq Scan on vuln_state_mat")
		walks := 0
		for i, l := range lines {
			if !strings.Contains(l, " on vuln_state_mat ") {
				continue
			}
			walks++
			if !strings.Contains(l, c.scan) || i == 0 || !strings.Contains(lines[i-1], "->  Limit") {
				bad = true
			}
		}
		if bad || walks == 0 {
			t.Errorf("%s: want walks (%s) under a Limit:\n%s", c.name, c.scan, plan)
		} else {
			t.Logf("%s:\n%s", c.name, plan)
		}
	}
}

func sprintfSelect(inner string) string { return strings.Replace(catalogueSelect, "%s", inner, 1) }
