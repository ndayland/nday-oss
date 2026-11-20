package site

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/state"
	"nday.land/nday/internal/testutil"
)

// The catalogue filtered by CVSS score reads neither vuln_state_mat nor
// vuln_score_mat sequentially, on a synthetic set shaped like production
// (TestCataloguePlans' rows, ~88% of them scored: 15% critical, 35% high,
// 32% medium, 6% low). Like TestCataloguePlans this proves the plan at
// 30,000 rows, not at production size.
func TestCatalogueCVSSPlans(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	t.Parallel()
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	n := 30000
	// NDAY_CVSS_PLAN_ROWS=426000 shows the plans at production size (slow)
	if v, err := strconv.Atoi(os.Getenv("NDAY_CVSS_PLAN_ROWS")); err == nil && v > 0 {
		n = v
	}
	for _, q := range []string{
		`INSERT INTO vuln (cve_id, first_seen_at)
		 SELECT format('CVE-%s-%s', CASE WHEN i % 10 < 4 THEN 2026 WHEN i % 10 < 6 THEN 2025 ELSE 1999 + (i % 26) END,
		               lpad(i::text, 6, '0')), now()
		 FROM generate_series(1, ` + strconv.Itoa(n) + `) i`,
		`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, is_backfill, dedupe_key, detail)
		 SELECT v.cve_id,
		        CASE WHEN i % 1000 = 3 THEN 'patch_released' WHEN i % 250 = 2 THEN 'kev_added'
		             WHEN i % 15 = 1 THEN 'poc_published' ELSE 'disclosed' END,
		        CASE WHEN i % 50 = 7 THEN NULL ELSE timestamptz '2026-11-01' - i * interval '17 minutes' END,
		        timestamptz '2026-11-01', 'synthetic', true, v.cve_id, '{}'::jsonb
		 FROM (SELECT cve_id, row_number() OVER (ORDER BY cve_id) AS i FROM vuln) v`,
		// the CVE record of each, with a score for 88% of them
		`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, is_backfill, dedupe_key, detail)
		 SELECT v.cve_id, 'disclosed', timestamptz '2020-01-01', timestamptz '2026-11-01', 'cvelist', true, v.cve_id,
		        CASE WHEN i % 100 < 12 THEN '{}'::jsonb
		             ELSE jsonb_build_object('cvss', jsonb_build_object('base_score',
		                  CASE WHEN i % 100 < 27 THEN 9 + (i % 11) / 10.0
		                       WHEN i % 100 < 62 THEN 7 + (i % 20) / 10.0
		                       WHEN i % 100 < 94 THEN 4 + (i % 30) / 10.0
		                       ELSE 0.1 + (i % 39) / 10.0 END)) END
		 FROM (SELECT cve_id, row_number() OVER (ORDER BY cve_id) AS i FROM vuln) v`,
		`INSERT INTO vuln_title (cve_id, rule_version) SELECT cve_id, 1 FROM vuln`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := state.Refresh(ctx, d.Conn, state.RefreshOptions{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `ANALYZE vuln_state_mat; ANALYZE vuln_score_mat; ANALYZE vuln; ANALYZE event; ANALYZE vuln_title`); err != nil {
		t.Fatal(err)
	}
	var scored int
	_ = d.Conn.QueryRow(ctx, `SELECT count(*) FROM vuln_score_mat`).Scan(&scored)
	if scored < n*8/10 {
		t.Fatalf("%d scored", scored)
	}
	var at time.Time
	var cve string
	var rank int
	if err := d.Conn.QueryRow(ctx, `SELECT last_transition_at, stage_rank, cve_id FROM vuln_state_mat
        WHERE last_transition_at IS NOT NULL AND NOT is_rejected
        ORDER BY last_transition_at DESC, stage_rank DESC, cve_id DESC OFFSET 5000 LIMIT 1`).Scan(&at, &rank, &cve); err != nil {
		t.Fatal(err)
	}
	deep := encodeCatCursor(catCursor{at: &at, rank: rank, cve: cve})
	ex := "EXPLAIN "
	if n != 30000 {
		ex = "EXPLAIN (ANALYZE, BUFFERS) "
	}
	for _, c := range []struct {
		name string
		p    CatalogueParams
		// loose: logged only. A single score between the bands' extremes
		// (1-2% of the rows) is a hash join over a sequential read of
		// vuln_state_mat at 30,000 rows; at 426,000 the planner walks the
		// indexes like the others (checked with NDAY_CVSS_PLAN_ROWS).
		loose bool
	}{
		{"min 9", CatalogueParams{CVSSMin: "9"}, false},
		{"min 7", CatalogueParams{CVSSMin: "7"}, false},
		{"high", CatalogueParams{CVSSMin: "7", CVSSMax: "8.9"}, false},
		{"medium", CatalogueParams{CVSSMin: "4", CVSSMax: "6.9"}, false},
		{"low", CatalogueParams{CVSSMin: "0.1", CVSSMax: "3.9"}, false},
		{"exact 9.8", CVSSMin9("9.8"), n == 30000},
		{"exact 1.0 (rare)", CVSSMin9("1"), false},
		{"min 9, deep cursor", CatalogueParams{CVSSMin: "9", Cursor: deep}, false},
		{"min 9, before", CatalogueParams{CVSSMin: "9", Before: deep}, false},
		{"min 9 + kev", CatalogueParams{CVSSMin: "9", Stage: "kev"}, false},
		{"min 7 + 2014", CatalogueParams{CVSSMin: "7", Year: 2014}, false},
		{"min 7 + poc + 2026", CatalogueParams{CVSSMin: "7", Stage: "poc", Year: 2026}, false},
	} {
		p, err := c.p.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		inner, args := catalogueRows(p)
		plan := explain(t, d, ex+sprintfSelect(inner), args...)
		if !c.loose && (strings.Contains(plan, "Seq Scan on vuln_state_mat") || strings.Contains(plan, "Seq Scan on vuln_score_mat") ||
			!strings.Contains(plan, "vuln_score_mat")) {
			t.Errorf("%s: a sequential scan:\n%s", c.name, plan)
		} else {
			t.Logf("%s:\n%s", c.name, plan)
		}
	}
	// the count (cached per filter) is logged, not asserted: it has to see
	// every matching row either way
	sql, args := catalogueCountQuery(mustNormalize(t, CatalogueParams{CVSSMin: "7"}))
	t.Logf("count, min 7:\n%s", explain(t, d, ex+sql, args...))
}

// CVSSMin9 is an exact-score filter.
func CVSSMin9(s string) CatalogueParams { return CatalogueParams{CVSSMin: s, CVSSMax: s} }

func mustNormalize(t *testing.T, p CatalogueParams) CatalogueParams {
	p, err := p.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func explain(t *testing.T, d *testutil.TestDB, sql string, args ...any) string {
	t.Helper()
	rows, err := d.Conn.Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}
