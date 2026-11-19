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

// The lists' counts (listcount.go) read an index range, not the whole of
// vuln_state_mat, on the synthetic data set of TestCataloguePlans (30,000
// rows shaped like production) plus two tags: a narrow one (xxe, 300 CVEs) and a
// broad one (network, 12,000). The cases whose plan legitimately reads the view
// (the densest year, a broad tag, a window of a year) are logged, not
// asserted: their cost is one pass, cached per filter combination
// (docs/pagination.md); production timings still have to be taken there.
func TestListCountPlans(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	t.Parallel()
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	const n = 30000
	for _, q := range []string{
		`INSERT INTO vuln (cve_id, first_seen_at)
		 SELECT format('CVE-%s-%s', CASE WHEN i % 10 < 4 THEN 2026 WHEN i % 10 < 6 THEN 2025 ELSE 1999 + (i % 26) END,
		               lpad(i::text, 6, '0')), now()
		 FROM generate_series(1, ` + strconv.Itoa(n) + `) i`,
		`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, is_backfill, dedupe_key)
		 SELECT v.cve_id,
		        CASE WHEN i % 1000 = 3 THEN 'patch_released' WHEN i % 250 = 2 THEN 'kev_added'
		             WHEN i % 15 = 1 THEN 'poc_published' ELSE 'disclosed' END,
		        CASE WHEN i % 50 = 7 THEN NULL ELSE timestamptz '2026-11-01' - i * interval '17 minutes' END,
		        timestamptz '2026-11-01', 'synthetic', true, v.cve_id
		 FROM (SELECT cve_id, row_number() OVER (ORDER BY cve_id) AS i FROM vuln) v`,
		`INSERT INTO vuln_tag (cve_id, tag, origin, rule_version)
		 SELECT cve_id, 'xxe', 'rule', 1 FROM vuln WHERE abs(hashtext(cve_id)) % 100 = 0
		 UNION ALL
		 SELECT cve_id, 'network', 'rule', 1 FROM vuln WHERE abs(hashtext(cve_id)) % 5 < 2`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := state.Refresh(ctx, d.Conn, state.RefreshOptions{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `ANALYZE vuln_state_mat; ANALYZE vuln; ANALYZE event; ANALYZE vuln_tag`); err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	pins := []string{"CVE-2026-000010", "CVE-2026-000020"}
	hot := func(since time.Duration, minStage string, tags ...string) (string, []any) {
		return hotCountQuery(end.Add(-since), hotTypes(minStage), false, pins, tags)
	}
	cat := func(p CatalogueParams) (string, []any) {
		p, err := p.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		return catalogueCountQuery(p)
	}
	type query func() (string, []any)
	for _, c := range []struct {
		name string
		q    query
		idx  []string // any of these must serve the count; nil: logged only
	}{
		{"hot 7d", func() (string, []any) { return hot(7*24*time.Hour, "disclosed") }, []string{"vuln_state_mat_hot_idx"}},
		{"hot 30d, patch and later", func() (string, []any) { return hot(30*24*time.Hour, "patch_released") }, []string{"vuln_state_mat_hot_idx"}},
		{"hot 30d, narrow tag", func() (string, []any) { return hot(30*24*time.Hour, "disclosed", "xxe") }, []string{"vuln_state_mat_hot_idx", "vuln_tag_tag_idx"}},
		{"hot 30d, broad tag", func() (string, []any) { return hot(30*24*time.Hour, "disclosed", "network") }, []string{"vuln_state_mat_hot_idx"}},
		{"catalogue year 2014", func() (string, []any) { return cat(CatalogueParams{Year: 2014}) }, []string{"vuln_state_mat_year_idx", "vuln_state_mat_stage_year_idx"}},
		{"catalogue year 2014, rejected too", func() (string, []any) { return cat(CatalogueParams{Year: 2014, IncludeRejected: true}) }, []string{"vuln_state_mat_year_idx", "vuln_state_mat_stage_year_idx"}},
		{"catalogue kev + 2025", func() (string, []any) { return cat(CatalogueParams{Stage: "kev", Year: 2025}) }, []string{"vuln_state_mat_stage_year_idx"}},
		{"catalogue poc + 2014", func() (string, []any) { return cat(CatalogueParams{Stage: "poc", Year: 2014}) }, []string{"vuln_state_mat_stage_year_idx"}},
		{"catalogue narrow tag", func() (string, []any) { return cat(CatalogueParams{Tags: []string{"xxe"}}) }, []string{"vuln_tag_tag_idx"}},
		{"catalogue narrow tag + 2014", func() (string, []any) { return cat(CatalogueParams{Tags: []string{"xxe"}, Year: 2014}) }, []string{"vuln_tag_tag_idx", "vuln_state_mat_year_idx"}},
		// logged: one pass over the view is the cheapest plan here
		{"hot 366d", func() (string, []any) { return hot(366*24*time.Hour, "disclosed") }, nil},
		{"catalogue year 2026 (40% of rows)", func() (string, []any) { return cat(CatalogueParams{Year: 2026}) }, nil},
		{"catalogue broad tag", func() (string, []any) { return cat(CatalogueParams{Tags: []string{"network"}}) }, nil},
	} {
		sql, args := c.q()
		rows, err := d.Conn.Query(ctx, "EXPLAIN "+sql, args...)
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
		if c.idx == nil {
			t.Logf("%s (logged):\n%s", c.name, plan)
			continue
		}
		found := false
		for _, ix := range c.idx {
			found = found || strings.Contains(plan, " using "+ix+" on ") || strings.Contains(plan, " on "+ix)
		}
		if strings.Contains(plan, "Seq Scan on vuln_state_mat") || !found {
			t.Errorf("%s: want an index range of %v, no sequential scan of vuln_state_mat:\n%s", c.name, c.idx, plan)
		} else {
			t.Logf("%s:\n%s", c.name, plan)
		}
	}
}
