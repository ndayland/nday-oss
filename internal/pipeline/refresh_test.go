package pipeline_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/testutil"
)

func matHas(t *testing.T, d *testutil.TestDB, cve string) bool {
	t.Helper()
	var n int
	if err := d.Conn.QueryRow(context.Background(), "SELECT count(*) FROM vuln_state_mat WHERE cve_id = $1", cve).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// A new event becomes visible in the materialized state after the run.
func TestRunRefreshesMaterializedState(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	c := &fake{name: "fakesrc", records: []model.RawRecord{rec("fakesrc", "CVE-2026-0001", 1, false)}}
	if _, err := run(t, d, c, T0); err != nil {
		t.Fatal(err)
	}
	if !matHas(t, d, "CVE-2026-0001") {
		t.Fatal("first run: not in vuln_state_mat")
	}
	c.records = append(c.records, rec("fakesrc", "CVE-2026-0002", 1, false))
	if _, err := run(t, d, c, T1); err != nil {
		t.Fatal(err)
	}
	if !matHas(t, d, "CVE-2026-0002") {
		t.Fatal("second run: not in vuln_state_mat")
	}
	var poc int
	_ = d.Conn.QueryRow(context.Background(), "SELECT poc_sources FROM vuln_state_mat WHERE cve_id = 'CVE-2026-0002'").Scan(&poc)
	if poc != 0 { // "fakesrc" is not a curated PoC source
		t.Errorf("poc_sources %d", poc)
	}
}

// A refresh failure is logged; the committed run still succeeds.
func TestRefreshFailureDoesNotFailTheRun(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	if _, err := d.Conn.Exec(ctx, "DROP INDEX vuln_state_mat_cve_idx"); err != nil { // CONCURRENTLY now fails
		t.Fatal(err)
	}
	var logs bytes.Buffer
	c := &fake{name: "fakesrc", records: []model.RawRecord{rec("fakesrc", "CVE-2026-0003", 1, false)}}
	st, err := pipeline.RunCollector(ctx, d.Conn, c, pipeline.Options{Now: func() time.Time { return T0 },
		Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil || st == nil || st.EventInserted != 1 {
		t.Fatalf("run failed: %v %+v", err, st)
	}
	var status string
	_ = d.Conn.QueryRow(ctx, "SELECT last_status FROM collector_state WHERE source = 'fakesrc'").Scan(&status)
	if status != "ok" {
		t.Errorf("status %q", status)
	}
	if !strings.Contains(logs.String(), "derived state refresh failed") {
		t.Errorf("no warning logged:\n%s", logs.String())
	}
	// Also when the materialized view is missing entirely (database not migrated to 0003).
	if _, err := d.Conn.Exec(ctx, "DROP MATERIALIZED VIEW vuln_state_mat"); err != nil {
		t.Fatal(err)
	}
	c.records = append(c.records, rec("fakesrc", "CVE-2026-0004", 1, false))
	if _, err := pipeline.RunCollector(ctx, d.Conn, c, pipeline.Options{Now: func() time.Time { return T1 },
		Logger: slog.New(slog.NewTextHandler(&logs, nil))}); err != nil {
		t.Fatalf("run failed without mat view: %v", err)
	}
}
