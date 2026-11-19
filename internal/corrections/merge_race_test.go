package corrections_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/pipeline"
)

// Defect 3: a submission for a GHSA-keyed vulnerability that waits for the
// merge moving it under its CVE gets the clean not-found answer (404), not
// an internal error. The merge takes the per-vulnerability lock Submit
// takes, so the submission waits there (not on the foreign key) and then
// finds no vulnerability.
func TestSubmitDuringMerge(t *testing.T) {
	const ghsa = "GHSA-gpwc-27cw-rh9r"
	h := newHarness(t, "", nil)
	ctx := context.Background()
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1)`, ghsa); err != nil {
		t.Fatal(err)
	}
	ada := h.member("ada")
	ada.submit(ghsa, "title", "first", nil)
	m, err := pgx.Connect(ctx, h.db.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)
	tx, err := m.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := pipeline.MergeVulnID(ctx, tx, ghsa, cveA, nil); err != nil {
		t.Fatal(err)
	}
	type result struct {
		resp *http.Response
		body []byte
	}
	done := make(chan result, 1)
	go func() {
		r, b := ada.post("/api/corrections/"+ghsa, jsonOf(map[string]any{"category": "title", "body": "late"}))
		done <- result{r, b}
	}()
	var waitedOn string
	for i := 0; ; i++ {
		if err := h.db.Conn.QueryRow(ctx, `SELECT COALESCE(min(wait_event), '') FROM pg_stat_activity
			WHERE $1::int = ANY(pg_blocking_pids(pid)) AND wait_event_type = 'Lock'`, int(m.PgConn().PID())).Scan(&waitedOn); err != nil {
			t.Fatal(err)
		}
		if waitedOn != "" {
			break
		}
		if i > 1500 {
			t.Fatal("the submission never waited on the merge")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if waitedOn != "advisory" {
		t.Errorf("the submission waited on %q, want the per-vulnerability advisory lock", waitedOn)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	expect(t, "submission after the merge", r.resp, r.body, 404, "not_found")
	if n := h.count(`SELECT count(*) FROM vuln_corrections WHERE cve_id = $1`, cveA); n != 1 {
		t.Errorf("corrections under the CVE: %d", n)
	}
}

// A deadlock (40P01) is retried once: the submission's transaction is
// chosen as the victim of a deadlock with another transaction, and the
// retry succeeds once that one commits.
func TestSubmitRetriesDeadlock(t *testing.T) {
	h := newHarness(t, "", nil)
	ctx := context.Background()
	ada := h.member("ada")
	o, err := pgx.Connect(ctx, h.db.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close(ctx)
	tx, err := o.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT 1 FROM vuln WHERE cve_id = $1 FOR UPDATE`, cveA); err != nil {
		t.Fatal(err)
	}
	type result struct {
		resp *http.Response
		body []byte
	}
	done := make(chan result, 1)
	go func() {
		r, b := ada.post("/api/corrections/"+cveA, jsonOf(map[string]any{"category": "title", "body": "while locked"}))
		done <- result{r, b}
	}()
	for i := 0; h.count(`SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))`, int(o.PgConn().PID())) == 0; i++ {
		if i > 1500 {
			t.Fatal("the submission never waited")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "nday.corrections.user:"+ada.id); err != nil {
		t.Fatalf("the other transaction was the victim: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.resp.StatusCode != http.StatusCreated {
		t.Fatalf("submission after a deadlock: %d %s", r.resp.StatusCode, r.body)
	}
}
