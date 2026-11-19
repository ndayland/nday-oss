package discuss_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/pipeline"
)

// waitBlockedBy polls until n backends wait on a lock held by backend pid.
func (h *harness) waitBlockedBy(pid uint32, n int) {
	h.t.Helper()
	for i := 0; i < 1500; i++ {
		if h.count(`SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))`, int(pid)) >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("fewer than %d backends ever waited on %d", n, pid)
}

// Defect 3: a post that saw the GHSA-keyed vulnerability, waited for the
// merge that moves it under its CVE and runs after it is gone gets the
// clean not-found answer (404), not an internal error, both for a new
// thread (the vuln's foreign key) and for a reply (its parent moved).
func TestPostDuringMerge(t *testing.T) {
	const ghsa = "GHSA-gpwc-27cw-rh9r"
	h := newHarness(t, hopt{terms: terms})
	ctx := context.Background()
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1)`, ghsa); err != nil {
		t.Fatal(err)
	}
	ada, bob := h.member("ada"), h.member("bob")
	for _, b := range []*browser{ada, bob} {
		h.establish(b.id)
		b.refresh()
	}
	top := ada.create(ghsa, "first", nil)
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
	thread, reply := make(chan result, 1), make(chan result, 1)
	go func() { r, b := ada.tryCreate(ghsa, "late thread", nil); thread <- result{r, b} }()
	go func() { r, b := bob.tryCreate(ghsa, "late reply", &top.ID); reply <- result{r, b} }()
	h.waitBlockedBy(m.PgConn().PID(), 2)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-thread
	expect(t, "new thread after the merge", r.resp, r.body, 404, "not_found")
	r = <-reply
	expect(t, "reply after the merge", r.resp, r.body, 404, "not_found")
	if n := h.count(`SELECT count(*) FROM comments WHERE cve_id = $1 AND body = 'first'`, cveA); n != 1 {
		t.Errorf("the thread did not move: %d", n)
	}
}

// A deadlock (40P01) is retried once: the post's transaction is chosen as
// the victim of a deadlock with another transaction, and the retry
// succeeds once that one commits.
func TestCreateRetriesDeadlock(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ctx := context.Background()
	ada := h.member("ada")
	h.establish(ada.id)
	ada.refresh()
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
	go func() { r, b := ada.tryCreate(cveA, "while locked", nil); done <- result{r, b} }()
	h.waitBlockedBy(o.PgConn().PID(), 1)
	// the post holds its author lock and waits for the vuln row: asking for
	// the author lock closes the cycle; the post (waiting longer) is aborted
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "nday.discuss.post:"+ada.id); err != nil {
		t.Fatalf("the other transaction was the victim: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.resp.StatusCode != http.StatusCreated {
		t.Fatalf("post after a deadlock: %d %s", r.resp.StatusCode, r.body)
	}
}
