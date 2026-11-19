package xdraft_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xdraft"
)

// Defect 4: a GHSA-keyed vuln merging into its CVE holds both vuln rows
// FOR UPDATE and then needs to move the events; a run holds the event
// table (SHARE) and must not then wait for those vuln rows. It defers
// instead, and the next run drafts the event under the CVE.
func TestGenerateVsMergeNoDeadlock(t *testing.T) {
	const gid, cve = "GHSA-2cm2-m3w5-gp2f", "CVE-2026-4001"
	x := newDB(t)
	x.run(xdraft.Options{})
	x.vuln(gid, "Sandbox escape")
	x.vuln(cve, "")
	x.ev(gid, "poc_published", "exploitdb", false, time.Hour, nil, "")
	ctx := context.Background()
	conn := func() *pgx.Conn {
		c, err := testutil.Connect(ctx, x.d.URL)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(ctx) })
		return c
	}
	m, gen, obs := conn(), conn(), conn()
	mtx, err := m.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mtx.Rollback(ctx) //nolint:errcheck
	// the merge's row locks (it takes them before it moves the events)
	if _, err := mtx.Exec(ctx, `SELECT 1 FROM vuln WHERE cve_id = ANY($1) ORDER BY cve_id FOR UPDATE`, []string{gid, cve}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	var res *xdraft.Result
	go func() {
		var err error
		res, err = xdraft.Generate(ctx, gen, xdraft.Options{Now: func() time.Time { return now }})
		done <- err
	}()
	// the run either waits on the merge's row lock or finished
	for i := 0; ; i++ {
		var blocked bool
		if err := obs.QueryRow(ctx, `SELECT $2::int = ANY(pg_blocking_pids($1::int))`, int(gen.PgConn().PID()), int(m.PgConn().PID())).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked || len(done) > 0 {
			break
		}
		if i > 1500 {
			t.Fatal("the run neither finished nor waited")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, merr := pipeline.MergeVulnID(ctx, mtx, gid, cve, nil)
	if merr == nil {
		merr = mtx.Commit(ctx)
	}
	gerr := <-done
	if gerr != nil || merr != nil {
		t.Fatalf("generate: %v; merge: %v", gerr, merr)
	}
	if res.Deferred != "vuln_busy" || res.Created != 0 {
		t.Errorf("run during the merge: %+v", res)
	}
	r := x.run(xdraft.Options{})
	if r.Created != 1 || len(r.Drafts) != 1 || r.Drafts[0].CVE != cve {
		t.Errorf("next run: %+v", r)
	}
}
