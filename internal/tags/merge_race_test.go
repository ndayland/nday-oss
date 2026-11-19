package tags

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/testutil"
)

// blockedOrDone polls until backend waiter waits on a lock held by holder,
// or done has a value (which it puts back).
func blockedOrDone(t *testing.T, obs *pgx.Conn, waiter, holder uint32, done chan error) {
	t.Helper()
	for i := 0; i < 1500; i++ {
		select {
		case err := <-done:
			done <- err
			return
		default:
		}
		var ok bool
		if err := obs.QueryRow(context.Background(), `SELECT $2::int = ANY(pg_blocking_pids($1::int))`,
			int(waiter), int(holder)).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("backend %d neither finished nor waited on %d", waiter, holder)
}

func (e *env) connect() *pgx.Conn {
	e.t.Helper()
	c, err := testutil.Connect(e.ctx, e.d.URL)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// Defect 4: a merge that commits between the batch's read and its write
// deletes the GHSA-keyed vuln; the batch must neither fail on the foreign
// key nor lose the work queued for the CVE.
func TestMergeDuringBatch(t *testing.T) {
	e := newEnv(t)
	const gid, cve = "GHSA-2cm2-m3w5-gp2f", "CVE-2026-0010"
	e.exec(`INSERT INTO vuln (cve_id) VALUES ($1), ($2)`, gid, cve)
	e.event(gid, "poc_published", "exploitdb", "1", `{}`)
	other, obs := e.connect(), e.connect()
	queued := e.count(`SELECT count(*) FROM tag_queue`)
	o := Options{Wait: true, MaxQueue: queued}
	done := make(chan error, 1)
	started := false
	o.afterRead = func(ctx context.Context, tx pgx.Tx) error {
		if started {
			return nil
		}
		started = true
		go func() {
			done <- pgx.BeginFunc(context.Background(), other, func(tx pgx.Tx) error {
				_, err := pipeline.MergeVulnID(context.Background(), tx, gid, cve, nil)
				return err
			})
		}()
		blockedOrDone(t, obs, other.PgConn().PID(), e.conn.PgConn().PID(), done)
		return nil
	}
	_, perr := Pending(e.ctx, e.conn, o)
	merr := <-done
	if perr != nil || merr != nil {
		t.Fatalf("tags: %v; merge: %v", perr, merr)
	}
	if n := e.count(`SELECT count(*) FROM tag_queue WHERE cve_id = $1`, cve); n == 0 {
		t.Fatal("the work queued for the CVE was lost")
	}
	e.pending()
	if got := e.tags(cve); got != "exploit-db" {
		t.Errorf("CVE tags after the merge: %q", got)
	}
	if n := e.count(`SELECT count(*) FROM vuln_tag WHERE cve_id = $1`, gid); n != 0 {
		t.Errorf("rows left under the GHSA id: %d", n)
	}
}

// Defect 4: a busy vuln row (a collector holds it FOR UPDATE) is skipped,
// not waited for, and its queue row stays.
func TestBusyVulnDeferred(t *testing.T) {
	e := newEnv(t)
	const cve = "CVE-2026-0011"
	e.exec(`INSERT INTO vuln (cve_id) VALUES ($1)`, cve)
	e.event(cve, "poc_published", "exploitdb", "1", `{}`)
	m := e.connect()
	mtx, err := m.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mtx.Rollback(e.ctx) //nolint:errcheck
	if _, err := mtx.Exec(e.ctx, `SELECT 1 FROM vuln WHERE cve_id = $1 FOR UPDATE`, cve); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	st, err := Pending(ctx, e.conn, Options{Wait: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Busy != 1 || e.count(`SELECT count(*) FROM tag_queue WHERE cve_id = $1`, cve) == 0 {
		t.Fatalf("busy row: %+v", st)
	}
	_ = mtx.Rollback(e.ctx)
	e.pending()
	if got := e.tags(cve); got != "exploit-db" {
		t.Errorf("after the collector committed: %q", got)
	}
}
