package classify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
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

func storeRawTx(ctx context.Context, tx pgx.Tx, source, key string, payload []byte, at time.Time) error {
	v, err := pyjson.Decode(payload)
	if err != nil {
		return err
	}
	rec := model.RawRecord{Source: source, SourceKey: key, Payload: v}
	h, err := rec.ContentHash()
	if err != nil {
		return err
	}
	_, err = pipeline.StoreRaw(ctx, tx, rec, h, at)
	return err
}

func noCVEAdvisory(gid, cwe string) []byte {
	return []byte(fmt.Sprintf(`{"ghsa_id":%q,"cve_id":null,"withdrawn_at":null,"cwes":[{"cwe_id":%q,"name":"n"}],
	  "cvss_severities":{"cvss_v3":{"score":9.8,"vector_string":%q}}}`, gid, cwe, v31b))
}

// Defect 4: a merge that commits between the batch's read and its write
// deletes the GHSA-keyed vuln; the batch must neither fail on the foreign
// key nor lose the work queued for the CVE.
func TestMergeDuringBatch(t *testing.T) {
	e := newEnv(t)
	const gid, cve = "GHSA-2cm2-m3w5-gp2f", "CVE-2026-0009"
	e.raw("ghsa", gid, noCVEAdvisory(gid, "CWE-94"), t0)
	e.vuln(gid, cve)
	other, obs := e.connect(), e.connect()
	queued := e.count(`SELECT count(*) FROM classify_queue`)
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
				if err := storeRawTx(context.Background(), tx, "ghsa", gid, ghsaRec(gid, cve, "CWE-94"), t0.Add(time.Hour)); err != nil {
					return err
				}
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
		t.Fatalf("classify: %v; merge: %v", perr, merr)
	}
	if n := e.count(`SELECT count(*) FROM classify_queue WHERE cve_id = $1`, cve); n == 0 {
		t.Fatal("the work queued for the CVE was lost")
	}
	e.pending()
	if got := e.rows(cve); !has(got, "cwe CWE-94 ghsa/"+gid) {
		t.Errorf("CVE not classified after the merge: %v", got)
	}
	if n := e.count(`SELECT count(*) FROM vuln_cwe WHERE cve_id = $1`, gid); n != 0 {
		t.Errorf("rows left under the GHSA id: %d", n)
	}
}

// Defect 4: the merge holds the CVE's row (FOR UPDATE, as the collector's
// upsert does) and then wants the GHSA-keyed rows the batch is rewriting;
// the batch must not wait on the CVE's row while it holds those.
func TestMergeHoldingCVENoDeadlock(t *testing.T) {
	e := newEnv(t)
	const gid, g2, cve = "GHSA-2cm2-m3w5-gp2f", "GHSA-4444-5555-6666", "CVE-2026-0009"
	e.vuln(gid, cve)
	e.raw("ghsa", gid, noCVEAdvisory(gid, "CWE-94"), t0)
	e.raw("ghsa", g2, ghsaRec(g2, cve, "CWE-79"), t0)
	e.pending()
	// both change again
	e.raw("ghsa", gid, noCVEAdvisory(gid, "CWE-89"), t0.Add(time.Hour))
	e.raw("ghsa", g2, ghsaRec(g2, cve, "CWE-22"), t0.Add(time.Hour))
	m, obs := e.connect(), e.connect()
	mtx, err := m.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mtx.Rollback(e.ctx) //nolint:errcheck
	if _, err := mtx.Exec(e.ctx, `SELECT 1 FROM vuln WHERE cve_id = $1 FOR UPDATE`, cve); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	var st *Stats
	go func() {
		var err error
		st, err = Pending(context.Background(), e.conn, Options{Wait: true})
		done <- err
	}()
	blockedOrDone(t, obs, e.conn.PgConn().PID(), m.PgConn().PID(), done)
	_, merr := pipeline.MergeVulnID(e.ctx, mtx, gid, cve, nil)
	if merr == nil {
		merr = mtx.Commit(e.ctx)
	}
	perr := <-done
	if perr != nil || merr != nil {
		t.Fatalf("classify: %v; merge: %v", perr, merr)
	}
	if st.Busy == 0 {
		t.Errorf("the CVE's row was busy but the run says otherwise: %+v", st)
	}
	if n := e.count(`SELECT count(*) FROM classify_queue WHERE cve_id = $1`, cve); n == 0 {
		t.Fatal("the work queued for the CVE was lost")
	}
	e.pending()
	if got := e.rows(cve); !has(got, "cwe CWE-22 ghsa/"+g2) {
		t.Errorf("CVE not classified: %v", got)
	}
}
