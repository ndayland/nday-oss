package state_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/state"
	"nday.land/nday/internal/testutil"
)

func inMat(t *testing.T, c *pgx.Conn, cve string) bool {
	t.Helper()
	var n int
	if err := c.QueryRow(context.Background(), "SELECT count(*) FROM vuln_state_mat WHERE cve_id = $1", cve).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func connect(t *testing.T, d *testutil.TestDB) *pgx.Conn {
	t.Helper()
	c, err := testutil.Connect(context.Background(), d.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func TestMigrateLeavesMatPopulatedAndRefreshPicksUpEvents(t *testing.T) {
	x := newDB(t)
	ctx := context.Background()
	var populated bool
	if err := x.Conn.QueryRow(ctx, "SELECT ispopulated FROM pg_matviews WHERE matviewname = 'vuln_state_mat' AND schemaname = current_schema()").Scan(&populated); err != nil || !populated {
		t.Fatalf("populated=%v %v", populated, err)
	}
	x.vuln("CVE-2024-1301")
	x.ev("CVE-2024-1301", "kev_added", evOpt{occ: p(d(1)), source: "kev", detail: `{"precision":"day"}`})
	if inMat(t, x.Conn, "CVE-2024-1301") {
		t.Fatal("visible before refresh")
	}
	res, err := state.Refresh(ctx, x.Conn, state.RefreshOptions{})
	if err != nil || res.Refreshes != 1 || res.Deferred || res.Pending {
		t.Fatalf("%+v %v", res, err)
	}
	if !inMat(t, x.Conn, "CVE-2024-1301") {
		t.Fatal("not visible after refresh")
	}
	// Extra columns.
	var hasDis, hasITW bool
	var poc int
	var evID *int64
	err = x.Conn.QueryRow(ctx, `SELECT has_disclosed, has_itw, poc_sources, last_transition_event_id
        FROM vuln_state_mat WHERE cve_id = 'CVE-2024-1301'`).Scan(&hasDis, &hasITW, &poc, &evID)
	if err != nil || hasDis || hasITW || poc != 0 || evID == nil {
		t.Errorf("%v %v %d %v %v", hasDis, hasITW, poc, evID, err)
	}
}

// The materialized view equals the vuln_state view (same columns) after a
// refresh: vuln_state stays the definition.
func TestMatEqualsView(t *testing.T) {
	x := newDB(t)
	for i, typ := range []string{"disclosed", "patch_released", "poc_published", "kev_added", "exploited_in_wild"} {
		cve := fmt.Sprintf("CVE-2024-14%02d", i)
		x.vuln(cve)
		x.ev(cve, typ, evOpt{occ: p(d(float64(i + 1)))})
		x.ev(cve, "disclosed", evOpt{obs: p(d(9)), backfill: i%2 == 0, key: "k"})
	}
	x.refresh()
	var diff int
	err := x.Conn.QueryRow(context.Background(), `SELECT count(*) FROM (
        (SELECT * FROM vuln_state EXCEPT SELECT cve_id, stage, stage_rank, has_patch, has_analysis, has_poc, exploited,
            in_kev, is_rejected, disclosed_at, patch_at, analysis_at, poc_at, exploited_at, kev_at, last_transition_at,
            last_transition_type, event_count, days_disclosed_to_exploited, days_disclosed_to_poc FROM vuln_state_mat)
        UNION ALL
        (SELECT cve_id, stage, stage_rank, has_patch, has_analysis, has_poc, exploited,
            in_kev, is_rejected, disclosed_at, patch_at, analysis_at, poc_at, exploited_at, kev_at, last_transition_at,
            last_transition_type, event_count, days_disclosed_to_exploited, days_disclosed_to_poc FROM vuln_state_mat
         EXCEPT SELECT * FROM vuln_state)) d`).Scan(&diff)
	if err != nil || diff != 0 {
		t.Errorf("diff %d %v", diff, err)
	}
}

func TestRefreshDeferredWhenAnotherSessionHoldsTheLock(t *testing.T) {
	x := newDB(t)
	ctx := context.Background()
	other := connect(t, x.TestDB)
	key := `(x'6e647374'::bigint << 32 | 'vuln_state_mat'::regclass::oid::bigint)`
	if _, err := other.Exec(ctx, "SELECT pg_advisory_lock"+key); err != nil {
		t.Fatal(err)
	}
	x.vuln("CVE-2024-1501")
	x.ev("CVE-2024-1501", "disclosed", evOpt{occ: p(d(1))})
	start := time.Now()
	res, err := state.Refresh(ctx, x.Conn, state.RefreshOptions{})
	if err != nil || !res.Deferred || res.Refreshes != 0 || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v %v", res, err)
	}
	if inMat(t, x.Conn, "CVE-2024-1501") {
		t.Fatal("refreshed although deferred")
	}
	// The holder finishes; its next refresh covers the deferred request.
	if _, err := other.Exec(ctx, "SELECT pg_advisory_unlock"+key); err != nil {
		t.Fatal(err)
	}
	res, err = state.Refresh(ctx, other, state.RefreshOptions{})
	if err != nil || res.Refreshes != 1 || !inMat(t, x.Conn, "CVE-2024-1501") {
		t.Fatalf("%+v %v", res, err)
	}
	// Wait mode blocks until the lock is free.
	if _, err := other.Exec(ctx, "SELECT pg_advisory_lock"+key); err != nil {
		t.Fatal(err)
	}
	done := make(chan state.RefreshResult)
	go func() {
		r, err := state.Refresh(ctx, x.Conn, state.RefreshOptions{Wait: true})
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	select {
	case <-done:
		t.Fatal("did not wait")
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := other.Exec(ctx, "SELECT pg_advisory_unlock"+key); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.Refreshes != 1 {
		t.Errorf("%+v", r)
	}
}

func TestRefreshCoveredByLaterRefresh(t *testing.T) {
	x := newDB(t)
	ctx := context.Background()
	// Simulate: a refresh that started after our request has already completed.
	if _, err := x.Conn.Exec(ctx, "UPDATE vuln_state_refresh SET refreshed_seq = requested + 1"); err != nil {
		t.Fatal(err)
	}
	res, err := state.Refresh(ctx, x.Conn, state.RefreshOptions{})
	if err != nil || !res.Covered || res.Refreshes != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

// Many writers commit and request a refresh at the same time (6 collector
// timers firing together): no error, nobody blocks, and every committed
// event is in the materialized view afterwards without any extra refresh.
func TestConcurrentRefreshRequestsLoseNothing(t *testing.T) {
	x := newDB(t)
	ctx := context.Background()
	const n = 8
	conns := make([]*pgx.Conn, n)
	for i := range conns {
		conns[i] = connect(t, x.TestDB)
	}
	for round := 0; round < 3; round++ {
		var wg sync.WaitGroup
		results := make([]state.RefreshResult, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c := conns[i]
				cve := fmt.Sprintf("CVE-2024-6%d%02d", round, i)
				if _, err := c.Exec(ctx, "INSERT INTO vuln (cve_id) VALUES ($1)", cve); err != nil {
					t.Error(err)
					return
				}
				if _, err := c.Exec(ctx, `INSERT INTO event (cve_id, type, occurred_at, observed_at, source)
                    VALUES ($1, 'disclosed', now(), now(), 'x')`, cve); err != nil {
					t.Error(err)
					return
				}
				r, err := state.Refresh(ctx, c, state.RefreshOptions{})
				if err != nil {
					t.Error(err)
				}
				results[i] = r
			}(i)
		}
		wg.Wait()
		total := 0
		for _, r := range results {
			total += r.Refreshes
		}
		if total == 0 || total > n {
			t.Errorf("round %d: %d refreshes", round, total)
		}
		for i := 0; i < n; i++ {
			if cve := fmt.Sprintf("CVE-2024-6%d%02d", round, i); !inMat(t, x.Conn, cve) {
				t.Errorf("round %d: %s lost (results %+v)", round, cve, results)
			}
		}
	}
	var req, done int64
	_ = x.Conn.QueryRow(ctx, "SELECT requested, refreshed_seq FROM vuln_state_refresh").Scan(&req, &done)
	if req != done || req < 3*n {
		t.Errorf("requested %d refreshed %d", req, done)
	}
}

func TestRefreshErrorIsRecorded(t *testing.T) {
	x := newDB(t)
	ctx := context.Background()
	// Without the unique index REFRESH ... CONCURRENTLY fails.
	if _, err := x.Conn.Exec(ctx, "DROP INDEX vuln_state_mat_cve_idx"); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Refresh(ctx, x.Conn, state.RefreshOptions{}); err == nil {
		t.Fatal("no error")
	}
	var msg *string
	_ = x.Conn.QueryRow(ctx, "SELECT last_error FROM vuln_state_refresh").Scan(&msg)
	if msg == nil {
		t.Error("last_error not recorded")
	}
	// The lock was released: another session can take it.
	other := connect(t, x.TestDB)
	var got bool
	_ = other.QueryRow(ctx, `SELECT pg_try_advisory_lock(x'6e647374'::bigint << 32 | 'vuln_state_mat'::regclass::oid::bigint)`).Scan(&got)
	if !got {
		t.Error("lock leaked")
	}
}
