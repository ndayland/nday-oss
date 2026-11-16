package xdraft_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xdraft"
)

var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

type db struct {
	t *testing.T
	d *testutil.TestDB
	n int
}

func newDB(t *testing.T) *db {
	return &db{t: t, d: testutil.NewMigratedDB(t)}
}

func (x *db) exec(q string, args ...any) {
	x.t.Helper()
	if _, err := x.d.Conn.Exec(context.Background(), q, args...); err != nil {
		x.t.Fatalf("%s: %v", q, err)
	}
}

func (x *db) count(q string, args ...any) int {
	x.t.Helper()
	var n int
	if err := x.d.Conn.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		x.t.Fatal(err)
	}
	return n
}

func (x *db) vuln(cve, title string) {
	x.exec(`INSERT INTO vuln (cve_id, title) VALUES ($1, nullif($2, '')) ON CONFLICT DO NOTHING`, cve, title)
}

// ev inserts an event observed `ago` before now.
func (x *db) ev(cve, typ, source string, backfill bool, ago time.Duration, occurred *time.Time, detail string) {
	x.t.Helper()
	x.vuln(cve, "")
	x.n++
	if detail == "" {
		detail = "{}"
	}
	x.exec(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, is_backfill, dedupe_key)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`, cve, typ, occurred, now.Add(-ago), source, detail, backfill,
		"k"+strings.Repeat("x", x.n%3)+string(rune('a'+x.n%26))+time.Duration(x.n).String())
}

func (x *db) run(o xdraft.Options) *xdraft.Result {
	x.t.Helper()
	if o.Now == nil {
		o.Now = func() time.Time { return now }
	}
	r, err := xdraft.Generate(context.Background(), x.d.Conn, o)
	if err != nil {
		x.t.Fatal(err)
	}
	return r
}

func (x *db) drafts() []string {
	x.t.Helper()
	rows, err := x.d.Conn.Query(context.Background(), `SELECT cve_id || ' ' || stage FROM x_draft ORDER BY id`)
	if err != nil {
		x.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		x.t.Fatal(err)
	}
	return out
}

func tp(t time.Time) *time.Time { return &t }

// TestGenerateRule: baseline, first-of-type, backfill, ITW after KEV,
// rejected, social_post, watermark, T+, text inputs, re-run.
func TestGenerateRule(t *testing.T) {
	x := newDB(t)
	// history before the first run: never drafted
	x.ev("CVE-2026-0001", "kev_added", "kev", false, time.Hour, nil, "")
	r := x.run(xdraft.Options{})
	baseline := r.To
	if !r.Baseline || r.Created != 0 || len(x.drafts()) != 0 {
		t.Fatalf("baseline run: %+v, drafts %v", r, x.drafts())
	}
	if r2 := x.run(xdraft.Options{}); r2.Baseline || r2.Candidates != 0 || r2.From != r.To {
		t.Errorf("idle run: %+v", r2)
	}

	x.vuln("CVE-2026-1000", "Remote code execution in @acme Widget via https://evil.example/x")
	x.exec(`INSERT INTO affected (cve_id, vendor, product) VALUES ('CVE-2026-1000', 'Acme', 'Acme Widget')`)
	disc := now.Add(-10 * 24 * time.Hour)
	x.ev("CVE-2026-1000", "disclosed", "cvelist", true, 240*time.Hour, &disc, `{"state":"PUBLISHED"}`)
	x.ev("CVE-2026-1000", "poc_published", "exploitdb", false, time.Hour, tp(now.Add(-2*time.Hour)), "") // first PoC: draft
	x.ev("CVE-2026-1000", "poc_published", "nuclei", false, time.Hour, nil, "")                          // second PoC: none
	// a live PoC after a backfilled one is not the first
	x.ev("CVE-2026-2000", "poc_published", "exploitdb", true, 2*time.Hour, nil, "")
	x.ev("CVE-2026-2000", "poc_published", "metasploit", false, time.Hour, nil, "")
	// backfilled events never make drafts
	x.ev("CVE-2026-3000", "kev_added", "kev", true, time.Hour, nil, "")
	// ITW after KEV: skipped; KEV drafted
	x.ev("CVE-2026-4000", "kev_added", "kev", false, time.Hour, nil, "")
	x.ev("CVE-2026-4000", "exploited_in_wild", "feedx", false, time.Hour, nil, "")
	// ITW before KEV (both new in this run): only KEV (the CVE has kev_added)
	x.ev("CVE-2026-4100", "exploited_in_wild", "feedx", false, time.Hour, nil, "")
	x.ev("CVE-2026-4100", "kev_added", "kev", false, time.Hour, nil, "")
	// ITW alone: drafted
	x.ev("CVE-2026-4200", "exploited_in_wild", "feedx", false, time.Hour, nil, "")
	// rejected CVE: skipped
	x.ev("CVE-2026-5000", "disclosed", "cvelist", false, time.Hour, nil, `{"state":"REJECTED"}`)
	x.ev("CVE-2026-5000", "kev_added", "kev", false, time.Hour, nil, "")
	// social posts and other types: ignored
	x.ev("CVE-2026-6000", "social_post", "xposts", false, time.Hour, nil, "")
	x.ev("CVE-2026-6000", "patch_released", "ghsa", false, time.Hour, nil, "")

	r = x.run(xdraft.Options{})
	got := strings.Join(x.drafts(), ",")
	want := "CVE-2026-1000 poc_published,CVE-2026-4000 kev_added,CVE-2026-4100 kev_added,CVE-2026-4200 exploited_in_wild"
	if got != want || r.Created != 4 {
		t.Errorf("drafts %s (%+v), want %s", got, r, want)
	}
	var body string
	_ = x.d.Conn.QueryRow(context.Background(), `SELECT body FROM x_draft WHERE cve_id = 'CVE-2026-1000'`).Scan(&body)
	wantBody := "CVE-2026-1000 +POC T+10d\nAcme / Widget\nRemote code execution in [at]acme Widget via\nPublic PoC available: Exploit-DB entry."
	if body != wantBody {
		t.Errorf("body:\n%s\nwant\n%s", body, wantBody)
	}

	// re-runs never add a second draft, even with the watermark reset
	if r := x.run(xdraft.Options{}); r.Created != 0 || r.Candidates != 0 {
		t.Errorf("re-run: %+v", r)
	}
	x.exec(`UPDATE x_draft_state SET last_event_id = $1`, baseline)
	if r := x.run(xdraft.Options{}); r.Created != 0 || r.Existing != 4 {
		t.Errorf("re-run from 0: %+v", r)
	}
	// a later KEV on a CVE with an ITW draft: a second draft for the new stage
	x.ev("CVE-2026-4200", "kev_added", "kev", false, time.Minute, nil, "")
	x.ev("CVE-2026-4200", "exploited_in_wild", "feedy", false, time.Minute, nil, "")
	if r := x.run(xdraft.Options{}); r.Created != 1 {
		t.Errorf("later KEV: %+v", r)
	}
	if n := x.count(`SELECT count(*) FROM x_draft`); n != 5 {
		t.Errorf("drafts: %d", n)
	}
	if n := x.count(`SELECT count(*) FROM x_draft WHERE event_id IS NULL OR status <> 'draft' OR version <> 1`); n != 0 {
		t.Errorf("bad rows: %d", n)
	}
}

// TestGenerateBounds: the cap per run (excess skipped for good), the
// maximum event age and the dry run.
func TestGenerateBounds(t *testing.T) {
	x := newDB(t)
	x.run(xdraft.Options{})
	for i := 0; i < 15; i++ {
		x.ev("CVE-2026-1"+strings.Repeat("0", 3)+string(rune('a'-'a'+'0'+i%10))+string(rune('0'+i/10)), "kev_added", "kev", false, time.Hour, nil, "")
	}
	x.ev("CVE-2026-9999", "kev_added", "kev", false, xdraft.MaxEventAge+time.Hour, nil, "") // too old
	before := x.count(`SELECT count(*) FROM x_draft_state WHERE last_event_id IS NOT NULL`)
	var wm int64
	_ = x.d.Conn.QueryRow(context.Background(), `SELECT last_event_id FROM x_draft_state`).Scan(&wm)
	dry := x.run(xdraft.Options{DryRun: true})
	if dry.Created != xdraft.MaxDraftsPerRun || len(dry.Drafts) != xdraft.MaxDraftsPerRun || x.count(`SELECT count(*) FROM x_draft`) != 0 {
		t.Errorf("dry run: %+v, %d rows", dry, x.count(`SELECT count(*) FROM x_draft`))
	}
	var wm2 int64
	_ = x.d.Conn.QueryRow(context.Background(), `SELECT last_event_id FROM x_draft_state`).Scan(&wm2)
	if wm2 != wm || before != 1 {
		t.Errorf("dry run moved the watermark %d -> %d", wm, wm2)
	}
	for _, d := range dry.Drafts {
		if d.Weight > xdraft.BodyBudget || d.ID != 0 {
			t.Errorf("dry draft %+v", d)
		}
	}
	// a small backlog over the cap (a CISA batch) is carried over
	r := x.run(xdraft.Options{})
	if r.Created != xdraft.MaxDraftsPerRun || r.Carried != 5 || r.SkippedCap != 0 || r.SkippedOld != 1 {
		t.Errorf("capped run: %+v", r)
	}
	if r := x.run(xdraft.Options{}); r.Created != 5 || r.Carried != 0 || r.SkippedOld != 1 {
		t.Errorf("carried-over run: %+v", r)
	}
	if r := x.run(xdraft.Options{}); r.Created != 0 || r.Candidates != 0 {
		t.Errorf("events came back: %+v", r)
	}
	if n := x.count(`SELECT count(*) FROM x_draft`); n != 15 {
		t.Errorf("drafts: %d", n)
	}
	var last string
	_ = x.d.Conn.QueryRow(context.Background(), `SELECT last_run->>'skipped_cap' FROM x_draft_state`).Scan(&last)
	if last != "0" { // the last run had nothing to do
		t.Errorf("last_run %s", last)
	}
	// a bulk change (more than MaxBacklog qualify): the rest is skipped for good
	for i := 0; i < xdraft.MaxBacklog+10; i++ {
		x.ev(fmt.Sprintf("CVE-2026-3%04d", i), "poc_published", "nuclei", false, time.Hour, nil, "")
	}
	if r := x.run(xdraft.Options{}); r.Created != xdraft.MaxDraftsPerRun || r.SkippedCap != xdraft.MaxBacklog || r.Carried != 0 {
		t.Errorf("bulk run: %+v", r)
	}
	if r := x.run(xdraft.Options{}); r.Created != 0 || r.Candidates != 0 {
		t.Errorf("skipped events came back: %+v", r)
	}
	_ = x.d.Conn.QueryRow(context.Background(), `SELECT last_run->>'skipped_cap' FROM x_draft_state`).Scan(&last)
	if n := x.count(`SELECT count(*) FROM x_draft`); n != 25 {
		t.Errorf("drafts after the bulk change: %d", n)
	}
}

// TestGenerateConcurrency: overlapping runs create each draft once; a run
// after a collector defers while a writer is in flight (and the events are
// drafted by the next run, never lost to the watermark), or while another
// run holds the watermark.
func TestGenerateConcurrency(t *testing.T) {
	x := newDB(t)
	x.run(xdraft.Options{})
	for i := 0; i < 8; i++ {
		x.ev("CVE-2026-20"+string(rune('0'+i))+"0", "poc_published", "exploitdb", false, time.Hour, nil, "")
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	created := make([]int, 4)
	for i := range created {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := testutil.Connect(ctx, x.d.URL)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close(ctx)
			r, err := xdraft.Generate(ctx, c, xdraft.Options{Now: func() time.Time { return now }})
			if err != nil {
				t.Error(err)
				return
			}
			created[i] = r.Created
		}(i)
	}
	wg.Wait()
	if sum := created[0] + created[1] + created[2] + created[3]; sum != 8 || x.count(`SELECT count(*) FROM x_draft`) != 8 {
		t.Errorf("overlapping runs created %v (%d rows)", created, x.count(`SELECT count(*) FROM x_draft`))
	}

	// a collector transaction in flight: its event has a LOWER id than one
	// committed after it
	w, err := testutil.Connect(ctx, x.d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(ctx)
	tx, err := w.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ('CVE-2026-3001')`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO event (cve_id, type, observed_at, source, dedupe_key) VALUES ('CVE-2026-3001', 'kev_added', $1, 'kev', 'a')`, now); err != nil {
		t.Fatal(err)
	}
	x.ev("CVE-2026-3002", "kev_added", "kev", false, time.Minute, nil, "") // committed, higher id
	if r := x.run(xdraft.Options{NoWait: true}); r.Deferred != "lock_busy" || r.Created != 0 {
		t.Errorf("run with a writer in flight: %+v", r)
	}
	// the deferral is recorded without moving the watermark or losing the counts
	var deferred, lastCreated string
	var wm int64
	_ = x.d.Conn.QueryRow(ctx, `SELECT last_run->>'deferred', last_run->>'created', last_event_id FROM x_draft_state`).Scan(&deferred, &lastCreated, &wm)
	if deferred != "lock_busy" || lastCreated == "" {
		t.Errorf("recorded deferral %q, created %q", deferred, lastCreated)
	}
	// a dry run never queues for the lock, even as a manual run
	start := time.Now()
	if r := x.run(xdraft.Options{DryRun: true}); r.Deferred != "lock_busy" || time.Since(start) > time.Second {
		t.Errorf("dry run with a writer in flight: %+v after %s", r, time.Since(start))
	}
	// a manual run waits WaitLock at most
	start = time.Now()
	if r := x.run(xdraft.Options{}); r.Deferred != "lock_busy" || time.Since(start) > xdraft.WaitLock+2*time.Second {
		t.Errorf("manual run with a writer in flight: %+v after %s", r, time.Since(start))
	}
	var wm2 int64
	_ = x.d.Conn.QueryRow(ctx, `SELECT last_event_id FROM x_draft_state`).Scan(&wm2)
	if wm2 != wm {
		t.Errorf("a deferral moved the watermark %d -> %d", wm, wm2)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if r := x.run(xdraft.Options{NoWait: true}); r.Created != 2 {
		t.Errorf("after the commit: %+v (drafts %v)", r, x.drafts())
	}
	if x.count(`SELECT count(*) FROM x_draft_state WHERE last_run ? 'deferred'`) != 0 {
		t.Error("a completed run kept the deferral")
	}

	// another run holds the watermark row
	tx, err = w.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM x_draft_state WHERE id = 1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	if r := x.run(xdraft.Options{NoWait: true}); r.Deferred != "another_run" {
		t.Errorf("run while another holds the watermark: %+v", r)
	}
	_ = tx.Rollback(ctx)
}
