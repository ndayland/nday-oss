package pipeline_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

// connect opens one more connection to d's schema, closed at cleanup.
func connect(t *testing.T, d *testutil.TestDB) *pgx.Conn {
	t.Helper()
	c, err := testutil.Connect(context.Background(), d.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// waitBlocked polls (on obs) until the backend waiter waits on a lock held
// by the backend holder.
func waitBlocked(t *testing.T, obs *pgx.Conn, waiter, holder uint32) {
	t.Helper()
	for i := 0; i < 1500; i++ {
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
	t.Fatalf("backend %d never waited on %d", waiter, holder)
}

// mergeAsync runs MergeVulnID(from, into) in its own transaction on conn and
// reports the result on the returned channel.
func mergeAsync(conn *pgx.Conn, from, into string, log *slog.Logger) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- pgx.BeginFunc(context.Background(), conn, func(tx pgx.Tx) error {
			_, err := pipeline.MergeVulnID(context.Background(), tx, from, into, log)
			return err
		})
	}()
	return done
}

func wait(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("merge never finished")
		return nil
	}
}

// Defect 1: per stage exactly one draft survives, posted > discarded >
// draft, the target's on a tie; dropping a decided draft is logged at warn
// level with its id, stage, status and post_url.
func TestMergeXDraftKeepsDecided(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	type side struct{ status, url string }
	posted := func(n int) side { return side{"posted", fmt.Sprintf("https://x.com/ndayland/status/%d", n)} }
	cases := []struct {
		g, c      side
		keepG     bool
		warnDrops bool // the dropped one was decided
	}{
		{posted(1), side{"discarded", ""}, true, true},
		{side{"discarded", ""}, posted(2), false, true},
		{posted(3), posted(4), false, true},
		{side{"draft", ""}, side{"discarded", ""}, false, false},
		{side{"discarded", ""}, side{"draft", ""}, true, false},
		{side{"draft", ""}, side{"draft", ""}, false, false},
	}
	ghsas := []string{"GHSA-2222-3333-4444", "GHSA-2222-3333-5555", "GHSA-2222-3333-6666",
		"GHSA-2222-3333-7777", "GHSA-2222-3333-8888", "GHSA-2222-3333-9999"}
	ins := func(cve string, s side) int64 {
		var decided *time.Time
		if s.status != "draft" {
			decided = &T1
		}
		var url *string
		if s.url != "" {
			url = &s.url
		}
		var id int64
		if err := d.Conn.QueryRow(ctx, `INSERT INTO x_draft (cve_id, stage, event_id, body, status, post_url, decided_at)
            VALUES ($1, 'poc_published', 1, $2, $3, $4, $5) RETURNING id`, cve, cve+" "+s.status, s.status, url, decided).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for i, tc := range cases {
		g, c := ghsas[i], fmt.Sprintf("CVE-2026-9100%d", i)
		exec(t, d.Conn, `INSERT INTO vuln (cve_id) VALUES ($1), ($2)`, g, c)
		gID, cID := ins(g, tc.g), ins(c, tc.c)
		// an audit row naming the draft that may be dropped (admin_audit is
		// append-only and target_id has no FK: it must survive)
		exec(t, d.Conn, `INSERT INTO admin_audit (actor_role, action, target_type, target_id, source)
            VALUES ('cli', 'x.draft.post', 'x_draft', $1, 'cli'), ('cli', 'x.draft.post', 'x_draft', $2, 'cli')`,
			fmt.Sprint(gID), fmt.Sprint(cID))
		var logs bytes.Buffer
		mc, err := pipeline.MergeVulnID(ctx, d.Conn, g, c, slog.New(slog.NewTextHandler(&logs, nil)))
		if err != nil || !mc.Merged {
			t.Fatalf("case %d: %+v %v", i, mc, err)
		}
		keep, drop, dropSide := cID, gID, tc.g
		if tc.keepG {
			keep, drop, dropSide = gID, cID, tc.c
		}
		var got int64
		if err := d.Conn.QueryRow(ctx, `SELECT id FROM x_draft WHERE cve_id = $1 AND stage = 'poc_published'`, c).Scan(&got); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got != keep {
			t.Errorf("case %d (G %s, C %s): kept draft %d, want %d", i, tc.g.status, tc.c.status, got, keep)
		}
		if n := count(t, d.Conn, `SELECT count(*) FROM x_draft WHERE id = $1`, drop); n != 0 {
			t.Errorf("case %d: dropped draft %d still there", i, drop)
		}
		warn := ""
		for _, l := range strings.Split(logs.String(), "\n") {
			if strings.Contains(l, "level=WARN") {
				warn += l
			}
		}
		if tc.warnDrops {
			for _, want := range []string{fmt.Sprintf("id=%d", drop), "stage=poc_published", "status=" + dropSide.status} {
				if !strings.Contains(warn, want) {
					t.Errorf("case %d: warn log %q lacks %q", i, warn, want)
				}
			}
			if dropSide.url != "" && !strings.Contains(warn, "post_url="+dropSide.url) {
				t.Errorf("case %d: warn log %q lacks the post_url", i, warn)
			}
		} else if warn != "" {
			t.Errorf("case %d: pending draft dropped with a warning: %s", i, warn)
		}
		if n := count(t, d.Conn, `SELECT count(*) FROM admin_audit WHERE target_type = 'x_draft' AND target_id = $1`, fmt.Sprint(drop)); n != 1 {
			t.Errorf("case %d: audit rows of the dropped draft: %d", i, n)
		}
	}
}

// Defect 2: a reply holds its parent comment FOR SHARE and then needs the
// vuln row (FK); the merge must never hold the vuln row while it waits for
// a comment of that vuln.
func TestMergeVsReplyNoDeadlock(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	exec(t, d.Conn, `INSERT INTO vuln (cve_id, title) VALUES ($1, 'G'), ($2, NULL)`, gid, cve1)
	exec(t, d.Conn, `INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ($1, $2, 'ghsa')`, cve1, gid)
	var top string
	if err := d.Conn.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, body, lang, links) VALUES ($1, false, 'top', 'en', true) RETURNING id`, gid).Scan(&top); err != nil {
		t.Fatal(err)
	}
	u, m := connect(t, d), connect(t, d)
	utx, err := u.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer utx.Rollback(ctx) //nolint:errcheck
	// the reply's CTE p
	exec(t, utx, `SELECT 1 FROM comments WHERE id = $1 AND cve_id = $2 FOR SHARE`, top, gid)
	done := mergeAsync(m, gid, cve1, nil)
	waitBlocked(t, d.Conn, m.PgConn().PID(), u.PgConn().PID())
	// the reply's INSERT: its FK check needs the vuln row
	_, uerr := utx.Exec(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, body, lang, links) VALUES ($1, $2, true, 'reply', 'en', true)`, gid, top)
	if uerr == nil {
		uerr = utx.Commit(ctx)
	} else {
		_ = utx.Rollback(ctx)
	}
	merr := wait(t, done)
	if uerr != nil || merr != nil {
		t.Fatalf("reply: %v; merge: %v", uerr, merr)
	}
	if n := count(t, d.Conn, `SELECT count(*) FROM comments WHERE cve_id = $1`, cve1); n != 2 {
		t.Errorf("comments under the CVE: %d", n)
	}
}

// Defect 2, the window between the merge's two lock steps: a new thread
// committed after the merge locked the existing comments, and a reply that
// locks it, must not deadlock either.
func TestMergeVsNewThreadNoDeadlock(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	exec(t, d.Conn, `INSERT INTO vuln (cve_id, title) VALUES ($1, 'G'), ($2, NULL)`, gid, cve1)
	exec(t, d.Conn, `INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ($1, $2, 'ghsa')`, cve1, gid)
	var q string
	if err := d.Conn.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, body, lang, links) VALUES ($1, false, 'q', 'en', true) RETURNING id`, gid).Scan(&q); err != nil {
		t.Fatal(err)
	}
	u0, u1, u2, m := connect(t, d), connect(t, d), connect(t, d), connect(t, d)
	for _, c := range []*pgx.Conn{u1, u2} {
		exec(t, c, `SET lock_timeout = '3s'`) // a wrong lock order fails instead of hanging
	}
	// an edit of q holds its row
	tx0, err := u0.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback(ctx) //nolint:errcheck
	exec(t, tx0, `SELECT 1 FROM comments WHERE id = $1 FOR UPDATE`, q)
	done := mergeAsync(m, gid, cve1, nil)
	waitBlocked(t, d.Conn, m.PgConn().PID(), u0.PgConn().PID())
	// a new thread is committed meanwhile, and a reply locks it
	var x string
	if err := u1.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, body, lang, links) VALUES ($1, false, 'x', 'en', true) RETURNING id`, gid).Scan(&x); err != nil {
		_ = tx0.Rollback(ctx)
		_ = wait(t, done)
		t.Fatalf("new thread while the merge waits: %v", err)
	}
	tx2, err := u2.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	exec(t, tx2, `SELECT 1 FROM comments WHERE id = $1 AND cve_id = $2 FOR SHARE`, x, gid)
	if err := tx0.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// the merge now finds x held by the reply and must back off
	waitBlocked(t, d.Conn, m.PgConn().PID(), u2.PgConn().PID())
	_, uerr := tx2.Exec(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, body, lang, links) VALUES ($1, $2, true, 'reply', 'en', true)`, gid, x)
	if uerr == nil {
		uerr = tx2.Commit(ctx)
	} else {
		_ = tx2.Rollback(ctx)
	}
	merr := wait(t, done)
	if uerr != nil || merr != nil {
		t.Fatalf("reply: %v; merge: %v", uerr, merr)
	}
	if n := count(t, d.Conn, `SELECT count(*) FROM comments WHERE cve_id = $1`, cve1); n != 3 {
		t.Errorf("comments under the CVE: %d", n)
	}
}

// Defect 5: an advisory withdrawn in the same version in which it gains a
// CVE contributes nothing to the CVE; comments, corrections and staff
// tags still move.
func TestWithdrawnAdvisoryGainingCVEContributesNothing(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	ghsaRows(t, d.Conn, gid)
	// the new version: withdrawn and naming the CVE (stored before apply,
	// like RunCollector does); normalize returns only the alias for it
	storeAdvisory(t, d.Conn, gid, cve1, true, T1)
	apply(t, d.Conn, &model.Normalized{Aliases: []model.Alias{{CVEID: cve1, Alias: gid, AliasType: "ghsa"}}}, T1)
	checkWithdrawnMerge(t, d.Conn, cve1, "")
}

// Defect 5, adjacent case: the advisory was withdrawn first (its event says
// REJECTED), and a CVE record names it later.
func TestAlreadyWithdrawnAdvisoryNamedByCVE(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	ghsaRows(t, d.Conn, gid)
	apply(t, d.Conn, ghsaNoCVE(gid, true), T1)
	apply(t, d.Conn, cvelistDisclosed(cve1, gid), T2)
	checkWithdrawnMerge(t, d.Conn, cve1, "CNA title")
	if n := count(t, d.Conn, `SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'disclosed' AND source = 'cvelist'`, cve1); n != 1 {
		t.Error("the CVE record's disclosure is missing")
	}
}

// ghsaRows gives the GHSA-keyed vuln classification rows from its advisory,
// a rule tag and a staff tag, a comment and a correction.
func ghsaRows(t *testing.T, db pipeline.Execer, g string) {
	t.Helper()
	exec(t, db, `INSERT INTO vuln_cwe (cve_id, cwe, source, source_org) VALUES ($1, 'CWE-94', 'ghsa', $1)`, g)
	exec(t, db, `INSERT INTO vuln_cvss (cve_id, version, vector, source, source_org) VALUES ($1, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'ghsa', $1)`, g)
	exec(t, db, `INSERT INTO vuln_classify_input (cve_id, source, source_key, content_hash, rejected) VALUES ($1, 'ghsa', $1, 'h1', false)`, g)
	exec(t, db, `INSERT INTO vuln_tag (cve_id, tag, origin, rule_version) VALUES ($1, 'rce', 'rule', 1), ($1, 'npm', 'staff', NULL)`, g)
	exec(t, db, `INSERT INTO comments (cve_id, is_reply, body, lang, links) VALUES ($1, false, 'top', 'en', true)`, g)
	exec(t, db, `INSERT INTO vuln_corrections (cve_id, category, body) VALUES ($1, 'title', 'please fix')`, g)
}

func storeAdvisory(t *testing.T, db pipeline.Execer, g, cve string, withdrawn bool, at time.Time) {
	t.Helper()
	p := pyjson.NewObject()
	p.Set("ghsa_id", g)
	p.Set("cve_id", cve)
	p.Set("summary", "Sandbox escape")
	if withdrawn {
		p.Set("withdrawn_at", at.Format(time.RFC3339))
	} else {
		p.Set("withdrawn_at", nil)
	}
	rec := model.RawRecord{Source: "ghsa", SourceKey: g, Payload: p}
	h, err := rec.ContentHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.StoreRaw(context.Background(), db, rec, h, at); err != nil {
		t.Fatal(err)
	}
}

func checkWithdrawnMerge(t *testing.T, db pipeline.Execer, cve, wantTitle string) {
	t.Helper()
	if n := count(t, db, `SELECT count(*) FROM vuln WHERE cve_id = $1`, gid); n != 0 {
		t.Fatal("GHSA-keyed row still there")
	}
	if n := count(t, db, `SELECT count(*) FROM event WHERE cve_id = $1 AND source = 'ghsa'`, cve); n != 0 {
		t.Errorf("events of the withdrawn advisory moved to the CVE: %d", n)
	}
	var title, desc *string
	if err := db.QueryRow(context.Background(), `SELECT title, description FROM vuln WHERE cve_id = $1`, cve).Scan(&title, &desc); err != nil {
		t.Fatal(err)
	}
	if (wantTitle == "" && title != nil) || (wantTitle != "" && (title == nil || *title != wantTitle)) || desc != nil {
		t.Errorf("the CVE took the withdrawn advisory's text: %v %v", title, desc)
	}
	for _, q := range []string{
		`SELECT count(*) FROM vuln_cwe WHERE cve_id = $1 AND source = 'ghsa'`,
		`SELECT count(*) FROM vuln_cvss WHERE cve_id = $1 AND source = 'ghsa'`,
		`SELECT count(*) FROM vuln_classify_input WHERE cve_id = $1 AND source = 'ghsa'`,
		`SELECT count(*) FROM vuln_tag WHERE cve_id = $1 AND origin = 'rule'`,
	} {
		if n := count(t, db, q, cve); n != 0 {
			t.Errorf("%s: %d", q, n)
		}
	}
	for table, want := range map[string]int{"comments": 1, "vuln_corrections": 1, "vuln_tag": 1} {
		if n := count(t, db, "SELECT count(*) FROM "+table+" WHERE cve_id = $1", cve); n != want {
			t.Errorf("%s under the CVE: %d, want %d", table, n, want)
		}
	}
	for _, table := range []string{"event", "vuln_cwe", "vuln_cvss", "vuln_classify_input", "vuln_tag", "comments", "vuln_corrections"} {
		if n := count(t, db, "SELECT count(*) FROM "+table+" WHERE cve_id = $1", gid); n != 0 {
			t.Errorf("%s left under %s: %d", table, gid, n)
		}
	}
}

// scripted is a collector whose records normalize to fixed results; hook
// runs at every Normalize call.
type scripted struct {
	name string
	keys []string
	out  map[string]*model.Normalized
	hook func(key string)
}

func (s *scripted) Name() string { return s.name }
func (s *scripted) Fetch(context.Context, model.CollectorState) (*model.FetchResult, error) {
	res := &model.FetchResult{}
	for _, k := range s.keys {
		p := pyjson.NewObject()
		p.Set("k", k)
		res.Records = append(res.Records, model.RawRecord{Source: s.name, SourceKey: k, Payload: p})
	}
	return res, nil
}
func (s *scripted) Normalize(rec model.RawRecord) (*model.Normalized, error) {
	if s.hook != nil {
		s.hook(rec.SourceKey)
	}
	return s.out[rec.SourceKey], nil
}

// Cross-run order: a ghsa run holds the CVE's row (upserted for an earlier
// advisory G0 naming it) when it reaches advisory G; a cvelist run whose
// record names G as an alias takes G's lock and then wants the CVE's row.
// The runs take their GHSA-id locks up front, so neither can hold a row
// while waiting for such a lock.
func TestCrossRunGHSALockNoDeadlock(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	const g0 = "GHSA-4444-5555-6666"
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	exec(t, d.Conn, `INSERT INTO vuln (cve_id) VALUES ($1)`, cve1)
	a, b, obs, probe := connect(t, d), connect(t, d), connect(t, d), connect(t, d)
	paused, resume := make(chan struct{}), make(chan struct{})
	once := false
	ghsaRun := &scripted{name: "ghsa", keys: []string{g0, gid}, out: map[string]*model.Normalized{
		g0:  {Vulns: []model.VulnUpsert{{CVEID: cve1}}, Aliases: []model.Alias{{CVEID: cve1, Alias: g0, AliasType: "ghsa"}}},
		gid: ghsaWithCVE(gid, cve1),
	}}
	// pause at G once the run holds the CVE's row
	ghsaRun.hook = func(key string) {
		if key != gid || once {
			return
		}
		held := false
		_ = pgx.BeginFunc(ctx, probe, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `SELECT 1 FROM vuln WHERE cve_id = $1 FOR UPDATE NOWAIT`, cve1)
			held = err != nil
			return errors.New("rollback")
		})
		if held {
			once = true
			close(paused)
			<-resume
		}
	}
	cvelistRun := &scripted{name: "cvelist", keys: []string{cve1}, out: map[string]*model.Normalized{cve1: cvelistDisclosed(cve1, gid)}}
	aerr, berr := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := pipeline.RunCollector(ctx, a, ghsaRun, pipeline.Options{Now: func() time.Time { return T1 }, SkipStateRefresh: true})
		aerr <- err
	}()
	select {
	case <-paused:
	case err := <-aerr:
		t.Fatalf("the ghsa run never paused: %v", err)
	}
	go func() {
		_, err := pipeline.RunCollector(ctx, b, cvelistRun, pipeline.Options{Now: func() time.Time { return T1 }, SkipStateRefresh: true})
		berr <- err
	}()
	waitBlocked(t, obs, b.PgConn().PID(), a.PgConn().PID())
	close(resume)
	ea, eb := wait(t, aerr), wait(t, berr)
	if ea != nil || eb != nil {
		t.Fatalf("ghsa run: %v; cvelist run: %v", ea, eb)
	}
	if n := count(t, d.Conn, `SELECT count(*) FROM vuln WHERE cve_id = $1`, gid); n != 0 {
		t.Error("not merged")
	}
}
