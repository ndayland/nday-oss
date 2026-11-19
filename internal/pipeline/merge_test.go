package pipeline_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/testutil"
)

const (
	gid  = "GHSA-2cm2-m3w5-gp2f"
	cve1 = "CVE-2026-90001"
	cve2 = "CVE-2026-90002"
)

func exec(t *testing.T, db pipeline.Execer, sql string, args ...any) {
	t.Helper()
	if _, err := db.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func count(t *testing.T, db pipeline.Execer, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func apply(t *testing.T, db pipeline.Execer, n *model.Normalized, at time.Time) *pipeline.Stats {
	t.Helper()
	if err := n.Validate(); err != nil {
		t.Fatal(err)
	}
	st := &pipeline.Stats{}
	if err := pipeline.ApplyNormalized(context.Background(), db, n, at, false, st); err != nil {
		t.Fatal(err)
	}
	return st
}

// ghsaNoCVE is what the ghsa collector makes of an advisory without a CVE.
func ghsaNoCVE(id string, withdrawn bool) *model.Normalized {
	pub := T0.Add(-48 * time.Hour)
	state := "PUBLISHED"
	if withdrawn {
		state = "REJECTED"
	}
	n := &model.Normalized{Events: []model.Event{{CVEID: id, Type: model.EventDisclosed, Source: "ghsa",
		OccurredAt: &pub, Detail: map[string]any{"ghsa_id": id, "state": state, "withdrawn_at": nil}, DedupeKey: id}}}
	if withdrawn {
		return n
	}
	n.Vulns = []model.VulnUpsert{{CVEID: id, Title: model.Ptr("Sandbox escape"), Description: model.Ptr("desc"),
		PublishedAt: &pub, ModifiedAt: &pub, Authoritative: true}}
	n.Events = append(n.Events, model.Event{CVEID: id, Type: model.EventPatchReleased, Source: "ghsa",
		Detail: map[string]any{"ghsa_id": id, "v": "1"}, DedupeKey: id})
	return n
}

// ghsaWithCVE is the same advisory once it names cve.
func ghsaWithCVE(id, cve string) *model.Normalized {
	return &model.Normalized{
		Vulns:   []model.VulnUpsert{{CVEID: cve, Title: model.Ptr("Sandbox escape")}},
		Aliases: []model.Alias{{CVEID: cve, Alias: id, AliasType: "ghsa"}},
		Events: []model.Event{{CVEID: cve, Type: model.EventPatchReleased, Source: "ghsa",
			Detail: map[string]any{"ghsa_id": id, "v": "2"}, DedupeKey: id}},
	}
}

// cvelistDisclosed is a CVE record's disclosed event naming the advisory.
func cvelistDisclosed(cve, alias string) *model.Normalized {
	pub := T0.Add(-24 * time.Hour)
	n := &model.Normalized{
		Vulns: []model.VulnUpsert{{CVEID: cve, Title: model.Ptr("CNA title"), PublishedAt: &pub, Authoritative: true}},
		Events: []model.Event{{CVEID: cve, Type: model.EventDisclosed, Source: "cvelist", OccurredAt: &pub,
			Detail: map[string]any{"state": "PUBLISHED"}}},
	}
	if alias != "" {
		n.Aliases = []model.Alias{{CVEID: cve, Alias: alias, AliasType: "ghsa"}}
	}
	return n
}

func TestValidateAcceptsGHSAKeys(t *testing.T) {
	if err := ghsaNoCVE(gid, false).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"GHSA-2CM2-M3W5-GP2F", "ghsa-2cm2-m3w5-gp2f", "GHSA-2cm2-m3w5-gp2", "GHSA-aaaa-bbbb-cccc"} {
		n := &model.Normalized{Vulns: []model.VulnUpsert{{CVEID: bad}}}
		if err := n.Validate(); err == nil || !strings.Contains(err.Error(), "invalid vuln id") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// An advisory without a CVE becomes a vuln keyed by its GHSA id; the same
// advisory naming a CVE later moves it there.
func TestGHSAVulnMovesToCVE(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1", gid); n != 2 {
		t.Fatalf("events under %s: %d", gid, n)
	}
	st := apply(t, d.Conn, ghsaWithCVE(gid, cve1), T1)
	if st.AliasInserted != 1 || st.EventInserted != 0 || st.EventUpdated != 1 {
		t.Errorf("stats %+v", st)
	}
	if n := count(t, d.Conn, "SELECT count(*) FROM vuln WHERE cve_id = $1", gid); n != 0 {
		t.Error("GHSA-keyed row still there")
	}
	var title string
	var pub *time.Time
	_ = d.Conn.QueryRow(context.Background(), "SELECT title, published_at FROM vuln WHERE cve_id = $1", cve1).Scan(&title, &pub)
	if title != "Sandbox escape" || pub == nil {
		t.Errorf("target %q %v", title, pub)
	}
	// both events moved (no CVE record yet: the advisory's disclosure stays),
	// the patch event kept its first observation and took the new detail
	var obs time.Time
	var v string
	_ = d.Conn.QueryRow(context.Background(), `SELECT observed_at, detail->>'v' FROM event
        WHERE cve_id = $1 AND type = 'patch_released'`, cve1).Scan(&obs, &v)
	if !obs.Equal(T0) || v != "2" {
		t.Errorf("patch event %v %s", obs, v)
	}
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'disclosed' AND source = 'ghsa'", cve1); n != 1 {
		t.Errorf("disclosed %d", n)
	}
	// the CVE record arrives: its disclosure replaces the advisory's
	apply(t, d.Conn, cvelistDisclosed(cve1, gid), T2)
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'disclosed'", cve1); n != 1 {
		t.Errorf("disclosed after CVE record %d", n)
	}
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1 AND source = 'ghsa' AND type = 'disclosed'", cve1); n != 0 {
		t.Error("ghsa disclosure kept next to the CVE record's")
	}
	// re-applying the old CVE-less version goes to the CVE, never recreates G
	apply(t, d.Conn, ghsaNoCVE(gid, false), T2)
	if n := count(t, d.Conn, "SELECT count(*) FROM vuln WHERE cve_id = $1", gid); n != 0 {
		t.Error("GHSA-keyed row recreated next to its alias")
	}
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1 AND source = 'ghsa' AND type = 'disclosed'", cve1); n != 0 {
		t.Error("redirected ghsa disclosure written next to the CVE record's")
	}
	var desc *string
	_ = d.Conn.QueryRow(context.Background(), "SELECT title, description FROM vuln WHERE cve_id = $1", cve1).Scan(&title, &desc)
	if title != "CNA title" || desc == nil || *desc != "desc" {
		t.Errorf("redirected upsert must be a stub: %q %v", title, desc)
	}
}

// The CVE record naming the advisory first (cvelist alias) merges too.
func TestCVERecordAliasMerges(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	apply(t, d.Conn, cvelistDisclosed(cve1, gid), T1)
	if n := count(t, d.Conn, "SELECT count(*) FROM vuln WHERE cve_id = $1", gid); n != 0 {
		t.Fatal("not merged")
	}
	// the CVE record has a disclosure: the advisory's is dropped
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'disclosed'", cve1); n != 1 {
		t.Errorf("disclosed %d", n)
	}
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'patch_released'", cve1); n != 1 {
		t.Error("patch event not moved")
	}
}

// Upstream changes the advisory's CVE from C1 to C2: the alias stays with C1
// (unique per GHSA id, first one wins, as before), C2 gets the advisory's
// rows like any CVE advisory, and the GHSA id never comes back as a vuln.
func TestAdvisoryCVEChanges(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	apply(t, d.Conn, ghsaWithCVE(gid, cve1), T1)
	apply(t, d.Conn, ghsaWithCVE(gid, cve2), T2)
	var to string
	_ = d.Conn.QueryRow(context.Background(), "SELECT cve_id FROM vuln_alias WHERE alias = $1", gid).Scan(&to)
	if to != cve1 {
		t.Errorf("alias -> %s", to)
	}
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'patch_released'", cve2); n != 1 {
		t.Error("C2 has no patch event")
	}
	if n := count(t, d.Conn, "SELECT count(*) FROM vuln WHERE cve_id = $1", gid); n != 0 {
		t.Error("GHSA-keyed row exists")
	}
	// a CVE-less version now goes to the alias's CVE
	apply(t, d.Conn, ghsaNoCVE(gid, false), T2.Add(time.Hour))
	if n := count(t, d.Conn, "SELECT count(*) FROM vuln WHERE cve_id = $1", gid); n != 0 {
		t.Error("GHSA-keyed row recreated")
	}
}

// Withdrawn: never stored -> nothing; stored -> its disclosed event says
// REJECTED and vuln_state reports it rejected.
func TestWithdrawnGHSAVuln(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	st := apply(t, d.Conn, ghsaNoCVE(gid, true), T0)
	if st.VulnInserted+st.EventInserted != 0 || count(t, d.Conn, "SELECT count(*) FROM vuln") != 0 {
		t.Fatalf("withdrawn, never stored: %+v", st)
	}
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	var rej bool
	_ = d.Conn.QueryRow(context.Background(), "SELECT is_rejected FROM vuln_state WHERE cve_id = $1", gid).Scan(&rej)
	if rej {
		t.Fatal("rejected before withdrawal")
	}
	st = apply(t, d.Conn, ghsaNoCVE(gid, true), T1)
	if st.EventUpdated != 1 {
		t.Errorf("stats %+v", st)
	}
	_ = d.Conn.QueryRow(context.Background(), "SELECT is_rejected FROM vuln_state WHERE cve_id = $1", gid).Scan(&rej)
	if !rej {
		t.Error("withdrawn advisory not rejected in vuln_state")
	}
	// a ghsa state on a CVE-keyed vuln is never read
	apply(t, d.Conn, &model.Normalized{Events: []model.Event{{CVEID: cve1, Type: model.EventDisclosed, Source: "ghsa",
		Detail: map[string]any{"state": "REJECTED"}, DedupeKey: gid}}}, T1)
	_ = d.Conn.QueryRow(context.Background(), "SELECT is_rejected FROM vuln_state WHERE cve_id = $1", cve1).Scan(&rej)
	if rej {
		t.Error("ghsa state read for a CVE")
	}
}

func TestMissingCVEsSkipsGHSAKeys(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	exec(t, d.Conn, "INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0001')")
	got, err := pipeline.MissingCVEs(context.Background(), d.Conn, "cvelist", 10)
	if err != nil || len(got) != 1 || got[0] != "CVE-2026-0001" {
		t.Errorf("%v %v", got, err)
	}
}

// mergeFixture fills G with one row in every table that holds a vuln id,
// and C with rows colliding with some of them.
func mergeFixture(t *testing.T, tx pgx.Tx) (top, reply string) {
	t.Helper()
	ctx := context.Background()
	exec(t, tx, `INSERT INTO vuln (cve_id, title, first_seen_at) VALUES ($1, 'G title', $2), ($3, NULL, $4)`, gid, T0, cve1, T1)
	exec(t, tx, `INSERT INTO event (cve_id, type, observed_at, source, dedupe_key, occurred_at, detail) VALUES
        ($1, 'disclosed', $3, 'ghsa', $1, $3, '{"state":"PUBLISHED"}'),
        ($1, 'patch_released', $3, 'ghsa', $1, NULL, '{"v":"g"}'),
        ($1, 'poc_published', $3, 'exploitdb', 'x1', NULL, '{}'),
        ($1, 'social_post', $3, 'xposts', '111', NULL, '{}'),
        ($2, 'disclosed', $3, 'cvelist', '', $3, '{"state":"PUBLISHED"}'),
        ($2, 'patch_released', $3, 'ghsa', $1, NULL, '{"v":"c"}')`, gid, cve1, T0)
	exec(t, tx, `INSERT INTO affected (cve_id, vendor, product) VALUES ($1, 'npm', 'vm2'), ($1, 'npm', 'other'), ($2, 'npm', 'vm2')`, gid, cve1)
	exec(t, tx, `INSERT INTO vuln_cwe (cve_id, cwe, source, source_org) VALUES ($1, 'CWE-94', 'ghsa', $1), ($2, 'CWE-94', 'ghsa', $1), ($1, 'CWE-20', 'ghsa', $1)`, gid, cve1)
	exec(t, tx, `INSERT INTO vuln_cvss (cve_id, version, vector, source, source_org) VALUES ($1, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'ghsa', $1)`, gid)
	exec(t, tx, `INSERT INTO vuln_classify_input (cve_id, source, source_key, content_hash, rejected) VALUES ($1, 'ghsa', $1, 'h1', false)`, gid)
	exec(t, tx, `INSERT INTO vuln_tag (cve_id, tag, origin, rule_version) VALUES ($1, 'rce', 'rule', 1), ($1, 'npm', 'staff', NULL), ($2, 'rce', 'rule', 1)`, gid, cve1)
	exec(t, tx, `INSERT INTO vuln_tag_suppress (cve_id, tag, reason) VALUES ($1, 'xss', 'wrong'), ($1, 'rce', 'g reason'), ($2, 'rce', 'c reason')`, gid, cve1)
	exec(t, tx, `INSERT INTO x_post_no_cve (post_id, author_id, text, posted_at, url, observed_at)
        VALUES ('222', '1', 'see advisory', $1, 'https://x.com/i/web/status/222', $1)`, T0)
	exec(t, tx, `INSERT INTO x_post_no_cve_link (post_id, cve_id) VALUES ('222', $1)`, gid)
	var pocID, cPatchID, gPatchID int64
	_ = tx.QueryRow(ctx, "SELECT id FROM event WHERE cve_id = $1 AND type = 'poc_published'", gid).Scan(&pocID)
	_ = tx.QueryRow(ctx, "SELECT id FROM event WHERE cve_id = $1 AND type = 'patch_released'", gid).Scan(&gPatchID)
	_ = tx.QueryRow(ctx, "SELECT id FROM event WHERE cve_id = $1 AND type = 'patch_released'", cve1).Scan(&cPatchID)
	// G's poc draft was posted by staff; C has a pending one for the same
	// stage: the posted one wins. G's kev draft points at an event that
	// collides (made up, to check the event_id follows the kept event).
	exec(t, tx, `INSERT INTO x_draft (cve_id, stage, event_id, body, status, decided_at) VALUES
        ($1, 'poc_published', $3, 'posted body', 'posted', $4),
        ($2, 'poc_published', 1, 'pending body', 'draft', NULL),
        ($1, 'kev_added', $5, 'kev body', 'draft', NULL)`, gid, cve1, pocID, T1, gPatchID)
	_ = tx.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, body, lang, links) VALUES ($1, false, 'top', 'en', true) RETURNING id`, gid).Scan(&top)
	_ = tx.QueryRow(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, body, lang, links) VALUES ($1, $2, true, 'reply', 'en', true) RETURNING id`, gid, top).Scan(&reply)
	exec(t, tx, `INSERT INTO vuln_corrections (cve_id, category, body) VALUES ($1, 'title', 'please fix')`, gid)
	exec(t, tx, `INSERT INTO classify_queue (cve_id) VALUES ($1)`, gid)
	exec(t, tx, `INSERT INTO tag_queue (cve_id) VALUES ($1)`, gid)
	exec(t, tx, `INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ($1, $2, 'ghsa')`, cve1, gid)
	_ = cPatchID
	return top, reply
}

func TestMergeVulnMovesEveryTable(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	tx, err := d.Conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	top, reply := mergeFixture(t, tx)
	exec(t, tx, "DELETE FROM classify_queue")
	exec(t, tx, "DELETE FROM tag_queue")
	exec(t, tx, `INSERT INTO classify_queue (cve_id) VALUES ($1)`, gid)
	var logs bytes.Buffer
	mc, err := pipeline.MergeVulnID(ctx, tx, gid, cve1, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !mc.Merged || mc.CreatedTarget {
		t.Errorf("%+v", mc)
	}
	if n := count(t, tx, "SELECT count(*) FROM vuln WHERE cve_id = $1", gid); n != 0 {
		t.Error("source row left")
	}
	for table, want := range map[string]int{
		"event": 4, "affected": 2, "vuln_cwe": 2, "vuln_cvss": 1, "vuln_classify_input": 1,
		"vuln_tag": 2, "vuln_tag_suppress": 2, "x_post_no_cve_link": 1, "x_draft": 2,
		"comments": 2, "vuln_corrections": 1, "vuln_alias": 1,
	} {
		if n := count(t, tx, "SELECT count(*) FROM "+table+" WHERE cve_id = $1", cve1); n != want {
			t.Errorf("%s under target: %d, want %d", table, n, want)
		}
		if n := count(t, tx, "SELECT count(*) FROM "+table+" WHERE cve_id = $1", gid); n != 0 {
			t.Errorf("%s under source: %d", table, n)
		}
	}
	// collisions: the target's row is kept
	var v, reason, body string
	_ = tx.QueryRow(ctx, "SELECT detail->>'v' FROM event WHERE cve_id = $1 AND type = 'patch_released'", cve1).Scan(&v)
	_ = tx.QueryRow(ctx, "SELECT reason FROM vuln_tag_suppress WHERE cve_id = $1 AND tag = 'rce'", cve1).Scan(&reason)
	if v != "c" || reason != "c reason" {
		t.Errorf("collision kept %s %s", v, reason)
	}
	// the CVE record's disclosure wins over the advisory's
	if n := count(t, tx, "SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'disclosed' AND source = 'ghsa'", cve1); n != 0 {
		t.Error("ghsa disclosed moved next to cvelist's")
	}
	// the posted draft beat the pending one; the kev draft points at the
	// target's patch event (the one kept)
	_ = tx.QueryRow(ctx, "SELECT body FROM x_draft WHERE cve_id = $1 AND stage = 'poc_published'", cve1).Scan(&body)
	if body != "posted body" {
		t.Errorf("x_draft kept %q", body)
	}
	if n := count(t, tx, `SELECT count(*) FROM x_draft d JOIN event e ON e.id = d.event_id
        WHERE d.stage = 'kev_added' AND e.cve_id = $1 AND e.type = 'patch_released'`, cve1); n != 1 {
		t.Error("draft event_id not repointed")
	}
	// the reply still hangs off its thread
	if n := count(t, tx, "SELECT count(*) FROM comments WHERE id = $1 AND parent_id = $2 AND cve_id = $3", reply, top, cve1); n != 1 {
		t.Error("reply lost its thread")
	}
	// target filled from the source (stub rule), first_seen_at the earlier one
	var title string
	var first time.Time
	_ = tx.QueryRow(ctx, "SELECT title, first_seen_at FROM vuln WHERE cve_id = $1", cve1).Scan(&title, &first)
	if title != "G title" || !first.Equal(T0) {
		t.Errorf("target %q %v", title, first)
	}
	// recomputation queued for the target; the source's pending row moved
	if n := count(t, tx, "SELECT count(*) FROM classify_queue WHERE cve_id = $1", cve1); n < 2 {
		t.Errorf("classify_queue %d", n)
	}
	if n := count(t, tx, "SELECT count(*) FROM classify_queue WHERE cve_id = $1", gid); n != 0 {
		t.Error("classify_queue row left under source")
	}
	if n := count(t, tx, "SELECT count(*) FROM tag_queue WHERE cve_id = $1", cve1); n < 1 {
		t.Error("tag_queue")
	}
	if !strings.Contains(logs.String(), "merged vuln "+gid+" into "+cve1) || !strings.Contains(logs.String(), "comments=2") {
		t.Errorf("log %s", logs.String())
	}
	// alias left in place
	if n := count(t, tx, "SELECT count(*) FROM vuln_alias WHERE alias = $1 AND cve_id = $2", gid, cve1); n != 1 {
		t.Error("alias")
	}
	// twice: nothing to do
	mc, err = pipeline.MergeVulnID(ctx, tx, gid, cve1, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil || mc.Merged {
		t.Errorf("second merge %+v %v", mc, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// No target yet and no CVE record: the target is created from the source and
// the advisory's disclosure moves with it.
func TestMergeVulnCreatesTarget(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	apply(t, d.Conn, ghsaNoCVE(gid, false), T0)
	mc, err := pipeline.MergeVulnID(ctx, d.Conn, gid, cve2, nil)
	if err != nil || !mc.Merged || !mc.CreatedTarget || mc.Moved["event"] != 2 {
		t.Fatalf("%+v %v", mc, err)
	}
	var title string
	var pub *time.Time
	_ = d.Conn.QueryRow(ctx, "SELECT title, published_at FROM vuln WHERE cve_id = $1", cve2).Scan(&title, &pub)
	if title != "Sandbox escape" || pub == nil {
		t.Errorf("%q %v", title, pub)
	}
	if n := count(t, d.Conn, "SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'disclosed' AND source = 'ghsa'", cve2); n != 1 {
		t.Error("disclosure dropped although the CVE has none")
	}
	// G with no rows at all: nothing happens
	if mc, err := pipeline.MergeVulnID(ctx, d.Conn, "GHSA-2222-3333-4444", cve2, nil); err != nil || mc.Merged {
		t.Errorf("%+v %v", mc, err)
	}
	if _, err := pipeline.MergeVulnID(ctx, d.Conn, cve1, cve2, nil); err == nil {
		t.Error("merging a CVE id accepted")
	}
}
