package ghsa

import (
	"context"
	"testing"
	"time"

	"nday.land/nday/internal/classify"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/testutil"
)

// End to end (docs/ghsa.md): an advisory without a CVE is stored as a vuln
// keyed by its GHSA id, people comment on it, it is classified; a later
// version names a CVE, and after that run everything is under the CVE and
// the GHSA-keyed row is gone (the GHSA id stays as an alias).
func TestEndToEndAdvisoryGainsCVE(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	const cve = "CVE-2026-99001"
	adv := atTS(t, f.noCVE, zfmt(f.now.Add(-2*time.Hour)))
	gid := str(adv.Get("ghsa_id"))
	gh := newFake(t, f, []*pyjson.Object{adv}, 100)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)

	if n := scalar(t, d, "SELECT count(*) FROM event WHERE cve_id = $1", gid); n != 2 {
		t.Fatalf("events under %s: %d", gid, n)
	}
	var stage string
	var disclosedAt *time.Time
	if err := d.Conn.QueryRow(ctx, "SELECT stage, disclosed_at FROM vuln_state_mat WHERE cve_id = $1", gid).Scan(&stage, &disclosedAt); err != nil {
		t.Fatalf("vuln_state_mat: %v", err)
	}
	if pub, _ := parseTS(adv.Get("published_at")); stage != "patch_released" || disclosedAt == nil || !disclosedAt.Equal(pub) {
		t.Errorf("state %s %v", stage, disclosedAt)
	}
	if _, err := classify.Pending(ctx, d.Conn, classify.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln_cwe WHERE cve_id = $1 AND source = 'ghsa'", gid); n == 0 {
		t.Error("no CWE rows for the GHSA-keyed vuln")
	}
	if _, err := tags.Pending(ctx, d.Conn, tags.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	var top string
	if err := d.Conn.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, body, lang, links)
        VALUES ($1, false, 'repro attached', 'en', true) RETURNING id`, gid).Scan(&top); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, body, lang, links)
        VALUES ($1, $2, true, 'thanks', 'en', true)`, gid, top); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO vuln_corrections (cve_id, category, body) VALUES ($1, 'title', 'typo')`, gid); err != nil {
		t.Fatal(err)
	}

	withCVE := atTS(t, adv, zfmt(f.now.Add(20*time.Minute)))
	withCVE.Set("cve_id", cve)
	gh.advisories[gid] = withCVE
	later := f.now.Add(time.Hour)
	run(t, d, gh.collector(cOpts{now: later}), later, false)

	if n := scalar(t, d, "SELECT count(*) FROM vuln WHERE cve_id = $1", gid); n != 0 {
		t.Fatal("GHSA-keyed vuln still there")
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln_alias WHERE alias = $1 AND cve_id = $2 AND alias_type = 'ghsa'", gid, cve); n != 1 {
		t.Error("alias")
	}
	for table, want := range map[string]int64{"event": 2, "comments": 2, "vuln_corrections": 1} {
		if n := scalar(t, d, "SELECT count(*) FROM "+table+" WHERE cve_id = $1", cve); n != want {
			t.Errorf("%s under %s: %d, want %d", table, cve, n, want)
		}
	}
	// no CVE record yet: the advisory's disclosure is the CVE's for now
	if n := scalar(t, d, "SELECT count(*) FROM event WHERE cve_id = $1 AND type = 'disclosed' AND source = 'ghsa'", cve); n != 1 {
		t.Error("disclosure lost")
	}
	if _, err := classify.Pending(ctx, d.Conn, classify.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln_cwe WHERE cve_id = $1 AND source_org = $2", cve, gid); n == 0 {
		t.Error("CWE rows not under the CVE")
	}
	for _, table := range []string{"vuln_cwe", "vuln_cvss", "vuln_classify_input", "vuln_tag", "event", "comments"} {
		if n := scalar(t, d, "SELECT count(*) FROM "+table+" WHERE cve_id = $1", gid); n != 0 {
			t.Errorf("%s left under %s: %d", table, gid, n)
		}
	}
	if _, err := tags.Pending(ctx, d.Conn, tags.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln_state_mat WHERE cve_id = $1", gid); n != 0 {
		t.Error("GHSA id still in vuln_state_mat")
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln_state_mat WHERE cve_id = $1", cve); n != 1 {
		t.Error("CVE not in vuln_state_mat")
	}
	// re-normalizing everything stored changes nothing (the parity oracle)
	st, err := pipeline.Renormalize(ctx, d.Conn, gh.collector(cOpts{now: later}), pipeline.RenormalizeOptions{
		Now: func() time.Time { return later }, SkipStateRefresh: true})
	if err != nil || st.VulnInserted+st.VulnUpdated+st.EventInserted+st.EventUpdated+st.AliasInserted != 0 {
		t.Errorf("renormalize %+v %v", st, err)
	}
}

// Defect 5 end to end: the advisory is withdrawn in the same version in
// which it gains a CVE. A withdrawn advisory contributes nothing to the
// CVE: its events, text and classification stay out; the comment moves.
func TestEndToEndWithdrawnWhenGainingCVE(t *testing.T) {
	t.Parallel()
	f := load(t)
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	const cve = "CVE-2026-99002"
	adv := atTS(t, f.noCVE, zfmt(f.now.Add(-2*time.Hour)))
	gid := str(adv.Get("ghsa_id"))
	gh := newFake(t, f, []*pyjson.Object{adv}, 100)
	run(t, d, gh.collector(cOpts{now: f.now}), f.now, false)
	if _, err := classify.Pending(ctx, d.Conn, classify.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO comments (cve_id, is_reply, body, lang, links) VALUES ($1, false, 'repro', 'en', true)`, gid); err != nil {
		t.Fatal(err)
	}
	gone := atTS(t, adv, zfmt(f.now.Add(20*time.Minute)))
	gone.Set("cve_id", cve)
	gone.Set("withdrawn_at", zfmt(f.now.Add(20*time.Minute)))
	gh.advisories[gid] = gone
	later := f.now.Add(time.Hour)
	run(t, d, gh.collector(cOpts{now: later}), later, false)

	if n := scalar(t, d, "SELECT count(*) FROM vuln WHERE cve_id = $1", gid); n != 0 {
		t.Fatal("GHSA-keyed vuln still there")
	}
	if n := scalar(t, d, "SELECT count(*) FROM event WHERE cve_id = $1", cve); n != 0 {
		t.Errorf("events of the withdrawn advisory under the CVE: %d", n)
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln WHERE cve_id = $1 AND (title IS NOT NULL OR description IS NOT NULL)", cve); n != 0 {
		t.Error("the CVE took the withdrawn advisory's text")
	}
	if n := scalar(t, d, "SELECT count(*) FROM comments WHERE cve_id = $1", cve); n != 1 {
		t.Errorf("comment under the CVE: %d", n)
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln_cwe WHERE cve_id = $1", cve) + scalar(t, d, "SELECT count(*) FROM vuln_cvss WHERE cve_id = $1", cve); n != 0 {
		t.Errorf("classification of the withdrawn advisory under the CVE before classify ran: %d", n)
	}
	if _, err := classify.Pending(ctx, d.Conn, classify.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if n := scalar(t, d, "SELECT count(*) FROM vuln_cwe WHERE cve_id = $1", cve); n != 0 {
		t.Errorf("classification of the withdrawn advisory under the CVE: %d", n)
	}
}
