package tags

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/titles"
)

const oracleDesc = "Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler). Supported versions that are affected are Oracle Java SE: 8u471."

// composed is the stored composed title of cve: "form|english" ("-" = no
// row, "|" = a row without a composed title).
func (e *env) composed(cve string) string {
	e.t.Helper()
	var form, en *string
	err := e.conn.QueryRow(e.ctx, `SELECT form, composed_en FROM vuln_title WHERE cve_id = $1`, cve).Scan(&form, &en)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return "-"
		}
		e.t.Fatal(err)
	}
	s := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return s(form) + "|" + s(en)
}

// Every input of the rule reaches the recomputation through tag_queue and
// the tag pass: a new vulnerability, its description, its title, its
// affected rows, its classification (type tags), a suppression and a staff
// tag. The staff columns are never touched by it.
func TestTitleMaintenance(t *testing.T) {
	e := newEnv(t)
	const cve = "CVE-2026-0101"
	// a new vulnerability (vuln insert trigger)
	e.exec(`INSERT INTO vuln (cve_id, description) VALUES ($1, $2)`, cve, oracleDesc)
	e.pending()
	if got := e.composed(cve); got != "excerpt|Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition…" {
		t.Fatalf("new vuln: %s", got)
	}
	// an affected row (0013 triggers): product tag java-se
	e.exec(`INSERT INTO affected (cve_id, vendor, product) VALUES ($1, 'Oracle Corporation', 'Java SE')`, cve)
	e.pending()
	if got := e.composed(cve); got != "component|Java SE: vulnerability in Compiler" {
		t.Fatalf("affected: %s", got)
	}
	// a weakness (classification: vuln_cwe trigger of 0011)
	e.exec(`INSERT INTO vuln_cwe (cve_id, cwe, source) VALUES ($1, 'CWE-787', 'cve-cna')`, cve)
	e.pending()
	if got := e.composed(cve); got != "full|Java SE: buffer overflow / out-of-bounds write in Compiler" {
		t.Fatalf("cwe: %s", got)
	}
	// staff title set by hand: never touched by the recomputation
	e.exec(`UPDATE vuln_title SET staff_title = 'Hand title', staff_at = now(), staff_version = 1 WHERE cve_id = $1`, cve)
	// the description (vuln update trigger)
	e.exec(`UPDATE vuln SET description = replace(description, 'Compiler', 'Hotspot') WHERE cve_id = $1`, cve)
	e.pending()
	if got := e.composed(cve); got != "full|Java SE: buffer overflow / out-of-bounds write in Hotspot" {
		t.Fatalf("description: %s", got)
	}
	// a suppressed tag (0011 trigger)
	e.exec(`INSERT INTO vuln_tag_suppress (cve_id, tag, reason) VALUES ($1, 'buffer-overflow', 'test')`, cve)
	e.pending()
	if got := e.composed(cve); got != "component|Java SE: vulnerability in Hotspot" {
		t.Fatalf("suppressed: %s", got)
	}
	// a staff tag (0031 trigger on staff rows)
	e.exec(`INSERT INTO vuln_tag (cve_id, tag, origin) VALUES ($1, 'sql-injection', 'staff')`, cve)
	e.pending()
	if got := e.composed(cve); got != "full|Java SE: SQL injection in Hotspot" {
		t.Fatalf("staff tag: %s", got)
	}
	// the record's title: nothing composed while it has one
	e.exec(`UPDATE vuln SET title = 'Record title' WHERE cve_id = $1`, cve)
	e.pending()
	if got := e.composed(cve); got != "|" {
		t.Fatalf("record title: %s", got)
	}
	e.exec(`UPDATE vuln SET title = NULL WHERE cve_id = $1`, cve)
	e.pending()
	if got := e.composed(cve); got != "full|Java SE: SQL injection in Hotspot" {
		t.Fatalf("record title removed: %s", got)
	}
	// the affected row goes: no product, the excerpt
	e.exec(`DELETE FROM affected WHERE cve_id = $1`, cve)
	e.pending()
	if got := e.composed(cve); !strings.HasPrefix(got, "excerpt|") {
		t.Fatalf("affected removed: %s", got)
	}
	if n := e.count(`SELECT count(*) FROM vuln_title WHERE cve_id = $1 AND staff_title = 'Hand title' AND staff_version = 1 AND rule_version = $2`,
		cve, titles.RuleVersion); n != 1 {
		t.Errorf("staff columns or rule version changed")
	}
	// an unrelated update of the vuln row queues nothing
	e.exec(`DELETE FROM tag_queue`)
	e.exec(`UPDATE vuln SET modified_at = now() WHERE cve_id = $1`, cve)
	if n := e.count(`SELECT count(*) FROM tag_queue`); n != 0 {
		t.Errorf("modified_at queued %d", n)
	}
	// an unchanged pass writes nothing
	e.exec(`INSERT INTO tag_queue (cve_id) VALUES ($1)`, cve)
	if st := e.pending(); st.TitlesWritten != 0 || st.CVEs != 1 {
		t.Errorf("unchanged pass %+v", st)
	}
}

// The triggers of 0031 exist for every write to vuln and vuln_tag that can
// change a title's input.
func TestTriggerCoverageTitles(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct{ table, ev string }{{"vuln", "INSERT"}, {"vuln", "UPDATE"}, {"vuln_tag", "INSERT"}, {"vuln_tag", "UPDATE"}, {"vuln_tag", "DELETE"}} {
		if n := e.count(`SELECT count(*) FROM information_schema.triggers
            WHERE event_object_schema = current_schema() AND event_object_table = $1 AND event_manipulation = $2 AND action_timing = 'AFTER'
              AND action_orientation = 'STATEMENT' AND action_statement LIKE '%title_enqueue%'`, c.table, c.ev); n != 1 {
			t.Errorf("%s %s: %d title triggers", c.table, c.ev, n)
		}
	}
}

// A GHSA merge moves the staff title to the CVE unless the CVE has its own;
// the composed parts are the target's.
func TestTitleMergeStaff(t *testing.T) {
	e := newEnv(t)
	const gid, cve = "GHSA-2cm2-m3w5-gp2f", "CVE-2026-0102"
	e.exec(`INSERT INTO vuln (cve_id, description) VALUES ($1, 'Acme Widget lets attackers in.'), ($2, NULL)`, gid, cve)
	e.pending()
	e.exec(`UPDATE vuln_title SET staff_title = 'Acme Widget: login bypass', staff_at = now(), staff_version = 3 WHERE cve_id = $1`, gid)
	tx, err := e.conn.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.MergeVulnID(e.ctx, tx, gid, cve, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.pending()
	if n := e.count(`SELECT count(*) FROM vuln_title WHERE cve_id = $1 AND staff_title = 'Acme Widget: login bypass'`, cve); n != 1 {
		t.Errorf("staff title not moved")
	}
	if n := e.count(`SELECT count(*) FROM vuln_title WHERE cve_id = $1`, gid); n != 0 {
		t.Errorf("GHSA row left")
	}
	if got := e.composed(cve); got != "excerpt|Acme Widget lets attackers in" {
		t.Errorf("composed after merge: %s", got)
	}
}

// The backfill: batches, a limit, resumable after a stop, idempotent, a
// rule version bump recomposes everything, the summary counts by form.
func TestTitlesBackfill(t *testing.T) {
	e := newEnv(t)
	for i := 1; i <= 25; i++ {
		id := fmt.Sprintf("CVE-2026-%04d", 1000+i)
		switch {
		case i%5 == 0: // record title
			e.exec(`INSERT INTO vuln (cve_id, title, description) VALUES ($1, 'Own title', 'Something happens here.')`, id)
		case i%5 == 1: // nothing usable
			e.exec(`INSERT INTO vuln (cve_id) VALUES ($1)`, id)
		case i%5 == 2: // product + weakness
			e.exec(`INSERT INTO vuln (cve_id, description) VALUES ($1, 'Bad things.')`, id)
			e.exec(`INSERT INTO affected (cve_id, vendor, product) VALUES ($1, 'Acme Inc.', 'Widget')`, id)
			e.exec(`INSERT INTO vuln_tag (cve_id, tag, origin, rule_version) VALUES ($1, 'xss', 'rule', 2)`, id)
		default: // excerpt
			e.exec(`INSERT INTO vuln (cve_id, description) VALUES ($1, 'Acme Widget allows remote attackers to read files.')`, id)
		}
	}
	// before the migration's backfill: nothing queued, nothing composed
	e.exec(`DELETE FROM tag_queue`)
	st, err := Titles(e.ctx, e.conn, TitlesOptions{BatchSize: 10, Limit: 12})
	if err != nil || st.Considered != 12 || st.Done || st.Batches != 2 {
		t.Fatalf("limited run %+v %v", st, err)
	}
	// a run stopped after its first batch
	stop := errors.New("stop")
	st, err = Titles(e.ctx, e.conn, TitlesOptions{BatchSize: 5, afterBatch: func(int) error { return stop }})
	if !errors.Is(err, stop) || st.Considered != 5 {
		t.Fatalf("stopped run %+v %v", st, err)
	}
	// resumed: the rest
	st, err = Titles(e.ctx, e.conn, TitlesOptions{BatchSize: 10})
	if err != nil || st.Considered != 8 || !st.Done {
		t.Fatalf("resumed run %+v %v", st, err)
	}
	if n := e.count(`SELECT count(*) FROM vuln_title WHERE rule_version = $1`, titles.RuleVersion); n != 25 {
		t.Fatalf("rows %d", n)
	}
	// idempotent
	st, err = Titles(e.ctx, e.conn, TitlesOptions{})
	if err != nil || st.Considered != 0 || st.Written != 0 || !st.Done {
		t.Errorf("second run %+v %v", st, err)
	}
	st, err = Titles(e.ctx, e.conn, TitlesOptions{All: true})
	want := map[string]int{"weakness": 5, "excerpt": 10}
	if err != nil || st.Considered != 25 || st.Written != 0 || st.RecordTitle != 5 || st.Untitled != 5 || fmt.Sprint(st.Composed) != fmt.Sprint(want) {
		t.Errorf("--all run %+v %v", st, err)
	}
	if got := e.composed("CVE-2026-1002"); got != "weakness|Acme Widget: XSS" {
		t.Errorf("CVE-2026-1002: %s", got)
	}
	// a rule version bump: every row recomposed by the plain run
	st, err = Titles(e.ctx, e.conn, TitlesOptions{ruleVersion: titles.RuleVersion + 1})
	if err != nil || st.Considered != 25 || st.Written != 25 || st.RuleVersion != titles.RuleVersion+1 {
		t.Errorf("bumped run %+v %v", st, err)
	}
	// the tag pass writes the current version again
	e.exec(`INSERT INTO tag_queue (cve_id) VALUES ('CVE-2026-1002')`)
	e.pending()
	if n := e.count(`SELECT rule_version FROM vuln_title WHERE cve_id = 'CVE-2026-1002'`); n != titles.RuleVersion {
		t.Errorf("tag pass version %d", n)
	}
}

// A vulnerability whose row a collector holds is skipped (not waited for)
// and queued for the tag pass.
func TestTitlesBackfillBusy(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id, description) VALUES ('CVE-2026-2001', 'Acme Widget leaks memory.'), ('CVE-2026-2002', 'Acme Gadget leaks memory.')`)
	e.exec(`DELETE FROM tag_queue`)
	m := e.connect()
	mtx, err := m.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mtx.Exec(e.ctx, `SELECT 1 FROM vuln WHERE cve_id = 'CVE-2026-2001' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	st, err := Titles(e.ctx, e.conn, TitlesOptions{})
	_ = mtx.Rollback(e.ctx)
	if err != nil || st.Busy != 1 || st.Considered != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	if n := e.count(`SELECT count(*) FROM tag_queue WHERE cve_id = 'CVE-2026-2001'`); n != 1 {
		t.Errorf("busy row not queued")
	}
	if st, err := Titles(e.ctx, e.conn, TitlesOptions{}); err != nil || st.Considered != 1 {
		t.Errorf("next run %+v %v", st, err)
	}
}

// The English weakness labels are the vocabulary's.
func TestTypeLabel(t *testing.T) {
	if TypeLabel("buffer-overflow") != "buffer overflow / out-of-bounds write" || TypeLabel("nope") != "nope" {
		t.Error(TypeLabel("buffer-overflow"))
	}
}
