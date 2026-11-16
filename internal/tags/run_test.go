package tags

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/classify"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/state"
	"nday.land/nday/internal/testutil"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

type env struct {
	t    *testing.T
	d    *testutil.TestDB
	ctx  context.Context
	conn *pgx.Conn
}

// DB tests run serially (shared max_connections).
func newEnv(t *testing.T) *env {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	return &env{t: t, d: d, ctx: context.Background(), conn: d.Conn}
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.conn.Exec(e.ctx, sql, args...); err != nil {
		e.t.Fatalf("%v\n%s", err, sql)
	}
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.conn.QueryRow(e.ctx, sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%v\n%s", err, sql)
	}
	return n
}

// raw stores a raw record exactly like the pipeline does.
func (e *env) raw(source, key string, payload string, at time.Time) {
	e.t.Helper()
	v, err := pyjson.Decode([]byte(payload))
	if err != nil {
		e.t.Fatal(err)
	}
	rec := model.RawRecord{Source: source, SourceKey: key, Payload: v}
	h, err := rec.ContentHash()
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := pipeline.StoreRaw(e.ctx, e.conn, rec, h, at); err != nil {
		e.t.Fatal(err)
	}
}

// event inserts a lifecycle event like the pipeline stores it.
func (e *env) event(cve, typ, source, key, detail string) int64 {
	e.t.Helper()
	var id int64
	if err := e.conn.QueryRow(e.ctx, `INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, dedupe_key)
        VALUES ($1, $2, $3, $3, $4, $5::jsonb, $6) RETURNING id`, cve, typ, t0, source, detail, key).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// classifyAndTag runs the two incremental passes like a collector run does.
func (e *env) classifyAndTag() *Stats {
	e.t.Helper()
	if _, err := classify.Pending(e.ctx, e.conn, classify.Options{Wait: true}); err != nil {
		e.t.Fatal(err)
	}
	return e.pending()
}

func (e *env) pending() *Stats {
	e.t.Helper()
	st, err := Pending(e.ctx, e.conn, Options{Wait: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

// tags renders the stored rule tags of a CVE: "slug" sorted by vocabulary.
func (e *env) tags(cve string) string {
	e.t.Helper()
	rows, err := e.conn.Query(e.ctx, `SELECT tag FROM vuln_tag WHERE cve_id = $1 AND origin = 'rule'`, cve)
	if err != nil {
		e.t.Fatal(err)
	}
	s, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		e.t.Fatal(err)
	}
	Sort(s)
	return strings.Join(s, " ")
}

func (e *env) visible(cve string) string {
	e.t.Helper()
	m, err := SlugsMany(e.ctx, e.conn, []string{cve})
	if err != nil {
		e.t.Fatal(err)
	}
	return strings.Join(m[cve], " ")
}

// fingerprint hashes everything the tag layer must never change.
func (e *env) fingerprint() string {
	e.t.Helper()
	if _, err := state.Refresh(e.ctx, e.conn, state.RefreshOptions{Wait: true}); err != nil {
		e.t.Fatal(err)
	}
	var parts []string
	for _, q := range []string{
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY id), '')) FROM event t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY cve_id), '')) FROM vuln t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY cve_id), '')) FROM vuln_state t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY cve_id), '')) FROM vuln_state_mat t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY id), '')) FROM raw_record t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY cve_id, cwe, source, source_org), '')) FROM vuln_cwe t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY cve_id, version, source, source_org), '')) FROM vuln_cvss t`,
	} {
		var s string
		if err := e.conn.QueryRow(e.ctx, q).Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

const v31a = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

func cve5(id, state, cwe, vector string) string {
	if state == "REJECTED" {
		return fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":"REJECTED","assignerShortName":"mitre"},"containers":{"cna":{"rejectedReasons":[{"lang":"en","value":"dup"}]}}}`, id)
	}
	return fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":%q,"assignerShortName":"mitre"},
	 "containers":{"cna":{"providerMetadata":{"shortName":"mitre"},
	   "problemTypes":[{"descriptions":[{"lang":"en","type":"CWE","cweId":%q,"description":"x"}]}],
	   "metrics":[{"cvssV3_1":{"version":"3.1","vectorString":%q,"baseScore":7.5,"baseSeverity":"HIGH"}}]}}}`,
		id, state, cwe, vector)
}

func nvdRec(id, status, cwe string) string {
	return fmt.Sprintf(`{"id":%q,"vulnStatus":%q,"weaknesses":[{"source":"nvd@nist.gov","type":"Primary","description":[{"lang":"en","value":%q}]}],
	  "metrics":{"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"2.0","vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P","baseScore":7.5},"baseSeverity":"HIGH"}]}}`, id, status, cwe)
}

func ghsaRec(gid, cve, eco, pkg string) string {
	return fmt.Sprintf(`{"ghsa_id":%q,"cve_id":%q,"withdrawn_at":null,"cwes":[],
	  "vulnerabilities":[{"package":{"ecosystem":%q,"name":%q},"vulnerable_version_range":"< 1","first_patched_version":null}, "junk"]}`, gid, cve, eco, pkg)
}

// The whole flow from raw records and events, idempotence, and isolation:
// tag runs write nothing outside the tag tables.
func TestFlowIdempotentAndIsolated(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0001'), ('CVE-2026-0002')`)
	e.raw("cvelist", "CVE-2026-0001", cve5("CVE-2026-0001", "PUBLISHED", "CWE-79", v31a), t0)
	e.raw("nvd", "CVE-2026-0002", nvdRec("CVE-2026-0002", "Analyzed", "CWE-89"), t0)
	e.raw("ghsa", "GHSA-aaaa-bbbb-cccc", ghsaRec("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", "pip", "pkg"), t0)
	e.event("CVE-2026-0001", "kev_added", "kev", "", `{"known_ransomware_campaign_use": "Known"}`)
	e.event("CVE-2026-0001", "poc_published", "metasploit", "exploit/x", `{}`)
	e.event("CVE-2026-0001", "social_post", "xposts", "post1", `{}`)
	if _, err := classify.Pending(e.ctx, e.conn, classify.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	before := e.fingerprint()
	dry, err := Pending(e.ctx, e.conn, Options{Wait: true, DryRun: true})
	if err != nil || dry.Inserted == 0 || e.count(`SELECT count(*) FROM vuln_tag`) != 0 || e.count(`SELECT count(*) FROM tag_queue`) == 0 {
		t.Fatalf("dry run %+v %v", dry, err)
	}
	st := e.pending()
	if st.Changed != 2 || e.count(`SELECT count(*) FROM tag_queue`) != 0 || !st.CountsRefreshed {
		t.Errorf("first pass %+v", st)
	}
	if got := e.tags("CVE-2026-0001"); got != "xss remote-unauth network no-auth no-interaction ransomware metasploit pypi" {
		t.Errorf("CVE-2026-0001: %s", got)
	}
	// NVD gives only CVSS 2.0: no no-interaction, no remote-unauth
	if got := e.tags("CVE-2026-0002"); got != "sql-injection network no-auth" {
		t.Errorf("CVE-2026-0002: %s", got)
	}
	if n := e.count(`SELECT count(DISTINCT rule_version) FROM vuln_tag WHERE rule_version = $1`, RuleVersion); n != 1 {
		t.Errorf("rule_version not stored")
	}
	if n := e.count(`SELECT n FROM vuln_tag_count WHERE tag = 'network'`); n != 2 {
		t.Errorf("count network %d", n)
	}
	// nothing pending, nothing to change
	if st := e.pending(); st.CVEs != 0 {
		t.Errorf("second pass %+v", st)
	}
	all, err := All(e.ctx, e.conn, Options{Wait: true})
	if err != nil || all.Changed != 0 || all.Unchanged != 2 || all.Inserted != 0 {
		t.Errorf("--all after pending %+v %v", all, err)
	}
	if after := e.fingerprint(); after != before {
		t.Errorf("tag runs changed data outside the tag tables:\n%s\n%s", before, after)
	}
}

// Never missed: a classification change (new raw record version -> classify
// rewrites vuln_cwe -> trigger) re-tags the CVE.
func TestNeverMissedClassification(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0003')`)
	e.raw("cvelist", "CVE-2026-0003", cve5("CVE-2026-0003", "PUBLISHED", "CWE-79", v31a), t0)
	e.classifyAndTag()
	if !strings.Contains(e.tags("CVE-2026-0003"), "xss") {
		t.Fatalf("start: %s", e.tags("CVE-2026-0003"))
	}
	e.raw("cvelist", "CVE-2026-0003", cve5("CVE-2026-0003", "PUBLISHED", "CWE-89", v31a), t0.Add(time.Hour))
	e.classifyAndTag()
	if got := e.tags("CVE-2026-0003"); strings.Contains(got, "xss") || !strings.Contains(got, "sql-injection") {
		t.Errorf("after the new version: %s", got)
	}
}

// Never missed: an event insert, an update of its detail and its delete.
func TestNeverMissedEvent(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0004')`)
	id := e.event("CVE-2026-0004", "kev_added", "kev", "", `{"known_ransomware_campaign_use": "Unknown"}`)
	e.pending()
	if got := e.tags("CVE-2026-0004"); got != "" {
		t.Fatalf("Unknown: %s", got)
	}
	e.exec(`UPDATE event SET detail = '{"known_ransomware_campaign_use": "Known"}' WHERE id = $1`, id)
	e.pending()
	if got := e.tags("CVE-2026-0004"); got != "ransomware" {
		t.Errorf("after update: %q", got)
	}
	e.exec(`DELETE FROM event WHERE id = $1`, id)
	e.pending()
	if got := e.tags("CVE-2026-0004"); got != "" {
		t.Errorf("after delete: %q", got)
	}
	// a social_post event does not even queue the CVE
	q := e.count(`SELECT count(*) FROM tag_queue`)
	e.event("CVE-2026-0004", "social_post", "xposts", "p", `{}`)
	if e.count(`SELECT count(*) FROM tag_queue`) != q {
		t.Error("a social_post event queued the CVE")
	}
}

// Never missed: the CVE record becoming REJECTED (cvelist disclosed event
// and the classification input) removes every tag; un-rejecting restores.
func TestNeverMissedRejected(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0005')`)
	e.raw("cvelist", "CVE-2026-0005", cve5("CVE-2026-0005", "PUBLISHED", "CWE-79", v31a), t0)
	e.raw("nvd", "CVE-2026-0005", nvdRec("CVE-2026-0005", "Analyzed", "CWE-79"), t0)
	disc := e.event("CVE-2026-0005", "disclosed", "cvelist", "", `{"state": "PUBLISHED"}`)
	e.classifyAndTag()
	if !strings.Contains(e.tags("CVE-2026-0005"), "xss") {
		t.Fatalf("start: %s", e.tags("CVE-2026-0005"))
	}
	// NVD alone says Rejected: its rows go, the input marks it rejected
	e.raw("nvd", "CVE-2026-0005", nvdRec("CVE-2026-0005", "Rejected", "CWE-79"), t0.Add(time.Hour))
	e.classifyAndTag()
	if got := e.tags("CVE-2026-0005"); got != "" {
		t.Errorf("NVD rejected: %q", got)
	}
	e.raw("nvd", "CVE-2026-0005", nvdRec("CVE-2026-0005", "Analyzed", "CWE-79"), t0.Add(2*time.Hour))
	e.classifyAndTag()
	if !strings.Contains(e.tags("CVE-2026-0005"), "xss") {
		t.Errorf("NVD un-rejected: %q", e.tags("CVE-2026-0005"))
	}
	// the CVE record's state on the disclosed event (what vuln_state reads)
	e.exec(`UPDATE event SET detail = '{"state": "REJECTED"}' WHERE id = $1`, disc)
	e.pending()
	if got := e.tags("CVE-2026-0005"); got != "" {
		t.Errorf("REJECTED event: %q", got)
	}
	e.exec(`UPDATE event SET detail = '{"state": "PUBLISHED"}' WHERE id = $1`, disc)
	e.pending()
	if !strings.Contains(e.tags("CVE-2026-0005"), "xss") {
		t.Errorf("PUBLISHED again: %q", e.tags("CVE-2026-0005"))
	}
}

// Never missed: an advisory changing its packages (classify rewrites the
// ghsa input row: new content hash) changes the ecosystem tags.
func TestNeverMissedAdvisory(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0006')`)
	e.raw("ghsa", "GHSA-aaaa-bbbb-dddd", ghsaRec("GHSA-aaaa-bbbb-dddd", "CVE-2026-0006", "npm", "a"), t0)
	e.classifyAndTag()
	if got := e.tags("CVE-2026-0006"); got != "npm" {
		t.Fatalf("start: %q", got)
	}
	e.raw("ghsa", "GHSA-aaaa-bbbb-dddd", ghsaRec("GHSA-aaaa-bbbb-dddd", "CVE-2026-0006", "go", "a"), t0.Add(time.Hour))
	e.classifyAndTag()
	if got := e.tags("CVE-2026-0006"); got != "go" {
		t.Errorf("after the new version: %q", got)
	}
}

// A rule version bump is recomputed by All: every rule row is rewritten
// with the new version (Pending alone does not touch unqueued CVEs).
func TestRuleVersionBump(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0008')`)
	e.event("CVE-2026-0008", "poc_published", "nuclei", "CVE-2026-0008", `{}`)
	e.pending()
	if _, err := All(e.ctx, e.conn, Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if v, _ := RuleVersionState(e.ctx, e.conn); v != RuleVersion {
		t.Errorf("tag_run version %d", v)
	}
	if st, _ := Pending(e.ctx, e.conn, Options{Wait: true, ruleVersion: RuleVersion + 1}); st.Changed != 0 {
		t.Errorf("pending rewrote unqueued CVEs: %+v", st)
	}
	st, err := All(e.ctx, e.conn, Options{Wait: true, ruleVersion: RuleVersion + 1})
	if err != nil || st.Changed != 1 || e.count(`SELECT count(*) FROM vuln_tag WHERE rule_version = $1`, RuleVersion+1) != 1 {
		t.Errorf("bump: %+v %v", st, err)
	}
	if v, _ := RuleVersionState(e.ctx, e.conn); v != RuleVersion+1 {
		t.Errorf("tag_run version after bump %d", v)
	}
}

// Suppression: a suppressed rule tag is hidden from every read path at
// once, removed and never re-added by recomputation, and comes back when
// the suppression is lifted. Staff rows are unaffected.
func TestSuppression(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0009')`)
	e.event("CVE-2026-0009", "poc_published", "exploitdb", "1", `{}`)
	e.event("CVE-2026-0009", "poc_published", "nuclei", "x", `{}`)
	e.pending()
	e.exec(`INSERT INTO vuln_tag (cve_id, tag, origin, basis) VALUES ('CVE-2026-0009', 'exploit-db', 'staff', '{}')`)
	if got := e.visible("CVE-2026-0009"); got != "exploit-db nuclei" {
		t.Fatalf("start: %q", got)
	}
	e.exec(`INSERT INTO vuln_tag_suppress (cve_id, tag, reason) VALUES ('CVE-2026-0009', 'nuclei', 'test')`)
	// read paths hide it before any recomputation
	if got := e.visible("CVE-2026-0009"); got != "exploit-db" {
		t.Errorf("visible right after suppress: %q", got)
	}
	vs, _ := ForMany(e.ctx, e.conn, []string{"CVE-2026-0009"})
	for _, v := range vs["CVE-2026-0009"] {
		if v.Slug == "nuclei" {
			t.Error("ForMany shows a suppressed tag")
		}
	}
	if n := e.count(`SELECT count(*) FROM vuln_tag_visible WHERE tag = 'nuclei'`); n != 0 {
		t.Error("filterable while suppressed")
	}
	e.pending()
	if got := e.tags("CVE-2026-0009"); got != "exploit-db" {
		t.Errorf("rule rows after suppress: %q", got)
	}
	if _, err := All(e.ctx, e.conn, Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if got := e.tags("CVE-2026-0009"); got != "exploit-db" {
		t.Errorf("--all re-added a suppressed tag: %q", got)
	}
	if n := e.count(`SELECT count(*) FROM vuln_tag_count WHERE tag = 'nuclei'`); n != 0 {
		t.Error("counted while suppressed")
	}
	// a suppressed rule tag does not hide a staff row of the same tag
	e.exec(`INSERT INTO vuln_tag_suppress (cve_id, tag, reason) VALUES ('CVE-2026-0009', 'exploit-db', 'test')`)
	e.pending()
	if got := e.visible("CVE-2026-0009"); got != "exploit-db" || e.tags("CVE-2026-0009") != "" {
		t.Errorf("staff row with a suppressed rule tag: visible %q rule %q", got, e.tags("CVE-2026-0009"))
	}
	e.exec(`DELETE FROM vuln_tag_suppress WHERE cve_id = 'CVE-2026-0009'`)
	e.pending()
	if got := e.tags("CVE-2026-0009"); got != "exploit-db nuclei" {
		t.Errorf("lifted: %q", got)
	}
}

// A write that commits while a batch runs keeps its own queue row.
func TestNeverMissedConcurrentWrite(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0010')`)
	e.event("CVE-2026-0010", "poc_published", "exploitdb", "1", `{}`)
	other, err := testutil.Connect(e.ctx, e.d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(e.ctx)
	queued := e.count(`SELECT count(*) FROM tag_queue`)
	o := Options{Wait: true, MaxQueue: queued}
	done := false
	o.afterRead = func(ctx context.Context, tx pgx.Tx) error {
		if done {
			return nil
		}
		done = true
		_, err := other.Exec(ctx, `INSERT INTO event (cve_id, type, observed_at, source, dedupe_key) VALUES ('CVE-2026-0010', 'poc_published', now(), 'metasploit', 'm')`)
		return err
	}
	if _, err := Pending(e.ctx, e.conn, o); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM tag_queue`) != 1 {
		t.Fatalf("the concurrent write's queue row must survive, have %d", e.count(`SELECT count(*) FROM tag_queue`))
	}
	e.pending()
	if got := e.tags("CVE-2026-0010"); got != "metasploit exploit-db" {
		t.Errorf("concurrent write missed: %q", got)
	}
}

// The post-collector pass does not wait for a running tag run.
func TestLockDefers(t *testing.T) {
	e := newEnv(t)
	other, err := testutil.Connect(e.ctx, e.d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(e.ctx)
	unlock, err := lock(e.ctx, other, true)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Pending(e.ctx, e.conn, Options{})
	if err != nil || !st.Deferred {
		t.Errorf("not deferred: %+v %v", st, err)
	}
	unlock()
	if st, err := Pending(e.ctx, e.conn, Options{}); err != nil || st.Deferred {
		t.Errorf("after unlock: %+v %v", st, err)
	}
}

// Every event type the derivation reads queues the CVE (the trigger's list
// equals EventTypes); other types do not.
func TestTriggerEventTypes(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0011')`)
	for _, typ := range []string{"disclosed", "patch_released", "analysis_published", "poc_published", "exploited_in_wild", "kev_added", "social_post"} {
		q := e.count(`SELECT count(*) FROM tag_queue`)
		e.event("CVE-2026-0011", typ, "src-"+typ, "k", `{}`)
		got := e.count(`SELECT count(*) FROM tag_queue`) > q
		want := false
		for _, x := range EventTypes {
			want = want || x == typ
		}
		if got != want {
			t.Errorf("%s: queued %t, want %t", typ, got, want)
		}
	}
}

// nvdCPE is an NVD record (the feed's cve object) with one vulnerable CPE
// and one platform CPE (vulnerable = false), like NVD's "running on" nodes.
func nvdCPE(id, vulnerable, platform string) string {
	return fmt.Sprintf(`{"id":%q,"vulnStatus":"Analyzed","configurations":[{"operator":"AND","nodes":[
	  {"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":%q,"matchCriteriaId":"A"}]},
	  {"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":false,"criteria":%q,"matchCriteriaId":"B"}]}]}]}`, id, vulnerable, platform)
}

// Never missed: an affected row inserted (as the pipeline writes it),
// updated and deleted re-tags the CVE; a conflicting insert (nothing
// written) queues nothing; deleting the vuln cascades without error.
func TestNeverMissedAffected(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0012')`)
	ins := `INSERT INTO affected (cve_id, vendor, product) VALUES ($1, $2, $3) ON CONFLICT (cve_id, vendor, product) DO NOTHING`
	e.exec(ins, "CVE-2026-0012", "Google", "Chrome")
	e.pending()
	if got := e.tags("CVE-2026-0012"); got != "chrome browser" {
		t.Fatalf("insert: %q", got)
	}
	q := e.count(`SELECT count(*) FROM tag_queue`)
	e.exec(ins, "CVE-2026-0012", "Google", "Chrome")
	if e.count(`SELECT count(*) FROM tag_queue`) != q {
		t.Error("an insert that wrote nothing queued the CVE")
	}
	e.exec(`UPDATE affected SET vendor = 'Mozilla', product = 'Firefox ESR' WHERE cve_id = 'CVE-2026-0012'`)
	e.pending()
	if got := e.tags("CVE-2026-0012"); got != "firefox browser" {
		t.Errorf("update: %q", got)
	}
	e.exec(ins, "CVE-2026-0012", "Tenda", "AC15")
	e.pending()
	if got := e.tags("CVE-2026-0012"); got != "firefox browser network-device" {
		t.Errorf("second row: %q", got)
	}
	var basis string
	if err := e.conn.QueryRow(e.ctx, `SELECT basis::text FROM vuln_tag WHERE cve_id = 'CVE-2026-0012' AND tag = 'network-device'`).Scan(&basis); err != nil ||
		!strings.Contains(basis, `"type_rules": ["vendor:tenda"]`) || !strings.Contains(basis, `{"vendor": "Tenda", "product": "AC15"}`) {
		t.Errorf("basis %s %v", basis, err)
	}
	e.exec(`DELETE FROM affected WHERE cve_id = 'CVE-2026-0012'`)
	e.pending()
	if got := e.tags("CVE-2026-0012"); got != "" {
		t.Errorf("delete: %q", got)
	}
	e.exec(ins, "CVE-2026-0012", "Google", "Chrome")
	e.exec(`DELETE FROM vuln WHERE cve_id = 'CVE-2026-0012'`)
	if st := e.pending(); st.CVEs != 1 || st.NoVuln != 1 {
		t.Errorf("cascade: %+v", st)
	}
}

// Never missed: a new NVD record version whose vulnerable CPE changes (and
// nothing else: same CWE, same CVSS) re-tags the CVE after the collector's
// classification pass, through the vuln_classify_input triggers of 0011.
// Platform CPEs (vulnerable = false) never give tags; a rejected NVD record
// gives none.
func TestNeverMissedNVDCPE(t *testing.T) {
	e := newEnv(t)
	e.exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0013')`)
	const win = "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"
	e.raw("nvd", "CVE-2026-0013", nvdCPE("CVE-2026-0013", "cpe:2.3:o:fortinet:fortios:7.2.0:*:*:*:*:*:*:*", win), t0)
	e.classifyAndTag()
	if got := e.tags("CVE-2026-0013"); got != "fortios firewall-vpn" {
		t.Fatalf("start: %q", got)
	}
	e.raw("nvd", "CVE-2026-0013", nvdCPE("CVE-2026-0013", "cpe:2.3:o:paloaltonetworks:pan-os:11.0.0:*:*:*:*:*:*:*", win), t0.Add(time.Hour))
	e.classifyAndTag()
	if got := e.tags("CVE-2026-0013"); got != "pan-os firewall-vpn" {
		t.Errorf("after the new version: %q", got)
	}
	var basis string
	if err := e.conn.QueryRow(e.ctx, `SELECT basis::text FROM vuln_tag WHERE cve_id = 'CVE-2026-0013' AND tag = 'pan-os'`).Scan(&basis); err != nil ||
		basis != `{"cpe": [{"part": "o", "vendor": "paloaltonetworks", "product": "pan-os"}], "cpe_count": 1}` {
		t.Errorf("basis %s %v", basis, err)
	}
	e.raw("nvd", "CVE-2026-0013", strings.Replace(nvdCPE("CVE-2026-0013", "cpe:2.3:o:paloaltonetworks:pan-os:11.0.0:*:*:*:*:*:*:*", win),
		`"Analyzed"`, `"Rejected"`, 1), t0.Add(2*time.Hour))
	e.classifyAndTag()
	if got := e.tags("CVE-2026-0013"); got != "" {
		t.Errorf("NVD rejected: %q", got)
	}
}

// Every write to affected queues the CVE (the triggers of 0013 exist for
// insert, update and delete), checked against the catalog so that a write
// path cannot silently lose its trigger.
func TestTriggerCoverageAffected(t *testing.T) {
	e := newEnv(t)
	for _, ev := range []string{"INSERT", "UPDATE", "DELETE"} {
		if n := e.count(`SELECT count(*) FROM information_schema.triggers
            WHERE event_object_schema = current_schema() AND event_object_table = 'affected' AND event_manipulation = $1 AND action_timing = 'AFTER'
              AND action_orientation = 'STATEMENT' AND action_statement LIKE '%tag_enqueue%'`, ev); n != 1 {
			t.Errorf("affected %s: %d tag triggers", ev, n)
		}
	}
}
