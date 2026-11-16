package classify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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

func (e *env) vuln(ids ...string) {
	e.t.Helper()
	for _, id := range ids {
		e.exec(`INSERT INTO vuln (cve_id) VALUES ($1) ON CONFLICT DO NOTHING`, id)
	}
}

// raw stores a raw record exactly like the pipeline does.
func (e *env) raw(source, key string, payload []byte, at time.Time) {
	e.t.Helper()
	v, err := pyjson.Decode(payload)
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

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.conn.QueryRow(e.ctx, sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%v\n%s", err, sql)
	}
	return n
}

func (e *env) pending() *Stats {
	e.t.Helper()
	st, err := Pending(e.ctx, e.conn, Options{Wait: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

// rows renders the classification of one CVE.
func (e *env) rows(cve string) []string {
	e.t.Helper()
	c, err := For(e.ctx, e.conn, cve)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, w := range c.CWE {
		for _, s := range w.Sources {
			out = append(out, "cwe "+w.ID+" "+s.Source+"/"+s.SourceOrg)
		}
	}
	for _, v := range c.CVSS {
		out = append(out, "cvss "+v.Version+" "+v.Source+"/"+v.SourceOrg+" "+v.Vector)
	}
	for _, in := range c.Inputs {
		out = append(out, fmt.Sprintf("input %s %s rejected=%t", in.Source, in.SourceKey, in.Rejected))
	}
	return out
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func cve5(id, state, cwe, vector string) []byte {
	if state == "REJECTED" {
		return []byte(fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":"REJECTED","assignerShortName":"mitre"},"containers":{"cna":{"rejectedReasons":[{"lang":"en","value":"dup"}]}}}`, id))
	}
	return []byte(fmt.Sprintf(`{"cveMetadata":{"cveId":%q,"state":%q,"assignerShortName":"mitre"},
	 "containers":{"cna":{"providerMetadata":{"shortName":"mitre"},
	   "problemTypes":[{"descriptions":[{"lang":"en","type":"CWE","cweId":%q,"description":"x"}]}],
	   "metrics":[{"cvssV3_1":{"version":"3.1","vectorString":%q,"baseScore":7.5,"baseSeverity":"HIGH"}}],
	   "affected":[{"vendor":"v","product":"p"}],"descriptions":[{"lang":"en","value":"d"}]},
	  "adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"problemTypes":[{"descriptions":[{"lang":"en","type":"CWE","cweId":"CWE-20","description":"CWE-20"}]}]}]}}`,
		id, state, cwe, vector))
}

func nvdRec(id, status, cwe string) []byte {
	return []byte(fmt.Sprintf(`{"id":%q,"vulnStatus":%q,"weaknesses":[{"source":"nvd@nist.gov","type":"Primary","description":[{"lang":"en","value":%q}]}],
	  "metrics":{"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"2.0","vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P","baseScore":7.5},"baseSeverity":"HIGH"}]},
	  "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}]}]}]}`, id, status, cwe))
}

func ghsaRec(gid, cve, cwe string) []byte {
	return []byte(fmt.Sprintf(`{"ghsa_id":%q,"cve_id":%q,"withdrawn_at":null,"cwes":[{"cwe_id":%q,"name":"n"}],
	  "cvss_severities":{"cvss_v3":{"score":5.3,"vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},"cvss_v4":{"score":0.0,"vector_string":null}}}`, gid, cve, cwe))
}

const v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
const v31b = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

// fingerprint hashes the event-side tables and the derived state, which
// classification must never change.
func (e *env) fingerprint() string {
	e.t.Helper()
	if _, err := state.Refresh(e.ctx, e.conn, state.RefreshOptions{Wait: true}); err != nil {
		e.t.Fatal(err)
	}
	var parts []string
	for _, q := range []string{
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY id), '')) FROM event t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY cve_id), '')) FROM vuln t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY id), '')) FROM vuln_alias t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY id), '')) FROM affected t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY cve_id), '')) FROM vuln_state t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY cve_id), '')) FROM vuln_state_mat t`,
		`SELECT md5(COALESCE(string_agg(t::text, '|' ORDER BY id), '')) FROM raw_record t`,
	} {
		var s string
		if err := e.conn.QueryRow(e.ctx, q).Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

// The whole flow, plus "classify writes nothing outside its tables".
func TestPendingFlowIdempotentAndIsolated(t *testing.T) {
	e := newEnv(t)
	e.vuln("CVE-2026-0001", "CVE-2026-0002")
	e.exec(`INSERT INTO event (cve_id, type, observed_at, source, detail) VALUES ('CVE-2026-0001', 'disclosed', $1, 'cvelist', '{"state":"PUBLISHED"}')`, t0)
	e.raw("cvelist", "CVE-2026-0001", cve5("CVE-2026-0001", "PUBLISHED", "CWE-79", v31), t0)
	e.raw("nvd", "CVE-2026-0001", nvdRec("CVE-2026-0001", "Analyzed", "CWE-79"), t0)
	e.raw("ghsa", "GHSA-aaaa-bbbb-cccc", ghsaRec("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", "CWE-80"), t0)
	e.raw("nvd", "CVE-2026-0002", nvdRec("CVE-2026-0002", "Analyzed", "NVD-CWE-noinfo"), t0)
	before := e.fingerprint()

	dry, err := Pending(e.ctx, e.conn, Options{Wait: true, DryRun: true})
	if err != nil || dry.CWEInserted != 4 || e.count(`SELECT count(*) FROM vuln_cwe`) != 0 || e.count(`SELECT count(*) FROM classify_queue`) == 0 {
		t.Fatalf("dry run %+v %v", dry, err)
	}
	st := e.pending()
	if st.CWEInserted != 4 || st.CVSSInserted != 4 || st.CWESkipped != 1 || e.count(`SELECT count(*) FROM classify_queue`) != 0 {
		t.Errorf("first pass %+v", st)
	}
	got := e.rows("CVE-2026-0001")
	for _, w := range []string{"cwe CWE-79 cve-cna/mitre", "cwe CWE-79 nvd-primary/nvd@nist.gov", "cwe CWE-20 cve-adp/CISA-ADP",
		"cwe CWE-80 ghsa/GHSA-aaaa-bbbb-cccc", "cvss 3.1 cve-cna/mitre " + v31, "cvss 2.0 nvd-primary/nvd@nist.gov AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"input cvelist CVE-2026-0001 rejected=false", "input nvd CVE-2026-0001 rejected=false", "input ghsa GHSA-aaaa-bbbb-cccc rejected=false"} {
		if !has(got, w) {
			t.Errorf("missing %q in %v", w, got)
		}
	}
	// re-running: queue empty; --all and --source write nothing
	if st := e.pending(); st.CVEs != 0 {
		t.Errorf("second pass %+v", st)
	}
	for _, f := range []func() (*Stats, error){
		func() (*Stats, error) { return All(e.ctx, e.conn, Options{Wait: true}) },
		func() (*Stats, error) { return BySource(e.ctx, e.conn, FamNVD, Options{Wait: true}) },
		func() (*Stats, error) { return BySource(e.ctx, e.conn, FamGHSA, Options{Wait: true}) },
		func() (*Stats, error) {
			return ByCVE(e.ctx, e.conn, []string{"CVE-2026-0001", "CVE-2026-0002"}, Options{Wait: true})
		},
	} {
		st, err := f()
		if err != nil || st.Changed != 0 || st.CWEInserted+st.CVSSInserted+st.CWEDeleted+st.CVSSDeleted != 0 || st.Unchanged == 0 {
			t.Errorf("rerun not idempotent: %+v %v", st, err)
		}
	}
	if after := e.fingerprint(); after != before {
		t.Errorf("classification changed event/vuln/state/raw tables:\n%s\n%s", before, after)
	}
}

// Never missed (1): a new content version of a raw record.
func TestNeverMissedNewVersion(t *testing.T) {
	e := newEnv(t)
	e.vuln("CVE-2026-0001")
	e.raw("cvelist", "CVE-2026-0001", cve5("CVE-2026-0001", "PUBLISHED", "CWE-79", v31), t0)
	e.pending()
	e.raw("cvelist", "CVE-2026-0001", cve5("CVE-2026-0001", "PUBLISHED", "CWE-89", v31b), t0.Add(time.Hour))
	e.pending()
	got := e.rows("CVE-2026-0001")
	if !has(got, "cwe CWE-89 cve-cna/mitre") || has(got, "cwe CWE-79 cve-cna/mitre") || !has(got, "cvss 3.1 cve-cna/mitre "+v31b) {
		t.Errorf("%v", got)
	}
}

// Never missed (2): upstream reverts to an older content version; the
// pipeline only bumps that row's fetched_at.
func TestNeverMissedRevert(t *testing.T) {
	e := newEnv(t)
	e.vuln("CVE-2026-0001")
	a := nvdRec("CVE-2026-0001", "Analyzed", "CWE-79")
	b := nvdRec("CVE-2026-0001", "Analyzed", "CWE-89")
	e.raw("nvd", "CVE-2026-0001", a, t0)
	e.raw("nvd", "CVE-2026-0001", b, t0.Add(time.Hour))
	e.pending()
	if got := e.rows("CVE-2026-0001"); !has(got, "cwe CWE-89 nvd-primary/nvd@nist.gov") {
		t.Fatalf("%v", got)
	}
	n := e.count(`SELECT count(*) FROM raw_record`)
	e.raw("nvd", "CVE-2026-0001", a, t0.Add(2*time.Hour)) // revert: no new row
	if e.count(`SELECT count(*) FROM raw_record`) != n {
		t.Fatal("expected a fetched_at bump, not an insert")
	}
	e.pending()
	if got := e.rows("CVE-2026-0001"); !has(got, "cwe CWE-79 nvd-primary/nvd@nist.gov") || has(got, "cwe CWE-89 nvd-primary/nvd@nist.gov") {
		t.Errorf("revert missed: %v", got)
	}
}

// Never missed (3): the NVD record arrives before the vuln row.
func TestNeverMissedLateVuln(t *testing.T) {
	e := newEnv(t)
	e.raw("nvd", "CVE-2026-0003", nvdRec("CVE-2026-0003", "Analyzed", "CWE-22"), t0)
	if st := e.pending(); st.NoVuln != 1 || e.count(`SELECT count(*) FROM vuln`) != 0 {
		t.Fatalf("%+v", st) // classify never creates vuln rows
	}
	if e.count(`SELECT count(*) FROM classify_queue`) != 0 {
		t.Fatal("queue not drained")
	}
	e.vuln("CVE-2026-0003") // e.g. the cvelist collector delivers it later
	e.pending()
	if got := e.rows("CVE-2026-0003"); !has(got, "cwe CWE-22 nvd-primary/nvd@nist.gov") {
		t.Errorf("late vuln missed: %v", got)
	}
}

// Never missed (4): the CVE becomes REJECTED: that source's rows go, the
// input row says rejected; other sources keep theirs.
func TestNeverMissedRejected(t *testing.T) {
	e := newEnv(t)
	e.vuln("CVE-2026-0004")
	e.raw("cvelist", "CVE-2026-0004", cve5("CVE-2026-0004", "PUBLISHED", "CWE-79", v31), t0)
	e.raw("nvd", "CVE-2026-0004", nvdRec("CVE-2026-0004", "Analyzed", "CWE-79"), t0)
	e.pending()
	e.raw("cvelist", "CVE-2026-0004", cve5("CVE-2026-0004", "REJECTED", "", ""), t0.Add(time.Hour))
	e.pending()
	got := e.rows("CVE-2026-0004")
	if has(got, "cwe CWE-79 cve-cna/mitre") || has(got, "cwe CWE-20 cve-adp/CISA-ADP") || !has(got, "input cvelist CVE-2026-0004 rejected=true") ||
		!has(got, "cwe CWE-79 nvd-primary/nvd@nist.gov") {
		t.Fatalf("%v", got)
	}
	c, _ := For(e.ctx, e.conn, "CVE-2026-0004")
	if rb := c.RejectedBy(); len(rb) != 1 || rb[0] != "cvelist" {
		t.Errorf("RejectedBy %v", rb)
	}
	e.raw("nvd", "CVE-2026-0004", nvdRec("CVE-2026-0004", "Rejected", "CWE-79"), t0.Add(time.Hour))
	e.pending()
	if n := e.count(`SELECT count(*) FROM vuln_cwe WHERE cve_id = 'CVE-2026-0004'`) + e.count(`SELECT count(*) FROM vuln_cvss WHERE cve_id = 'CVE-2026-0004'`); n != 0 {
		t.Errorf("rows left for a CVE rejected by both: %d", n)
	}
}

// Never missed (5): a GHSA advisory moves to another CVE id.
func TestNeverMissedGHSAMoved(t *testing.T) {
	e := newEnv(t)
	e.vuln("CVE-2026-0005", "CVE-2026-0006")
	e.raw("ghsa", "GHSA-aaaa-bbbb-cccc", ghsaRec("GHSA-aaaa-bbbb-cccc", "CVE-2026-0005", "CWE-79"), t0)
	e.pending()
	e.raw("ghsa", "GHSA-aaaa-bbbb-cccc", ghsaRec("GHSA-aaaa-bbbb-cccc", "CVE-2026-0006", "CWE-79"), t0.Add(time.Hour))
	e.pending()
	if got := e.rows("CVE-2026-0005"); len(got) != 0 {
		t.Errorf("old CVE keeps ghsa rows: %v", got)
	}
	if got := e.rows("CVE-2026-0006"); !has(got, "cwe CWE-79 ghsa/GHSA-aaaa-bbbb-cccc") {
		t.Errorf("new CVE: %v", got)
	}
}

// Never missed (6): a raw write that commits while a batch is running is
// picked up by the next pass (its queue row is not consumed).
func TestNeverMissedConcurrentWrite(t *testing.T) {
	e := newEnv(t)
	e.vuln("CVE-2026-0007")
	e.raw("cvelist", "CVE-2026-0007", cve5("CVE-2026-0007", "PUBLISHED", "CWE-79", v31), t0)
	other, err := testutil.Connect(e.ctx, e.d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(e.ctx)
	queued := e.count(`SELECT count(*) FROM classify_queue`)
	// MaxQueue: only the rows queued so far, so the call stops after the
	// batch the concurrent write races with
	o := Options{Wait: true, MaxQueue: queued}
	done := false
	o.afterRead = func(ctx context.Context, tx pgx.Tx) error {
		if done {
			return nil
		}
		done = true
		// another writer commits a new version after this batch read the raw records
		v, _ := pyjson.Decode(cve5("CVE-2026-0007", "PUBLISHED", "CWE-89", v31))
		rec := model.RawRecord{Source: "cvelist", SourceKey: "CVE-2026-0007", Payload: v}
		h, _ := rec.ContentHash()
		_, err := pipeline.StoreRaw(ctx, other, rec, h, t0.Add(time.Hour))
		return err
	}
	if _, err := Pending(e.ctx, e.conn, o); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM classify_queue`) != 1 {
		t.Fatalf("the concurrent write's queue row must survive, have %d", e.count(`SELECT count(*) FROM classify_queue`))
	}
	e.pending()
	if got := e.rows("CVE-2026-0007"); !has(got, "cwe CWE-89 cve-cna/mitre") {
		t.Errorf("concurrent write missed: %v", got)
	}
}

func TestReadAPIBulk(t *testing.T) {
	e := newEnv(t)
	e.vuln("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0009")
	e.raw("cvelist", "CVE-2026-0001", cve5("CVE-2026-0001", "PUBLISHED", "CWE-79", v31), t0)
	e.raw("nvd", "CVE-2026-0001", nvdRec("CVE-2026-0001", "Analyzed", "CWE-79"), t0)
	e.raw("nvd", "CVE-2026-0002", nvdRec("CVE-2026-0002", "Analyzed", "CWE-22"), t0)
	e.raw("ghsa", "GHSA-aaaa-bbbb-cccc", ghsaRec("GHSA-aaaa-bbbb-cccc", "CVE-2026-0002", "CWE-22"), t0)
	if _, err := All(e.ctx, e.conn, Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM classify_queue`) != 0 {
		t.Error("All must clear the queue rows queued before it")
	}
	ids := []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0009", "CVE-2026-9999"}
	m, err := ForMany(e.ctx, e.conn, ids)
	if err != nil {
		t.Fatal(err)
	}
	c1 := m["CVE-2026-0001"]
	if len(c1.CWE) != 2 || c1.CWE[0].ID != "CWE-20" || c1.CWE[1].ID != "CWE-79" ||
		c1.CWE[1].Sources[0].Source != SrcCNA || c1.CWE[1].Sources[1].Source != SrcNVDPrimary {
		t.Errorf("cwe order/provenance %+v", c1.CWE)
	}
	if c1.CVSS[0].Version != V31 || c1.CVSS[1].Version != V2 {
		t.Errorf("cvss order %+v", c1.CVSS)
	}
	if c := m["CVE-2026-0002"]; len(c.CWE) != 1 || len(c.CWE[0].Sources) != 2 || c.CWE[0].Sources[1].Source != SrcGHSA {
		t.Errorf("%+v", c.CWE)
	}
	if c := m["CVE-2026-9999"]; c == nil || len(c.CWE)+len(c.CVSS)+len(c.Inputs) != 0 {
		t.Errorf("unknown CVE: %+v", c)
	}
	best, err := BestCVSSMany(e.ctx, e.conn, ids)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		c := m[id]
		want := c.BestCVSS()
		if len(want) != len(best[id]) {
			t.Errorf("%s: %v vs %v", id, want, best[id])
		}
		for v, w := range want {
			if b := best[id][v]; b.Source != w.Source || b.SourceOrg != w.SourceOrg || b.Vector != w.Vector {
				t.Errorf("%s %s: sql %+v go %+v", id, v, b, w)
			}
		}
	}
	if best["CVE-2026-0002"][V31].Source != SrcGHSA || best["CVE-2026-0002"][V2].Source != SrcNVDPrimary || best["CVE-2026-0001"][V31].Source != SrcCNA {
		t.Errorf("best %+v", best)
	}
}

// Two runs at once (go test -race): the lock serialises them; a non-waiting
// pass defers; the result equals a single run.
func TestConcurrentRuns(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 30; i++ {
		id := fmt.Sprintf("CVE-2026-1%03d", i)
		e.vuln(id)
		e.raw("cvelist", id, cve5(id, "PUBLISHED", "CWE-79", v31), t0)
		e.raw("nvd", id, nvdRec(id, "Analyzed", "CWE-89"), t0)
	}
	conns := make([]*pgx.Conn, 2)
	for i := range conns {
		c, err := testutil.Connect(e.ctx, e.d.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(e.ctx)
		conns[i] = c
	}
	var wg sync.WaitGroup
	results := make([]*Stats, 2)
	errs := make([]error, 2)
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o := Options{Wait: true, BatchSize: 7}
			if i == 0 {
				results[i], errs[i] = All(e.ctx, conns[i], o)
			} else {
				results[i], errs[i] = Pending(e.ctx, conns[i], o)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatal(i, err)
		}
	}
	if results[0].CWEInserted+results[1].CWEInserted != 90 {
		t.Errorf("rows written twice or lost: %+v %+v", results[0], results[1])
	}
	if e.count(`SELECT count(*) FROM vuln_cwe`) != 90 || e.count(`SELECT count(*) FROM vuln_cvss`) != 60 {
		t.Errorf("cwe %d cvss %d", e.count(`SELECT count(*) FROM vuln_cwe`), e.count(`SELECT count(*) FROM vuln_cvss`))
	}
	// a non-waiting pass while the lock is held defers
	unlock, err := lock(e.ctx, conns[0], true)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Pending(e.ctx, conns[1], Options{})
	unlock()
	if err != nil || !st.Deferred {
		t.Errorf("%+v %v", st, err)
	}
}

func TestDeriveErrorKeepsRows(t *testing.T) {
	e := newEnv(t)
	e.vuln("CVE-2026-0001")
	e.raw("nvd", "CVE-2026-0001", nvdRec("CVE-2026-0001", "Analyzed", "CWE-79"), t0)
	e.pending()
	// a payload that is not an object cannot be derived: rows are kept
	e.exec(`INSERT INTO raw_record (source, source_key, fetched_at, content_hash, payload) VALUES ('nvd', 'CVE-2026-0001', $1, 'h-bad', '[1]')`, t0.Add(time.Hour))
	st := e.pending()
	if st.DeriveErrors != 1 || !has(e.rows("CVE-2026-0001"), "cwe CWE-79 nvd-primary/nvd@nist.gov") {
		t.Errorf("%+v %v", st, e.rows("CVE-2026-0001"))
	}
	b, _ := json.Marshal(st)
	if !strings.Contains(string(b), "nvd/CVE-2026-0001") {
		t.Errorf("%s", b)
	}
}
