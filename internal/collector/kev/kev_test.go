package kev_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/kev"
	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

var (
	T0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	T1 = T0.Add(24 * time.Hour)
)

const fixture = "tests/fixtures/kev_sample.json"

const countSQL = `SELECT (SELECT count(*) FROM raw_record), (SELECT count(*) FROM vuln),
                      (SELECT count(*) FROM vuln_alias), (SELECT count(*) FROM affected),
                      (SELECT count(*) FROM event)`

type counts [5]int64

func getCounts(t *testing.T, d *testutil.TestDB) counts {
	t.Helper()
	var c counts
	if err := d.Conn.QueryRow(context.Background(), countSQL).Scan(&c[0], &c[1], &c[2], &c[3], &c[4]); err != nil {
		t.Fatal(err)
	}
	return c
}

func feed(t *testing.T) *pyjson.Object {
	t.Helper()
	v, err := pyjson.Decode(testutil.ReadFile(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*pyjson.Object)
}

func vulns(f *pyjson.Object) []any { return f.Get("vulnerabilities").([]any) }

func entry(t *testing.T, f *pyjson.Object, cve string) *pyjson.Object {
	for _, e := range vulns(f) {
		if e.(*pyjson.Object).Get("cveID") == cve {
			return e.(*pyjson.Object)
		}
	}
	t.Fatalf("no entry %s", cve)
	return nil
}

func body(t *testing.T, f *pyjson.Object) []byte {
	s, err := pyjson.Encode(f, pyjson.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

// newKev returns a KEV collector whose HTTP layer serves b (no network) and
// asserts the URL, like conftest.make_kev_collector.
func newKev(t *testing.T, b []byte) (*kev.Collector, *testutil.FakeTransport) {
	ft := &testutil.FakeTransport{Handler: func(r *http.Request) (int, http.Header, []byte, error) {
		if r.URL.String() != kev.FeedURL {
			t.Errorf("unexpected URL %s", r.URL)
		}
		return 200, nil, b, nil
	}}
	return kev.New(kev.Options{Transport: ft}), ft
}

func run(t *testing.T, d *testutil.TestDB, c collector.Collector, now time.Time, renorm bool) *pipeline.Stats {
	t.Helper()
	st, err := pipeline.RunCollector(context.Background(), d.Conn, c, pipeline.Options{Now: func() time.Time { return now }, Renormalize: renorm})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return st
}

// ------------------------------------------------------------ golden parity

func TestGoldenParityWithPython(t *testing.T) {
	newC := func(ft *testutil.FakeTransport) collector.Collector { return kev.New(kev.Options{Transport: ft}) }
	for _, g := range []string{"kev_sample", "feed_edge", "edge_records"} {
		t.Run(g, func(t *testing.T) {
			testutil.CheckGolden(t, "internal/collector/kev/testdata/golden/"+g+".golden.json", newC)
		})
	}
}

// ------------------------------------------------------------ pure normalize

func TestCVEIDValidation(t *testing.T) {
	for id, ok := range map[string]bool{
		"CVE-2026-124194": true, "CVE-2021-43890": true, "CVE-2021-123": false, "cve-2021-43890": false,
	} {
		if model.IsValidCVEID(id) != ok {
			t.Errorf("%s: want %v", id, ok)
		}
	}
}

func TestNormalizeOutput(t *testing.T) {
	f := feed(t)
	e := entry(t, f, "CVE-2026-102895")
	norm, err := kev.New(kev.Options{}).Normalize(model.RawRecord{Source: "kev", SourceKey: "CVE-2026-102895", Payload: e})
	if err != nil {
		t.Fatal(err)
	}
	if len(norm.Vulns) != 1 || *norm.Vulns[0].Title != e.Get("vulnerabilityName") ||
		*norm.Vulns[0].Description != e.Get("shortDescription") || norm.Vulns[0].Authoritative {
		t.Errorf("vulns %+v", norm.Vulns)
	}
	if len(norm.Affected) != 1 || norm.Affected[0] != (model.Affected{CVEID: "CVE-2026-102895",
		Vendor: e.Get("vendorProject").(string), Product: e.Get("product").(string)}) {
		t.Errorf("affected %+v", norm.Affected)
	}
	if len(norm.Aliases) != 0 || len(norm.Events) != 1 {
		t.Fatalf("aliases/events %d/%d", len(norm.Aliases), len(norm.Events))
	}
	ev := norm.Events[0]
	if ev.Type != "kev_added" || ev.Source != "kev" || *ev.URL != kev.CatalogURL ||
		!ev.OccurredAt.Equal(time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)) || ev.Detail["precision"] != "day" {
		t.Errorf("event %+v", ev)
	}
	for k, src := range map[string]string{"known_ransomware_campaign_use": "knownRansomwareCampaignUse",
		"required_action": "requiredAction", "due_date": "dueDate", "notes": "notes", "forensic_triage": "forensicTriage"} {
		if ev.Detail[k] != e.Get(src) {
			t.Errorf("detail[%s] = %v", k, ev.Detail[k])
		}
	}
	if got, _ := pyjson.Canonical(ev.Detail["cwes"]); got != `["CWE-287","CWE-290","CWE-346"]` {
		t.Errorf("cwes %s", got)
	}
}

func TestNormalizeNeverFabricatesOccurredAt(t *testing.T) {
	e := entry(t, feed(t), "CVE-2021-43890").Clone()
	e.Set("dateAdded", "")
	norm, err := kev.New(kev.Options{}).Normalize(model.RawRecord{Source: "kev", SourceKey: "CVE-2021-43890", Payload: e})
	if err != nil {
		t.Fatal(err)
	}
	if norm.Events[0].OccurredAt != nil {
		t.Error("occurred_at fabricated")
	}
	if _, ok := norm.Events[0].Detail["precision"]; ok {
		t.Error("precision set")
	}
}

func TestNormalizeRejectsBadCVE(t *testing.T) {
	e := entry(t, feed(t), "CVE-2021-43890").Clone()
	e.Set("cveID", "CVE-21-1")
	_, err := kev.New(kev.Options{}).Normalize(model.RawRecord{Source: "kev", SourceKey: "CVE-21-1", Payload: e})
	var ne *collector.NormalizeError
	if !errors.As(err, &ne) || ne.Msg != "bad cveID: 'CVE-21-1'" {
		t.Fatalf("got %v", err)
	}
}

// ------------------------------------------------------------ pipeline + DB

func TestFirstRunInsertsAndSendsGenericUserAgent(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := feed(t)
	c, ft := newKev(t, body(t, f))
	st := run(t, d, c, T0, false)
	n := len(vulns(f))
	if st.RawNew != n || st.VulnInserted != n || st.AffectedInserted != n || st.EventInserted != n {
		t.Errorf("stats %+v", st)
	}
	if got := getCounts(t, d); got != (counts{int64(n), int64(n), 0, int64(n), int64(n)}) {
		t.Errorf("counts %v", got)
	}
	if ua := ft.Requests[0].Header.Get("User-Agent"); ua != "nday-collector/0.1.0" {
		t.Errorf("UA %q", ua)
	}
	ctx := context.Background()
	var title, prec string
	var firstSeen, occ, obs time.Time
	if err := d.Conn.QueryRow(ctx, `SELECT v.title, v.first_seen_at, e.occurred_at, e.observed_at, e.detail->>'precision'
           FROM vuln v JOIN event e USING (cve_id) WHERE cve_id = 'CVE-2021-43890'`).Scan(&title, &firstSeen, &occ, &obs, &prec); err != nil {
		t.Fatal(err)
	}
	e := entry(t, f, "CVE-2021-43890")
	if title != e.Get("vulnerabilityName") || !firstSeen.Equal(T0) || !occ.Equal(time.Date(2021, 12, 15, 0, 0, 0, 0, time.UTC)) ||
		!obs.Equal(T0) || prec != "day" {
		t.Errorf("row %v %v %v %v %v", title, firstSeen, occ, obs, prec)
	}
	var other int
	_ = d.Conn.QueryRow(ctx, "SELECT count(*) FROM event WHERE type <> 'kev_added'").Scan(&other)
	if other != 0 {
		t.Error("non-kev_added events")
	}
	var status, ver string
	var ok time.Time
	if err := d.Conn.QueryRow(ctx, "SELECT last_status, last_success_at, cursor->>'catalogVersion' FROM collector_state").Scan(&status, &ok, &ver); err != nil {
		t.Fatal(err)
	}
	if status != "ok" || !ok.Equal(T0) || ver != f.Get("catalogVersion") {
		t.Errorf("state %s %v %s", status, ok, ver)
	}
	// The stored cursor is exactly Python's {k: data.get(k)} for the three keys.
	var cur string
	_ = d.Conn.QueryRow(ctx, "SELECT cursor::text FROM collector_state").Scan(&cur)
	if cur != `{"count": 5, "dateReleased": "2026-11-10T19:03:29.8375Z", "catalogVersion": "2026.11.10"}` {
		t.Errorf("cursor %s", cur)
	}
}

func snapshot(t *testing.T, d *testutil.TestDB) []string {
	rows, err := d.Conn.Query(context.Background(),
		`SELECT cve_id || '|' || updated_at::text || '|' || observed_at::text || '|' || is_backfill::text
         FROM vuln JOIN event USING (cve_id) ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func TestSecondRunIsIdempotent(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := feed(t)
	b := body(t, f)
	c, _ := newKev(t, b)
	run(t, d, c, T0, false)
	before, snap := getCounts(t, d), snapshot(t, d)
	st := run(t, d, c, T1, false)
	if getCounts(t, d) != before {
		t.Error("rows added")
	}
	if st.RawUnchanged != len(vulns(f)) || st.RawNew+st.VulnInserted+st.VulnUpdated+st.EventInserted+st.EventUpdated+st.AffectedInserted != 0 {
		t.Errorf("stats %+v", st)
	}
	if s := snapshot(t, d); len(s) != len(snap) || s[0] != snap[0] || s[len(s)-1] != snap[len(snap)-1] {
		t.Error("vuln/event rows changed")
	}
	// --renormalize on unchanged data must not add rows either.
	st = run(t, d, c, T1, true)
	if getCounts(t, d) != before || st.EventUpdated != 0 || st.VulnUpdated != 0 {
		t.Errorf("renormalize changed rows: %+v", st)
	}
}

func TestBackfillFlagFirstVsLaterRun(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := feed(t)
	all := vulns(f)
	newest := all[len(all)-1].(*pyjson.Object).Get("cveID").(string)
	older := f.Clone()
	older.Set("vulnerabilities", all[:len(all)-1])
	c1, _ := newKev(t, body(t, older))
	if s1 := run(t, d, c1, T0, false); !s1.IsBackfill {
		t.Error("first run must be backfill")
	}
	c2, _ := newKev(t, body(t, f))
	s2 := run(t, d, c2, T1, false)
	if s2.IsBackfill || s2.EventInserted != 1 {
		t.Errorf("second run %+v", s2)
	}
	rows, _ := d.Conn.Query(context.Background(), "SELECT cve_id, is_backfill, observed_at FROM event")
	n := 0
	for rows.Next() {
		var id string
		var bf bool
		var obs time.Time
		_ = rows.Scan(&id, &bf, &obs)
		if id == newest {
			if bf || !obs.Equal(T1) {
				t.Errorf("newest: backfill=%v observed=%v", bf, obs)
			}
		} else {
			n++
			if !bf {
				t.Errorf("%s should be backfill", id)
			}
		}
	}
	if n == 0 {
		t.Error("no older events")
	}
}

func TestFailedFirstRunKeepsBackfillForNextRun(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	boom := kev.New(kev.Options{Transport: &testutil.FakeTransport{Handler: func(*http.Request) (int, http.Header, []byte, error) {
		return 503, nil, nil, nil
	}}})
	_, err := pipeline.RunCollector(context.Background(), d.Conn, boom, pipeline.Options{Now: func() time.Time { return T0 }})
	var se *httpc.StatusError
	if !errors.As(err, &se) || se.Status != 503 {
		t.Fatalf("want 503 StatusError, got %v", err)
	}
	var status string
	var okAt *time.Time
	var lastErr string
	_ = d.Conn.QueryRow(context.Background(), "SELECT last_status, last_success_at, last_error FROM collector_state").Scan(&status, &okAt, &lastErr)
	if status != "error" || okAt != nil || lastErr == "" {
		t.Errorf("state %s %v %q", status, okAt, lastErr)
	}
	c, _ := newKev(t, body(t, feed(t)))
	if st := run(t, d, c, T1, false); !st.IsBackfill {
		t.Error("run after failed first run must still be backfill")
	}
}

func TestStubDoesNotOverwriteExistingTitle(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	cve := "CVE-2026-59310"
	if _, err := d.Conn.Exec(ctx, "INSERT INTO vuln (cve_id, title, description) VALUES ($1, 'Existing title', '')", cve); err != nil {
		t.Fatal(err)
	}
	f := feed(t)
	c, _ := newKev(t, body(t, f))
	st := run(t, d, c, T0, false)
	var title, desc string
	var firstSeen time.Time
	_ = d.Conn.QueryRow(ctx, "SELECT title, description, first_seen_at FROM vuln WHERE cve_id = $1", cve).Scan(&title, &desc, &firstSeen)
	if title != "Existing title" || desc != entry(t, f, cve).Get("shortDescription") || firstSeen.Equal(T0) {
		t.Errorf("%q %q %v", title, desc, firstSeen)
	}
	if st.VulnUpdated != 1 || st.VulnInserted != len(vulns(f))-1 {
		t.Errorf("stats %+v", st)
	}
}

func TestChangedUpstreamEntryUpdatesEventDetailWithoutNewEvent(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := feed(t)
	c, _ := newKev(t, body(t, f))
	run(t, d, c, T0, false)
	changed := f.Clone()
	vs := append([]any(nil), vulns(f)...)
	first := vs[0].(*pyjson.Object).Clone()
	first.Set("dueDate", "2099-01-01")
	vs[0] = first
	changed.Set("vulnerabilities", vs)
	c2, _ := newKev(t, body(t, changed))
	st := run(t, d, c2, T1, false)
	if st.RawNew != 1 || st.EventInserted != 0 || st.EventUpdated != 1 {
		t.Errorf("stats %+v", st)
	}
	cve := first.Get("cveID").(string)
	var due string
	var obs time.Time
	var bf bool
	_ = d.Conn.QueryRow(context.Background(), "SELECT detail->>'due_date', observed_at, is_backfill FROM event WHERE cve_id = $1", cve).Scan(&due, &obs, &bf)
	if due != "2099-01-01" || !obs.Equal(T0) || !bf {
		t.Errorf("%s %v %v", due, obs, bf)
	}
	var n int
	_ = d.Conn.QueryRow(context.Background(), "SELECT count(*) FROM raw_record WHERE source_key = $1", cve).Scan(&n)
	if n != 2 {
		t.Errorf("raw versions %d", n)
	}
}

func TestRenormalizeDryRunIsZeroAndRollsBack(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	c, ft := newKev(t, body(t, feed(t)))
	run(t, d, c, T0, false)
	reqs := len(ft.Requests)
	st, err := pipeline.Renormalize(ctx, d.Conn, c, pipeline.RenormalizeOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Fetched != 5 || st.VulnInserted+st.VulnUpdated+st.EventInserted+st.EventUpdated+st.AffectedInserted+st.AliasInserted != 0 {
		t.Errorf("stats %+v", st)
	}
	if len(ft.Requests) != reqs {
		t.Error("renormalize used the network")
	}
	// Tamper with the DB: renormalize must detect it, and dry-run must not write.
	if _, err := d.Conn.Exec(ctx, `UPDATE event SET detail = detail || '{"due_date": "x"}' WHERE cve_id = 'CVE-2021-43890'`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `DELETE FROM affected WHERE cve_id = 'CVE-2021-43890'`); err != nil {
		t.Fatal(err)
	}
	st, err = pipeline.Renormalize(ctx, d.Conn, c, pipeline.RenormalizeOptions{DryRun: true})
	if err != nil || st.EventUpdated != 1 || st.AffectedInserted != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	var due string
	_ = d.Conn.QueryRow(ctx, "SELECT detail->>'due_date' FROM event WHERE cve_id = 'CVE-2021-43890'").Scan(&due)
	if due != "x" {
		t.Error("dry run wrote to the database")
	}
	// Real run repairs it.
	if _, err := pipeline.Renormalize(ctx, d.Conn, c, pipeline.RenormalizeOptions{}); err != nil {
		t.Fatal(err)
	}
	_ = d.Conn.QueryRow(ctx, "SELECT detail->>'due_date' FROM event WHERE cve_id = 'CVE-2021-43890'").Scan(&due)
	if due != "2021-12-29" {
		t.Errorf("due_date %q", due)
	}
}
