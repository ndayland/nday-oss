package osssec_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"nday.land/nday/internal/collector/osssec"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/testutil"
)

// End to end through the pipeline against a test database: an unknown CVE
// gets a stub and its event, a GHSA alias lands on its CVE, a post without
// ids is stored but gives nothing, and a second run writes nothing new.
func TestPipeline(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := d.Conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-5555')`)
	exec(`INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ('CVE-2026-5555', 'GHSA-2cm2-m3w5-gp2f', 'ghsa')`)

	s := newSite(t)
	s.index["2026/q4"] = []int{788, 789, 790}
	s.etag["2026/q4"] = `"v1"`
	s.pages["2026/q4/788"] = fixture(t, "msg_788.html")
	s.pages["2026/q4/789"] = synthPage("Advisory for libfoo", "Jane Doe &lt;jd () example org&gt;", "Thu, 19 Nov 2026 10:00:00 +0000",
		"Fixed in 1.2: GHSA-2CM2-M3W5-GP2F", "")
	s.pages["2026/q4/790"] = synthPage("Meeting notes", "Jane Doe &lt;jd () example org&gt;", "Thu, 19 Nov 2026 11:00:00 +0000",
		"nothing to see", "")
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	runOnce := func() *pipeline.Stats {
		t.Helper()
		c := newCollector(t, s, now, nil, 0).c
		st, err := pipeline.RunCollector(ctx, d.Conn, c, pipeline.Options{Now: func() time.Time { return now },
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	st := runOnce()
	if st.Fetched != 3 || st.RawNew != 3 || st.EventInserted != 2 || st.VulnInserted != 1 || st.NormalizeErrors != 0 {
		t.Fatalf("%+v", st)
	}
	var occurred time.Time
	var url, subject string
	if err := d.Conn.QueryRow(ctx, `SELECT occurred_at, url, detail->>'subject' FROM event
        WHERE cve_id = 'CVE-2026-124749' AND type = 'analysis_published' AND source = 'osssec' AND dedupe_key = '2026/q4/788'`).
		Scan(&occurred, &url, &subject); err != nil {
		t.Fatal(err)
	}
	if !occurred.Equal(time.Date(2026, 11, 19, 16, 59, 24, 0, time.UTC)) || url != "https://seclists.org/oss-sec/2026/q4/788" || subject == "" {
		t.Errorf("%s %s %q", occurred, url, subject)
	}
	if n := count(`SELECT count(*) FROM vuln WHERE cve_id = 'CVE-2026-124749' AND title IS NULL AND description IS NULL`); n != 1 {
		t.Errorf("stub vuln: %d", n)
	}
	if n := count(`SELECT count(*) FROM event WHERE cve_id = 'CVE-2026-5555' AND source = 'osssec' AND dedupe_key = '2026/q4/789'`); n != 1 {
		t.Errorf("GHSA alias event: %d", n)
	}
	if n := count(`SELECT count(*) FROM vuln WHERE cve_id LIKE 'GHSA-%'`); n != 0 {
		t.Errorf("%d GHSA vulns", n)
	}
	if n := count(`SELECT count(*) FROM raw_record WHERE source = 'osssec' AND payload::text LIKE '%nothing to see%'`); n != 0 {
		t.Error("the body was stored")
	}
	if n := count(`SELECT count(*) FROM raw_record WHERE source = 'osssec' AND payload::text LIKE '%example org%'`); n != 0 {
		t.Error("an address was stored")
	}
	if got := count(`SELECT stage_rank FROM vuln_state WHERE cve_id = 'CVE-2026-124749'`); got != 3 {
		t.Errorf("stage rank %d", got)
	}

	// second run: the index answers 304, nothing is fetched or written
	s.reset()
	st = runOnce()
	if st.Fetched != 0 || st.RawNew != 0 || st.EventInserted != 0 || len(s.messageReqs()) != 0 {
		t.Fatalf("%+v %v", st, s.reqs)
	}
	// offline renormalize from the stored raw records changes nothing either
	c, _ := osssec.New(osssec.Options{})
	st, err := pipeline.Renormalize(ctx, d.Conn, c, pipeline.RenormalizeOptions{Now: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil || st.EventInserted != 0 || st.EventUpdated != 0 || st.NormalizeErrors != 0 {
		t.Fatalf("%v %+v", err, st)
	}
}
