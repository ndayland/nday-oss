package zerowire_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/testutil"
)

// End to end through the pipeline against a test database, fed by the fake
// network: date-only events per id, a GHSA alias lands on its CVE, an
// advisory without ids is stored but gives nothing, an updated advisory
// (new guid date, new title) updates its events in place, a CVE it gains
// adds one event, and one it drops keeps its old event.
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
	// GHSA-34m4-m9fh-gqp5 (named by ruby2shell) is an alias of a known CVE
	exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-5555')`)
	exec(`INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ('CVE-2026-5555', 'GHSA-34m4-m9fh-gqp5', 'ghsa')`)

	body := fixture(t, "feed_sample.xml")
	f := &fakeNet{handler: func(*http.Request) *http.Response { return respond(200, nil, body) }}
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	runOnce := func() *pipeline.Stats {
		t.Helper()
		st, err := pipeline.RunCollector(ctx, d.Conn, newCollector(f), pipeline.Options{Now: func() time.Time { return now },
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// ruby2shell: 1 CVE + 2 GHSA (one alias, one unknown: nothing written);
	// nginx2root: 7 CVEs; emudhra: none
	st := runOnce()
	if st.Fetched != 3 || st.RawNew != 3 || st.EventInserted != 9 || st.NormalizeErrors != 0 {
		t.Fatalf("%+v", st)
	}
	var occurred time.Time
	var url, title, prec string
	if err := d.Conn.QueryRow(ctx, `SELECT occurred_at, url, detail->>'title', detail->>'precision' FROM event
        WHERE cve_id = 'CVE-2026-132825' AND type = 'analysis_published' AND source = 'zerowire' AND dedupe_key = 'ruby2shell'`).
		Scan(&occurred, &url, &title, &prec); err != nil {
		t.Fatal(err)
	}
	if !occurred.Equal(time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)) || prec != "day" ||
		url != "https://radar.cloudflare.com/zero-wire/ruby2shell" || title != "ruby2shell: heap overflow in Ruby string case conversion" {
		t.Errorf("%s %s %q %q", occurred, url, title, prec)
	}
	if n := count(`SELECT count(*) FROM event WHERE cve_id = 'CVE-2026-5555' AND source = 'zerowire' AND dedupe_key = 'ruby2shell'`); n != 1 {
		t.Errorf("GHSA alias event: %d", n)
	}
	if n := count(`SELECT count(*) FROM vuln WHERE cve_id LIKE 'GHSA-%'`); n != 0 {
		t.Errorf("%d GHSA vulns", n)
	}
	if n := count(`SELECT count(*) FROM event WHERE source = 'zerowire' AND dedupe_key = 'nginx2root'`); n != 7 {
		t.Errorf("nginx2root events: %d", n)
	}
	if n := count(`SELECT count(*) FROM raw_record WHERE source = 'zerowire' AND source_key = 'emudhra-certificate-compromise'`); n != 1 {
		t.Errorf("no-id advisory raw record: %d", n)
	}
	if n := count(`SELECT count(*) FROM raw_record WHERE source = 'zerowire' AND (payload::text LIKE '%Prioritize%' OR payload::text LIKE '%Cloudforce One%')`); n != 0 {
		t.Error("advisory text was stored")
	}
	if got := count(`SELECT stage_rank FROM vuln_state WHERE cve_id = 'CVE-2026-132825'`); got != 3 {
		t.Errorf("stage rank %d", got)
	}

	// same feed again: nothing new
	if st = runOnce(); st.RawNew != 0 || st.EventInserted != 0 || st.EventUpdated != 0 {
		t.Fatalf("%+v", st)
	}

	// only the guid's date changes: same raw record, nothing written
	body = []byte(strings.Replace(string(body), "ruby2shell@2026-11-19", "ruby2shell@2026-11-21", 1))
	if st = runOnce(); st.RawNew != 0 || st.EventInserted != 0 || st.EventUpdated != 0 {
		t.Fatalf("guid only: %+v", st)
	}

	// an update: new guid date and pubDate, new title, and the advisory now
	// names one more CVE: 3 events updated in place, 1 added
	s := string(body)
	s = strings.Replace(s, "ruby2shell@2026-11-21", "ruby2shell@2026-11-22", 1)
	s = strings.Replace(s, "<title>ruby2shell: heap overflow in Ruby string case conversion</title>",
		"<title>ruby2shell (updated): heap overflow, CVE-2026-140000</title>", 1)
	i := strings.Index(s, "<link>https://radar.cloudflare.com/zero-wire/ruby2shell</link>")
	j := i + strings.Index(s[i:], "<pubDate>")
	s = s[:j] + strings.Replace(s[j:], "Thu, 19 Nov 2026", "Sun, 22 Nov 2026", 1)
	body = []byte(s)
	st = runOnce()
	if st.RawNew != 1 || st.EventInserted != 1 || st.EventUpdated != 2 {
		t.Fatalf("update: %+v", st)
	}
	if n := count(`SELECT count(*) FROM event WHERE source = 'zerowire' AND dedupe_key = 'ruby2shell'`); n != 3 {
		t.Errorf("ruby2shell events: %d", n)
	}
	if err := d.Conn.QueryRow(ctx, `SELECT occurred_at, detail->>'title' FROM event
        WHERE cve_id = 'CVE-2026-132825' AND source = 'zerowire' AND dedupe_key = 'ruby2shell'`).Scan(&occurred, &title); err != nil {
		t.Fatal(err)
	}
	// the title follows the update; the time stays the first day we saw
	if title != "ruby2shell (updated): heap overflow, CVE-2026-140000" || !occurred.Equal(time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("%s %q", occurred, title)
	}
	if n := count(`SELECT count(*) FROM event WHERE cve_id = 'CVE-2026-140000' AND source = 'zerowire' AND occurred_at = '2026-11-22T00:00:00Z'`); n != 1 {
		t.Errorf("gained CVE: %d", n)
	}

	// an id that disappears from the advisory keeps its event
	body = []byte(strings.Replace(string(body), "CVE-2026-120993", "CVE-2026-1", -1))
	runOnce()
	if n := count(`SELECT count(*) FROM event WHERE cve_id = 'CVE-2026-120993' AND source = 'zerowire'`); n != 1 {
		t.Errorf("dropped id: %d events", n)
	}
}
