package cveimport

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/collector/cvelist"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

var (
	snapshot = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	importAt = time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC)
)

// cveJSON builds a CVE JSON 5 record.
func cveJSON(id, state, title, updated string) string {
	switch state {
	case "RESERVED":
		return fmt.Sprintf(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":%q,"state":"RESERVED","assignerShortName":"mitre","dateReserved":"2020-01-01T00:00:00"}}`, id)
	case "REJECTED":
		return fmt.Sprintf(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":%q,"state":"REJECTED","assignerShortName":"mitre","datePublished":"2019-02-01T00:00:00","dateRejected":"2019-03-01T00:00:00","dateUpdated":%q},"containers":{"cna":{"rejectedReasons":[{"lang":"en","value":"DO NOT USE. Duplicate."}],"replacedBy":["CVE-2019-0001"]}}}`, id, updated)
	}
	return fmt.Sprintf(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":%q,"state":"PUBLISHED","assignerShortName":"mitre","datePublished":"2014-04-07T22:55:03","dateUpdated":%q},
	 "containers":{"cna":{"title":%q,"descriptions":[{"lang":"en","value":"Desc of %s"}],
	   "affected":[{"vendor":"OpenSSL","product":"OpenSSL"},{"vendor":"n/a","product":"n/a"},{"vendor":"OpenSSL","product":"OpenSSL"}],
	   "source":{"advisory":"GHSA-%s"},
	   "metrics":[{"cvssV3_1":{"version":"3.1","baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},
	 "adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc","content":{"timestamp":"2024-01-01T00:00:00Z","options":[{"Exploitation":"active"},{"Automatable":"yes"},{"Technical Impact":"partial"}]}}}]}]}}`,
		id, updated, title, id, ghsaFor(id))
}

// ghsaFor makes a valid, id-specific GHSA suffix.
func ghsaFor(id string) string {
	alpha := "23456789cfghjmpqrvwx"
	h := 0
	for _, c := range id {
		h = h*31 + int(c)
	}
	var b strings.Builder
	for g := 0; g < 3; g++ {
		if g > 0 {
			b.WriteByte('-')
		}
		for k := 0; k < 4; k++ {
			if h < 0 {
				h = -h
			}
			b.WriteByte(alpha[h%len(alpha)])
			h /= 3
			h += g*7 + k
		}
	}
	return b.String()
}

func memberPath(id string) string {
	p := strings.Split(id, "-")
	n := 0
	fmt.Sscanf(p[2], "%d", &n)
	return fmt.Sprintf("cves/%s/%dxxx/%s.json", p[1], n/1000, id)
}

// writeBaseline writes an upstream-shaped nested baseline (outer zip with
// one cves.zip member) and returns its path.
func writeBaseline(t *testing.T, dir string, files map[string]string, nested bool) string {
	t.Helper()
	var inner bytes.Buffer
	zw := zip.NewWriter(&inner)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(files[n]))
	}
	zw.Close()
	path := filepath.Join(dir, "2026-11-13_all_CVEs_at_midnight.zip.zip")
	if !nested {
		os.WriteFile(path, inner.Bytes(), 0o644)
		return path
	}
	var outer bytes.Buffer
	ow := zip.NewWriter(&outer)
	w, _ := ow.Create("cves.zip")
	w.Write(inner.Bytes())
	ow.Close()
	if err := os.WriteFile(path, outer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func records(recs map[string]string) map[string]string {
	out := map[string]string{}
	for id, j := range recs {
		out[memberPath(id)] = j
	}
	return out
}

func openArc(t *testing.T, path string) *Archive {
	t.Helper()
	a, err := OpenArchive(path, t.TempDir(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func newC(t *testing.T) *cvelist.Collector {
	c, err := cvelist.New(cvelist.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func opts() Options {
	return Options{SnapshotAt: snapshot, Now: func() time.Time { return importAt }, BatchSize: 2, Workers: 3}
}

func mustImport(t *testing.T, conn *pgx.Conn, a *Archive, o Options) *Stats {
	t.Helper()
	st, err := Import(context.Background(), conn, a, newC(t), o)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// rowsOf renders every row of the data tables for the given CVEs (ids and
// timestamps that legitimately differ between runs excluded unless full).
func rowsOf(t *testing.T, conn *pgx.Conn, ids []string, full bool) string {
	t.Helper()
	extra := ""
	if full {
		extra = ", first_seen_at, created_at, updated_at"
	}
	evExtra := ""
	if full {
		evExtra = ", observed_at, id, created_at"
	}
	rawExtra := ""
	if full {
		rawExtra = ", fetched_at, id"
	}
	qs := []string{
		`SELECT cve_id, title, description, published_at, modified_at` + extra + ` FROM vuln WHERE cve_id = ANY($1) ORDER BY 1`,
		`SELECT cve_id, type, occurred_at, source, url, detail::text, is_backfill, dedupe_key` + evExtra + ` FROM event WHERE cve_id = ANY($1) ORDER BY cve_id, type, source`,
		`SELECT cve_id, vendor, product FROM affected WHERE cve_id = ANY($1) ORDER BY 1, 2, 3`,
		`SELECT cve_id, alias, alias_type FROM vuln_alias WHERE cve_id = ANY($1) ORDER BY 1, 2`,
		`SELECT source, source_key, content_hash, payload::text` + rawExtra + ` FROM raw_record WHERE source_key = ANY($1) ORDER BY 2, 3`,
	}
	var b strings.Builder
	for _, q := range qs {
		rows, err := conn.Query(context.Background(), q, ids)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				t.Fatal(err)
			}
			for i, v := range vals {
				if tm, ok := v.(time.Time); ok {
					vals[i] = tm.UTC().Format(time.RFC3339Nano)
				}
			}
			fmt.Fprintf(&b, "%v\n", vals)
		}
		if rows.Err() != nil {
			t.Fatal(rows.Err())
		}
		b.WriteString("--\n")
	}
	return b.String()
}

func count(t *testing.T, conn *pgx.Conn, q string, args ...any) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// fixed is the real cvelist collector (its Normalize) with Fetch replaced by
// a fixed record list, to run the collector's own pipeline path offline.
type fixed struct {
	*cvelist.Collector
	recs []model.RawRecord
}

func (f fixed) Fetch(context.Context, model.CollectorState) (*model.FetchResult, error) {
	return &model.FetchResult{Records: f.recs, Cursor: map[string]any{"last_fetch_time": "2026-11-13T00:00:00Z"}}, nil
}

func rawRec(t *testing.T, id, js string) model.RawRecord {
	v, err := pyjson.DecodeString(js)
	if err != nil {
		t.Fatal(err)
	}
	return model.RawRecord{Source: cvelist.Name, SourceKey: id, Payload: v}
}

var basicRecs = map[string]string{
	"CVE-2014-0160":  cveJSON("CVE-2014-0160", "PUBLISHED", "Heartbleed", "2024-01-01T00:00:00"),
	"CVE-2017-0144":  cveJSON("CVE-2017-0144", "PUBLISHED", "EternalBlue", "2024-02-01T00:00:00"),
	"CVE-2019-1000":  cveJSON("CVE-2019-1000", "REJECTED", "", "2019-03-01T00:00:00"),
	"CVE-2026-98432": cveJSON("CVE-2026-98432", "PUBLISHED", "New one", "2026-11-12T10:00:00"),
	"CVE-2026-1000":  cveJSON("CVE-2026-1000", "RESERVED", "", ""),
	"CVE-2026-1001":  cveJSON("CVE-2026-1001", "PUBLISHED", "Second", "2026-11-12T10:00:00"),
	"CVE-2026-1002":  cveJSON("CVE-2026-1003", "PUBLISHED", "Mismatched id", "2026-11-12T10:00:00"),                                               // NormalizeError
	"CVE-2026-1004":  `{"dataType":"CVE_RECORD","cveMetadata":{"cveId":"CVE-2026-1004","state":"PUBLISHED"},"containers":{"cna":{"affected":5}}}`, // TypeError: fatal for the collector
}

func basicFiles() map[string]string {
	f := records(basicRecs)
	f["cves/2026/1xxx/CVE-2026-1005.json"] = `{"broken": `         // invalid JSON
	f["cves/2026/1xxx/CVE-2026-1006.json"] = `["not","an object"]` // ignored by the collector
	f["cves/delta.json"] = `{}`
	f["cves/deltaLog.json"] = `[]`
	return f
}

func TestOpenArchiveNestedAndPlain(t *testing.T) {
	for _, nested := range []bool{true, false} {
		dir := t.TempDir()
		path := writeBaseline(t, dir, basicFiles(), nested)
		tmp := t.TempDir()
		a, err := OpenArchive(path, tmp, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, m := range a.Members {
			ids = append(ids, m.CVE)
		}
		want := "CVE-2014-0160 CVE-2017-0144 CVE-2019-1000 CVE-2026-1000 CVE-2026-1001 CVE-2026-1002 CVE-2026-1004 CVE-2026-1005 CVE-2026-1006 CVE-2026-98432"
		if strings.Join(ids, " ") != want || a.Ignored != 2 {
			t.Fatalf("nested=%v: %v ignored=%d", nested, ids, a.Ignored)
		}
		left, _ := os.ReadDir(tmp)
		if nested != (len(left) == 1) {
			t.Fatalf("nested=%v: temp dir %v", nested, left)
		}
		a.Close()
		if left, _ := os.ReadDir(tmp); len(left) != 0 {
			t.Fatalf("extracted archive not removed: %v", left)
		}
	}
}

func TestOpenArchiveRejectsOversizedInnerAndCorruption(t *testing.T) {
	dir := t.TempDir()
	path := writeBaseline(t, dir, basicFiles(), true)
	tmp := t.TempDir()
	if _, err := OpenArchive(path, tmp, 100, nil); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("cap: %v", err)
	}
	// Flip a byte inside the deflated inner member: CRC/inflate error, temp removed.
	data, _ := os.ReadFile(path)
	data[len(data)/2] ^= 0xff
	os.WriteFile(path, data, 0o644)
	if _, err := OpenArchive(path, tmp, 0, nil); err == nil {
		t.Fatal("corruption not detected")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("temp left: %v", left)
	}
}

func TestImportMatchesCollectorPath(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	a := openArc(t, writeBaseline(t, t.TempDir(), basicFiles(), true))
	var reqBefore int
	d.Conn.QueryRow(context.Background(), `SELECT requested FROM vuln_state_refresh`).Scan(&reqBefore)
	st := mustImport(t, d.Conn, a, opts())

	if st.Selected != 10 || st.Imported != 7 || st.Published != 5 || st.Rejected != 1 || st.Reserved != 1 ||
		st.NormalizeErrors != 1 || st.FatalErrors != 1 || st.DecodeErrors != 1 || st.NotObject != 1 ||
		st.SkippedExisting != 0 || st.Processed != 10 || st.Interrupted {
		t.Fatalf("%+v", st)
	}
	if len(st.Errors) != 4 || !strings.Contains(strings.Join(st.Errors, "\n"), "CVE-2026-1002: normalize: cveId CVE-2026-1003 != source_key CVE-2026-1002") {
		t.Fatalf("errors: %q", st.Errors)
	}
	// Exactly what the cvelist collector's own pipeline path writes for the
	// same records (its first run is a backfill run too), in a second schema.
	ref := testutil.NewMigratedDB(t)
	var recs []model.RawRecord
	var ids []string
	for id, js := range basicRecs {
		ids = append(ids, id)
		if id == "CVE-2026-1004" {
			continue // fatal for the collector: it would abort its whole run
		}
		recs = append(recs, rawRec(t, id, js))
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].SourceKey < recs[j].SourceKey })
	if _, err := pipeline.RunCollector(context.Background(), ref.Conn, fixed{newC(t), recs},
		pipeline.Options{Now: func() time.Time { return importAt }, SkipStateRefresh: true}); err != nil {
		t.Fatal(err)
	}
	if got, want := rowsOf(t, d.Conn, ids, false), rowsOf(t, ref.Conn, ids, false); got != want {
		t.Fatalf("import differs from the collector path:\n--- import\n%s\n--- collector\n%s", got, want)
	}
	// is_backfill on every event, observed_at = import time, raw fetched_at = snapshot.
	if n := count(t, d.Conn, `SELECT count(*) FROM event WHERE NOT is_backfill OR observed_at <> $1`, importAt); n != 0 {
		t.Fatalf("%d events not backfill/import time", n)
	}
	if n := count(t, d.Conn, `SELECT count(*) FROM raw_record WHERE fetched_at <> $1`, snapshot); n != 0 {
		t.Fatalf("%d raw rows with other fetched_at", n)
	}
	// RESERVED: raw only; REJECTED: vuln dates + rejection event.
	if count(t, d.Conn, `SELECT count(*) FROM vuln WHERE cve_id = 'CVE-2026-1000'`) != 0 ||
		count(t, d.Conn, `SELECT count(*) FROM raw_record WHERE source_key = 'CVE-2026-1000'`) != 1 ||
		count(t, d.Conn, `SELECT count(*) FROM event WHERE cve_id = 'CVE-2019-1000' AND detail->>'state' = 'REJECTED'`) != 1 {
		t.Fatal("reserved/rejected handling")
	}
	// Not stored: fatal, invalid JSON, non-object.
	if n := count(t, d.Conn, `SELECT count(*) FROM raw_record WHERE source_key IN ('CVE-2026-1004','CVE-2026-1005','CVE-2026-1006')`); n != 0 {
		t.Fatalf("%d unusable records stored", n)
	}
	// collector_state untouched, no refresh requested by Import.
	var reqAfter int
	d.Conn.QueryRow(context.Background(), `SELECT requested FROM vuln_state_refresh`).Scan(&reqAfter)
	if count(t, d.Conn, `SELECT count(*) FROM collector_state`) != 0 || reqAfter != reqBefore {
		t.Fatalf("collector_state or refresh touched (requested %d -> %d)", reqBefore, reqAfter)
	}
	// Re-run: nothing imported, nothing written (fatal/broken retried and failing again).
	before := rowsOf(t, d.Conn, ids, true)
	st2 := mustImport(t, d.Conn, a, opts())
	if st2.Imported != 0 || st2.SkippedExisting != 7 || st2.FatalErrors != 1 || st2.DecodeErrors != 1 || st2.NotObject != 1 {
		t.Fatalf("rerun: %+v", st2)
	}
	if after := rowsOf(t, d.Conn, ids, true); after != before {
		t.Fatal("re-run changed rows")
	}
}

// An older baseline version must never replace a newer stored one.
func TestNeverRegressNewerCollectorData(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	newer := cveJSON("CVE-2014-0160", "PUBLISHED", "Heartbleed (newer)", "2026-11-13T03:00:00")
	if _, err := pipeline.RunCollector(ctx, d.Conn, fixed{newC(t), []model.RawRecord{rawRec(t, "CVE-2014-0160", newer)}},
		pipeline.Options{Now: func() time.Time { return importAt.Add(-time.Hour) }, SkipStateRefresh: true}); err != nil {
		t.Fatal(err)
	}
	// Also a vuln that only exists as a stub from another source: imported.
	if _, err := d.Conn.Exec(ctx, `INSERT INTO vuln (cve_id, title) VALUES ('CVE-2017-0144', 'KEV title')`); err != nil {
		t.Fatal(err)
	}
	ids := []string{"CVE-2014-0160"}
	before := rowsOf(t, d.Conn, ids, true)
	older := map[string]string{
		"CVE-2014-0160": cveJSON("CVE-2014-0160", "PUBLISHED", "Heartbleed (older baseline)", "2024-01-01T00:00:00"),
		"CVE-2017-0144": cveJSON("CVE-2017-0144", "PUBLISHED", "EternalBlue", "2024-02-01T00:00:00"),
	}
	a := openArc(t, writeBaseline(t, t.TempDir(), records(older), true))
	st := mustImport(t, d.Conn, a, opts())
	if st.SkippedExisting != 1 || st.Imported != 1 {
		t.Fatalf("%+v", st)
	}
	if after := rowsOf(t, d.Conn, ids, true); after != before {
		t.Fatalf("existing CVE changed:\n%s\n%s", before, after)
	}
	var title string
	d.Conn.QueryRow(ctx, `SELECT title FROM vuln WHERE cve_id = 'CVE-2017-0144'`).Scan(&title)
	if title != "EternalBlue" { // authoritative cvelist record over the stub, like the collector's backfill
		t.Fatalf("stub not completed: %q", title)
	}
}

func manyRecs(n int) map[string]string {
	m := map[string]string{}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("CVE-2020-%d", 10000+i)
		m[id] = cveJSON(id, "PUBLISHED", "T"+id, "2024-01-01T00:00:00")
	}
	return m
}

func TestLimitResumeAndYearFilter(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	recs := manyRecs(9)
	recs["CVE-2021-0001"] = cveJSON("CVE-2021-0001", "PUBLISHED", "x", "2024-01-01T00:00:00")
	a := openArc(t, writeBaseline(t, t.TempDir(), records(recs), true))
	o := opts()
	o.Limit, o.Year = 4, 2020
	if st := mustImport(t, d.Conn, a, o); st.Imported != 4 || st.Selected != 9 || st.Batches != 2 {
		t.Fatalf("%+v", st)
	}
	o.Limit = 0
	if st := mustImport(t, d.Conn, a, o); st.Imported != 5 || st.SkippedExisting != 4 {
		t.Fatalf("%+v", st)
	}
	o.Year = 0
	if st := mustImport(t, d.Conn, a, o); st.Imported != 1 || st.SkippedExisting != 9 {
		t.Fatalf("%+v", st)
	}
	if n := count(t, d.Conn, `SELECT count(*) - count(DISTINCT source_key) FROM raw_record`); n != 0 {
		t.Fatalf("%d duplicate raw rows", n)
	}
	if n := count(t, d.Conn, `SELECT count(*) FROM event`); n != 10 {
		t.Fatalf("events %d", n)
	}
}

func TestStopFinishesBatchAndCancelRollsBack(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	a := openArc(t, writeBaseline(t, t.TempDir(), records(manyRecs(9)), true))
	// Graceful stop requested while batch 1 is being written: batch 1 commits.
	stop := make(chan struct{})
	o := opts()
	o.Stop = stop
	o.beforeCommit = func(context.Context, pgx.Tx) error {
		select {
		case <-stop:
		default:
			close(stop)
		}
		return nil
	}
	st, err := Import(context.Background(), d.Conn, a, newC(t), o)
	if err != nil || !st.Interrupted || st.Imported != 2 || st.Batches != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	// Hard cancel inside batch 2 of the next run: that batch is rolled back.
	ctx, cancel := context.WithCancel(context.Background())
	o = opts()
	n := 0
	o.beforeCommit = func(ctx context.Context, tx pgx.Tx) error {
		n++
		if n == 2 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	st, err = Import(ctx, d.Conn, a, newC(t), o)
	if !errors.Is(err, context.Canceled) || st.Imported != 2 {
		t.Fatalf("%+v %v", st, err)
	}
	if c := count(t, d.Conn, `SELECT count(*) FROM raw_record`); c != 4 {
		t.Fatalf("raw rows %d, want 4 (2 batches committed)", c)
	}
	// Resume: the rest, no duplicates, consistent counts.
	st = mustImport(t, d.Conn, a, opts())
	if st.Imported != 5 || st.SkippedExisting != 4 {
		t.Fatalf("%+v", st)
	}
	if c := count(t, d.Conn, `SELECT (SELECT count(*) FROM raw_record) + (SELECT count(*) FROM vuln) + (SELECT count(*) FROM event)`); c != 27 {
		t.Fatalf("rows %d", c)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	// One CVE already stored by the collector.
	if _, err := pipeline.RunCollector(context.Background(), d.Conn, fixed{newC(t), []model.RawRecord{rawRec(t, "CVE-2014-0160", basicRecs["CVE-2014-0160"])}},
		pipeline.Options{Now: func() time.Time { return importAt }, SkipStateRefresh: true}); err != nil {
		t.Fatal(err)
	}
	ids := []string{"CVE-2014-0160", "CVE-2017-0144"}
	before := rowsOf(t, d.Conn, ids, true)
	a := openArc(t, writeBaseline(t, t.TempDir(), basicFiles(), true))
	o := opts()
	o.DryRun = true
	st := mustImport(t, d.Conn, a, o)
	if st.Imported != 0 || st.DryRunSkips != 1 || st.DryRunImport != 9 || st.Published != 6 || st.Rejected != 1 ||
		st.Reserved != 1 || st.NormalizeErrors != 1 || st.FatalErrors != 1 || st.DecodeErrors != 1 || st.NotObject != 1 {
		t.Fatalf("%+v", st)
	}
	if after := rowsOf(t, d.Conn, ids, true); after != before || count(t, d.Conn, `SELECT count(*) FROM raw_record`) != 1 {
		t.Fatal("dry run wrote")
	}
}

// waitBlocked waits until a session is waiting for a lock on raw_record.
func waitBlocked(t *testing.T, conn *pgx.Conn, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := conn.QueryRow(context.Background(), `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid)
			WHERE NOT l.granted AND a.query ILIKE $1`, "%"+what+"%").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no session blocked on %q", what)
}

// Race 1: a cvelist run has written (not yet committed) a newer version of
// a CVE that the import wants. The import's batch waits for it, then sees
// the committed row and skips the CVE.
func TestRaceCollectorCommitsDuringBatch(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	other, err := testutil.Connect(ctx, d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	watcher, err := testutil.Connect(ctx, d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close(ctx)

	newer := rawRec(t, "CVE-2014-0160", cveJSON("CVE-2014-0160", "PUBLISHED", "Heartbleed (newer)", "2026-11-13T03:00:00"))
	// Simulate the collector's transaction with the pipeline's own writes.
	tx, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := newer.ContentHash()
	if _, err := pipeline.StoreRaw(ctx, tx, newer, h, importAt); err != nil {
		t.Fatal(err)
	}
	norm, _, err := pipeline.NormalizeOne(newC(t), newer)
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.ApplyNormalized(ctx, tx, norm, importAt, false, &pipeline.Stats{}); err != nil {
		t.Fatal(err)
	}

	a := openArc(t, writeBaseline(t, t.TempDir(), records(map[string]string{
		"CVE-2014-0160": cveJSON("CVE-2014-0160", "PUBLISHED", "Heartbleed (older)", "2024-01-01T00:00:00"),
		"CVE-2017-0144": cveJSON("CVE-2017-0144", "PUBLISHED", "EternalBlue", "2024-02-01T00:00:00"),
	}), true))
	var st *Stats
	var ierr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		st, ierr = Import(ctx, d.Conn, a, newC(t), opts())
	}()
	waitBlocked(t, watcher, "LOCK TABLE raw_record")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	if ierr != nil || st.SkippedExisting != 0 || st.SkippedRace != 1 || st.Imported != 1 {
		t.Fatalf("%+v %v", st, ierr)
	}
	var title string
	var nraw int
	d.Conn.QueryRow(ctx, `SELECT v.title, (SELECT count(*) FROM raw_record WHERE source_key = v.cve_id) FROM vuln v WHERE cve_id = 'CVE-2014-0160'`).Scan(&title, &nraw)
	if title != "Heartbleed (newer)" || nraw != 1 {
		t.Fatalf("regressed: %q raw=%d", title, nraw)
	}
}

// Race 2: a cvelist run starts while an import batch holds its lock. The
// run waits (no deadlock), then writes its newer version on top: the newer
// data wins everywhere, including "latest raw" (fetched_at = snapshot <
// the run's time).
func TestRaceCollectorRunsDuringBatch(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	other, err := testutil.Connect(ctx, d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	watcher, err := testutil.Connect(ctx, d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close(ctx)

	a := openArc(t, writeBaseline(t, t.TempDir(), records(map[string]string{
		"CVE-2014-0160": cveJSON("CVE-2014-0160", "PUBLISHED", "Heartbleed (older)", "2024-01-01T00:00:00"),
	}), true))
	inBatch, release := make(chan struct{}), make(chan struct{})
	o := opts()
	o.beforeCommit = func(context.Context, pgx.Tx) error {
		close(inBatch)
		<-release
		return nil
	}
	var st *Stats
	var ierr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		st, ierr = Import(ctx, d.Conn, a, newC(t), o)
	}()
	<-inBatch
	newer := rawRec(t, "CVE-2014-0160", cveJSON("CVE-2014-0160", "PUBLISHED", "Heartbleed (newer)", "2026-11-13T03:00:00"))
	var cst *pipeline.Stats
	var cerr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cst, cerr = pipeline.RunCollector(ctx, other, fixed{newC(t), []model.RawRecord{newer}},
			pipeline.Options{Now: func() time.Time { return importAt.Add(time.Minute) }})
	}()
	waitBlocked(t, watcher, "INSERT INTO raw_record")
	close(release)
	<-done
	wg.Wait()
	if ierr != nil || st.Imported != 1 || cerr != nil || cst.RawNew != 1 || cst.VulnUpdated != 1 {
		t.Fatalf("import %+v %v / collector %+v %v", st, ierr, cst, cerr)
	}
	var title, latest string
	d.Conn.QueryRow(ctx, `SELECT title FROM vuln WHERE cve_id = 'CVE-2014-0160'`).Scan(&title)
	d.Conn.QueryRow(ctx, `SELECT payload->'containers'->'cna'->>'title' FROM raw_record WHERE source_key = 'CVE-2014-0160'
		ORDER BY fetched_at DESC, id DESC LIMIT 1`).Scan(&latest)
	var detailTitle string
	d.Conn.QueryRow(ctx, `SELECT detail->>'date_published' FROM event WHERE cve_id = 'CVE-2014-0160'`).Scan(&detailTitle)
	if title != "Heartbleed (newer)" || latest != "Heartbleed (newer)" {
		t.Fatalf("vuln title %q, latest raw %q", title, latest)
	}
	// The renormalize oracle agrees: the stored rows are what the latest raw produces.
	rst, err := pipeline.Renormalize(ctx, d.Conn, newC(t), pipeline.RenormalizeOptions{DryRun: true})
	if err != nil || rst.VulnUpdated+rst.VulnInserted+rst.EventInserted+rst.EventUpdated != 0 {
		t.Fatalf("renormalize: %+v %v", rst, err)
	}
}
