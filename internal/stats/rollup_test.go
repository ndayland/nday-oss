package stats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/testutil"
)

var sgt = time.FixedZone("SGT", 8*3600)

// fixedSalt makes visitor hashes reproducible in tests.
var fixedSalt = bytes.Repeat([]byte{0x5a}, 32)

func newDB(t *testing.T) *testutil.TestDB {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	if _, err := d.Conn.Exec(context.Background(), "INSERT INTO stats_salt (salt) VALUES ($1)", fixedSalt); err != nil {
		t.Fatal(err)
	}
	return d
}

// copyDir copies the golden logs to a temp dir with fixed mtimes.
func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	mt := time.Date(2026, 11, 13, 23, 0, 0, 123456789, time.UTC)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dst, e.Name())
		if err := os.WriteFile(p, b, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func opts(dir string) Options {
	return Options{Dir: dir, Now: func() time.Time { return time.Date(2026, 11, 13, 23, 30, 0, 0, sgt) },
		Location: sgt, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
}

func runRollup(t *testing.T, conn *pgx.Conn, o Options) *Result {
	t.Helper()
	res, err := Rollup(context.Background(), conn, o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// dump renders every stats table (except volatile timestamps) as text.
func dump(t *testing.T, conn *pgx.Conn) string {
	t.Helper()
	ctx := context.Background()
	var b strings.Builder
	q := func(sql string, f func(pgx.CollectableRow) (string, error)) {
		rows, err := conn.Query(ctx, sql)
		if err != nil {
			t.Fatal(err)
		}
		lines, err := pgx.CollectRows(rows, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
	}
	q(`SELECT file, day::text, size, lines, bad_lines, other_days::text FROM stats_files ORDER BY file`, func(r pgx.CollectableRow) (string, error) {
		var f, d, o string
		var s, l, bad int64
		err := r.Scan(&f, &d, &s, &l, &bad, &o)
		return fmt.Sprintf("file %s day=%s size=%d lines=%d bad=%d other_days=%s", f, d, s, l, bad, o), err
	})
	q(`SELECT day::text, metric, dim, value FROM stats_daily ORDER BY 1, 2, 3`, func(r pgx.CollectableRow) (string, error) {
		var d, m, dim string
		var v int64
		err := r.Scan(&d, &m, &dim, &v)
		return fmt.Sprintf("daily %s %s %s %d", d, m, dim, v), err
	})
	q(`SELECT day::text, kind, key, value FROM stats_top ORDER BY 1, 2, 4 DESC, 3`, func(r pgx.CollectableRow) (string, error) {
		var d, k, key string
		var v int64
		err := r.Scan(&d, &k, &key, &v)
		return fmt.Sprintf("top %s %s %q %d", d, k, key, v), err
	})
	q(`SELECT day::text, count(*), count(*) FILTER (WHERE human) FROM stats_visitors GROUP BY 1 ORDER BY 1`, func(r pgx.CollectableRow) (string, error) {
		var d string
		var n, h int64
		err := r.Scan(&d, &n, &h)
		return fmt.Sprintf("visitors %s rows=%d human=%d", d, n, h), err
	})
	return b.String()
}

func TestRollupGolden(t *testing.T) {
	d := newDB(t)
	dir := copyDir(t, "testdata/golden")
	res := runRollup(t, d.Conn, opts(dir))
	got := dump(t, d.Conn)
	golden := "testdata/golden_rows.txt"
	if os.Getenv("NDAY_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("rows differ from %s (NDAY_UPDATE_GOLDEN=1 rewrites it):\n%s", golden, got)
	}
	// day 12 first (own file), then 13; 13's misfiled lines link 12 again.
	var days []string
	for _, dr := range res.Days {
		days = append(days, dr.Day+":"+dr.Status)
	}
	if strings.Join(days, ",") != "2026-11-12:recomputed,2026-11-13:recomputed,2026-11-12:recomputed" {
		t.Errorf("days %v", days)
	}
	// privacy: the single-visitor term never appears; raw IPs and UAs never stored
	for _, bad := range []string{"secretterm", "203.0.113.10", "Safari", "q=secret", "item?id", "/search"} {
		if strings.Contains(got, bad) {
			t.Errorf("rows contain %q", bad)
		}
	}
}

// Rolling up twice gives the same rows; appending to one day's file
// recomputes that day only.
func TestRollupIdempotentAndAppend(t *testing.T) {
	d := newDB(t)
	dir := t.TempDir()
	writeLines(t, dir, "2026-11-12", 0, 5)
	writeLines(t, dir, "2026-11-13", 0, 7)
	o := opts(dir)
	runRollup(t, d.Conn, o)
	first := dump(t, d.Conn)
	if res := runRollup(t, d.Conn, o); len(res.Days) != 0 {
		t.Errorf("second run recomputed %+v", res.Days)
	}
	o2 := o
	o2.All = true
	runRollup(t, d.Conn, o2)
	if again := dump(t, d.Conn); again != first {
		t.Errorf("--all changed rows:\n%s\nvs\n%s", again, first)
	}
	o3 := o
	o3.Days = []string{"2026-11-13", "2026-11-12"}
	runRollup(t, d.Conn, o3)
	if again := dump(t, d.Conn); again != first {
		t.Error("--day changed rows")
	}

	day12 := rowsOfDay(first, "2026-11-12")
	writeLines(t, dir, "2026-11-13", 7, 3) // append 3 lines
	res := runRollup(t, d.Conn, o)
	if len(res.Days) != 1 || res.Days[0].Day != "2026-11-13" || res.Days[0].Requests != 10 {
		t.Fatalf("after append: %+v", res.Days)
	}
	after := dump(t, d.Conn)
	if rowsOfDay(after, "2026-11-12") != day12 {
		t.Error("day 12 changed")
	}
	if !strings.Contains(after, "daily 2026-11-13 req all 10\n") || !strings.Contains(after, "lines=10 ") {
		t.Errorf("day 13 not updated:\n%s", after)
	}
}

func rowsOfDay(dump, day string) string {
	var out []string
	for _, l := range strings.Split(dump, "\n") {
		if strings.Contains(l, " "+day+" ") || strings.Contains(l, "day="+day) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// writeLines appends n page-view lines (distinct visitors) to day's file.
func writeLines(t *testing.T, dir, day string, from, n int) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "access-"+day+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := from; i < from+n; i++ {
		b, _ := json.Marshal(map[string]any{"time": fmt.Sprintf("%sT10:00:%02d.000+08:00", day, i%60),
			"client_ip": fmt.Sprintf("203.0.113.%d", i), "domain": "www.nday.land", "method": "GET",
			"uri": "/vuln/CVE-2024-3094", "status": 200, "request_time": 0.01 * float64(i+1), "bytes_sent": 100,
			"user_agent": "Mozilla/5.0 Firefox/132.0", "country": "SG"})
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	// a distinct mtime even on coarse file systems
	mt := time.Date(2026, 11, 13, 12, 0, from, 0, time.UTC)
	if err := os.Chtimes(f.Name(), mt, mt); err != nil {
		t.Fatal(err)
	}
}

func tableCounts(t *testing.T, conn *pgx.Conn) string {
	t.Helper()
	var parts []string
	for _, tb := range []string{"stats_salt", "stats_files", "stats_daily", "stats_top", "stats_visitors"} {
		var n int
		if err := conn.QueryRow(context.Background(), "SELECT count(*) FROM "+tb).Scan(&n); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, fmt.Sprintf("%s=%d", tb, n))
	}
	return strings.Join(parts, " ")
}

func TestRollupDryRunWritesNothing(t *testing.T) {
	d := testutil.NewMigratedDB(t) // no salt yet: a dry run must not create one either
	dir := copyDir(t, "testdata/golden")
	before := tableCounts(t, d.Conn)
	o := opts(dir)
	o.DryRun = true
	res := runRollup(t, d.Conn, o)
	if !res.DryRun || len(res.Days) < 2 || res.Days[0].Requests == 0 {
		t.Errorf("dry run result %+v", res)
	}
	if after := tableCounts(t, d.Conn); after != before {
		t.Errorf("dry run wrote: %s -> %s", before, after)
	}
	// with existing rows, a dry run of a changed file leaves them alone too
	runRollup(t, d.Conn, opts(dir))
	full := dump(t, d.Conn)
	writeLines(t, dir, "2026-11-13", 100, 4)
	runRollup(t, d.Conn, o)
	if dump(t, d.Conn) != full {
		t.Error("dry run changed rows")
	}
}

// stats_visitors rows older than the retention are pruned (and never
// written for old days); the unique counts in stats_daily stay.
func TestVisitorPruning(t *testing.T) {
	d := newDB(t)
	dir := t.TempDir()
	writeLines(t, dir, "2026-08-01", 0, 3)
	o := opts(dir)
	o.Now = func() time.Time { return time.Date(2026, 8, 2, 9, 0, 0, 0, sgt) }
	runRollup(t, d.Conn, o)
	if got := dump(t, d.Conn); !strings.Contains(got, "visitors 2026-08-01 rows=3 human=3") {
		t.Fatalf("visitor rows not written:\n%s", got)
	}
	// 2026-10-30: cutoff 2026-08-01 is still kept (older than 90 days = before today-90)
	o.Now = func() time.Time { return time.Date(2026, 10, 30, 9, 0, 0, 0, sgt) }
	if res := runRollup(t, d.Conn, o); res.PrunedVisitors != 0 {
		t.Errorf("pruned %d on day 90", res.PrunedVisitors)
	}
	o.Now = func() time.Time { return time.Date(2026, 10, 31, 0, 30, 0, 0, sgt) }
	res := runRollup(t, d.Conn, o)
	if res.PrunedVisitors != 3 {
		t.Errorf("pruned %d, want 3", res.PrunedVisitors)
	}
	got := dump(t, d.Conn)
	if strings.Contains(got, "visitors 2026-08-01") || !strings.Contains(got, "daily 2026-08-01 uv all 3") {
		t.Errorf("after pruning:\n%s", got)
	}
	// recomputing an old day does not write visitor rows again
	o.All = true
	runRollup(t, d.Conn, o)
	if got := dump(t, d.Conn); strings.Contains(got, "visitors 2026-08-01") || !strings.Contains(got, "daily 2026-08-01 uv all 3") {
		t.Errorf("after recompute of an old day:\n%s", got)
	}
}

type fileState struct {
	size  int64
	mtime time.Time
	mode  fs.FileMode
}

func snapshot(t *testing.T, root string) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		out[p] = fileState{info.Size(), info.ModTime(), info.Mode()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLogDirectoryNeverModified(t *testing.T) {
	d := newDB(t)
	dir := copyDir(t, "testdata/golden")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "error-2026-11-13.log"), []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range []string{dir, filepath.Join(dir, "sub")} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshot(t, dir)
	for _, mut := range []func(*Options){func(*Options) {}, func(o *Options) { o.All = true },
		func(o *Options) { o.DryRun = true; o.All = true }, func(o *Options) { o.Days = []string{"2026-11-11"} }} {
		o := opts(dir)
		mut(&o)
		runRollup(t, d.Conn, o)
	}
	after := snapshot(t, dir)
	if len(before) != len(after) {
		t.Fatalf("entries %d -> %d", len(before), len(after))
	}
	for p, s := range before {
		if a, ok := after[p]; !ok || a.size != s.size || !a.mtime.Equal(s.mtime) || a.mode != s.mode {
			t.Errorf("%s: %+v -> %+v", p, s, a)
		}
	}
}

// A day whose log file is gone keeps its rows; a file listed as holding
// misfiled lines that vanished is skipped with a warning.
func TestMissingFiles(t *testing.T) {
	d := newDB(t)
	dir := copyDir(t, "testdata/golden")
	runRollup(t, d.Conn, opts(dir))
	full := dump(t, d.Conn)
	if err := os.Remove(filepath.Join(dir, "access-2026-11-13.log")); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	o := opts(dir)
	o.Log = slog.New(slog.NewTextHandler(&logBuf, nil))
	o.Days = []string{"2026-11-13"}
	res := runRollup(t, d.Conn, o)
	if len(res.Days) != 1 || res.Days[0].Status != "no-file" {
		t.Errorf("result %+v", res.Days)
	}
	if dump(t, d.Conn) != full {
		t.Error("rows of a day without its file changed")
	}
	// day 12 is recomputed from its own file; the vanished day-13 file
	// (recorded as holding day-12 lines) is skipped with a warning.
	o.Days = []string{"2026-11-12"}
	res = runRollup(t, d.Conn, o)
	if len(res.Days) != 1 || res.Days[0].Status != "recomputed" || res.Days[0].MisfiledIn != 0 {
		t.Errorf("result %+v", res.Days)
	}
	if !strings.Contains(logBuf.String(), "vanished") {
		t.Errorf("no warning: %s", logBuf.String())
	}

	// Own file gone while another file still holds misfiled lines of the
	// day: the misfiled lines alone must not replace the day's rows.
	d2 := newDB(t)
	dir2 := copyDir(t, "testdata/golden")
	runRollup(t, d2.Conn, opts(dir2))
	full2 := dump(t, d2.Conn)
	if err := os.Remove(filepath.Join(dir2, "access-2026-11-12.log")); err != nil {
		t.Fatal(err)
	}
	o = opts(dir2)
	o.Days = []string{"2026-11-12"}
	if res := runRollup(t, d2.Conn, o); len(res.Days) != 1 || res.Days[0].Status != "no-file" {
		t.Errorf("result %+v", res.Days)
	}
	writeLines(t, dir2, "2026-11-13", 200, 1) // day 13 changes and links day 12
	o.Days = nil
	res = runRollup(t, d2.Conn, o)
	if len(res.Days) != 2 || res.Days[0].Day != "2026-11-13" || res.Days[1].Status != "no-file" {
		t.Errorf("result %+v", res.Days)
	}
	if got := dump(t, d2.Conn); rowsOfDay(got, "2026-11-12") != rowsOfDay(full2, "2026-11-12") {
		t.Error("rows of day 12 replaced by misfiled lines only")
	}
}

// Two rollups at once must not double count (advisory lock).
func TestConcurrentRollups(t *testing.T) {
	d := newDB(t)
	dir := copyDir(t, "testdata/golden")
	ctx := context.Background()
	want := func() string {
		ref := newDB(t)
		runRollup(t, ref.Conn, opts(dir))
		return dump(t, ref.Conn)
	}()
	for round, mut := range []func(*Options){func(*Options) {}, func(o *Options) { o.All = true }} {
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			conn, err := testutil.Connect(ctx, d.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close(ctx)
			wg.Add(1)
			go func(i int, conn *pgx.Conn) {
				defer wg.Done()
				o := opts(dir)
				mut(&o)
				_, errs[i] = Rollup(ctx, conn, o)
			}(i, conn)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("round %d rollup %d: %v", round, i, err)
			}
		}
		if got := dump(t, d.Conn); got != want {
			t.Errorf("round %d: concurrent rows differ:\n%s", round, got)
		}
	}
}

func TestRollupBadOptions(t *testing.T) {
	d := newDB(t)
	o := opts(filepath.Join(t.TempDir(), "missing"))
	if _, err := Rollup(context.Background(), d.Conn, o); err == nil {
		t.Error("missing dir accepted")
	}
	o = opts(t.TempDir())
	o.Days = []string{"2026-02-30"}
	if _, err := Rollup(context.Background(), d.Conn, o); err == nil {
		t.Error("bad day accepted")
	}
}

// TestThroughput measures a recompute of a generated 500k-line day
// (NDAY_STATS_BENCH=1; numbers quoted in docs/stats.md).
func TestThroughput(t *testing.T) {
	if os.Getenv("NDAY_STATS_BENCH") != "1" {
		t.Skip("set NDAY_STATS_BENCH=1")
	}
	const n = 500_000
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "access-2026-11-13.log"))
	if err != nil {
		t.Fatal(err)
	}
	uas := []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "curl/8.7.1"}
	uris := []string{"/", "/vuln/CVE-2024-%d", "/vuln?q=term%d", "/static/app.css", "/zh-hans/stats", "/nope%d"}
	var size int64
	for i := 0; i < n; i++ {
		uri := uris[i%len(uris)]
		if strings.Contains(uri, "%d") {
			uri = fmt.Sprintf(uri, 1000+i%5000)
		}
		domain := "www.nday.land"
		if i%7 == 0 {
			domain, uri = "api.nday.land", fmt.Sprintf("/v1/vuln/CVE-2025-%d", 1000+i%3000)
		}
		status := 200
		if strings.HasPrefix(uri, "/nope") {
			status = 404
		}
		b, _ := json.Marshal(map[string]any{"time": fmt.Sprintf("2026-11-13T%02d:%02d:%02d.000+08:00", i/20000%24, i/60%60, i%60),
			"client_ip": fmt.Sprintf("10.%d.%d.%d", i%7, i%251, i%13), "remote_addr": "172.68.0.1", "domain": domain,
			"host": domain, "method": "GET", "uri": uri, "status": status, "referer": "https://news.ycombinator.com/item?id=1",
			"http_x_forwarded_for": "", "server_port": 443, "request_length": 420, "request_time": float64(i%300) / 1000,
			"ssl_protocol": "TLSv1.3", "ssl_cipher": "TLS_AES_128_GCM_SHA256", "bytes_sent": 5000, "proto": "HTTP/2.0",
			"user_agent": uas[i%len(uas)], "cf_ray": "8e0000000000-SIN", "country": "SG"})
		k, _ := f.Write(append(b, '\n'))
		size += int64(k)
	}
	f.Close()

	in, err := os.Open(filepath.Join(dir, "access-2026-11-13.log"))
	if err != nil {
		t.Fatal(err)
	}
	agg := newDayAgg("2026-11-13", fixedSalt, func(string) bool { return false })
	start := time.Now()
	res, err := scanLines(in, func(l Line) { agg.add(&l) })
	in.Close()
	if err != nil || res.Lines != n {
		t.Fatal(err, res)
	}
	agg.rows(res, 0)
	parse := time.Since(start)

	d := newDB(t)
	start = time.Now()
	r := runRollup(t, d.Conn, opts(dir))
	full := time.Since(start)
	t.Logf("file %d lines, %.1f MB; parse+aggregate %v (%.0f lines/s); full rollup incl. DB %v (%.0f lines/s); uv=%d",
		n, float64(size)/1e6, parse.Round(time.Millisecond), n/parse.Seconds(), full.Round(time.Millisecond), n/full.Seconds(),
		r.Days[0].Visitors)
}
