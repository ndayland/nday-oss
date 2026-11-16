// Command sitebench times the website's read queries (internal/site) and
// the derived-state refresh against a database, read-only except for the
// refresh, and prints EXPLAIN (ANALYZE, BUFFERS) summaries of the SQL each
// call ran. Used to check query targets at full data size, e.g.
//
//	NDAY_DATABASE_URL=postgresql://…/nday_fullimport go run ./tools/sitebench -refresh
//
// Each call is run -n times; the reported time is the median of runs 2..n
// (the first run warms caches and prepared statements).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/config"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/state"
)

type captured struct {
	sql  string
	args []any
}

// tracer records every query a call issues.
type tracer struct {
	on  bool
	got []captured
}

func (t *tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if t.on {
		t.got = append(t.got, captured{d.SQL, d.Args})
	}
	return ctx
}
func (t *tracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Batched queries (pgx.Batch) are traced through BatchTracer.
func (t *tracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return ctx
}
func (t *tracer) TraceBatchQuery(_ context.Context, _ *pgx.Conn, d pgx.TraceBatchQueryData) {
	if t.on {
		t.got = append(t.got, captured{d.SQL, d.Args})
	}
}
func (t *tracer) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

func main() {
	n := flag.Int("n", 7, "runs per call")
	refresh := flag.Bool("refresh", false, "also time REFRESH MATERIALIZED VIEW CONCURRENTLY (writes vuln_state_mat)")
	explain := flag.Bool("explain", true, "print EXPLAIN (ANALYZE, BUFFERS) summary lines")
	vulnID := flag.String("vuln", "CVE-2014-0160", "CVE for the detail query")
	flag.Parse()
	ctx := context.Background()
	url, err := config.DatabaseURL()
	if err != nil {
		fail(err)
	}
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		fail(err)
	}
	tr := &tracer{}
	cfg.Tracer = tr
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		fail(err)
	}
	defer conn.Close(ctx)
	store := site.New(site.SingleConn(conn))

	calls := []struct {
		name string
		fn   func() error
	}{
		{"hot 30d patch_released (feed)", func() error {
			_, err := store.Hot(ctx, site.HotParams{Since: 30 * 24 * time.Hour, MinStage: "patch_released", Limit: 50})
			return err
		}},
		{"hot 7d disclosed incl. rejected", func() error {
			_, err := store.Hot(ctx, site.HotParams{Since: 7 * 24 * time.Hour, MinStage: "disclosed", IncludeRejected: true, Limit: 50})
			return err
		}},
		{"hot 366d disclosed offset 5000", func() error {
			_, err := store.Hot(ctx, site.HotParams{Since: 366 * 24 * time.Hour, MinStage: "disclosed", Limit: 50, Offset: 5000})
			return err
		}},
		{"vuln detail " + *vulnID, func() error {
			_, found, err := store.Vuln(ctx, *vulnID)
			if err == nil && !found {
				err = fmt.Errorf("%s not found", *vulnID)
			}
			return err
		}},
		{"search 'openssl'", func() error { _, err := store.Search(ctx, "openssl", 20); return err }},
		{"search 'remote code execution'", func() error { _, err := store.Search(ctx, "remote code execution", 20); return err }},
		{"search 'CVE-2021-44'", func() error { _, err := store.Search(ctx, "CVE-2021-44", 20); return err }},
		{"search 'xz'", func() error { _, err := store.Search(ctx, "xz", 20); return err }},
		{"stats (/api/stats)", func() error { _, err := store.Stats(ctx); return err }},
		{"sources (/api/sources)", func() error { _, err := store.Sources(ctx); return err }},
	}
	var pending []func()
	for _, c := range calls {
		var times []time.Duration
		for i := 0; i < *n; i++ {
			tr.on, tr.got = i == 0, nil
			t0 := time.Now()
			if err := c.fn(); err != nil {
				fail(fmt.Errorf("%s: %w", c.name, err))
			}
			times = append(times, time.Since(t0))
			tr.on = false
			if i == 0 && *explain {
				name, qs := c.name, tr.got
				pending = append(pending, func() { explainAll(ctx, conn, name, qs) })
			}
		}
		fmt.Printf("%-36s median %7.1f ms  (min %.1f, max %.1f, first %.1f; %d runs)\n", c.name,
			ms(median(times[1:])), ms(minD(times[1:])), ms(maxD(times[1:])), ms(times[0]), *n)
	}
	if *refresh {
		for i := 0; i < 2; i++ {
			res, err := state.Refresh(ctx, conn, state.RefreshOptions{Wait: true})
			if err != nil {
				fail(err)
			}
			fmt.Printf("%-36s %7.1f ms  (refreshes=%d)\n", "state refresh (CONCURRENTLY)", ms(res.Elapsed), res.Refreshes)
		}
	}
	fmt.Println()
	for _, f := range pending {
		f()
	}
}

func explainAll(ctx context.Context, conn *pgx.Conn, name string, qs []captured) {
	for i, q := range qs {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q.sql)), "SELECT") &&
			!strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q.sql)), "WITH") {
			continue
		}
		rows, err := conn.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+q.sql, q.args...)
		if err != nil {
			fmt.Printf("## %s q%d: explain failed: %v\n", name, i+1, err)
			continue
		}
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			fmt.Printf("## %s q%d: explain failed: %v\n", name, i+1, err)
			continue
		}
		top := ""
		if len(lines) > 0 {
			top = strings.TrimSpace(lines[0])
		}
		var keep []string
		for _, l := range lines {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "Planning Time") || strings.HasPrefix(t, "Execution Time") ||
				strings.Contains(t, "Seq Scan") || (strings.HasPrefix(t, "Buffers") && len(keep) == 0) {
				keep = append(keep, t)
			}
		}
		fmt.Printf("## %s q%d: %s\n     %s\n", name, i+1, top, strings.Join(keep, "\n     "))
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func median(ds []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func minD(ds []time.Duration) time.Duration {
	m := ds[0]
	for _, d := range ds {
		m = min(m, d)
	}
	return m
}

func maxD(ds []time.Duration) time.Duration {
	m := ds[0]
	for _, d := range ds {
		m = max(m, d)
	}
	return m
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
