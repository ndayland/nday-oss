package jobrun_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"nday.land/nday/internal/jobrun"
	"nday.land/nday/internal/testutil"
)

func TestCleanError(t *testing.T) {
	for in, want := range map[string]string{
		`Get "https://user:secret@api.example.com/repos/a/b?access_token=tok#x": EOF`: `Get "https://api.example.com/repos/a/b": EOF`,
		"fetch http://h.example?q=1 failed":                                           "fetch http://h.example failed",
		"fetch https://h.example/?q=1 failed":                                         "fetch https://h.example/ failed",
		"line\none\x1b[31m":                                                           "line one [31m",
		"  plain  ":                                                                   "plain",
	} {
		if got := jobrun.CleanError(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	long := jobrun.CleanError(strings.Repeat("é", 2000))
	if n := utf8.RuneCountInString(long); n != jobrun.MaxError || !strings.HasSuffix(long, "…") {
		t.Errorf("long: %d runes", n)
	}
}

type row struct {
	started, finished, success *time.Time
	ok                         *bool
	err, detail                *string
}

func read(t *testing.T, d *testutil.TestDB, name string) row {
	t.Helper()
	var r row
	if err := d.Conn.QueryRow(context.Background(), `SELECT started_at, finished_at, ok, error, last_success_at, detail::text
		FROM job_run WHERE name = $1`, name).Scan(&r.started, &r.finished, &r.ok, &r.err, &r.success, &r.detail); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestStartFinish: a run's record, the last success kept across a failed
// run, the counters, the sanitised error.
func TestStartFinish(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	now := t0
	clock := func() time.Time { return now }

	r := jobrun.Start(ctx, d.Conn, jobrun.GitHubFetch, clock)
	got := read(t, d, jobrun.GitHubFetch)
	if !got.started.Equal(t0) || got.finished != nil || got.ok != nil || got.success != nil {
		t.Fatalf("started: %+v", got)
	}
	now = t0.Add(time.Minute)
	r.Finish(ctx, nil, struct {
		OK      int  `json:"ok"`
		Limited bool `json:"rate_limited"`
	}{3, true})
	got = read(t, d, jobrun.GitHubFetch)
	if !*got.ok || !got.finished.Equal(now) || !got.success.Equal(now) || got.err != nil || *got.detail != `{"ok": 3, "rate_limited": true}` {
		t.Fatalf("finished ok: %+v %s", got, *got.detail)
	}

	// a failed run: last_success_at stays, the error is cleaned
	now = t0.Add(time.Hour)
	r = jobrun.Start(ctx, d.Conn, jobrun.GitHubFetch, clock)
	if got = read(t, d, jobrun.GitHubFetch); got.finished != nil || got.detail != nil || !got.success.Equal(t0.Add(time.Minute)) {
		t.Fatalf("restarted: %+v", got)
	}
	now = now.Add(time.Minute)
	r.Finish(ctx, errors.New(`Get "https://x:tok@api.github.com/repos/a/b?t=1": timeout`), nil)
	got = read(t, d, jobrun.GitHubFetch)
	if *got.ok || *got.err != `Get "https://api.github.com/repos/a/b": timeout` || !got.success.Equal(t0.Add(time.Minute)) || got.detail != nil {
		t.Fatalf("failed: %+v", got)
	}

	// Finish without a Start row (the start write was lost) still records
	r = jobrun.Start(ctx, d.Conn, jobrun.SiteIcons, clock)
	if _, err := d.Conn.Exec(ctx, `DELETE FROM job_run WHERE name = $1`, jobrun.SiteIcons); err != nil {
		t.Fatal(err)
	}
	r.Finish(ctx, nil, nil)
	if got = read(t, d, jobrun.SiteIcons); !*got.ok || !got.success.Equal(now) || !got.started.Equal(now) {
		t.Fatalf("finish only: %+v", got)
	}
	(&jobrun.Run{}).Finish(ctx, nil, nil) // a zero Run must not panic either
	var nilRun *jobrun.Run
	nilRun.Finish(ctx, nil, nil)
}

// TestNoTable: without migration 0035 the helper logs and carries on.
func TestNoTable(t *testing.T) {
	d := testutil.NewDB(t)
	ctx := context.Background()
	r := jobrun.Start(ctx, d.Conn, jobrun.SiteIcons, nil)
	r.Finish(ctx, errors.New("x"), nil)
	// the connection is still usable (no aborted transaction left behind)
	var one int
	if err := d.Conn.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatal(one, err)
	}
}
