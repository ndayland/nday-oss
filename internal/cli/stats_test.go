package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
)

func statsCounts(t *testing.T, d *testutil.TestDB) string {
	t.Helper()
	var parts []string
	for _, tb := range []string{"stats_salt", "stats_files", "stats_daily", "stats_top", "stats_visitors"} {
		var n int
		if err := d.Conn.QueryRow(context.Background(), "SELECT count(*) FROM "+tb).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			parts = append(parts, tb)
		}
	}
	return strings.Join(parts, ",")
}

func TestStatsRollupCommand(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	dir := t.TempDir()
	src := filepath.Join(testutil.RepoRoot(), "internal/stats/testdata/golden")
	for _, n := range []string{"access-2026-11-12.log", "access-2026-11-13.log"} {
		b, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	env := cli.Env{}

	code, out, errOut := runCLI(t, env, "stats-rollup", "--dir", dir, "--dry-run")
	if code != 0 || !strings.Contains(out, "2026-11-13 recomputed files=1 lines=58 bad=5 partial=1") ||
		!strings.Contains(out, "dry run: every transaction rolled back, nothing written") {
		t.Fatalf("dry run: %d\n%s\n%s", code, out, errOut)
	}
	if c := statsCounts(t, d); c != "" {
		t.Fatalf("dry run wrote %s", c)
	}

	t.Setenv("NDAY_LOG_DIR", dir) // --dir defaults to NDAY_LOG_DIR
	code, out, errOut = runCLI(t, env, "stats-rollup")
	if code != 0 || !strings.Contains(out, "2026-11-12 recomputed files=2 lines=3 bad=0 partial=0 misfiled_in=2 misfiled_out=0 requests=5 pv=4 uv=3\n") ||
		!strings.Contains(out, "days: 3, visitor rows pruned: 0\n") {
		t.Fatalf("rollup: %d\n%s\n%s", code, out, errOut)
	}
	if c := statsCounts(t, d); c != "stats_salt,stats_files,stats_daily,stats_top,stats_visitors" {
		t.Errorf("tables with rows: %s", c)
	}
	code, out, _ = runCLI(t, env, "stats-rollup")
	if code != 0 || out != "days: 0, visitor rows pruned: 0\n" {
		t.Errorf("unchanged: %d %q", code, out)
	}
	code, out, _ = runCLI(t, env, "stats-rollup", "--day", "2026-11-13", "--day=2026-11-12")
	if code != 0 || !strings.HasPrefix(out, "2026-11-12 recomputed") {
		t.Errorf("--day: %d %q", code, out)
	}

	for _, args := range [][]string{
		{"stats-rollup", "--day", "2026-13-01"},
		{"stats-rollup", "--day"},
		{"stats-rollup", "--all", "--day", "2026-11-13"},
		{"stats-rollup", "--all=1"},
		{"stats-rollup", "--bogus"},
		{"stats-rollup", "extra"},
	} {
		if code, _, errOut := runCLI(t, env, args...); code != 2 || !strings.Contains(errOut, "nday stats-rollup: error:") {
			t.Errorf("%v: exit %d %q", args, code, errOut)
		}
	}
	t.Setenv("NDAY_LOG_DIR", "")
	if code, _, errOut := runCLI(t, env, "stats-rollup"); code != 2 || !strings.Contains(errOut, "NDAY_LOG_DIR") {
		t.Errorf("no dir: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, env, "stats-rollup", "--dir", filepath.Join(dir, "missing")); code != 1 || !strings.Contains(errOut, "log directory") {
		t.Errorf("missing dir: %d %q", code, errOut)
	}
}
