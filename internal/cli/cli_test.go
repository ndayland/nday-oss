package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
)

// These tests set NDAY_DATABASE_URL with t.Setenv, so they do not run in
// parallel with each other (other packages still run concurrently).

func runCLI(t *testing.T, env cli.Env, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	env.Stdout, env.Stderr = &out, &errb
	code := cli.Main(context.Background(), args, env)
	return code, out.String(), errb.String()
}

func kevEnv(t *testing.T, now time.Time) cli.Env {
	body := testutil.ReadFile(t, "tests/fixtures/kev_sample.json")
	return cli.Env{Now: func() time.Time { return now }, Transport: testutil.Serve(body)}
}

func TestMigrateCollectStatusHot(t *testing.T) {
	d := testutil.NewDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	now := time.Now().UTC()
	env := kevEnv(t, now)

	if code, out, _ := runCLI(t, env, "migrate"); code != 0 || out != "applied: 0001_init, 0002_vuln_state, 0003_vuln_state_mat, 0004_auth, 0005_discuss, 0006_stats, 0007_admin, 0008_xposts, 0009_classify, 0010_follows, 0011_tags, 0012_xdrafts, 0013_affected_tags, 0014_settings, 0015_xposts_no_cve, 0016_comment_purpose, 0017_corrections, 0018_correction_audit_details, 0019_xposts_links_candidates, 0020_web_page, 0021_catalogue_indexes, 0022_suspended_identities, 0023_github_repo, 0024_api_tokens, 0025_github_discovery, 0026_vuln_id_ghsa, 0027_ghsa_vuln_classify, 0028_site_icon, 0029_web_page_published, 0030_x_account_profile, 0031_vuln_title, 0032_github_poc, 0033_github_poc_gap, 0034_xdraft_form, 0035_job_run, 0036_github_trusted_owner\n" {
		t.Fatalf("migrate: %d %q", code, out)
	}
	if code, out, _ := runCLI(t, env, "migrate"); code != 0 || out != "applied: (none, up to date)\n" {
		t.Fatalf("migrate again: %d %q", code, out)
	}
	code, out, _ := runCLI(t, env, "collect", "kev")
	want := `{
  "source": "kev",
  "is_backfill": true,
  "fetched": 5,
  "raw_unchanged": 0,
  "raw_new": 5,
  "normalize_errors": 0,
  "vuln_inserted": 5,
  "vuln_updated": 0,
  "alias_inserted": 0,
  "affected_inserted": 5,
  "event_inserted": 5,
  "event_updated": 0
}
`
	if code != 0 || out != want {
		t.Fatalf("collect: %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, env, "-v", "collect", "kev", "--renorm")
	if code != 0 || !strings.Contains(out, `"raw_unchanged": 5,`) || !strings.Contains(out, `"event_inserted": 0,`) {
		t.Fatalf("collect again: %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, env, "renormalize", "kev", "--dry-run")
	if code != 0 || !strings.Contains(out, `"event_updated": 0`) || !strings.Contains(out, `"fetched": 5,`) {
		t.Fatalf("renormalize: %d\n%s", code, out)
	}

	code, out, _ = runCLI(t, env, "status")
	ts := now.Truncate(time.Microsecond).Format("2006-01-02 15:04:05.000000") + "+00:00"
	ts = strings.Replace(ts, ".000000+", "+", 1)
	for _, line := range []string{
		"table counts:\n  raw_record       5\n  vuln             5\n  vuln_alias       0\n  affected         5\n  event            5\n  collector_state  1\n",
		"events by type / is_backfill:\n  kev_added            backfill=True  5\n",
		"collector_state:\n  kev: status=ok last_run_at=" + ts + " last_success_at=" + ts + "\n",
		`    cursor={"count": 5, "dateReleased": "2026-11-10T19:03:29.8375Z", "catalogVersion": "2026.11.10"}` + "\n",
		"stage counts:\n  kev_added            5\n",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("status missing %q in:\n%s", line, out)
		}
	}
	// Fixture dateAdded values are days in 2021/2026; a 3650-day window shows them.
	code, out, _ = runCLI(t, env, "hot", "--since", "3650d", "--limit=2", "--min-stage", "kev_added")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if code != 0 || len(lines) != 2 || !strings.HasPrefix(lines[1], "CVE-2026-102895  kev_added          kev_added          2026-11-09 00:00 ---XK- ") {
		t.Fatalf("hot: %d\n%s", code, out)
	}
	if code, out, _ := runCLI(t, env, "hot", "--since", "1h"); code != 0 || out != "(none)\n" {
		t.Fatalf("hot none: %d %q", code, out)
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	env := cli.Env{}
	for _, args := range [][]string{
		{}, {"bogus"}, {"collect"}, {"collect", "nope"}, {"hot", "--since", "5m"},
		{"hot", "--limit", "x"}, {"hot", "--min-stage", "zzz"}, {"migrate", "extra"}, {"collect", "kev", "--dry-run"},
		{"hot", "--since"}, {"status", "--x"},
	} {
		code, _, _ := runCLI(t, env, args...)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	// --in is an unambiguous prefix of --include-rejected, --s of --since (argparse allow_abbrev).
	if code, _, _ := runCLI(t, env, "hot", "--in", "--s", "x"); code != 2 {
		t.Errorf("bad --since value must be a usage error")
	}
}

func TestMissingDatabaseURLExit1(t *testing.T) {
	t.Setenv("NDAY_DATABASE_URL", "")
	t.Chdir(t.TempDir()) // no .env here
	code, _, errOut := runCLI(t, cli.Env{}, "status")
	if code != 1 || !strings.Contains(errOut, "NDAY_DATABASE_URL is not set") {
		t.Fatalf("%d %q", code, errOut)
	}
}

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Duration{"24h": 24 * time.Hour, " 7d ": 7 * 24 * time.Hour, "0h": 0} {
		if got, err := cli.ParseSince(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"7", "d", "1.5h", "-1h", "1w", "24H"} {
		if _, err := cli.ParseSince(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
