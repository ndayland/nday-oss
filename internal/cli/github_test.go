package cli_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/testutil"
)

// github-enqueue queues the repository links of stored posts (idempotent);
// github-fetch with nothing due makes no request; bad arguments are usage
// errors. No network.
func TestGitHubCommands(t *testing.T) {
	d := testutil.NewDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	ft := &testutil.FakeTransport{Handler: func(r *http.Request) (int, http.Header, []byte, error) {
		t.Errorf("unexpected request %s", r.URL)
		return 500, nil, nil, nil
	}}
	env := cli.Env{Transport: ft}
	if code, _, errs := runCLI(t, env, "migrate"); code != 0 {
		t.Fatal(errs)
	}
	ctx := context.Background()
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status) VALUES
        ('2000000000000000001', 0, 'https://t.co/a', 'https://github.com/o/r', 'https://github.com/o/r', 'github.com', 'code', 'api', 'ok'),
        ('2000000000000000001', 1, 'https://t.co/b', 'https://github.com/o/r/commit/1', 'https://github.com/o/r/commit/1', 'github.com', 'patch', 'api', 'ok')`); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCLI(t, env, "github-enqueue")
	if code != 0 || compactJSON(out) != `{"candidates":1,"added":1,"not_repo":0,"post_cves":0,"revived":0}` {
		t.Errorf("github-enqueue: %d %s %s", code, out, errs)
	}
	if code, out, _ = runCLI(t, env, "github-enqueue"); code != 0 || compactJSON(out) != `{"candidates":0,"added":0,"not_repo":0,"post_cves":0,"revived":0}` {
		t.Errorf("github-enqueue again: %d %s", code, out)
	}
	// nothing due (the queued row made its attempts, and so did the check of
	// the root link to it): no request
	if _, err := d.Conn.Exec(ctx, `UPDATE github_repo SET attempts = 3`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE x_post_link SET repo_check_attempts = 3 WHERE repo_root_key IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runCLI(t, env, "github-fetch", "--limit", "5")
	if code != 0 || !strings.Contains(compactJSON(out), `"candidates":0`) || !strings.Contains(compactJSON(out), `"requests":0`) {
		t.Errorf("github-fetch: %d %s %s", code, out, errs)
	}
	if got := jobRun(t, d, "github-fetch"); !strings.HasPrefix(got, `true  {`) || !strings.Contains(got, `"candidates": 0`) {
		t.Errorf("github-fetch job_run: %s", got)
	}
	for _, args := range [][]string{{"github-fetch", "--limit", "0"}, {"github-fetch", "x"}, {"github-enqueue", "extra"},
		{"github-discover", "--max-requests", "0"}, {"github-discover", "--max-requests", "101"}, {"github-discover", "x"},
		{"github-discover", "--limit", "5"}} {
		if code, _, errs := runCLI(t, env, args...); code != 2 || !strings.Contains(errs, "error") {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	// github-discover while another run holds the lock: nothing done, no request
	if _, err := d.Conn.Exec(ctx, `SELECT pg_advisory_lock($1, hashtext(current_schema()))`, ghrepo.DiscoverLockID); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runCLI(t, env, "github-discover", "--max-requests", "3")
	if code != 0 || !strings.Contains(compactJSON(out), `"locked":true`) || !strings.Contains(compactJSON(out), `"requests":0`) {
		t.Errorf("github-discover locked: %d %s %s", code, out, errs)
	}
	// both steps of the run left their record (a locked run is still ok)
	if got := jobRun(t, d, "github-discover"); !strings.HasPrefix(got, `true  {`) || !strings.Contains(got, `"locked": true`) ||
		!strings.Contains(got, `"skipped_forks": 0`) {
		t.Errorf("github-discover job_run: %s", got)
	}
	if got := jobRun(t, d, "github-poc"); !strings.HasPrefix(got, `true  {`) || !strings.Contains(got, `"dry_run": false`) {
		t.Errorf("github-poc job_run: %s", got)
	}
	if _, err := d.Conn.Exec(ctx, `SELECT pg_advisory_unlock($1, hashtext(current_schema()))`, ghrepo.DiscoverLockID); err != nil {
		t.Fatal(err)
	}
}

// jobRun is the job_run row of name as "ok error detail" ("" when none).
func jobRun(t *testing.T, d *testutil.TestDB, name string) string {
	t.Helper()
	var got string
	err := d.Conn.QueryRow(context.Background(), `SELECT concat_ws(' ', ok::text, coalesce(error, ''), coalesce(detail::text, ''))
		FROM job_run WHERE name = $1`, name).Scan(&got)
	if err != nil {
		return err.Error()
	}
	return got
}
