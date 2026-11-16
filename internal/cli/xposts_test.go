package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xlookup/xfake"
)

func TestXCommands(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	file := filepath.Join(t.TempDir(), "accounts.txt")
	write := func(s string) {
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("# test list\n1001 alice_sec  # Alice\n20 @bob\n")
	code, out, errOut := runCLI(t, cli.Env{}, "x-accounts-import", file)
	if code != 0 || out != "inserted 1001 @alice_sec\ninserted 20 @bob\nx-accounts-import: inserted=2 updated=0 unchanged=0\n" {
		t.Fatalf("import: %d %q %q", code, out, errOut)
	}
	if code, out, errOut = runCLI(t, cli.Env{}, "x-accounts-disable", "20"); code != 0 || out != "x-accounts-disable: 20\n" {
		t.Fatalf("disable: %d %q %q", code, out, errOut)
	}
	write("1001 alice_new\n20 bob\n")
	if code, out, errOut = runCLI(t, cli.Env{}, "x-accounts-import", file); code != 0 ||
		out != "updated 1001 @alice_new\nx-accounts-import: inserted=0 updated=1 unchanged=1\n" {
		t.Fatalf("re-import: %d %q %q", code, out, errOut)
	}
	if code, out, errOut = runCLI(t, cli.Env{}, "x-accounts-list"); code != 0 ||
		out != "20 @bob disabled\n1001 @alice_new enabled  # Alice\nx-accounts: 2 total, 1 enabled\n" {
		t.Fatalf("list: %d %q %q", code, out, errOut)
	}
	if code, _, errOut = runCLI(t, cli.Env{}, "x-accounts-enable", "999"); code != 1 || !strings.Contains(errOut, "no X account with user id 999") {
		t.Fatalf("enable missing: %d %q", code, errOut)
	}
	write("1001 alice\nbad line here\n")
	if code, _, errOut = runCLI(t, cli.Env{}, "x-accounts-import", file); code != 1 || !strings.Contains(errOut, "line 2:") {
		t.Fatalf("bad file: %d %q", code, errOut)
	}

	want := "enabled=on (default)\nmax_posts=500 (default, 10..5000)\nmax_requests=20 (default, 1..100)\n" +
		"bootstrap_days=7 (default, 1..7)\nmax_query_length=512 (default, 64..4096)\n"
	if code, out, errOut = runCLI(t, cli.Env{}, "x-settings"); code != 0 || out != want {
		t.Fatalf("settings: %d %q %q", code, out, errOut)
	}
	if code, out, errOut = runCLI(t, cli.Env{}, "x-settings", "--enabled", "off", "--max-posts", "100", "--bootstrap-days=3"); code != 0 ||
		out != "enabled=off (stored)\nmax_posts=100 (stored, 10..5000)\nmax_requests=20 (default, 1..100)\n"+
			"bootstrap_days=3 (stored, 1..7)\nmax_query_length=512 (default, 64..4096)\n" {
		t.Fatalf("set: %d %q %q", code, out, errOut)
	}
	if code, out, errOut = runCLI(t, cli.Env{}, "x-settings", "--max-posts", "default", "--enabled", "default", "--bootstrap-days", "default"); code != 0 || out != want {
		t.Fatalf("reset: %d %q %q", code, out, errOut)
	}
	for _, bad := range [][]string{{"--max-posts", "9"}, {"--max-requests", "101"}, {"--bootstrap-days", "8"},
		{"--max-query-length", "x"}, {"--enabled", "maybe"}} {
		if code, _, errOut = runCLI(t, cli.Env{}, append([]string{"x-settings"}, bad...)...); code != 2 || !strings.Contains(errOut, "argument "+bad[0]) {
			t.Errorf("%v: %d %q", bad, code, errOut)
		}
	}
	if code, out, _ = runCLI(t, cli.Env{}, "x-settings"); out != want {
		t.Errorf("bad values were stored: %q", out)
	}
}

// TestXImportHandles: `nday x-accounts-import` resolves handle-only lines
// through the X API with the token of its environment (the fake answers
// in-process through Env.Transport); without a token such lines are an
// error that says so; an unresolved line imports nothing; the token never
// shows.
func TestXImportHandles(t *testing.T) {
	const tok = "XCLI-SECRET-0a1b2c3d"
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	file := filepath.Join(t.TempDir(), "accounts.txt")
	write := func(s string) {
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := xfake.New(tok)
	f.Add("2244994945", "XDevelopers")
	f.Suspended["gone_bad"] = true
	env := cli.Env{Transport: f.Transport()}
	var all strings.Builder
	run := func(args ...string) (int, string, string) {
		code, out, errOut := runCLI(t, env, args...)
		all.WriteString(out + errOut)
		return code, out, errOut
	}
	write("@xdevelopers # devs\n20 bob\n")
	t.Setenv("NDAY_X_BEARER_TOKEN", "")
	if code, _, errOut := run("x-accounts-import", file); code != 1 || !strings.Contains(errOut, "line(s) 1 give only a handle") ||
		!strings.Contains(errOut, "NDAY_X_BEARER_TOKEN") || f.Requests() != 0 {
		t.Fatalf("no token: %d %q", code, errOut)
	}
	t.Setenv("NDAY_X_BEARER_TOKEN", tok)
	write("@xdevelopers\n@nobody\n@gone_bad\n20 bob\n")
	if code, _, errOut := run("x-accounts-import", file); code != 1 || !strings.Contains(errOut, "line 2: @nobody: no X account") ||
		!strings.Contains(errOut, "line 3: @gone_bad: the X account is suspended") || !strings.Contains(errOut, "nothing was imported") {
		t.Fatalf("unresolved: %d %q", code, errOut)
	}
	if _, out, _ := run("x-accounts-list"); out != "x-accounts: 0 total, 0 enabled\n" {
		t.Fatalf("an unresolved import wrote: %q", out)
	}
	write("@xdevelopers # devs\n20 bob\n")
	if code, out, errOut := run("x-accounts-import", file); code != 0 ||
		out != "inserted 2244994945 @XDevelopers (id looked up)\ninserted 20 @bob\nx-accounts-import: inserted=2 updated=0 unchanged=0\n" {
		t.Fatalf("import: %d %q %q", code, out, errOut)
	}
	for _, a := range f.Auths() {
		if a != "Bearer "+tok {
			t.Errorf("Authorization %q", a)
		}
	}
	f.RateLimited["xdevelopers"] = true
	if code, _, errOut := run("x-accounts-import", file); code != 1 || !strings.Contains(errOut, "rate limit") {
		t.Fatalf("429: %d %q", code, errOut)
	}
	t.Setenv("NDAY_X_BEARER_TOKEN", "WRONG")
	delete(f.RateLimited, "xdevelopers")
	if code, _, errOut := run("x-accounts-import", file); code != 1 || !strings.Contains(errOut, "refused the credentials") {
		t.Fatalf("401: %d %q", code, errOut)
	}
	var audit string
	conn := d.Conn
	_ = conn.QueryRow(context.Background(), `SELECT details::text FROM admin_audit WHERE action = 'x.accounts.import'`).Scan(&audit)
	if !strings.Contains(audit, `"inserted 2244994945 @XDevelopers lookup"`) || !strings.Contains(audit, `"looked_up": 1`) {
		t.Errorf("audit: %s", audit)
	}
	if strings.Contains(all.String()+audit, tok) {
		t.Error("the token reached the output or the audit")
	}
}
