package cli_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
)

// TestCLIWritesAudit: the server-side commands that change accounts or
// comments write one audit row each (actor "cli", source "cli"), in the
// same transaction as the change; a refused command writes none.
func TestCLIWritesAudit(t *testing.T) {
	clearAuthEnv(t)
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	ctx := context.Background()
	var uid, cid string
	if err := d.Conn.QueryRow(ctx, `INSERT INTO users (display_name) VALUES ('Ada') RETURNING id::text`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO namespaces (name, kind) VALUES ('ada', 'user');
		UPDATE users SET handle = 'Ada', handle_key = 'ada'; INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0001')`); err != nil {
		t.Fatal(err)
	}
	if err := d.Conn.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links)
		VALUES ('CVE-2026-0001', false, $1, 'buy   pills'||chr(10)||'now', 'en', true) RETURNING id::text`, uid).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	steps := [][]string{
		{"auth-role", uid, "moderator"},
		{"auth-role", "ada", "admin", "--yes"},
		{"auth-suspend", uid, "--for", "1d", "--reason", "cool down"},
		{"auth-unsuspend", uid},
		{"discuss-hide", cid, "--reason", "spam"},
		{"discuss-unhide", cid},
	}
	for i, s := range steps {
		if code, out, errOut := runCLI(t, cli.Env{}, s...); code != 0 {
			t.Fatalf("%v: %d %q %q", s, code, out, errOut)
		}
		var n int
		_ = d.Conn.QueryRow(ctx, `SELECT count(*) FROM admin_audit`).Scan(&n)
		if n != i+1 {
			t.Fatalf("after %v: %d audit rows", s, n)
		}
	}
	rows, err := d.Conn.Query(ctx, `SELECT action, target_type, target_id, coalesce(target_label, ''), coalesce(reason, ''), details::text,
		actor_role, source, actor_id IS NULL, client_addr IS NULL FROM admin_audit ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var a, tt, tid, label, reason, details, role, src string
		var noActor, noAddr bool
		if err := rows.Scan(&a, &tt, &tid, &label, &reason, &details, &role, &src, &noActor, &noAddr); err != nil {
			t.Fatal(err)
		}
		if role != "cli" || src != "cli" || !noActor || !noAddr {
			t.Errorf("%s: actor %s/%s", a, role, src)
		}
		if (tt == "user" && tid != uid) || (tt == "comment" && tid != cid) {
			t.Errorf("%s: target %s %s", a, tt, tid)
		}
		got = append(got, a+"|"+label+"|"+reason+"|"+details)
	}
	want := []string{
		`user.role|Ada||{"to": "moderator", "from": "user"}`,
		`user.role|Ada||{"to": "admin", "from": "moderator"}`,
		`user.suspend|Ada|cool down|`,
		`user.unsuspend|Ada||{}`,
		`comment.hide|buy pills now|spam|{"cve": "CVE-2026-0001", "resolved_reports": 0}`,
		`comment.unhide|buy pills now||{"cve": "CVE-2026-0001"}`,
	}
	for i := range want {
		if i >= len(got) || !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("row %d: %q, want prefix %q", i, got[i], want[i])
		}
	}
	// refused commands write nothing
	runCLI(t, cli.Env{}, "discuss-unhide", cid)                                       // already visible
	runCLI(t, cli.Env{}, "auth-role", "00000000-0000-0000-0000-000000000001", "user") // unknown
	var n int
	_ = d.Conn.QueryRow(ctx, `SELECT count(*) FROM admin_audit`).Scan(&n)
	if n != len(steps) {
		t.Errorf("refused commands wrote rows: %d", n)
	}
}

// TestXCommandsWriteAudit: x-accounts-import, x-accounts-enable|disable and
// x-settings write one cli audit row when they change something (none when
// they do not); their output is unchanged.
func TestXCommandsWriteAudit(t *testing.T) {
	clearAuthEnv(t)
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	ctx := context.Background()
	file := t.TempDir() + "/x.txt"
	if err := os.WriteFile(file, []byte("1001 alice # a\n1002 bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		_ = d.Conn.QueryRow(ctx, `SELECT count(*) FROM admin_audit WHERE actor_role = 'cli' AND source = 'cli' AND actor_id IS NULL`).Scan(&n)
		return n
	}
	steps := []struct {
		args []string
		out  string
		rows int
	}{
		{[]string{"x-accounts-import", file}, "inserted 1001 @alice\ninserted 1002 @bob\nx-accounts-import: inserted=2 updated=0 unchanged=0\n", 1},
		{[]string{"x-accounts-import", file}, "x-accounts-import: inserted=0 updated=0 unchanged=2\n", 1},
		{[]string{"x-accounts-disable", "1002"}, "x-accounts-disable: 1002\n", 2},
		{[]string{"x-accounts-disable", "1002"}, "x-accounts-disable: 1002\n", 2},
		{[]string{"x-accounts-enable", "1002"}, "x-accounts-enable: 1002\n", 3},
		{[]string{"x-settings", "--max-posts", "200"}, "", 4},
		{[]string{"x-settings", "--max-posts", "200"}, "", 4},
		{[]string{"x-settings"}, "", 4},
	}
	for _, s := range steps {
		code, out, errOut := runCLI(t, cli.Env{}, s.args...)
		if code != 0 || (s.out != "" && out != s.out) {
			t.Errorf("%v: %d %q %q", s.args, code, out, errOut)
		}
		if n := count(); n != s.rows {
			t.Errorf("after %v: %d audit rows, want %d", s.args, n, s.rows)
		}
	}
	var acts string
	_ = d.Conn.QueryRow(ctx, `SELECT string_agg(action || ' ' || target_id || ' ' || details::text, ' | ' ORDER BY id) FROM admin_audit`).Scan(&acts)
	want := `x.accounts.import import {"changed": ["inserted 1001 @alice", "inserted 1002 @bob"], "updated": 0, "inserted": 2, "looked_up": 0, "unchanged": 0} | x.account.disable 1002 {} | x.account.enable 1002 {} | ` +
		`x.settings.update 1 {"max_posts": {"to": 200, "from": null}}`
	if acts != want {
		t.Errorf("audit:\n%s\nwant\n%s", acts, want)
	}
	// a refused command writes nothing
	runCLI(t, cli.Env{}, "x-accounts-enable", "999")
	runCLI(t, cli.Env{}, "x-settings", "--max-posts", "5001")
	if n := count(); n != 4 {
		t.Errorf("refused commands wrote rows: %d", n)
	}
}
