package cli_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/testutil"
)

// `nday collect` runs the tag pass after the classification pass; the
// command's modes and usage errors.
func TestTagsCommandAndPostRunPass(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	env := kevEnv(t, time.Now().UTC())
	if code, _, errb := runCLI(t, env, "collect", "kev"); code != 0 || !strings.Contains(errb, "tag pass") {
		t.Fatalf("collect: %d %s", code, errb)
	}
	var n, queue int
	if err := d.Conn.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM vuln_tag WHERE tag = 'ransomware'),
        (SELECT count(*) FROM tag_queue)`).Scan(&n, &queue); err != nil {
		t.Fatal(err)
	}
	if n != 2 || queue != 0 {
		t.Errorf("after collect: %d ransomware tags, %d queued", n, queue)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"tags", "--all", "--dry-run"}, `"dry_run": true`},
		{[]string{"tags", "--all"}, `"changed": 0`},
		{[]string{"tags", "--cve", "cve-2021-44228"}, `"no_vuln": 1`},
		{[]string{"tags", "--pending"}, `"queue_rows": 0`},
	} {
		code, out, errb := runCLI(t, env, c.args...)
		if code != 0 || !strings.Contains(out, c.want) {
			t.Errorf("%v: %d %s %s", c.args, code, out, errb)
		}
	}
	// the last --all recorded the rule version: no stale warning
	if _, _, errb := runCLI(t, env, "collect", "kev"); strings.Contains(errb, "rows may be stale") {
		t.Errorf("stale warning after --all: %s", errb)
	}
	for _, bad := range [][]string{{"tags"}, {"tags", "--all", "--pending"}, {"tags", "--cve"}, {"tags", "--cve", "nope"},
		{"tags", "--all", "CVE-2026-1"}, {"tags", "--all", "--batch-size", "0"}, {"tags", "--source", "nvd"}} {
		if code, _, _ := runCLI(t, env, bad...); code != 2 {
			t.Errorf("%v: exit %d, want 2", bad, code)
		}
	}
}
