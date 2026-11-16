package cli_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/testutil"
)

// TestXDraftsCommand: the pass after a collector run (baseline on the first
// one), the manual command with --dry-run and without, and a failing pass
// that never fails the collector run.
func TestXDraftsCommand(t *testing.T) {
	d := testutil.NewDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	now := time.Now().UTC()
	env := kevEnv(t, now)
	if code, _, errs := runCLI(t, env, "migrate"); code != 0 {
		t.Fatal(errs)
	}
	code, _, errs := runCLI(t, env, "collect", "kev")
	if code != 0 || !strings.Contains(errs, "x draft pass") || !strings.Contains(errs, "baseline=true") {
		t.Fatalf("collect: %d %s", code, errs)
	}
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.Conn.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string) int {
		var n int
		if err := d.Conn.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// the bulk import made no drafts
	if n := count(`SELECT count(*) FROM x_draft`); n != 0 {
		t.Fatalf("drafts after the backfill: %d", n)
	}
	exec(`INSERT INTO vuln (cve_id, title) VALUES ('CVE-2026-55555', 'Example flaw')`)
	exec(`INSERT INTO event (cve_id, type, observed_at, source, dedupe_key) VALUES ('CVE-2026-55555', 'kev_added', $1, 'kev', 'x')`, now)
	var res struct {
		Created int  `json:"created"`
		DryRun  bool `json:"dry_run"`
		Drafts  []struct {
			CVE    string `json:"cve_id"`
			Body   string `json:"body"`
			Weight int    `json:"weighted_length"`
		} `json:"drafts"`
	}
	code, out, errs := runCLI(t, env, "x-drafts", "--dry-run")
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || !res.DryRun || res.Created != 1 || len(res.Drafts) != 1 ||
		res.Drafts[0].Body != "CVE-2026-55555 +KEV\nExample flaw\nAdded to the CISA KEV catalog (known exploited)." {
		t.Fatalf("dry run: %d %s %s", code, out, errs)
	}
	if n := count(`SELECT count(*) FROM x_draft`); n != 0 {
		t.Fatalf("the dry run wrote %d drafts", n)
	}
	code, out, _ = runCLI(t, env, "x-drafts")
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.Created != 1 || count(`SELECT count(*) FROM x_draft`) != 1 {
		t.Fatalf("run: %d %s", code, out)
	}
	if code, _, _ := runCLI(t, env, "x-drafts", "--bogus"); code != 2 {
		t.Errorf("bad flag: exit %d", code)
	}
	// a failing pass is logged; the collector run still succeeds
	exec(`ALTER TABLE x_draft RENAME TO x_draft_moved`)
	exec(`INSERT INTO event (cve_id, type, observed_at, source, dedupe_key) VALUES ('CVE-2026-55555', 'poc_published', $1, 'nuclei', 'y')`, now)
	code, _, errs = runCLI(t, env, "collect", "kev")
	if code != 0 || !strings.Contains(errs, "x draft pass") {
		t.Fatalf("collect with a failing pass: %d %s", code, errs)
	}
}
