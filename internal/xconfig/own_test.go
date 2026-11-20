package xconfig_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xconfig"
)

func TestIsOwnHandle(t *testing.T) {
	t.Parallel()
	for h, want := range map[string]bool{
		"ndayland": true, "NdayLand": true, "NDAYLAND": true, "@ndayland": true,
		"ndayland2": false, "nday": false, "": false, "xndayland": false, "ndayland_": false,
	} {
		if got := xconfig.IsOwnHandle(h); got != want {
			t.Errorf("IsOwnHandle(%q) = %v, want %v", h, got, want)
		}
	}
}

// Every write of an allowlist handle refuses the site's own account.
func TestOwnAccountRefused(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	own := func(err error) bool { return errors.Is(err, xconfig.ErrOwnAccount) }

	if err := xconfig.InsertAccount(ctx, d.Conn, "7001", "NdayLand", ""); !own(err) {
		t.Errorf("InsertAccount: %v", err)
	}
	if _, err := xconfig.UpsertAccount(ctx, d.Conn, "7001", "ndayland", "n"); !own(err) {
		t.Errorf("UpsertAccount: %v", err)
	}
	if as, _ := xconfig.ListAccounts(ctx, d.Conn); len(as) != 0 {
		t.Fatalf("a refused write left rows: %+v", as)
	}
	// rename of a listed account to the own handle: refused, row unchanged
	if err := xconfig.InsertAccount(ctx, d.Conn, "7002", "alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := xconfig.UpdateAccount(ctx, d.Conn, "7002", "NDAYLAND", ""); !own(err) {
		t.Errorf("UpdateAccount: %v", err)
	}
	if _, err := xconfig.UpsertAccount(ctx, d.Conn, "7002", "ndayland", ""); !own(err) {
		t.Errorf("UpsertAccount rename: %v", err)
	}
	if a, _ := xconfig.GetAccount(ctx, d.Conn, "7002"); a.Handle != "alice" {
		t.Errorf("handle changed to %q", a.Handle)
	}

	// import file: both line formats are line errors
	_, errs := xconfig.ParseAccounts(strings.NewReader("7003 alice2\n7004 @NdayLand  # me\n@ndayland\nbob\n"))
	if len(errs) != 2 || errs[0].Line != 2 || errs[1].Line != 3 || !own(errs[0]) || !own(errs[1]) {
		t.Errorf("ParseAccounts: %v", errs)
	}
	if _, err := xconfig.ParseAccountsFile(strings.NewReader("ndayland\n")); !own(err) {
		t.Errorf("ParseAccountsFile: %v", err)
	}

	// a row inserted behind the checks cannot be switched on (off is fine)
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('7005', 'NdayLand', false)`); err != nil {
		t.Fatal(err)
	}
	if err := xconfig.SetAccountEnabled(ctx, d.Conn, "7005", true); !own(err) {
		t.Errorf("SetAccountEnabled: %v", err)
	}
	if err := xconfig.SetAccountEnabled(ctx, d.Conn, "7005", false); err != nil {
		t.Errorf("disable: %v", err)
	}
	if err := xconfig.SetAccountEnabled(ctx, d.Conn, "7999", true); !errors.Is(err, xconfig.ErrNotFound) {
		t.Errorf("absent: %v", err)
	}
}

// ListCandidates / CountCandidates never show a candidate with the own
// handle (any case), but keep a candidate without a handle.
func TestCandidatesExcludeOwn(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := xconfig.InsertAccount(ctx, d.Conn, "1001", "alice", ""); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"3001", "NdayLand"}, {"3002", "carol"}, {"3003", ""}} {
		var h any
		if c[1] != "" {
			h = c[1]
		}
		exec(`INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at) VALUES ($1, $2, '2026-11-01', '2026-11-02')`, c[0], h)
		exec(`INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at) VALUES ($1, '11', '1001', 'mentioned', '2026-11-02')`, c[0])
	}
	cs, err := xconfig.ListCandidates(ctx, d.Conn, "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range cs {
		ids = append(ids, c.UserID)
	}
	if len(ids) != 2 || !(ids[0] == "3002" && ids[1] == "3003" || ids[0] == "3003" && ids[1] == "3002") {
		t.Errorf("listed %v, want 3002 and 3003 only", ids)
	}
	if n, err := xconfig.CountCandidates(ctx, d.Conn, ""); err != nil || n != 2 {
		t.Errorf("CountCandidates = %d, %v; want 2", n, err)
	}
}
