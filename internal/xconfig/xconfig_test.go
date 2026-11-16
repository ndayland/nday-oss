package xconfig_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xconfig"
)

func ptr[T any](v T) *T { return &v }

func TestParseAccountsFile(t *testing.T) {
	in := "\ufeff# comment\n\n1001 alice_sec   # Alice, researcher\n  1002 @bob_sec\n12345678901234567 c # note # with hash\n"
	got, err := xconfig.ParseAccountsFile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []xconfig.FileAccount{
		{Line: 3, UserID: "1001", Handle: "alice_sec", Note: "Alice, researcher"},
		{Line: 4, UserID: "1002", Handle: "bob_sec"},
		{Line: 5, UserID: "12345678901234567", Handle: "c", Note: "note # with hash"},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v want %+v", i, got[i], want[i])
		}
	}
	for _, bad := range []string{
		"1001\n",                   // no handle
		"1001 a b\n",               // three fields
		"alice 1001\n",             // swapped
		"01001 alice\n",            // leading zero
		"12345678901234567890 a\n", // 20 digits
		"1001 alice-sec\n",         // bad handle
		"1001 abcdefghijklmnop\n",  // 16 characters
		"1001 a\n1001 b\n",         // duplicate id
		"1001 a # " + strings.Repeat("x", 501) + "\n", // note too long
	} {
		if _, err := xconfig.ParseAccountsFile(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "line ") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// the shipped example parses and lists no accounts
	f, err := os.Open(testutil.RepoRoot() + "/deploy/x-accounts.example.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if as, err := xconfig.ParseAccountsFile(f); err != nil || len(as) != 0 {
		t.Errorf("example: %v %v", as, err)
	}
}

// TestParseHandleOnly: one-field lines are handles to look up; all-digit
// handles need '@'; duplicates (any case) and bad handles are refused.
func TestParseHandleOnly(t *testing.T) {
	in := "@Alice_Sec # looked up\nbob_sec\n@12345 # an all-digit handle\n1001 carol\n"
	got, errs := xconfig.ParseAccounts(strings.NewReader(in))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	want := []xconfig.FileAccount{
		{Line: 1, Handle: "Alice_Sec", Note: "looked up"},
		{Line: 2, Handle: "bob_sec"},
		{Line: 3, Handle: "12345", Note: "an all-digit handle"},
		{Line: 4, UserID: "1001", Handle: "carol"},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v want %+v", i, got[i], want[i])
		}
	}
	bad := "12345\n@a-b\n@alice\n@ALICE\nabcdefghijklmnop\n@\nx # " + strings.Repeat("y", 501) + "\n"
	_, errs = xconfig.ParseAccounts(strings.NewReader(bad))
	var lines []int
	for _, e := range errs {
		lines = append(lines, e.Line)
	}
	if fmt.Sprint(lines) != "[1 2 4 5 6 7]" || !strings.Contains(errs[0].Error(), "ambiguous") || !strings.Contains(errs[2].Error(), "already on line 3") {
		t.Errorf("errors: %v", errs)
	}
}

func TestAccounts(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	as, err := xconfig.ListEnabledAccounts(ctx, d.Conn)
	if err != nil || len(as) != 0 {
		t.Fatalf("%v %v", as, err)
	}
	steps := []struct {
		id, handle, note string
		want             xconfig.UpsertResult
	}{
		{"1001", "alice", "first", xconfig.Inserted},
		{"20", "bob", "", xconfig.Inserted},
		{"1001", "alice", "", xconfig.Unchanged},      // empty note keeps the stored one
		{"1001", "alice", "first", xconfig.Unchanged}, // same values
		{"1001", "alice_new", "", xconfig.Updated},    // rename
		{"1001", "alice_new", "second", xconfig.Updated},
	}
	for _, s := range steps {
		r, err := xconfig.UpsertAccount(ctx, d.Conn, s.id, s.handle, s.note)
		if err != nil || r != s.want {
			t.Fatalf("%+v: %v %v", s, r, err)
		}
	}
	if _, err := xconfig.UpsertAccount(ctx, d.Conn, "x", "a", ""); err == nil {
		t.Error("bad id accepted")
	}
	if err := xconfig.SetAccountEnabled(ctx, d.Conn, "20", false); err != nil {
		t.Fatal(err)
	}
	if err := xconfig.SetAccountEnabled(ctx, d.Conn, "999", true); !errors.Is(err, xconfig.ErrNotFound) {
		t.Errorf("%v", err)
	}
	// re-import does not re-enable
	if r, err := xconfig.UpsertAccount(ctx, d.Conn, "20", "bob2", ""); err != nil || r != xconfig.Updated {
		t.Fatal(r, err)
	}
	all, err := xconfig.ListAccounts(ctx, d.Conn)
	if err != nil || len(all) != 2 || all[0].UserID != "20" || all[0].Enabled || all[0].Handle != "bob2" ||
		all[1].UserID != "1001" || all[1].Handle != "alice_new" || all[1].Note != "second" || !all[1].Enabled {
		t.Fatalf("%+v %v", all, err)
	}
	en, err := xconfig.ListEnabledAccounts(ctx, d.Conn)
	if err != nil || len(en) != 1 || en[0].UserID != "1001" {
		t.Fatalf("%+v %v", en, err)
	}
	if a, err := xconfig.GetAccount(ctx, d.Conn, "20"); err != nil || a.Handle != "bob2" {
		t.Errorf("%+v %v", a, err)
	}
	if _, err := xconfig.GetAccount(ctx, d.Conn, "21"); !errors.Is(err, xconfig.ErrNotFound) {
		t.Errorf("%v", err)
	}
	// the table CHECKs refuse what the Go validation refuses
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle) VALUES ('01', 'a')`); err == nil {
		t.Error("CHECK user_id missing")
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle) VALUES ('5', 'a b')`); err == nil {
		t.Error("CHECK handle missing")
	}
}

func TestSettings(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	s, w, err := xconfig.GetSettings(ctx, d.Conn)
	if err != nil || s != xconfig.Defaults || len(w) != 0 {
		t.Fatalf("%+v %v %v", s, w, err)
	}
	if err := xconfig.SaveSettings(ctx, d.Conn, xconfig.Stored{MaxPosts: ptr(5001)}); err == nil {
		t.Error("out of range saved")
	}
	if err := xconfig.SaveSettings(ctx, d.Conn, xconfig.Stored{Enabled: ptr(false), MaxPosts: ptr(100), BootstrapDays: ptr(3)}); err != nil {
		t.Fatal(err)
	}
	st, err := xconfig.LoadSettings(ctx, d.Conn)
	if err != nil || st.UpdatedAt == nil || *st.MaxPosts != 100 || st.MaxRequests != nil {
		t.Fatalf("%+v %v", st, err)
	}
	s, _, _ = xconfig.GetSettings(ctx, d.Conn)
	if s != (xconfig.Settings{Enabled: false, MaxPosts: 100, MaxRequests: 20, BootstrapDays: 3, MaxQueryLength: 512}) {
		t.Errorf("%+v", s)
	}
	// the DB refuses out-of-range values too
	if _, err := d.Conn.Exec(ctx, `UPDATE x_settings SET max_requests = 1000`); err == nil {
		t.Error("CHECK max_requests missing")
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_settings (id) VALUES (2)`); err == nil {
		t.Error("second row accepted")
	}
	// and if the CHECKs are gone, reads clamp into the hard bounds
	if _, err := d.Conn.Exec(ctx, `ALTER TABLE x_settings DROP CONSTRAINT x_settings_max_posts_check,
        DROP CONSTRAINT x_settings_max_requests_check, DROP CONSTRAINT x_settings_bootstrap_days_check,
        DROP CONSTRAINT x_settings_max_query_length_check`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE x_settings SET max_posts = 1000000, max_requests = -5, bootstrap_days = 30, max_query_length = 1`); err != nil {
		t.Fatal(err)
	}
	s, w, err = xconfig.GetSettings(ctx, d.Conn)
	if err != nil || s.MaxPosts != xconfig.MaxMaxPosts || s.MaxRequests != xconfig.MinMaxRequests ||
		s.BootstrapDays != xconfig.MaxBootstrapDays || s.MaxQueryLength != xconfig.MinMaxQueryLength || len(w) != 4 {
		t.Errorf("%+v %v %v", s, w, err)
	}
}

func TestParseAccountsAllErrors(t *testing.T) {
	in := "1001 alice\n1002\n01003 bob\n1001 again\n1004 ok # " + strings.Repeat("x", 501) + "\n1005 fine\n"
	got, errs := xconfig.ParseAccounts(strings.NewReader(in))
	var lines []int
	for _, e := range errs {
		lines = append(lines, e.Line)
	}
	if len(got) != 2 || got[0].UserID != "1001" || got[1].UserID != "1005" || len(lines) != 4 ||
		lines[0] != 2 || lines[1] != 3 || lines[2] != 4 || lines[3] != 5 {
		t.Errorf("%+v %v", got, lines)
	}
	if !strings.HasPrefix(errs[0].Error(), "line 2: ") {
		t.Errorf("%v", errs[0])
	}
	// ParseAccountsFile reports the first error, as before
	if _, err := xconfig.ParseAccountsFile(strings.NewReader(in)); err == nil || !strings.HasPrefix(err.Error(), "line 2: ") {
		t.Errorf("%v", err)
	}
}

func TestInsertUpdateLock(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	if err := xconfig.InsertAccount(ctx, d.Conn, "1001", "alice", "n"); err != nil {
		t.Fatal(err)
	}
	if err := xconfig.InsertAccount(ctx, d.Conn, "1001", "other", ""); !errors.Is(err, xconfig.ErrExists) {
		t.Errorf("duplicate: %v", err)
	}
	if err := xconfig.InsertAccount(ctx, d.Conn, "1002", "bad handle", ""); err == nil {
		t.Error("bad handle accepted")
	}
	if a, _ := xconfig.GetAccount(ctx, d.Conn, "1001"); a.Handle != "alice" || a.Note != "n" || !a.Enabled {
		t.Errorf("%+v", a)
	}
	for _, c := range []struct {
		handle, note string
		changed      bool
	}{{"alice", "n", false}, {"alice2", "n", true}, {"alice2", "", true}, {"alice2", "", false}} {
		ch, err := xconfig.UpdateAccount(ctx, d.Conn, "1001", c.handle, c.note)
		if err != nil || ch != c.changed {
			t.Errorf("%+v: %v %v", c, ch, err)
		}
	}
	if _, err := xconfig.UpdateAccount(ctx, d.Conn, "999", "x", ""); !errors.Is(err, xconfig.ErrNotFound) {
		t.Errorf("absent: %v", err)
	}
	if _, err := xconfig.UpdateAccount(ctx, d.Conn, "1001", "a-b", ""); err == nil {
		t.Error("bad handle accepted")
	}
	tx, err := d.Conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if a, err := xconfig.GetAccountForUpdate(ctx, tx, "1001"); err != nil || a.Handle != "alice2" || a.Note != "" {
		t.Errorf("%+v %v", a, err)
	}
	if _, err := xconfig.GetAccountForUpdate(ctx, tx, "5"); !errors.Is(err, xconfig.ErrNotFound) {
		t.Errorf("%v", err)
	}
	if err := xconfig.LockSettings(ctx, tx); err != nil {
		t.Error(err)
	}
	a, b := xconfig.Stored{MaxPosts: ptr(10)}, xconfig.Stored{MaxPosts: ptr(10)}
	if !a.Equal(b) || a.Equal(xconfig.Stored{}) || (xconfig.Stored{Enabled: ptr(false)}).Equal(xconfig.Stored{Enabled: ptr(true)}) {
		t.Error("Equal")
	}
}

// TestSearchAccounts: CountAccounts / SearchAccounts match a substring of
// the handle in any case; % _ and \ are literal characters, never LIKE
// wildcards; rows come in ListAccounts' order with limit and offset.
func TestSearchAccounts(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	// ids out of insertion order: the order is numeric by user id
	for _, a := range [][2]string{{"30", "Sec_Team"}, {"4", "secXteam"}, {"100", "alice_SEC"}, {"25", "bob"}, {"7", "a_b"}, {"8", "axb"}} {
		if err := xconfig.InsertAccount(ctx, d.Conn, a[0], a[1], ""); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(as []xconfig.Account) string {
		var s []string
		for _, a := range as {
			s = append(s, a.UserID)
		}
		return strings.Join(s, ",")
	}
	for _, c := range []struct {
		q    string
		want string
	}{
		{"", "4,7,8,25,30,100"},
		{"sec", "4,30,100"},  // substring, any case
		{"SEC_", "30"},       // '_' is literal: secXteam does not match
		{"_", "7,30,100"},    // only handles that contain '_'
		{"a_b", "7"},         // not axb
		{"%", ""},            // no handle holds '%'; not a wildcard
		{"%sec%", ""},        // LIKE syntax is just text
		{`\`, ""},            // backslash is literal, no escape
		{`sec\_team`, ""},    // an escaped LIKE pattern is literal too
		{"ALICE_sec", "100"}, // the whole handle, other case
		{"nobody", ""},
	} {
		n, err := xconfig.CountAccounts(ctx, d.Conn, c.q)
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		as, err := xconfig.SearchAccounts(ctx, d.Conn, c.q, 100, 0)
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		if got := ids(as); got != c.want || n != len(as) {
			t.Errorf("%q: %q (count %d), want %q", c.q, got, n, c.want)
		}
	}
	// limit and offset page through the same order
	for _, c := range []struct {
		q             string
		limit, offset int
		want          string
	}{
		{"", 2, 0, "4,7"}, {"", 2, 2, "8,25"}, {"", 2, 4, "30,100"}, {"", 2, 6, ""}, {"", 4, 4, "30,100"},
		{"sec", 2, 0, "4,30"}, {"sec", 2, 2, "100"}, {"sec", 0, 0, ""},
	} {
		as, err := xconfig.SearchAccounts(ctx, d.Conn, c.q, c.limit, c.offset)
		if err != nil || ids(as) != c.want {
			t.Errorf("%q limit %d offset %d: %q %v, want %q", c.q, c.limit, c.offset, ids(as), err, c.want)
		}
	}
	if as, err := xconfig.SearchAccounts(ctx, d.Conn, "sec", 2, 0); err != nil || as[0].Handle != "secXteam" || !as[0].Enabled {
		t.Errorf("row content: %+v %v", as, err)
	}
	if _, err := xconfig.SearchAccounts(ctx, d.Conn, "", -1, 0); err == nil {
		t.Error("negative limit accepted")
	}
}
