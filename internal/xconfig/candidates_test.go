package xconfig_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xconfig"
)

// ListCandidates: ordering (distinct enabled referrers, refs, last seen),
// exclusion of allowlisted ids (enabled or not) and of other statuses,
// samples; Dismiss / Restore.
func TestCandidates(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range [][2]string{{"1001", "alice"}, {"1002", "bob"}, {"1003", "carl"}} {
		if _, err := xconfig.UpsertAccount(ctx, d.Conn, a[0], a[1], ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := xconfig.SetAccountEnabled(ctx, d.Conn, "1003", false); err != nil {
		t.Fatal(err)
	}
	// (user, handle, status, last seen day)
	for _, c := range []struct{ id, handle, status, last string }{
		{"3001", "carol", "pending", "2026-11-10"}, {"3002", "dave", "pending", "2026-11-10"},
		{"3003", "", "pending", "2026-11-14"}, {"3005", "eve", "pending", "2026-11-12"},
		{"3006", "fay", "dismissed", "2026-11-14"}, {"1003", "carl", "pending", "2026-11-14"},
	} {
		var h any
		if c.handle != "" {
			h = c.handle
		}
		exec(`INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at, status) VALUES ($1, $2, '2026-11-01', $3, $4)`,
			c.id, h, c.last, c.status)
	}
	ref := func(user, post, referrer, kind, at string) {
		exec(`INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at) VALUES ($1, $2, $3, $4, $5)`,
			user, post, referrer, kind, at)
	}
	// 3001: 2 enabled referrers, 3 refs over 2 posts (one post twice)
	ref("3001", "11", "1001", "quoted", "2026-11-05")
	ref("3001", "11", "1001", "mentioned", "2026-11-05")
	ref("3001", "12", "1002", "mentioned", "2026-11-10")
	// 3002 and 3005: 1 enabled referrer, 3 refs; 3005 seen later
	for i, at := range []string{"2026-11-08", "2026-11-09", "2026-11-10"} {
		ref("3002", fmt.Sprint(20+i), "1001", "mentioned", at)
		ref("3005", fmt.Sprint(50+i), "1002", "replied_to", at)
	}
	// 3003: only the disabled account refers to it, 4 times
	for i := 0; i < 4; i++ {
		ref("3003", fmt.Sprint(30+i), "1003", "quoted", fmt.Sprintf("2026-11-1%d", i))
	}
	ref("3006", "60", "1001", "quoted", "2026-11-14")
	ref("1003", "70", "1001", "quoted", "2026-11-14") // allowlisted (disabled): never listed

	line := func(c xconfig.Candidate) string {
		h := "-"
		if c.Handle != nil {
			h = *c.Handle
		}
		return fmt.Sprintf("%s %s %s r=%d n=%d %s %s %s", c.UserID, h, c.Status, c.Referrers, c.Refs, strings.Join(c.Kinds, ","),
			c.LastSeenAt.Format("2006-01-02"), strings.Join(c.SamplePosts, ","))
	}
	list := func(status string, limit, offset int) []string {
		t.Helper()
		cs, err := xconfig.ListCandidates(ctx, d.Conn, status, limit, offset)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cs {
			out = append(out, line(c))
		}
		return out
	}
	want := []string{
		"3001 carol pending r=2 n=3 mentioned,quoted 2026-11-10 12,11",
		"3005 eve pending r=1 n=3 replied_to 2026-11-12 52,51,50",
		"3002 dave pending r=1 n=3 mentioned 2026-11-10 22,21,20",
		"3003 - pending r=0 n=4 quoted 2026-11-14 33,32,31",
	}
	if got := list("", 50, 0); !slices.Equal(got, want) {
		t.Fatalf("pending:\n%s", strings.Join(got, "\n"))
	}
	if got := list("pending", 2, 1); !slices.Equal(got, want[1:3]) {
		t.Errorf("page:\n%s", strings.Join(got, "\n"))
	}
	if got := list("dismissed", 50, 0); !slices.Equal(got, []string{"3006 fay dismissed r=1 n=1 quoted 2026-11-14 60"}) {
		t.Errorf("dismissed:\n%s", strings.Join(got, "\n"))
	}
	if _, err := xconfig.ListCandidates(ctx, d.Conn, "bogus", 1, 0); err == nil {
		t.Error("bad status accepted")
	}

	// dismiss / restore
	if ch, err := xconfig.DismissCandidate(ctx, d.Conn, "3001"); err != nil || !ch {
		t.Fatalf("%v %v", ch, err)
	}
	if ch, err := xconfig.DismissCandidate(ctx, d.Conn, "3001"); err != nil || ch {
		t.Errorf("second dismiss: %v %v", ch, err)
	}
	cs, err := xconfig.ListCandidates(ctx, d.Conn, "dismissed", 50, 0)
	if err != nil || len(cs) != 2 || cs[0].UserID != "3001" || cs[0].DecidedAt == nil {
		t.Errorf("%+v %v", cs, err)
	}
	if got := list("", 50, 0); !slices.Equal(got, want[1:]) {
		t.Errorf("after dismiss:\n%s", strings.Join(got, "\n"))
	}
	if ch, err := xconfig.RestoreCandidate(ctx, d.Conn, "3001"); err != nil || !ch {
		t.Errorf("%v %v", ch, err)
	}
	if got := list("", 50, 0); !slices.Equal(got, want) {
		t.Errorf("after restore:\n%s", strings.Join(got, "\n"))
	}
	if _, err := xconfig.DismissCandidate(ctx, d.Conn, "4242"); !errors.Is(err, xconfig.ErrCandidateNotFound) {
		t.Errorf("%v", err)
	}

	// CountCandidates counts what ListCandidates lists (no ref: not counted)
	exec(`INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at) VALUES ('3007', 'noref', '2026-11-01', '2026-11-01')`)
	for st, n := range map[string]int{"": len(want), "pending": len(want), "dismissed": 1} {
		if got, err := xconfig.CountCandidates(ctx, d.Conn, st); err != nil || got != n {
			t.Errorf("count %q: %d %v, want %d", st, got, err, n)
		}
	}
	if _, err := xconfig.CountCandidates(ctx, d.Conn, "bogus"); err == nil {
		t.Error("bad status counted")
	}

	// GetCandidateForUpdate
	tx, err := d.Conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if h, st, err := xconfig.GetCandidateForUpdate(ctx, tx, "3001"); err != nil || h == nil || *h != "carol" || st != "pending" {
		t.Errorf("3001: %v %q %v", h, st, err)
	}
	if h, st, err := xconfig.GetCandidateForUpdate(ctx, tx, "3003"); err != nil || h != nil || st != "pending" {
		t.Errorf("3003: %v %q %v", h, st, err)
	}
	if _, _, err := xconfig.GetCandidateForUpdate(ctx, tx, "4242"); !errors.Is(err, xconfig.ErrCandidateNotFound) {
		t.Errorf("4242: %v", err)
	}
}
