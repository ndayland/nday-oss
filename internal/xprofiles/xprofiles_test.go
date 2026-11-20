package xprofiles_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xlookup"
	"nday.land/nday/internal/xlookup/xfake"
	"nday.land/nday/internal/xprofiles"
)

const token = "XPROFILES-TOKEN-secret-1"

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// setup: n enabled allow-listed accounts, ids 1001..1000+n, every one known
// to the fake with a name and a valid avatar URL; plus one disabled
// account (never asked for).
func setup(t *testing.T, n int) (*pgx.Conn, *xfake.Server, *xlookup.Client) {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	f := xfake.New(token)
	ctx := context.Background()
	for i := 1; i <= n; i++ {
		id, h := fmt.Sprint(1000+i), fmt.Sprintf("user%d", i)
		if _, err := d.Conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle, enabled) VALUES ($1, $2, true)`, id, h); err != nil {
			t.Fatal(err)
		}
		f.Users[h] = xfake.User{ID: id, Username: h, Name: "Name " + h,
			ProfileImageURL: "https://pbs.twimg.com/profile_images/" + id + "/a_normal.jpg"}
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('999', 'off', false)`); err != nil {
		t.Fatal(err)
	}
	f.Users["off"] = xfake.User{ID: "999", Username: "off"}
	c, err := xlookup.New(xlookup.Options{Token: token, Transport: f.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	return d.Conn, f, c
}

func opts(at time.Time, dry, onlyMissing bool) xprofiles.Options {
	return xprofiles.Options{DryRun: dry, OnlyMissing: onlyMissing, Now: func() time.Time { return at },
		Sleep: func(context.Context, time.Duration) error { return nil }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func count(t *testing.T, c *pgx.Conn) int {
	t.Helper()
	var n int
	if err := c.QueryRow(context.Background(), `SELECT count(*) FROM x_user`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRun: 150 accounts in two requests; a suspended and an unknown
// account are counted, not fatal; a non-twimg avatar is refused (stored
// as no avatar) and its host logged; names are cleaned; seen_at is the
// fetch time; the disabled account is never asked for.
func TestRun(t *testing.T) {
	c, f, lk := setup(t, 150)
	ctx := context.Background()
	f.Suspended["user7"] = true
	delete(f.Users, "user8") // deleted on X
	u9 := f.Users["user9"]
	u9.ProfileImageURL = "https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png"
	u9.Name = "\u202e\u3164"
	f.Users["user9"] = u9
	u10 := f.Users["user10"]
	u10.Name = "  Ten\u202e  Name "
	f.Users["user10"] = u10

	res, err := xprofiles.Run(ctx, c, lk, opts(now, false, true))
	if err != nil {
		t.Fatal(err)
	}
	want := xprofiles.Result{Considered: 150, Requested: 150, Returned: 148, WithName: 147, AvatarAccepted: 147, AvatarRejected: 1,
		RejectedSample: []string{"https://abs.twimg.com/sticky"}, NotReturned: 2, Written: 148, Requests: 2}
	if fmt.Sprint(res) != fmt.Sprint(want) {
		t.Fatalf("result\n got %+v\nwant %+v", res, want)
	}
	if q := f.Queries(); len(q) != 2 || len(strings.Split(q[0], ",")) != 100 || len(strings.Split(q[1], ",")) != 50 || strings.Contains(strings.Join(q, ","), "999") {
		t.Fatalf("queries %v", q)
	}
	for _, a := range f.Auths() {
		if a != "Bearer "+token {
			t.Errorf("Authorization %q", a)
		}
	}
	type row struct {
		name, avatar *string
		seen         time.Time
	}
	get := func(id string) *row {
		var r row
		err := c.QueryRow(ctx, `SELECT name, avatar_url, seen_at FROM x_user WHERE user_id = $1`, id).Scan(&r.name, &r.avatar, &r.seen)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return &r
	}
	if r := get("1001"); r == nil || *r.name != "Name user1" || *r.avatar != "https://pbs.twimg.com/profile_images/1001/a_normal.jpg" || !r.seen.Equal(now) {
		t.Errorf("1001: %+v", r)
	}
	if get("1007") != nil || get("1008") != nil || get("999") != nil {
		t.Error("a suspended, deleted or disabled account got a row")
	}
	if r := get("1009"); r == nil || r.name != nil || r.avatar != nil {
		t.Errorf("1009 (no visible name, refused avatar): %+v", r)
	}
	if r := get("1010"); r == nil || *r.name != "Ten Name" {
		t.Errorf("1010: %+v", r)
	}

	// only-missing: everything fresh except the two never returned, and a
	// row made stale by hand
	if _, err := c.Exec(ctx, `UPDATE x_user SET seen_at = $1 WHERE user_id = '1001'`, now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	before := len(f.Queries())
	res, err = xprofiles.Run(ctx, c, lk, opts(now.Add(time.Hour), false, true))
	if err != nil || res.Considered != 3 || res.Requests != 1 || res.Written != 1 || res.NotReturned != 2 {
		t.Fatalf("only-missing: %+v %v", res, err)
	}
	if q := f.Queries()[before:]; len(q) != 1 || q[0] != "1001,1007,1008" {
		t.Errorf("only-missing queries %v", q)
	}
	if r := get("1001"); !r.seen.Equal(now.Add(time.Hour)) {
		t.Errorf("stale row not refreshed: %+v", r)
	}
	// --all asks for everyone again
	if res, err := xprofiles.Run(ctx, c, lk, opts(now.Add(2*time.Hour), false, false)); err != nil || res.Considered != 150 || res.Requests != 2 {
		t.Fatalf("all: %+v %v", res, err)
	}
}

// TestDryRun: everything is fetched and counted, nothing is written.
func TestDryRun(t *testing.T) {
	c, f, lk := setup(t, 3)
	res, err := xprofiles.Run(context.Background(), c, lk, opts(now, true, true))
	if err != nil || res.Returned != 3 || res.AvatarAccepted != 3 || res.Written != 0 || !res.DryRun || f.Requests() != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := count(t, c); n != 0 {
		t.Fatalf("dry run wrote %d rows", n)
	}
}

// TestRateLimited: HTTP 429 on the second request stops the run cleanly;
// the first request's rows stay.
func TestRateLimited(t *testing.T) {
	c, f, lk := setup(t, 120)
	f.RateLimited["user110"] = true
	res, err := xprofiles.Run(context.Background(), c, lk, opts(now, false, true))
	if err != nil || !res.RateLimited || res.Requests != 2 || res.Written != 100 || res.Requested != 100 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := count(t, c); n != 100 {
		t.Fatalf("%d rows", n)
	}
}

// TestCap: at most MaxRequests requests a run.
func TestCap(t *testing.T) {
	c, f, lk := setup(t, xlookup.MaxPerRequest*xprofiles.MaxRequests+5)
	res, err := xprofiles.Run(context.Background(), c, lk, opts(now, true, true))
	if err != nil || !res.Capped || res.Requests != xprofiles.MaxRequests || f.Requests() != xprofiles.MaxRequests {
		t.Fatalf("%+v %v", res, err)
	}
}
