package xavatar

import (
	"context"
	"net/http"
	"testing"
	"time"

	"nday.land/nday/internal/siteicon"
	"nday.land/nday/internal/testutil"
)

// TestRun: only users the public outline shows (enabled, allow-listed,
// with a post in some vulnerability's outline) with an avatar URL are due; an
// image is stored with its sniffed type and hash; a broken URL is 'none'
// and not due again for 30 days unless the URL changes; a failing refresh
// keeps the stored image; Load serves by hash, and never a disabled
// account's picture.
func TestRun(t *testing.T) {
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	c := d.Conn
	good, other := pngBytes(t, 48, 48), pngBytes(t, 32, 32)
	busy := false
	f, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case busy:
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.URL.Path == "/profile_images/1/a.png":
			w.Write(good)
		case r.URL.Path == "/profile_images/2/c.png":
			w.Write(other)
		default:
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte("<html>not an image</html>"))
		}
	})
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for _, q := range []string{
		`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('1', 'alice', true), ('2', 'bob', true), ('3', 'off', false), ('4', 'noimg', true),
            ('6', 'nocve', true)`,
		`INSERT INTO vuln (cve_id, first_seen_at) VALUES ('CVE-2026-20001', now())`,
		// posts in the outline of CVE-2026-20001 for 1-4; user 6's only post
		// names no CVE (x_post_no_cve), so no page lists them
		`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url, detail, dedupe_key)
            SELECT 'CVE-2026-20001', 'social_post', '2026-11-01T00:00:00Z', now(), 'xposts', NULL,
                   jsonb_build_object('post_id', id, 'author_id', id), id FROM unnest(ARRAY['1', '2', '3', '4']) AS id`,
		`INSERT INTO x_post_no_cve (post_id, author_id, author_handle, text, posted_at, url, observed_at)
            VALUES ('60', '6', 'nocve', 'no id here', '2026-11-01T00:00:00Z', 'https://x.com/nocve/status/60', now())`,
		`INSERT INTO x_user (user_id, name, avatar_url, seen_at) VALUES
            ('1', 'Alice', '` + base + `a.png', now()),
            ('2', 'Bob', '` + base + `b.png', now()),
            ('3', 'Off', '` + base + `a.png', now()),
            ('4', 'No image', NULL, now()),
            ('5', 'Not listed', '` + base + `a.png', now()),
            ('6', 'No CVE', '` + base + `a.png', now())`,
	} {
		if _, err := c.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	opts := func(at time.Time) Options {
		return Options{Fetcher: f, Now: func() time.Time { return at }, Sleep: func(context.Context, time.Duration) error { return nil }}
	}
	type row struct {
		status, hash, ct *string
		failures         int
		next             *time.Time
	}
	get := func(id string) row {
		t.Helper()
		var r row
		if err := c.QueryRow(ctx, `SELECT avatar_status, avatar_hash, avatar_type, avatar_failures, avatar_next_try_at FROM x_user WHERE user_id = $1`, id).
			Scan(&r.status, &r.hash, &r.ct, &r.failures, &r.next); err != nil {
			t.Fatal(err)
		}
		return r
	}

	res, err := Run(ctx, c, opts(now))
	if err != nil {
		t.Fatal(err)
	}
	if res.Candidates != 2 || res.OK != 1 || res.None != 1 || res.Error != 0 {
		t.Fatalf("first run: %+v", res)
	}
	a, b := get("1"), get("2")
	if *a.status != "ok" || *a.ct != "image/png" || *a.hash != siteicon.Hash(good) || !a.next.Equal(now.Add(RefreshOK)) {
		t.Fatalf("alice: %+v", a)
	}
	if *b.status != "none" || b.hash != nil || !b.next.Equal(now.Add(RetryNone)) {
		t.Fatalf("bob: %+v", b)
	}
	if get("3").status != nil || get("5").status != nil || get("6").status != nil {
		t.Fatal("a disabled, unlisted or outline-less user was fetched")
	}
	av, err := Load(ctx, c, *a.hash, now)
	if err != nil || av == nil || av.ContentType != "image/png" || string(av.Image) != string(good) {
		t.Fatalf("load: %+v %v", av, err)
	}
	for _, h := range []string{"0000000000000000", "../../etc", "", "ABCDEF0123456789"} {
		if av, err := Load(ctx, c, h, now); av != nil || err != nil {
			t.Errorf("load %q: %+v %v", h, av, err)
		}
	}

	// nothing is due a day later
	if res, err := Run(ctx, c, opts(now.Add(24*time.Hour))); err != nil || res.Candidates != 0 {
		t.Fatalf("second run: %+v %v", res, err)
	}
	// a new URL is due at once
	if _, err := c.Exec(ctx, `UPDATE x_user SET avatar_url = $1 WHERE user_id = '2'`, "https://pbs.twimg.com/profile_images/2/c.png"); err != nil {
		t.Fatal(err)
	}
	if res, err := Run(ctx, c, opts(now.Add(25*time.Hour))); err != nil || res.Candidates != 1 || res.OK != 1 {
		t.Fatalf("new URL: %+v %v", res, err)
	}
	// a failing refresh keeps the image, backs off, counts failures
	busy = true
	later := now.Add(RefreshOK + time.Hour)
	if res, err := Run(ctx, c, opts(later)); err != nil || res.Candidates != 1 || res.Error != 1 {
		t.Fatalf("busy run: %+v %v", res, err)
	}
	if a := get("1"); *a.status != "ok" || *a.hash != siteicon.Hash(good) || a.failures != 1 || !a.next.Equal(later.Add(siteicon.ErrorDelay(1))) {
		t.Fatalf("alice after a failure: %+v", a)
	}
	// a disabled account's picture is not served
	if _, err := c.Exec(ctx, `UPDATE x_accounts SET enabled = false WHERE user_id = '1'`); err != nil {
		t.Fatal(err)
	}
	if av, err := Load(ctx, c, *a.hash, now); err != nil || av != nil {
		t.Fatalf("disabled account served: %+v %v", av, err)
	}
	// an outline-less author's stored picture (written by hand) is never
	// served either
	if _, err := c.Exec(ctx, `UPDATE x_user SET avatar_status = 'ok', avatar_type = 'image/png', avatar_image = $1,
        avatar_hash = 'fedcba9876543210' WHERE user_id = '6'`, good); err != nil {
		t.Fatal(err)
	}
	if av, err := Load(ctx, c, "fedcba9876543210", now); err != nil || av != nil {
		t.Fatalf("outline-less author served: %+v %v", av, err)
	}
	if b := get("2"); b.hash == nil || *b.hash != siteicon.Hash(other) {
		t.Fatalf("bob: %+v", b)
	}
}
