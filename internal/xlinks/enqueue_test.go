package xlinks_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xlinks"
)

// EnqueuePages queues the final URLs of 'ok' links of the shown kinds,
// once per key, refusing URLs that break the fetch rules; idempotent.
func TestEnqueuePages(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, final_url, kind, title, origin, status, created_at) VALUES
        ('2000000000000000001', 0, 'https://t.co/a', 'https://blog.example/post', 'other', NULL, 'api', 'ok', '2026-11-01'),
        ('2000000000000000001', 1, 'https://t.co/b', 'https://github.com/o/r/commit/abc', 'patch', 'API title', 'api', 'ok', '2026-11-01'),
        ('2000000000000000001', 2, 'https://t.co/c', 'https://pbs.twimg.com/media/x.jpg', 'media', NULL, 'api', 'ok', '2026-11-01'),
        ('2000000000000000001', 3, 'https://t.co/d', 'https://x.com/a/status/1', 'quote', NULL, 'api', 'ok', '2026-11-01'),
        ('2000000000000000001', 4, 'https://t.co/e', 'http://127.0.0.1/admin', 'other', NULL, 'api', 'ok', '2026-11-01'),
        ('2000000000000000001', 5, 'https://t.co/f', 'javascript:alert(1)', 'other', NULL, 'api', 'ok', '2026-11-01'),
        ('2000000000000000001', 6, 'https://t.co/g', NULL, 'other', NULL, 'api', 'pending', '2026-11-01'),
        ('2000000000000000001', 7, 'https://t.co/h', 'https://failed.example/', 'other', NULL, 'resolver', 'failed', '2026-11-01'),
        ('2000000000000000002', 0, 'https://t.co/i', 'https://BLOG.example/post/', 'other', NULL, 'api', 'ok', '2026-11-02'),
        ('2000000000000000002', 1, 'https://t.co/j', 'https://blog.example/post', 'other', NULL, 'api', 'ok', '2026-11-02'),
        ('2000000000000000002', 2, 'https://t.co/k', 'https://exploit-db.com/exploits/1', 'poc', NULL, 'api', 'ok', '2026-11-02')`); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(&strings.Builder{}, nil))
	res, err := xlinks.EnqueuePages(ctx, d.Conn, log)
	if err != nil {
		t.Fatal(err)
	}
	if res != (xlinks.EnqueueResult{Candidates: 7, Added: 3, Refused: 2}) {
		t.Errorf("sweep 1: %+v", res)
	}
	rows, err := d.Conn.Query(ctx, `SELECT url_key || ' ' || url || ' ' || status || ' ' || first_source FROM web_page ORDER BY url_key`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		got = append(got, s)
	}
	want := []string{"https://blog.example/post https://blog.example/post pending xposts",
		"https://exploit-db.com/exploits/1 https://exploit-db.com/exploits/1 pending xposts",
		"https://github.com/o/r/commit/abc https://github.com/o/r/commit/abc pending xposts"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("queue:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// again: nothing is re-read (refused URLs and other spellings of a
	// queued key included: no churn)
	res, err = xlinks.EnqueuePages(ctx, d.Conn, log)
	if err != nil || res != (xlinks.EnqueueResult{}) {
		t.Errorf("sweep 2: %+v %v", res, err)
	}
	// a link whose final URL changes is swept again
	if _, err := d.Conn.Exec(ctx, `UPDATE x_post_link SET final_url = 'https://blog.example/new' WHERE post_id = '2000000000000000002' AND pos = 0`); err != nil {
		t.Fatal(err)
	}
	res, err = xlinks.EnqueuePages(ctx, d.Conn, log)
	if err != nil || res != (xlinks.EnqueueResult{Candidates: 1, Added: 1}) {
		t.Errorf("sweep 3: %+v %v", res, err)
	}
}
