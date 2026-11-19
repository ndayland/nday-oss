package webpages_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"nday.land/nday/internal/pagefetch"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/webpages"
)

func TestEnqueueAndFetch(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if r.Header.Get("User-Agent") != webpages.UserAgent {
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<head><meta property="og:site_name" content="Blog"><title>A write-up | Blog</title></head>`))
		case "/notitle":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<head></head><body>x</body>`))
		case "/wall":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<title>Just a moment...</title>`))
		case "/pdf":
			w.Header().Set("Content-Type", "application/pdf")
			w.Write([]byte("%PDF"))
		case "/gone":
			w.WriteHeader(404)
		case "/busy":
			w.WriteHeader(503)
		case "/slow":
			w.WriteHeader(429)
		case "/toprivate":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	lis := srv.Listener.Addr().String()
	client := pagefetch.New(pagefetch.Options{UserAgent: webpages.UserAgent,
		RewriteAddr: func(a string) string {
			if strings.HasSuffix(a, ".test:80") {
				return lis
			}
			return a
		},
		DialControl: func(_, address string, _ syscall.RawConn) error {
			if address != lis {
				return errors.Join(pagefetch.ErrRefused, errors.New("not the listener"))
			}
			return nil
		}})

	// Enqueue: validation, idempotent by key
	for _, u := range []string{"http://a.test/ok", "http://a.test/notitle", "http://a.test/wall", "http://a.test/pdf",
		"http://a.test/gone", "http://a.test/busy", "http://a.test/slow", "http://a.test/toprivate"} {
		if added, err := webpages.Enqueue(ctx, d.Conn, u, "xposts"); err != nil || !added {
			t.Fatalf("enqueue %s: %v %v", u, added, err)
		}
	}
	if added, err := webpages.Enqueue(ctx, d.Conn, "HTTP://A.TEST/ok/#frag", "other_src"); err != nil || added {
		t.Errorf("same key enqueued again: %v %v", added, err)
	}
	for _, u := range []string{"http://127.0.0.1/x", "https://a.test:8443/", "https://u@a.test/", "javascript:alert(1)"} {
		if _, err := webpages.Enqueue(ctx, d.Conn, u, "xposts"); !errors.Is(err, pagefetch.ErrRefused) {
			t.Errorf("enqueue %s: %v", u, err)
		}
	}
	if _, err := webpages.Enqueue(ctx, d.Conn, "http://a.test/x", "Bad Source"); !errors.Is(err, webpages.ErrSource) {
		t.Errorf("bad source: %v", err)
	}
	// a stored row that no longer passes the URL rules: refused without a request
	if _, err := d.Conn.Exec(ctx, `INSERT INTO web_page (url_key, url, first_source, created_at) VALUES ('http://10.0.0.1', 'http://10.0.0.1/', 'xposts', '2000-01-01')`); err != nil {
		t.Fatal(err)
	}
	// an 'ok' row is not picked again
	if _, err := d.Conn.Exec(ctx, `INSERT INTO web_page (url_key, url, first_source, status, title) VALUES ('http://done.test', 'http://done.test/', 'xposts', 'ok', 'Done')`); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	sleeps := 0
	opt := webpages.Options{Client: client, Now: func() time.Time { return now },
		Sleep:  func(context.Context, time.Duration) error { sleeps++; return nil },
		Logger: slog.New(slog.NewTextHandler(&strings.Builder{}, nil))}
	res, err := webpages.FetchPending(ctx, d.Conn, opt)
	if err != nil {
		t.Fatal(err)
	}
	if want := (webpages.Result{Candidates: 9, OK: 1, None: 6, Retry: 2, Refused: 2, Requests: 8}); res != want || sleeps != 7 {
		t.Errorf("pass 1: %+v (sleeps %d), want %+v", res, sleeps, want)
	}
	type row struct {
		status   string
		attempts int
		title    *string
		site     *string
		fetched  *time.Time
	}
	get := func(key string) row {
		t.Helper()
		var r row
		if err := d.Conn.QueryRow(ctx, `SELECT status, attempts, title, site_name, fetched_at FROM web_page WHERE url_key = $1`, key).
			Scan(&r.status, &r.attempts, &r.title, &r.site, &r.fetched); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		return r
	}
	if r := get("http://a.test/ok"); r.status != "ok" || r.attempts != 1 || r.title == nil || *r.title != "A write-up" ||
		r.site == nil || *r.site != "Blog" || r.fetched == nil || !r.fetched.Equal(now) {
		t.Errorf("ok: %+v", r)
	}
	for _, k := range []string{"http://a.test/notitle", "http://a.test/wall", "http://a.test/pdf", "http://a.test/gone", "http://a.test/toprivate"} {
		if r := get(k); r.status != "none" || r.attempts != 1 || r.title != nil {
			t.Errorf("%s: %+v", k, r)
		}
	}
	if r := get("http://10.0.0.1"); r.status != "none" || r.attempts != 0 || r.fetched != nil {
		t.Errorf("refused row: %+v", r)
	}
	if r := get("http://a.test/busy"); r.status != "pending" || r.attempts != 1 {
		t.Errorf("busy: %+v", r)
	}
	// two more passes: the transient ones become 'failed' at 3 attempts
	for i := 0; i < 2; i++ {
		if _, err := webpages.FetchPending(ctx, d.Conn, opt); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"http://a.test/busy", "http://a.test/slow"} {
		if r := get(k); r.status != "failed" || r.attempts != 3 {
			t.Errorf("%s: %+v", k, r)
		}
	}
	res, err = webpages.FetchPending(ctx, d.Conn, opt)
	if err != nil || res.Candidates != 0 {
		t.Errorf("pass 4: %+v %v", res, err)
	}
	mu.Lock()
	if hits["/ok"] != 1 || hits["/busy"] != 3 || hits["/latest/meta-data/"] != 0 {
		t.Errorf("hits: %v", hits)
	}
	mu.Unlock()

	// limit, oldest first, and a cancelled context stops the pass
	for _, u := range []string{"http://b.test/ok", "http://c.test/ok"} {
		if _, err := webpages.Enqueue(ctx, d.Conn, u, "xposts"); err != nil {
			t.Fatal(err)
		}
	}
	opt.Limit = 1
	res, err = webpages.FetchPending(ctx, d.Conn, opt)
	if err != nil || res.Candidates != 1 || res.OK != 1 || get("http://b.test/ok").status != "ok" || get("http://c.test/ok").status != "pending" {
		t.Errorf("limit 1: %+v %v", res, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := webpages.FetchPending(cctx, d.Conn, opt); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// TestPublishedAndBackfill: a new fetch stores the publication time the page
// states; the backfill re-fetches older 'ok' pages once each (oldest first,
// at most Backfill per pass), writes only the publication time and the
// mark, and never touches status, attempts or title, whatever the outcome.
func TestPublishedAndBackfill(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/new":
			w.Write([]byte(`<head><title>New one</title><meta property="article:published_time" content="2026-11-10T08:00:00+01:00"></head>`))
		case "/old1":
			w.Write([]byte(`<head><title>Changed title</title></head><body><script type="application/ld+json">{"@type":"Article","datePublished":"2026-10-01"}</script>`))
		case "/old2":
			w.Write([]byte(`<head><title>No date</title></head>`))
		case "/future":
			w.Write([]byte(`<head><title>Future</title><meta name="date" content="2027-01-01"></head>`))
		default:
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	lis := srv.Listener.Addr().String()
	client := pagefetch.New(pagefetch.Options{UserAgent: webpages.UserAgent,
		RewriteAddr: func(a string) string {
			if strings.HasSuffix(a, ".test:80") {
				return lis
			}
			return a
		},
		DialControl: func(_, address string, _ syscall.RawConn) error {
			if address != lis {
				return errors.Join(pagefetch.ErrRefused, errors.New("not the listener"))
			}
			return nil
		}})
	for _, q := range []string{
		`INSERT INTO web_page (url_key, url, first_source, status, attempts, title, fetched_at, created_at) VALUES
			('http://a.test/old1', 'http://a.test/old1', 'xposts', 'ok', 1, 'Old one', '2026-01-01', '2026-01-01'),
			('http://a.test/old2', 'http://a.test/old2', 'xposts', 'ok', 1, 'Old two', '2026-01-01', '2026-01-02'),
			('http://a.test/old3', 'http://a.test/old3', 'xposts', 'ok', 2, 'Old three', '2026-01-01', '2026-01-03'),
			('http://a.test/old4', 'http://a.test/old4', 'xposts', 'ok', 1, 'Old four', '2026-01-01', '2026-01-04'),
			('http://a.test/none', 'http://a.test/none', 'xposts', 'none', 1, NULL, '2026-01-01', '2026-01-01')`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []string{"http://a.test/new", "http://a.test/future"} {
		if _, err := webpages.Enqueue(ctx, d.Conn, u, "xposts"); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	opt := webpages.Options{Client: client, Now: func() time.Time { return now },
		Sleep:  func(context.Context, time.Duration) error { return nil },
		Logger: slog.New(slog.NewTextHandler(&strings.Builder{}, nil))}
	// without Backfill, old rows are not requested
	res, err := webpages.FetchPending(ctx, d.Conn, opt)
	if err != nil || res.OK != 2 || res.Published != 1 || res.Backfilled != 0 || res.Requests != 2 {
		t.Fatalf("pass 1: %+v %v", res, err)
	}
	type row struct {
		status, title string
		attempts      int
		at            *time.Time
		prec, src     *string
		checked       *time.Time
	}
	get := func(key string) row {
		t.Helper()
		var r row
		if err := d.Conn.QueryRow(ctx, `SELECT status, COALESCE(title, ''), attempts, published_at, published_precision, published_source, published_checked_at
            FROM web_page WHERE url_key = $1`, key).Scan(&r.status, &r.title, &r.attempts, &r.at, &r.prec, &r.src, &r.checked); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		return r
	}
	if r := get("http://a.test/new"); r.at == nil || !r.at.Equal(time.Date(2026, 11, 10, 7, 0, 0, 0, time.UTC)) || *r.prec != "exact" ||
		*r.src != "meta:article:published_time" || r.checked == nil || !r.checked.Equal(now) {
		t.Errorf("new: %+v", r)
	}
	if r := get("http://a.test/future"); r.status != "ok" || r.at != nil || r.prec != nil || r.checked == nil {
		t.Errorf("implausible date stored: %+v", r)
	}
	// backfill: two per pass, oldest first
	opt.Backfill = 2
	res, err = webpages.FetchPending(ctx, d.Conn, opt)
	if err != nil || res.Candidates != 0 || res.Backfilled != 2 || res.Published != 1 || res.Requests != 2 {
		t.Fatalf("backfill 1: %+v %v", res, err)
	}
	if r := get("http://a.test/old1"); r.status != "ok" || r.title != "Old one" || r.attempts != 1 || r.at == nil ||
		!r.at.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || *r.prec != "day" || *r.src != "json-ld" || r.checked == nil {
		t.Errorf("old1: %+v", r)
	}
	if r := get("http://a.test/old2"); r.at != nil || r.checked == nil || r.title != "Old two" {
		t.Errorf("old2: %+v", r)
	}
	if r := get("http://a.test/old3"); r.checked != nil {
		t.Errorf("old3 visited in pass 1: %+v", r)
	}
	// a failure (503) only marks the page; it is not tried again
	res, err = webpages.FetchPending(ctx, d.Conn, opt)
	if err != nil || res.Backfilled != 2 || res.Published != 0 {
		t.Fatalf("backfill 2: %+v %v", res, err)
	}
	if r := get("http://a.test/old3"); r.status != "ok" || r.attempts != 2 || r.title != "Old three" || r.at != nil || r.checked == nil {
		t.Errorf("old3: %+v", r)
	}
	res, err = webpages.FetchPending(ctx, d.Conn, opt)
	if err != nil || res.Backfilled != 0 || res.Requests != 0 {
		t.Errorf("backfill 3: %+v %v", res, err)
	}
	if r := get("http://a.test/none"); r.checked != nil {
		t.Errorf("a 'none' page was backfilled: %+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range []string{"/old1", "/old2", "/old3", "/old4", "/new"} {
		if hits[p] != 1 {
			t.Errorf("%s requested %d times", p, hits[p])
		}
	}
	// a deadline closer than one request: the backfill stops without error
	if _, err := d.Conn.Exec(ctx, `UPDATE web_page SET published_checked_at = NULL WHERE url_key = 'http://a.test/old4'`); err != nil {
		t.Fatal(err)
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if res, err := webpages.FetchPending(dctx, d.Conn, opt); err != nil || res.Backfilled != 0 {
		t.Errorf("near deadline: %+v %v", res, err)
	}
}
