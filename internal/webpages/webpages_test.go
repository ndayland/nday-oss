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
