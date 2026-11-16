package webpages

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"nday.land/nday/internal/pagefetch"
	"nday.land/nday/internal/testutil"
)

// testClient reaches srv under any *.test name on port 80 and nothing else.
func testClient(srv *httptest.Server) *pagefetch.Client {
	lis := srv.Listener.Addr().String()
	return pagefetch.New(pagefetch.Options{UserAgent: UserAgent,
		RewriteAddr: func(a string) string {
			if strings.HasSuffix(a, ".test:80") || strings.HasSuffix(a, ".test.:80") {
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
}

func TestSameHost(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"http://a.example/x", "https://a.example/y", true},
		{"https://www.a.example/x", "https://A.EXAMPLE./y", true},
		{"https://a.example/x", "https://a.example:443/y", true},
		{"https://trusted.example/r?to=evil", "https://evil.example/", false},
		{"https://a.example/", "https://sub.a.example/", false},
		{"https://www.www.a.example/", "https://a.example/", false},
		{"https://a.example/", "::bad", false},
	} {
		if got := sameHost(c.a, c.b); got != c.want {
			t.Errorf("sameHost(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// Regressions: a page whose handling panics is made 'none' and the pass
// goes on; a redirect to another host gives no title; a context that
// expires during a request leaves the row 'pending' with attempts unchanged.
func TestFetchPendingRobust(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, "http://evil.test/page", http.StatusFound)
		case "/www":
			http.Redirect(w, r, "http://WWW.Same.test./page", http.StatusFound)
		case "/hang":
			close(hang)
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<title>Title of " + r.Host + r.URL.Path + "</title>"))
	}))
	defer srv.Close()
	for i, u := range []string{"http://boom.test/p", "http://ok.test/p", "http://trusted.test/away", "http://same.test/www"} {
		if _, err := d.Conn.Exec(ctx, `INSERT INTO web_page (url_key, url, first_source, created_at) VALUES ($1, $1, 'xposts', $2)`,
			u, time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
	}
	var logs strings.Builder
	opt := Options{Client: testClient(srv), Sleep: func(context.Context, time.Duration) error { return nil },
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		extract: func(p *pagefetch.Page) pagefetch.Meta {
			if strings.Contains(p.URL, "boom") {
				panic("boom extract")
			}
			return pagefetch.ExtractMeta(p)
		}}
	res, err := FetchPending(ctx, d.Conn, opt)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Result{Candidates: 4, OK: 2, None: 2, OtherHost: 1, Panics: 1, Requests: 4}); res != want {
		t.Errorf("%+v, want %+v", res, want)
	}
	got := map[string]string{}
	rows, _ := d.Conn.Query(ctx, `SELECT url_key, status || ' ' || attempts || ' ' || COALESCE(title, '-') FROM web_page`)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		got[k] = v
	}
	for k, want := range map[string]string{
		"http://boom.test/p":       "none 1 -",
		"http://ok.test/p":         "ok 1 Title of ok.test/p",
		"http://trusted.test/away": "none 1 -",
		"http://same.test/www":     "ok 1 Title of WWW.Same.test./page",
	} {
		if got[k] != want {
			t.Errorf("%s: %q, want %q", k, got[k], want)
		}
	}
	if !strings.Contains(logs.String(), "boom extract") || strings.Contains(logs.String(), "<title>") {
		t.Errorf("log: %s", logs.String())
	}

	// a deadline that expires during the request
	if _, err := d.Conn.Exec(ctx, `INSERT INTO web_page (url_key, url, first_source) VALUES ('http://hang.test/hang', 'http://hang.test/hang', 'xposts')`); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	go func() { <-hang; cancel() }()
	if _, err := FetchPending(cctx, d.Conn, opt); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled pass: %v", err)
	}
	var st string
	var att int
	if err := d.Conn.QueryRow(ctx, `SELECT status, attempts FROM web_page WHERE url_key = 'http://hang.test/hang'`).Scan(&st, &att); err != nil || st != "pending" || att != 0 {
		t.Errorf("after cancel: %s %d %v", st, att, err)
	}
}

// Slow retry: a 'failed' page is tried again only when its last attempt is
// older than SlowRetryAfter, up to MaxTotalAttempts in all.
func TestSlowRetry(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<title>Back up</title>"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for _, r := range []struct {
		url      string
		attempts int
		ago      time.Duration
	}{
		{"http://recent.test/x", 3, 23 * time.Hour}, // not yet
		{"http://old.test/x", 3, 25 * time.Hour},    // eligible: 503 again
		{"http://five.test/x", 5, 48 * time.Hour},   // eligible: last try
		{"http://six.test/x", 6, 100 * time.Hour},   // capped
		{"http://back.test/ok", 4, 30 * time.Hour},  // eligible: now ok
	} {
		if _, err := d.Conn.Exec(ctx, `INSERT INTO web_page (url_key, url, first_source, status, attempts, fetched_at)
            VALUES ($1, $1, 'xposts', 'failed', $2, $3)`, r.url, r.attempts, now.Add(-r.ago)); err != nil {
			t.Fatal(err)
		}
	}
	opt := Options{Client: testClient(srv), Now: func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil }, Logger: slog.New(slog.NewTextHandler(&strings.Builder{}, nil))}
	res, err := FetchPending(ctx, d.Conn, opt)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Result{Candidates: 3, OK: 1, Failed: 2, Requests: 3}); res != want {
		t.Errorf("%+v, want %+v", res, want)
	}
	state := func(u string) string {
		var s string
		var a int
		var at time.Time
		if err := d.Conn.QueryRow(ctx, `SELECT status, attempts, fetched_at FROM web_page WHERE url_key = $1`, u).Scan(&s, &a, &at); err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%s %d %v", s, a, now.Sub(at))
	}
	for u, want := range map[string]string{
		"http://recent.test/x": "failed 3 23h0m0s", "http://old.test/x": "failed 4 0s", "http://five.test/x": "failed 6 0s",
		"http://six.test/x": "failed 6 100h0m0s", "http://back.test/ok": "ok 5 0s",
	} {
		if got := state(u); got != want {
			t.Errorf("%s: %s, want %s", u, got, want)
		}
	}
	// a day later: recent (3) and old (4) are tried again; five and six are capped
	opt.Now = func() time.Time { return now.Add(SlowRetryAfter + time.Minute) }
	res, err = FetchPending(ctx, d.Conn, opt)
	if err != nil || res.Candidates != 2 {
		t.Errorf("next day: %+v %v", res, err)
	}
	if state("http://five.test/x")[:8] != "failed 6" || state("http://old.test/x")[:8] != "failed 5" {
		t.Errorf("next day states: %s / %s", state("http://five.test/x"), state("http://old.test/x"))
	}
}
