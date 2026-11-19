package xlinks_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xlinks"
)

func TestClassify(t *testing.T) {
	const post = "2000000000000000001"
	for _, tc := range []struct {
		url, host, kind string
	}{
		{"https://x.com/alice_sec/status/2000000000000000001/photo/1", "x.com", "media"},
		{"https://twitter.com/alice_sec/status/2000000000000000001/video/1", "twitter.com", "media"},
		{"https://x.com/alice_sec/status/2000000000000000002/photo/1", "x.com", "quote"},
		{"https://twitter.com/bob_sec/status/1999999999999999999", "twitter.com", "quote"},
		{"https://x.com/i/web/status/1999999999999999999", "x.com", "quote"},
		{"https://x.com/alice_sec", "x.com", "other"},
		{"https://github.com/acme/widget/commit/0123abcd", "github.com", "patch"},
		{"https://github.com/acme/widget/pull/42", "github.com", "patch"},
		{"https://github.com/acme/widget/compare/v1.0...v1.1", "github.com", "patch"},
		{"https://www.github.com/acme/widget", "github.com", "code"},
		{"https://github.com/acme/widget-poc/blob/main/exploit.py", "github.com", "code"},
		{"https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "github.com", "advisory"},
		// a repository's own security advisories are advisories, not code
		{"https://github.com/acme/widget/security/advisories/GHSA-gpwc-27cw-rh9r", "github.com", "advisory"},
		{"https://www.github.com/acme/widget/security/advisories", "github.com", "advisory"},
		{"https://github.com/acme/widget/security/advisories/", "github.com", "advisory"},
		{"https://github.com/acme/widget/security/policy", "github.com", "code"},
		{"https://github.com/acme/widget/security/advisories-list", "github.com", "code"},
		{"https://github.com/acme/security/advisories", "github.com", "code"}, // the repository "security" of acme
		{"https://github.com/acme", "github.com", "other"},
		{"https://gist.github.com/someone/0123abcd", "gist.github.com", "code"},
		{"https://gitlab.com/acme/widget", "gitlab.com", "code"},
		{"https://gitlab.com/acme/widget/-/commit/0123abcd", "gitlab.com", "patch"},
		{"https://chromium-review.googlesource.com/c/v8/v8/+/1234567", "chromium-review.googlesource.com", "patch"},
		{"https://crbug.com/123456", "crbug.com", "patch"},
		{"https://issues.chromium.org/issues/123456", "issues.chromium.org", "patch"},
		{"https://www.exploit-db.com/exploits/12345", "exploit-db.com", "poc"},
		{"https://packetstormsecurity.com/files/1/x.html", "packetstormsecurity.com", "poc"},
		{"https://packetstorm.news/files/id/1", "packetstorm.news", "poc"},
		{"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1111", "msrc.microsoft.com", "advisory"},
		{"https://NVD.NIST.GOV/vuln/detail/CVE-2026-1111", "nvd.nist.gov", "advisory"},
		{"https://www.cve.org/CVERecord?id=CVE-2026-1111", "cve.org", "advisory"},
		{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "cisa.gov", "advisory"},
		{"https://blog.cisa.gov.evil.example/x", "blog.cisa.gov.evil.example", "other"},
		{"http://example.com/writeup", "example.com", "other"},
		{"ftp://exploit-db.com/x", "", "other"},
		{"javascript:alert(1)", "", "other"},
		{"not a url", "", "other"},
		{"https://", "", "other"},
		{"", "", "other"},
	} {
		host, kind := xlinks.Classify(tc.url, post)
		if host != tc.host || kind != tc.kind {
			t.Errorf("%q: %q %q, want %q %q", tc.url, host, kind, tc.host, tc.kind)
		}
	}
}

func TestIsShortURL(t *testing.T) {
	for s, want := range map[string]bool{
		"https://t.co/AbC123":      true,
		"http://t.co/AbC123":       false,
		"https://t.co/":            false,
		"https://t.co/AbC/1":       false,
		"https://t.co.evil/AbC":    false,
		"https://t.co/AbC?x=1":     false,
		"https://evil.example/AbC": false,
	} {
		if xlinks.IsShortURL(s) != want {
			t.Errorf("%q: want %v", s, want)
		}
	}
}

// The resolver against a local server standing in for t.co: one request per
// link, no redirect followed, non-t.co rows refused without a request.
func TestResolve(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/okPatch":
			w.Header().Set("Location", "https://github.com/acme/widget/commit/0123abcd")
			w.WriteHeader(http.StatusMovedPermanently)
		case "/okMedia":
			w.Header().Set("Location", "https://x.com/alice_sec/status/2000000000000000001/photo/1")
			w.WriteHeader(http.StatusMovedPermanently)
		case "/loop":
			// a redirect to ourselves: must not be followed
			w.Header().Set("Location", "http://"+r.Host+"/never")
			w.WriteHeader(http.StatusFound)
		default: // no Location
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO x_post_link (post_id, pos, short_url, kind, origin, status, created_at) VALUES
        ('2000000000000000001', 0, 'https://t.co/okPatch', 'other', 'api', 'pending', '2026-11-01'),
        ('2000000000000000001', 1, 'https://t.co/okMedia', 'other', 'api', 'pending', '2026-11-01'),
        ('2000000000000000001', 2, 'https://t.co/noLoc', 'other', 'api', 'pending', '2026-11-01'),
        ('2000000000000000001', 3, 'https://evil.example/abc', 'other', 'api', 'pending', '2026-11-01'),
        ('2000000000000000001', 4, 'https://t.co/loop', 'other', 'api', 'pending', '2026-11-01'),
        ('2000000000000000002', 0, 'https://t.co/done', 'other', 'api', 'ok', '2026-11-01')`)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	sleeps := 0
	opt := xlinks.Options{BaseURL: srv.URL, Now: func() time.Time { return now },
		Sleep:  func(context.Context, time.Duration) error { sleeps++; return nil },
		Logger: slog.New(slog.NewTextHandler(&strings.Builder{}, nil))}

	res, err := xlinks.Resolve(ctx, d.Conn, opt)
	if err != nil {
		t.Fatal(err)
	}
	if res != (xlinks.Result{Candidates: 5, Resolved: 3, Retry: 1, Refused: 1, Requests: 4}) || sleeps != 3 {
		t.Fatalf("%+v sleeps=%d", res, sleeps)
	}
	type row struct {
		final, host          *string
		kind, origin, status string
		attempts             int
		resolved             *time.Time
	}
	get := func(post string, pos int) row {
		t.Helper()
		var r row
		if err := d.Conn.QueryRow(ctx, `SELECT final_url, host, kind, origin, status, attempts, resolved_at FROM x_post_link
            WHERE post_id = $1 AND pos = $2`, post, pos).Scan(&r.final, &r.host, &r.kind, &r.origin, &r.status, &r.attempts, &r.resolved); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := get("2000000000000000001", 0); r.final == nil || *r.final != "https://github.com/acme/widget/commit/0123abcd" ||
		*r.host != "github.com" || r.kind != "patch" || r.origin != "resolver" || r.status != "ok" || r.resolved == nil || !r.resolved.Equal(now) {
		t.Errorf("patch row %+v", r)
	}
	if r := get("2000000000000000001", 1); r.kind != "media" || r.status != "ok" {
		t.Errorf("media row %+v", r)
	}
	// the redirect target is stored, never requested
	if r := get("2000000000000000001", 4); r.status != "ok" || *r.host != "127.0.0.1" || hits["/never"] != 0 {
		t.Errorf("loop row %+v hits %v", r, hits)
	}
	if r := get("2000000000000000001", 3); r.status != "failed" || r.attempts != 0 {
		t.Errorf("refused row %+v", r)
	}
	if r := get("2000000000000000001", 2); r.status != "pending" || r.attempts != 1 {
		t.Errorf("no-Location row %+v", r)
	}
	// two more passes: the no-Location row fails at 3 attempts, nothing else is requested
	for i := 0; i < 2; i++ {
		if _, err := xlinks.Resolve(ctx, d.Conn, opt); err != nil {
			t.Fatal(err)
		}
	}
	if r := get("2000000000000000001", 2); r.status != "failed" || r.attempts != 3 {
		t.Errorf("no-Location row %+v", r)
	}
	res, err = xlinks.Resolve(ctx, d.Conn, opt)
	if err != nil || res.Candidates != 0 || res.Requests != 0 {
		t.Errorf("%+v %v", res, err)
	}
	if hits["/okPatch"] != 1 || hits["/noLoc"] != 3 || len(hits) != 4 {
		t.Errorf("hits %v", hits)
	}

	// a cancelled context stops before any request
	exec(`INSERT INTO x_post_link (post_id, pos, short_url, kind, origin, status) VALUES
        ('2000000000000000003', 0, 'https://t.co/okPatch', 'other', 'api', 'pending')`)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if res, err := xlinks.Resolve(cctx, d.Conn, opt); err == nil || res.Requests != 0 {
		t.Errorf("cancelled: %+v %v", res, err)
	}
}
