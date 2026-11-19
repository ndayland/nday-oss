package siteicon

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/testutil"
)

type row struct {
	status   string
	ct, hash *string
	image    []byte
	next     time.Time
	failures int
}

func readRow(t *testing.T, c *pgx.Conn, host string) *row {
	t.Helper()
	var r row
	err := c.QueryRow(context.Background(), `SELECT status, content_type, hash, image, next_try_at, failures FROM site_icon WHERE host = $1`, host).
		Scan(&r.status, &r.ct, &r.hash, &r.image, &r.next, &r.failures)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return &r
}

// TestRun: the hosts of stored links (event URLs, PoC and fix-commit URLs
// in event.detail, resolved X post links) and the built-in hosts are due;
// outcomes are stored with their back-off; a failing refresh keeps a good
// icon; not-due hosts are left alone; Lookup and Load read what is stored.
func TestRun(t *testing.T) {
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	c := d.Conn
	for _, q := range []string{
		`INSERT INTO vuln (cve_id, first_seen_at) VALUES ('CVE-2026-10001', now()), ('CVE-2026-10002', now())`,
		`INSERT INTO event (cve_id, type, observed_at, source, url, dedupe_key) VALUES
            ('CVE-2026-10001', 'disclosed', now(), 'cvelist', 'https://ICO.test/rec', ''),
            ('CVE-2026-10001', 'kev_added', now(), 'kev', 'https://err.test/kev', ''),
            ('CVE-2026-10001', 'analysis_published', now(), 'blog', 'https://user@b.test:8443/x', ''),
            ('CVE-2026-10002', 'disclosed', now(), 'cvelist', 'https://ico.test/rec2', '')`,
		`INSERT INTO event (cve_id, type, observed_at, source, url, detail, dedupe_key) VALUES
            ('CVE-2026-10001', 'poc_published', now(), 'exploitdb', NULL, '{"url": "https://cross.test/poc"}', '1'),
            ('CVE-2026-10001', 'patch_released', now(), 'ghsa', 'https://ico.test/adv', '{"fix_commit_urls": ["https://html.test/c/1", "not a url", "https://[::1]/x"]}', 'g')`,
		`INSERT INTO x_post_link (post_id, pos, short_url, final_url, kind, origin, status) VALUES
            ('1', 0, 'https://t.co/a', 'https://link.test/p', 'other', 'api', 'ok'),
            ('1', 1, 'https://t.co/b', 'https://pending.test/p', 'other', 'api', 'pending'),
            ('1', 2, 'https://t.co/c', 'https://10.1.2.3/p', 'other', 'api', 'ok')`,
	} {
		if _, err := c.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	// the built-in hosts come first, then by linking vulnerabilities
	// (ico.test: 2)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	due, err := Due(ctx, c, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range due {
		got = append(got, x.Host)
	}
	want := "cwe.mitre.org github.com x.com ico.test 10.1.2.3 b.test cross.test err.test html.test link.test"
	if strings.Join(got, " ") != want {
		t.Fatalf("due: %s\nwant %s", strings.Join(got, " "), want)
	}

	ico := icoBytes(t)
	f, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSuffix(r.Host, ":443") + r.URL.Path {
		case "ico.test/favicon.ico":
			w.Write(ico)
		case "err.test/favicon.ico":
			w.WriteHeader(http.StatusBadGateway)
		case "cross.test/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<link rel="icon" href="https://cdn.test/i.ico">`))
		case "cdn.test/i.ico":
			w.Write(ico)
		default:
			http.NotFound(w, r)
		}
	})
	slept := 0
	o := Options{Limit: 100, Fetcher: f, Now: func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { slept++; return nil }}
	// the built-in hosts are refused by the test's dial control (no real
	// host is contacted): 'none' like any refused host
	res, err := Run(ctx, c, o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Candidates != 10 || res.OK != 2 || res.Error != 1 || res.None != 7 || res.Kept != 0 || res.Refused != 6 || res.TimedOut || slept == 0 {
		t.Errorf("run 1: %+v slept %d", res, slept)
	}
	if r := readRow(t, c, "ico.test"); r == nil || r.status != StatusOK || *r.ct != TypeICO || *r.hash != Hash(ico) ||
		string(r.image) != string(ico) || !r.next.Equal(now.Add(RefreshOK)) || r.failures != 0 {
		t.Errorf("ico.test: %+v", r)
	}
	if r := readRow(t, c, "cross.test"); r == nil || r.status != StatusOK {
		t.Errorf("cross.test: %+v", r)
	}
	if r := readRow(t, c, "html.test"); r == nil || r.status != StatusNone || r.image != nil || !r.next.Equal(now.Add(RetryNone)) {
		t.Errorf("html.test: %+v", r)
	}
	if r := readRow(t, c, "10.1.2.3"); r == nil || r.status != StatusNone {
		t.Errorf("address: %+v", r)
	}
	if r := readRow(t, c, "err.test"); r == nil || r.status != StatusError || r.failures != 1 || !r.next.Equal(now.Add(time.Hour)) {
		t.Errorf("err.test: %+v", r)
	}
	if readRow(t, c, "pending.test") != nil {
		t.Error("a pending X link's host was fetched")
	}

	// two hours later only the failed host is due; the second failure
	// waits 4 h
	now = now.Add(2 * time.Hour)
	res, err = Run(ctx, c, o)
	if err != nil || res.Candidates != 1 || res.Error != 1 {
		t.Errorf("run 2: %+v %v", res, err)
	}
	if r := readRow(t, c, "err.test"); r == nil || r.failures != 2 || !r.next.Equal(now.Add(4*time.Hour)) {
		t.Errorf("err.test after 2: %+v", r)
	}

	// a month later ico.test is refreshed and fails: the icon is kept
	if _, err := c.Exec(ctx, `UPDATE site_icon SET next_try_at = $1 WHERE host = 'ico.test'`, now); err != nil {
		t.Fatal(err)
	}
	f2, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	o.Fetcher, o.Limit = f2, 1
	now = now.Add(time.Minute)
	if res, err = Run(ctx, c, o); err != nil || res.Candidates != 1 || res.Kept != 1 {
		t.Errorf("run 3: %+v %v", res, err)
	}
	if r := readRow(t, c, "ico.test"); r == nil || r.status != StatusOK || string(r.image) != string(ico) || r.failures != 1 {
		t.Errorf("ico.test kept: %+v", r)
	}

	// what the site reads
	m, err := Lookup(ctx, c, []string{"ico.test", "cross.test", "html.test", "err.test", "nope.test", "BAD host"})
	if err != nil || len(m) != 2 || m["ico.test"] != Hash(ico) || m["cross.test"] != Hash(ico) {
		t.Errorf("lookup: %v %v", m, err)
	}
	if ic, err := Load(ctx, c, "ico.test"); err != nil || ic == nil || ic.ContentType != TypeICO || ic.Hash != Hash(ico) {
		t.Errorf("load: %+v %v", ic, err)
	}
	for _, h := range []string{"html.test", "nope.test", "ICO.test", "../etc"} {
		if ic, err := Load(ctx, c, h); err != nil || ic != nil {
			t.Errorf("load %q: %+v %v", h, ic, err)
		}
	}

	// the budget stops a run cleanly, leaving the rest due
	if _, err := c.Exec(ctx, `UPDATE site_icon SET next_try_at = $1`, now); err != nil {
		t.Fatal(err)
	}
	o.Limit, o.Budget = 100, time.Nanosecond
	if res, err = Run(ctx, c, o); err != nil || !res.TimedOut || res.OK+res.None+res.Error != 0 {
		t.Errorf("budget: %+v %v", res, err)
	}
}

// TestLookupWithoutTable: before migration 0028 the site has no icons.
func TestLookupWithoutTable(t *testing.T) {
	d := testutil.NewDB(t)
	m, err := Lookup(context.Background(), d.Conn, []string{"github.com"})
	if err != nil || len(m) != 0 {
		t.Errorf("lookup: %v %v", m, err)
	}
	if ic, err := Load(context.Background(), d.Conn, "github.com"); err != nil || ic != nil {
		t.Errorf("load: %v %v", ic, err)
	}
}

func execAll(t *testing.T, c *pgx.Conn, qs ...string) {
	t.Helper()
	for _, q := range qs {
		if _, err := c.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
}

// TestDueRanking: hosts rank by the number of distinct vulnerabilities
// linking them, not by repeated rows; one bucket (last two labels) gives
// at most PerBucket hosts a run.
func TestDueRanking(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	c := d.Conn
	execAll(t, c,
		`INSERT INTO vuln (cve_id, first_seen_at) SELECT 'CVE-2026-' || (20000 + g), now() FROM generate_series(1, 3) g`,
		// spam.test: one vulnerability, 50 events and 50 post links
		`INSERT INTO event (cve_id, type, observed_at, source, url, dedupe_key)
            SELECT 'CVE-2026-20001', 'analysis_published', now(), 'blog', 'https://spam.test/' || g, g::text FROM generate_series(1, 50) g`,
		`INSERT INTO x_post_link (post_id, pos, short_url, final_url, kind, origin, status)
            SELECT '7', g, 'https://t.co/' || g, 'https://spam.test/p' || g, 'other', 'api', 'ok' FROM generate_series(0, 49) g`,
		// real.test: three vulnerabilities, one link each
		`INSERT INTO event (cve_id, type, observed_at, source, url, dedupe_key)
            SELECT 'CVE-2026-' || (20000 + g), 'disclosed', now(), 'cvelist', 'https://real.test/' || g, '' FROM generate_series(1, 3) g`,
		// wildcard subdomains of one site, each linked by two vulnerabilities
		`INSERT INTO event (cve_id, type, observed_at, source, url, dedupe_key)
            SELECT 'CVE-2026-' || (20000 + v), 'poc_published', now(), 'blog', 'https://s' || g || '.wild.test/x', g::text
            FROM generate_series(1, 8) g, generate_series(1, 2) v`,
	)
	due, err := Due(context.Background(), c, time.Now(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	wild := 0
	for _, x := range due {
		if strings.HasSuffix(x.Host, ".wild.test") {
			wild++
			continue
		}
		got = append(got, x.Host)
	}
	if strings.Join(got, " ") != "cwe.mitre.org github.com x.com real.test spam.test" || wild != PerBucket {
		t.Errorf("due: %v, %d wild.test hosts", got, wild)
	}
	// spam.test (1 vulnerability) after the wild.test hosts (2 each)
	if last := due[len(due)-1].Host; last != "spam.test" {
		t.Errorf("last: %s", last)
	}
}

// TestPrune: rows of hosts no page links any more are deleted once their
// last attempt is 90 days old; linked and recent rows stay.
func TestPrune(t *testing.T) {
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	c := d.Conn
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	old, recent := now.Add(-StaleAfter-time.Hour), now.Add(-StaleAfter+time.Hour)
	execAll(t, c,
		`INSERT INTO vuln (cve_id, first_seen_at) VALUES ('CVE-2026-30001', now())`,
		`INSERT INTO event (cve_id, type, observed_at, source, url, dedupe_key) VALUES ('CVE-2026-30001', 'disclosed', now(), 'cvelist', 'https://kept.test/x', '')`)
	for h, at := range map[string]time.Time{"gone.test": old, "fresh.test": recent, "kept.test": old, "github.com": old} {
		if _, err := c.Exec(ctx, `INSERT INTO site_icon (host, status, fetched_at, next_try_at) VALUES ($1, 'none', $2, $2)`, h, at); err != nil {
			t.Fatal(err)
		}
	}
	n, err := Prune(ctx, c, now)
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if readRow(t, c, "gone.test") != nil {
		t.Error("gone.test kept")
	}
	for _, h := range []string{"fresh.test", "kept.test", "github.com"} {
		if readRow(t, c, h) == nil {
			t.Errorf("%s deleted", h)
		}
	}
	// a run prunes at its end
	execAll(t, c, `INSERT INTO site_icon (host, status, fetched_at, next_try_at) VALUES ('gone2.test', 'none', '2020-01-01', '2099-01-01')`,
		`UPDATE site_icon SET next_try_at = '2099-01-01'`)
	f, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	res, err := Run(ctx, c, Options{Fetcher: f, Now: func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil || res.Deleted != 1 || readRow(t, c, "gone2.test") != nil {
		t.Errorf("run: %+v %v", res, err)
	}
}
