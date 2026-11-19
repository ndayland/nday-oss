package ghrepo_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/testutil"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// day0 is the test clock; rows created by the tests get created_at day0
// (fixCreated) so the 'gone' retry window does not depend on the real time.
var day0 = time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)

func fixCreated(t *testing.T, d *testutil.TestDB) {
	t.Helper()
	if _, err := d.Conn.Exec(context.Background(), `UPDATE github_repo SET created_at = $1`, day0); err != nil {
		t.Fatal(err)
	}
}

func noSleep(context.Context, time.Duration) error { return nil }

// seedPostLinks stores two posts (CVE-2026-0001 and CVE-2026-0002) with
// links (x_post_link) and returns the DB.
func seedPostLinks(t *testing.T) *testutil.TestDB {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0001'), ('CVE-2026-0002')`,
		`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, dedupe_key) VALUES
            ('CVE-2026-0001', 'social_post', now(), now(), 'xposts', '{}', '2000000000000000001'),
            ('CVE-2026-0002', 'social_post', now(), now(), 'xposts', '{}', '2000000000000000002'),
            ('CVE-2026-0001', 'social_post', now(), now(), 'xposts', '{}', '2000000000000000002')`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	link("2000000000000000001", 0, "https://github.com/Alice/CVE-2026-0001-poc", "code")(t, d)
	link("2000000000000000001", 1, "https://github.com/alice/cve-2026-0001-POC/blob/main/x.py", "code")(t, d) // same key
	link("2000000000000000001", 2, "https://github.com/o/r/commit/abc", "patch")(t, d)                        // not swept
	link("2000000000000000001", 3, "https://github.com/topics/cve", "code")(t, d)                             // not a repository
	link("2000000000000000002", 0, "https://github.com/bob/tool", "code")(t, d)
	link("2000000000000000002", 1, "https://github.com/old/name", "code")(t, d)
	link("2000000000000000002", 2, "https://github.com/acme/name", "code")(t, d)
	link("2000000000000000002", 3, "https://github.com/carol/missing", "code")(t, d)
	link("2000000000000000002", 4, "https://github.com/dave/broken", "code")(t, d)
	return d
}

func link(id string, pos int, final, kind string) func(*testing.T, *testutil.TestDB) {
	return func(t *testing.T, d *testutil.TestDB) {
		t.Helper()
		if _, err := d.Conn.Exec(context.Background(), `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status)
            VALUES ($1, $2, 'https://t.co/x', $3, $3, 'github.com', $4, 'api', 'ok')`, id, pos, final, kind); err != nil {
			t.Fatal(err)
		}
	}
}

func count(t *testing.T, d *testutil.TestDB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := d.Conn.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEnqueue(t *testing.T) {
	t.Parallel()
	d := seedPostLinks(t)
	ctx := context.Background()
	res, err := ghrepo.Enqueue(ctx, d.Conn, quiet)
	if err != nil || res != (ghrepo.EnqueueResult{Candidates: 8, Added: 6, NotRepo: 1, PostCVEs: 1 + 5*2}) {
		t.Fatalf("%+v %v", res, err)
	}
	if res, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil || res != (ghrepo.EnqueueResult{}) {
		t.Errorf("again: %+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE state = 'pending' AND github_id IS NULL AND first_source = 'xposts'`); n != 6 {
		t.Errorf("%d repos", n)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo_cve c JOIN github_repo_name n ON n.repo_id = c.repo_id
        WHERE n.name_key = 'bob/tool' AND c.basis = 'post'`); n != 2 {
		t.Errorf("bob/tool post CVEs: %d", n)
	}
	// a changed final URL is swept again
	if _, err := d.Conn.Exec(ctx, `UPDATE x_post_link SET final_url = 'https://github.com/erin/new' WHERE pos = 3 AND post_id = '2000000000000000001'`); err != nil {
		t.Fatal(err)
	}
	if res, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil || res != (ghrepo.EnqueueResult{Candidates: 1, Added: 1, PostCVEs: 1}) {
		t.Errorf("changed: %+v %v", res, err)
	}
}

// fakeGitHub serves the repositories of seedPostLinks; carol/missing
// answers 404 until *carolPublic is set.
func fakeGitHub(t *testing.T, limitAfter int, carolPublic *bool) *ghrepo.TestServer {
	var mu sync.Mutex
	n := 0
	repo := func(id int, full, desc string, topics string) string {
		return fmt.Sprintf(`{"id": %d, "full_name": %q, "private": false, "visibility": "public", "owner": {"login": %q, "type": "User"},
            "description": %q, "stargazers_count": 10, "forks_count": 1, "language": "Go", "topics": [%s], "fork": false, "archived": false,
            "created_at": "2026-02-03T00:00:00Z", "pushed_at": "2026-02-04T00:00:00Z"}`, id, full, strings.Split(full, "/")[0], desc, topics)
	}
	return ghrepo.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		k := n
		public := carolPublic != nil && *carolPublic
		mu.Unlock()
		w.Header().Set("X-RateLimit-Remaining", "50")
		if limitAfter > 0 && k > limitAfter {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(403)
			return
		}
		switch strings.ToLower(r.URL.Path) {
		case "/repos/alice/cve-2026-0001-poc", "/repositories/1":
			w.Header().Set("ETag", `"a1"`)
			w.Write([]byte(repo(1, "Alice/CVE-2026-0001-poc", "exploit", `"poc"`)))
		case "/repos/bob/tool", "/repositories/2":
			if r.Header.Get("If-None-Match") == `"b1"` {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"b1"`)
			w.Write([]byte(repo(2, "bob/tool", "scanner for CVE-2026-0002", `"cve-2026-0009"`)))
		case "/repos/old/name":
			http.Redirect(w, r, "/repositories/3", http.StatusMovedPermanently)
		case "/repos/acme/name", "/repositories/3":
			w.Write([]byte(repo(3, "acme/Name", "", "")))
		case "/repos/dave/broken":
			w.Write([]byte(`{"id": "x"`))
		case "/repos/carol/missing", "/repositories/4":
			if public {
				w.Write([]byte(repo(4, "carol/missing", "", "")))
				return
			}
			w.WriteHeader(404)
		default:
			w.WriteHeader(404)
		}
	})
}

func TestFetchPending(t *testing.T) {
	t.Parallel()
	d := seedPostLinks(t)
	ctx := context.Background()
	if _, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil {
		t.Fatal(err)
	}
	fixCreated(t, d)
	a := fakeGitHub(t, 0, nil)
	now := day0
	o := ghrepo.Options{Client: a.Client(""), Now: func() time.Time { return now }, Logger: quiet, Sleep: noSleep}
	res, err := ghrepo.FetchPending(ctx, d.Conn, o)
	// 6 placeholders: alice ok, bob ok, old/name -> 301 -> id 3 (the placeholder
	// becomes it; the acme/name placeholder is folded into it and not asked),
	// carol 404 gone, dave malformed retry
	// (6 requests: the redirect of old/name is one more against the limit)
	if err != nil || res.Candidates != 6 || res.OK != 3 || res.Merged != 1 || res.Gone != 1 || res.Retry != 1 || res.Requests != 6 || res.RateLimited {
		t.Fatalf("%+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo`); n != 5 {
		t.Errorf("%d rows after the fold", n)
	}
	// the identity holds its current name only; the old name is free
	if gh(t, d, 3) != "trusted/rule ok [acme/name]" || holder(t, d, "old/name") != "free" ||
		count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 3 AND full_name = 'acme/Name'`) != 1 {
		t.Errorf("renamed: %s, old/name %s", gh(t, d, 3), holder(t, d, "old/name"))
	}
	// post associations of both names survive the fold
	if n := count(t, d, `SELECT count(*) FROM github_repo_cve c JOIN github_repo r ON r.id = c.repo_id WHERE r.github_id = 3 AND basis = 'post'`); n != 2 {
		t.Errorf("folded post associations: %d", n)
	}
	// root links are checked by the request for their own key: alice's deep
	// link and the link to a non-repository have no root key; the link to
	// the old name is stamped with the identity that answered through
	// GitHub's redirect; the link to acme/name is checked by the next pass
	for pos, want := range []string{"alice/cve-2026-0001-poc|1|checked", "-|-|unchecked", "-|-|unchecked", "-|-|unchecked"} {
		if got := stamp(t, d, "2000000000000000001", pos); got != want {
			t.Errorf("post 1 link %d: %s, want %s", pos, got, want)
		}
	}
	for pos, want := range []string{"bob/tool|2|checked", "old/name|3|checked", "acme/name|-|unchecked", "carol/missing|-|checked", "dave/broken|-|unchecked"} {
		if got := stamp(t, d, "2000000000000000002", pos); got != want {
			t.Errorf("post 2 link %d: %s, want %s", pos, got, want)
		}
	}
	if gh(t, d, 1) != "trusted/rule ok [alice/cve-2026-0001-poc]" || gh(t, d, 2) != "trusted/rule ok [bob/tool]" {
		t.Errorf("rule trust: %s | %s", gh(t, d, 1), gh(t, d, 2))
	}
	if got := strings.Join(assoc(t, d, 1), " "); got != "CVE-2026-0001:name CVE-2026-0001:post" {
		t.Errorf("alice: %s", got)
	}
	if got := strings.Join(assoc(t, d, 2), " "); got != "CVE-2026-0001:post CVE-2026-0002:description CVE-2026-0002:post CVE-2026-0009:topic" {
		t.Errorf("bob: %s", got)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE queued_name = 'carol/missing' AND state = 'gone'`); n != 1 {
		t.Error("carol not gone")
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE queued_name = 'dave/broken' AND state = 'pending' AND attempts = 1`); n != 1 {
		t.Error("dave not retried")
	}
	// next passes: dave fails twice more -> failed; the first of them also
	// checks the link to acme/name (one request by name); nothing else is due
	for i := 0; i < 2; i++ {
		res, err := ghrepo.FetchPending(ctx, d.Conn, o)
		if err != nil || res.Requests != 2-i || res.LinkChecks != 1-i {
			t.Fatalf("pass %d: %+v %v", i+2, res, err)
		}
	}
	if got := stamp(t, d, "2000000000000000002", 2); got != "acme/name|3|checked" {
		t.Errorf("acme/name link: %s", got)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE queued_name = 'dave/broken' AND state = 'failed' AND attempts = 3`); n != 1 {
		t.Error("dave not failed")
	}
	if res, err := ghrepo.FetchPending(ctx, d.Conn, o); err != nil || res.Candidates != 0 || res.Requests != 0 {
		t.Errorf("idle: %+v %v", res, err)
	}
	// a week later: the ok rows are refreshed by id (RefreshLimit 2: oldest
	// first), bob with its ETag -> 304; dave's slow retry is due too;
	// carol ('gone', queued more than GoneRetryWindow ago) is final
	now = now.Add(ghrepo.RefreshAfter + time.Hour)
	o.RefreshLimit = 2
	if _, err := d.Conn.Exec(ctx, `UPDATE github_repo SET fetched_at = fetched_at - interval '1 minute' WHERE github_id = 2`); err != nil {
		t.Fatal(err)
	}
	res, err = ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || res.Candidates != 3 || res.NotModified != 1 || res.OK != 1 || res.Failed != 1 {
		t.Errorf("refresh: %+v %v", res, err)
	}
	if res, err := ghrepo.FetchPending(ctx, d.Conn, o); err != nil || res.Candidates != 1 {
		t.Errorf("refresh 2: %+v %v", res, err)
	}
}

// A 'gone' repository is retried at most once per GoneRetryAfter while it
// was queued less than GoneRetryWindow ago (sharing RefreshLimit), then it
// is final; a retry that answers 200 makes it 'ok'.
func TestGoneRetry(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	if _, _, err := ghrepo.Queue(ctx, d.Conn, "carol/missing", ghrepo.Source); err != nil {
		t.Fatal(err)
	}
	fixCreated(t, d)
	public := false
	a := fakeGitHub(t, 0, &public)
	now := day0
	o := ghrepo.Options{Client: a.Client(""), Now: func() time.Time { return now }, Logger: quiet, Sleep: noSleep}
	state := func() (s string, attempts int) {
		t.Helper()
		if err := d.Conn.QueryRow(ctx, `SELECT state, attempts FROM github_repo`).Scan(&s, &attempts); err != nil {
			t.Fatal(err)
		}
		return
	}
	pass := func() ghrepo.Result {
		t.Helper()
		res, err := ghrepo.FetchPending(ctx, d.Conn, o)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := pass(); res.Gone != 1 {
		t.Fatalf("first: %+v", res)
	}
	// within 24 h: not retried
	now = day0.Add(23 * time.Hour)
	if res := pass(); res.Candidates != 0 {
		t.Errorf("before 24 h: %+v", res)
	}
	// after 24 h: retried (404 again: still gone)
	now = day0.Add(25 * time.Hour)
	if res := pass(); res.Candidates != 1 || res.Gone != 1 {
		t.Errorf("after 24 h: %+v", res)
	}
	// RefreshLimit < 0: no refreshes, no gone retries
	now = day0.Add(50 * time.Hour)
	o.RefreshLimit = -1
	if res := pass(); res.Candidates != 0 {
		t.Errorf("no refresh slots: %+v", res)
	}
	o.RefreshLimit = 0
	// made public later in the window: the retry stores it
	public = true
	if res := pass(); res.Candidates != 1 || res.OK != 1 {
		t.Errorf("now public: %+v", res)
	}
	if s, n := state(); s != "ok" || n != 0 {
		t.Errorf("state %s %d", s, n)
	}
	// gone again, but queued more than 7 days ago: final
	public = false
	if _, err := d.Conn.Exec(ctx, `UPDATE github_repo SET state = 'gone', fetched_at = $1`, day0); err != nil {
		t.Fatal(err)
	}
	now = day0.Add(ghrepo.GoneRetryWindow + time.Hour)
	if res := pass(); res.Candidates != 0 {
		t.Errorf("after the window: %+v", res)
	}
	// a transient failure of a gone retry keeps it gone
	if _, err := d.Conn.Exec(ctx, `UPDATE github_repo SET created_at = $1`, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	b := ghrepo.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) })
	o.Client = b.Client("")
	if res := pass(); res.Candidates != 1 || res.Retry != 1 {
		t.Errorf("transient: %+v", res)
	}
	if s, _ := state(); s != "gone" {
		t.Errorf("state after a transient failure: %s", s)
	}
}

// A NEW link (never swept) to a 'gone' repository makes it 'pending'
// again once; a re-sweep of a changed URL of an old link does not.
func TestEnqueueRevivesGone(t *testing.T) {
	t.Parallel()
	d := seedPostLinks(t)
	ctx := context.Background()
	if _, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE github_repo SET state = 'gone', attempts = 1, fetched_at = now() WHERE queued_name = 'carol/missing'`); err != nil {
		t.Fatal(err)
	}
	// an old link whose final URL changed to carol's repository: no revival
	if _, err := d.Conn.Exec(ctx, `UPDATE x_post_link SET final_url = 'https://github.com/carol/missing/issues/1'
        WHERE post_id = '2000000000000000001' AND pos = 3`); err != nil {
		t.Fatal(err)
	}
	if res, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil || res.Candidates != 1 || res.Revived != 0 {
		t.Errorf("changed URL: %+v %v", res, err)
	}
	// a new post's link: revived once
	link("2000000000000000003", 0, "https://github.com/Carol/missing", "code")(t, d)
	if res, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil || res.Candidates != 1 || res.Revived != 1 || res.Added != 0 {
		t.Errorf("new link: %+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE queued_name = 'carol/missing' AND state = 'pending' AND attempts = 0`); n != 1 {
		t.Error("not revived")
	}
	if res, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil || res != (ghrepo.EnqueueResult{}) {
		t.Errorf("again: %+v %v", res, err)
	}
}

func assoc(t *testing.T, d *testutil.TestDB, gid int64) []string {
	t.Helper()
	rows, err := d.Conn.Query(context.Background(), `SELECT c.cve_id || ':' || c.basis FROM github_repo_cve c JOIN github_repo r ON r.id = c.repo_id
        WHERE r.github_id = $1 ORDER BY 1`, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// The rate limit stops the pass cleanly: no error, rows left as they were.
// A panic while decoding is recovered as a transient failure.
func TestFetchPendingRateLimitAndPanic(t *testing.T) {
	t.Parallel()
	d := seedPostLinks(t)
	ctx := context.Background()
	if _, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil {
		t.Fatal(err)
	}
	a := fakeGitHub(t, 2, nil)
	o := ghrepo.Options{Client: a.Client(""), Logger: quiet, Sleep: noSleep}
	res, err := ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || !res.RateLimited || res.Requests != 3 || res.OK != 2 || res.Remaining != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE state = 'pending' AND attempts = 0`); n != 4 {
		t.Errorf("%d untouched pending rows", n)
	}
	b := fakeGitHub(t, 0, nil)
	o.Client = b.Client("")
	ghrepo.SetDecode(&o, func([]byte) (*ghrepo.Repo, error) { panic("boom") })
	res, err = ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || res.Panics != 3 || res.Retry != 3 || res.Gone != 1 {
		t.Fatalf("panic pass: %+v %v", res, err)
	}
	// MinRemaining: a response reporting few requests left stops the pass
	c := ghrepo.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "3")
		w.WriteHeader(404)
	})
	o.Client = c.Client("")
	ghrepo.SetDecode(&o, nil)
	res, err = ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || !res.RateLimited || res.Requests != 1 || res.Remaining != 3 {
		t.Fatalf("min remaining: %+v %v", res, err)
	}
}

// The new name fetched first, the old name later (its 301 leads to the
// same GitHub id): the old name's placeholder is folded into the identity,
// which keeps holding its current name only.
func TestRenamedNameFolded(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for _, k := range []string{"acme/name", "old/name"} {
		if _, _, err := ghrepo.Queue(ctx, d.Conn, k, ghrepo.Source); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo_cve (repo_id, cve_id, basis)
        SELECT repo_id, 'CVE-2026-0003', 'post' FROM github_repo_name WHERE name_key = 'old/name'`); err != nil {
		t.Fatal(err)
	}
	a := fakeGitHub(t, 0, nil)
	o := ghrepo.Options{Client: a.Client(""), Logger: quiet, Sleep: noSleep}
	res, err := ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || res.OK != 2 || res.Merged != 1 || res.Requests != 3 { // 2 steps, one of them redirected
		t.Fatalf("%+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo`); n != 1 {
		t.Errorf("%d rows", n)
	}
	if gh(t, d, 3) != "unverified/- ok [acme/name]" || holder(t, d, "old/name") != "free" {
		t.Errorf("%s, old/name %s", gh(t, d, 3), holder(t, d, "old/name"))
	}
	if got := strings.Join(assoc(t, d, 3), " "); got != "CVE-2026-0003:post" {
		t.Errorf("associations %s", got)
	}
	// queueing a held name adds nothing; the released old name is queued
	// again (and folded again by its next fetch)
	if _, added, err := ghrepo.Queue(ctx, d.Conn, "acme/name", ghrepo.Source); err != nil || added {
		t.Errorf("requeue of a held name: %v %v", added, err)
	}
	if _, added, err := ghrepo.Queue(ctx, d.Conn, "old/name", ghrepo.Source); err != nil || !added {
		t.Errorf("requeue of the old name: %v %v", added, err)
	}
	if res, err := ghrepo.FetchPending(ctx, d.Conn, o); err != nil || res.Merged != 1 || count(t, d, `SELECT count(*) FROM github_repo`) != 1 {
		t.Errorf("second fold: %+v %v", res, err)
	}
}
