package ghrepo_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/testutil"
)

// Tests for the findings of the third review (A1..A8; A2 is also in
// TestMigrationBackfill, A5 in TestGoneNameCreatedLater). Each replays the
// reviewer's probe.

// A1: an identity that lost its name key (a stale search result of another
// id under its name) is asked by id WITHOUT If-None-Match, so it gets a 200
// and its name back; the other identity then learns by id that it is gone.
// A rejection while keyless still records the name the admin saw.
func TestKeylessIdentityGetsItsNameBack(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	var mu sync.Mutex
	var core []string
	a := fakeRepo{id: 10, full: "o/CVE-2026-0001-a", created: old}
	srv := ghrepo.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		core = append(core, r.URL.Path+"|"+r.Header.Get("If-None-Match"))
		mu.Unlock()
		switch r.URL.Path {
		case "/repos/o/cve-2026-0001-a":
			w.Header().Set("ETag", `"e1"`)
			w.Write([]byte(a.json()))
		case "/repositories/10":
			if r.Header.Get("If-None-Match") == `"e1"` {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"e1"`)
			w.Write([]byte(a.json()))
		default:
			w.WriteHeader(404)
		}
	})
	take := func() string {
		mu.Lock()
		defer mu.Unlock()
		s := strings.Join(core, " ")
		core = nil
		return s
	}
	o := ghrepo.Options{Client: srv.Client(""), Now: func() time.Time { return now0 }, Logger: quiet, Sleep: noSleep}
	link(post1, 0, "https://github.com/o/CVE-2026-0001-a", "code")(t, d)
	sweep(t, d)
	if res, err := ghrepo.FetchPending(ctx, d.Conn, o); err != nil || res.OK != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	take()
	// a stale search result: another id under 10's name
	found(t, d, fakeRepo{id: 20, full: "o/CVE-2026-0001-a", created: old})
	if gh(t, d, 10) != "trusted/rule ok []" {
		t.Fatalf("10: %s", gh(t, d, 10))
	}
	// rejected while keyless: the name of its stored full name is recorded
	decide(t, d, 10, ghrepo.StatusRejected)
	if n := count(t, d, `SELECT count(*) FROM github_rejected_name j JOIN github_repo r ON r.id = j.repo_id
        WHERE r.github_id = 10 AND j.name_key = 'o/cve-2026-0001-a'`); n != 1 {
		t.Errorf("rejection of a keyless identity recorded %d names", n)
	}
	res, err := ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || res.OK != 1 || res.NotModified != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := take(); got != "/repositories/10|" { // unconditional
		t.Errorf("requests %q", got)
	}
	if gh(t, d, 10) != "rejected/admin ok [o/cve-2026-0001-a]" || gh(t, d, 20) != "unverified/- ok []" {
		t.Errorf("10 %s, 20 %s", gh(t, d, 10), gh(t, d, 20))
	}
	// 20 holds no name now: asked by id, gone
	if res, err := ghrepo.FetchPending(ctx, d.Conn, o); err != nil || res.Gone != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := take(); got != "/repositories/20|" || gh(t, d, 20) != "unverified/- gone []" {
		t.Errorf("requests %q, 20 %s", got, gh(t, d, 20))
	}
	// with its key, 10 is refreshed conditionally again
	due(t, d)
	if res, err := ghrepo.FetchPending(ctx, d.Conn, o); err != nil || res.NotModified != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := take(); got != `/repositories/10|"e1"` || gh(t, d, 10) != "rejected/admin ok [o/cve-2026-0001-a]" {
		t.Errorf("requests %q, 10 %s", got, gh(t, d, 10))
	}
}

// A1, the 304 rule (holdName): an identity that answered 304 and holds no
// name takes the key of its stored name when it is free or held by a
// placeholder (which stays queued); when another identity holds it, the key
// stays there and the ETag is dropped, so the next refresh is a 200 that
// decides.
func TestNotModifiedHoldsName(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for i, full := range []string{"o/free", "o/queued", "o/taken"} {
		found(t, d, fakeRepo{id: 31 + i, full: full, desc: "CVE-2026-0031", created: old})
	}
	exec(t, d, `UPDATE github_repo SET etag = '"e"'`)
	exec(t, d, `DELETE FROM github_repo_name`)
	if _, _, err := ghrepo.Queue(ctx, d.Conn, "o/queued", ghrepo.Source); err != nil {
		t.Fatal(err)
	}
	found(t, d, fakeRepo{id: 40, full: "o/taken", desc: "CVE-2026-0031", created: old})
	for _, id := range []int{31, 32, 33} {
		if err := ghrepo.HoldName(ctx, d.Conn, repoID(t, d, id)); err != nil {
			t.Fatal(err)
		}
	}
	if gh(t, d, 31) != "unverified/- ok [o/free]" || gh(t, d, 32) != "unverified/- ok [o/queued]" || gh(t, d, 33) != "unverified/- ok []" ||
		gh(t, d, 40) != "unverified/- ok [o/taken]" {
		t.Errorf("31 %s | 32 %s | 33 %s | 40 %s", gh(t, d, 31), gh(t, d, 32), gh(t, d, 33), gh(t, d, 40))
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id IN (31, 32) AND etag IS NOT NULL`); n != 2 {
		t.Errorf("%d ETags kept", n)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 33 AND etag IS NULL`); n != 1 {
		t.Error("the ETag of the identity that did not get its name was kept")
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE queued_name = 'o/queued' AND github_id IS NULL AND state = 'pending'`); n != 1 {
		t.Error("the placeholder did not stay queued")
	}
}

// A2 (probe): a link the phase-1 binary marked swept (repo_queued_url)
// after the migration is still swept by the new code, once.
func TestSweepIgnoresPhase1Marker(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	link(post1, 0, "https://github.com/o/k", "code")(t, d)
	exec(t, d, `UPDATE x_post_link SET repo_queued_url = final_url`)
	if res := sweep(t, d); res.Candidates != 1 || res.Added != 1 || stamp(t, d, post1, 0) != "o/k|-|unchecked" {
		t.Errorf("%+v %s", res, stamp(t, d, post1, 0))
	}
	if res := sweep(t, d); res.Candidates != 0 {
		t.Errorf("again: %+v", res)
	}
	if n := count(t, d, `SELECT count(*) FROM x_post_link WHERE repo_swept_url = final_url AND repo_queued_url = final_url`); n != 1 {
		t.Error("markers")
	}
}

// A3 (probe): a link checked with a 404 is stamped later only while the
// name's 'gone' placeholder is inside GoneRetryWindow. A month later, a
// check of the key that another link triggers stamps that other link only.
func TestLateStampOnlyInsideWindow(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := newFakeSearch(t)
	month := now0.Add(-30 * 24 * time.Hour)
	linkAt(t, d, post1, 0, "https://github.com/o/k", month)
	linkAt(t, d, post2, 0, "https://github.com/o/k/issues/1", month)
	sweep(t, d)
	if res := pass(t, d, f); res.Gone != 1 || stamp(t, d, post1, 0) != "o/k|-|checked" {
		t.Fatalf("%+v %s", res, stamp(t, d, post1, 0))
	}
	// a month passes; the owner renames an OLD repository into o/k
	exec(t, d, `UPDATE github_repo SET created_at = $1, fetched_at = $2`, month, now0.Add(-29*24*time.Hour))
	f.set(fakeRepo{id: 50, full: "o/k", created: old})
	if res := pass(t, d, f); res.Requests != 0 {
		t.Fatalf("expected an idle pass: %+v", res)
	}
	// post2's link becomes a root link of o/k: its check asks the name
	exec(t, d, `UPDATE x_post_link SET final_url = 'https://github.com/o/k' WHERE post_id = $1`, post2)
	sweep(t, d)
	if res := pass(t, d, f); res.OK != 1 || res.Stamped != 1 {
		t.Fatalf("%+v", res)
	}
	if stamp(t, d, post1, 0) != "o/k|-|checked" || stamp(t, d, post2, 0) != "o/k|50|checked" {
		t.Errorf("post1 %s, post2 %s", stamp(t, d, post1, 0), stamp(t, d, post2, 0))
	}
}

// A4 (probe): rule trust exists exactly while a stamp does. When the sweep
// clears the last stamp of an identity (the link's root key changed), it
// goes back to unverified; with another stamp left it stays trusted; an
// admin's decision is not touched.
func TestRuleTrustFollowsStamps(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := newFakeSearch(t, fakeRepo{id: 60, full: "o/CVE-2026-0060", created: old}, fakeRepo{id: 61, full: "o/CVE-2026-0061", created: old},
		fakeRepo{id: 62, full: "o/CVE-2026-0062", created: old})
	link(post1, 0, "https://github.com/o/CVE-2026-0060", "code")(t, d)
	link(post1, 1, "https://github.com/o/CVE-2026-0061", "code")(t, d)
	link(post2, 0, "https://github.com/o/CVE-2026-0061", "code")(t, d)
	link(post1, 2, "https://github.com/o/CVE-2026-0062", "code")(t, d)
	sweep(t, d)
	if res := pass(t, d, f); res.Stamped != 4 {
		t.Fatalf("%+v", res)
	}
	decide(t, d, 62, ghrepo.StatusTrusted)
	exec(t, d, `UPDATE x_post_link SET final_url = 'https://github.com/other/thing' || pos WHERE post_id = $1`, post1)
	sweep(t, d)
	for id, want := range map[int]string{60: "unverified/- ok [o/cve-2026-0060]", 61: "trusted/rule ok [o/cve-2026-0061]", 62: "trusted/admin ok [o/cve-2026-0062]"} {
		if got := gh(t, d, id); got != want {
			t.Errorf("%d: %s, want %s", id, got, want)
		}
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 60 AND status_at IS NULL`); n != 1 {
		t.Error("status_at left on an identity nobody decided about")
	}
	// the invariant, over the whole table
	if n := count(t, d, `SELECT count(*) FROM github_repo g WHERE (g.status = 'trusted' AND g.status_by = 'rule')
        <> (g.status_by IS DISTINCT FROM 'admin' AND g.status <> 'rejected' AND EXISTS (SELECT 1 FROM x_post_link l WHERE l.repo_github_id = g.github_id))`); n != 0 {
		t.Errorf("%d rows break: trusted by rule iff stamped", n)
	}
	// stamped again: trusted again
	exec(t, d, `UPDATE x_post_link SET final_url = 'https://github.com/o/CVE-2026-0060' WHERE post_id = $1 AND pos = 0`, post1)
	sweep(t, d)
	pass(t, d, f)
	if gh(t, d, 60) != "trusted/rule ok [o/cve-2026-0060]" {
		t.Errorf("60 after a new stamp: %s", gh(t, d, 60))
	}
}

// A6: an admin decision takes the store lock before the row lock, as the
// passes do: GetForUpdate waits while a store transaction holds the lock,
// and takes no row lock while it waits.
func TestGetForUpdateTakesStoreLock(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	found(t, d, fakeRepo{id: 70, full: "o/CVE-2026-0070", created: old})
	id := repoID(t, d, 70)
	other, err := testutil.Connect(ctx, d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	hold, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext(current_schema()))`, ghrepo.StoreLockID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- pgx.BeginFunc(ctx, d.Conn, func(tx pgx.Tx) error {
			if _, _, _, err := ghrepo.GetForUpdate(ctx, tx, id); err != nil {
				return err
			}
			_, err := ghrepo.SetStatus(ctx, tx, id, ghrepo.StatusRejected)
			return err
		})
	}()
	select {
	case err := <-done:
		t.Fatalf("GetForUpdate did not wait for the store lock: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	// the waiting decision holds no row lock: the lock holder can write the row
	if _, err := hold.Exec(ctx, `SET LOCAL lock_timeout = '2s'`); err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(ctx, `UPDATE github_repo SET stars = 5 WHERE id = $1`, id); err != nil {
		t.Fatalf("the waiting admin transaction holds the row: %v", err)
	}
	if err := hold.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if gh(t, d, 70) != "rejected/admin ok [o/cve-2026-0070]" {
		t.Errorf("70: %s", gh(t, d, 70))
	}
}

// A7: a one-minute window that comes back incomplete on
// ScanIncompleteRetries consecutive runs is passed, with a count, so a
// year's scan cannot be stopped for good.
func TestScanIncompleteWindowIsPassed(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	t0 := now0.Add(-6 * time.Hour)
	f := newFakeSearch(t, fakeRepo{id: 1, full: "u/CVE-2026-50001", created: t0.Add(10 * time.Second)},
		fakeRepo{id: 2, full: "later/CVE-2026-50002", created: t0.Add(3 * time.Hour)})
	exec(t, d, `INSERT INTO github_search_scan (scan_key, created_after, window_end, next_page) VALUES ('name:CVE-2026', $1, $2, 1)`, t0, t0.Add(time.Minute))
	f.incomplete = func(q string, page int) bool {
		return strings.Contains(q, "2026-11-16T06:00:00Z..2026-11-16T06:01:00Z")
	}
	run := func() ghrepo.DiscoverResult {
		t.Helper()
		o := discoverOpts(f, now0, &sleeps{})
		o.HotCVEs = -1
		res, err := ghrepo.Discover(ctx, d.Conn, o)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if ghrepo.ScanIncompleteRetries != 3 {
		t.Fatalf("ScanIncompleteRetries %d", ghrepo.ScanIncompleteRetries)
	}
	for i := 1; i <= 2; i++ {
		if res := run(); res.ScanDropped != 0 || cursor(t, d, "name:CVE-2026") != "2026-11-16T06:00:00" ||
			count(t, d, `SELECT window_retries FROM github_search_scan WHERE scan_key = 'name:CVE-2026'`) != i {
			t.Fatalf("run %d: %+v %s", i, res, scanState(t, d, "name:CVE-2026"))
		}
	}
	res := run()
	if res.ScanDropped != 1 || cursor(t, d, "name:CVE-2026") <= "2026-11-16T06:00:00" ||
		count(t, d, `SELECT window_retries FROM github_search_scan WHERE scan_key = 'name:CVE-2026'`) != 0 ||
		count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 1`) != 1 {
		t.Errorf("third run: %+v %s", res, scanState(t, d, "name:CVE-2026"))
	}
}

// A8: a request by name may be redirected (two requests against the
// limit), so the pass does not make one when fewer than MinRemaining+2
// requests are left; a request by id is still made.
func TestRedirectBudget(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	found(t, d, fakeRepo{id: 80, full: "o/CVE-2026-0080", created: old})
	decide(t, d, 80, ghrepo.StatusTrusted)
	for _, k := range []string{"n/one", "n/two"} {
		if _, _, err := ghrepo.Queue(ctx, d.Conn, k, ghrepo.Source); err != nil {
			t.Fatal(err)
		}
	}
	remaining := ghrepo.MinRemaining + 2
	var paths []string
	srv := ghrepo.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		remaining--
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.WriteHeader(404)
	})
	o := ghrepo.Options{Client: srv.Client(""), Now: func() time.Time { return now0 }, Logger: quiet, Sleep: noSleep}
	res, err := ghrepo.FetchPending(ctx, d.Conn, o)
	// n/one is asked (7 left before it, 6 after); n/two is not (6 < 7)
	if err != nil || res.Requests != 1 || !res.RateLimited || strings.Join(paths, " ") != "/repos/n/one" {
		t.Fatalf("%+v %v %q", res, err, paths)
	}
	// a request by id costs one: it is made with 6 left
	exec(t, d, `DELETE FROM github_repo WHERE github_id IS NULL`)
	due(t, d)
	paths, remaining = nil, ghrepo.MinRemaining+1
	res, err = ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || res.Requests != 1 || strings.Join(paths, " ") != "/repositories/80" {
		t.Fatalf("by id: %+v %v %q", res, err, paths)
	}
}
