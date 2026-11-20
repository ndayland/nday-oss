package ghrepo_test

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/testutil"
)

// fakeCore answers GET /repositories/{id} from repos (404 when unknown),
// with X-RateLimit-Remaining counting down from remaining (when > 0), and
// every search with one page holding hit. status(n, path), when set and
// not 0, answers the n-th core request (1-based) with that status instead.
type fakeCore struct {
	mu        sync.Mutex
	repos     map[string]fakeRepo // by GitHub id
	hit       fakeRepo
	remaining int
	status    func(n int, path string) int
	core      []string // core request paths
	inm       []string // their If-None-Match
	searches  int
	*ghrepo.TestServer
}

func newFakeCore(t *testing.T, hit fakeRepo, repos ...fakeRepo) *fakeCore {
	f := &fakeCore{repos: map[string]fakeRepo{}, hit: hit}
	for _, r := range repos {
		f.repos[strconv.Itoa(r.id)] = r
	}
	f.TestServer = ghrepo.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/search/repositories" {
			f.searches++
			w.Header().Set("X-RateLimit-Resource", "search")
			w.Header().Set("X-RateLimit-Remaining", "9")
			fmt.Fprintf(w, `{"total_count": 1, "incomplete_results": false, "items": [%s]}`, f.hit.json())
			return
		}
		id, ok := strings.CutPrefix(r.URL.Path, "/repositories/")
		if !ok {
			w.WriteHeader(404)
			return
		}
		f.core = append(f.core, r.URL.Path)
		f.inm = append(f.inm, r.Header.Get("If-None-Match"))
		if f.remaining > 0 {
			f.remaining--
			w.Header().Set("X-RateLimit-Resource", "core")
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(f.remaining))
		}
		if f.status != nil {
			if st := f.status(len(f.core), r.URL.Path); st != 0 {
				w.WriteHeader(st)
				return
			}
		}
		x, ok := f.repos[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("ETag", `"e`+id+`"`)
		w.Write([]byte(x.json()))
	})
	return f
}

func (f *fakeCore) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.core...)
}

// seedSearched stores r as search found it at at ('unverified', fetched_at at).
func seedSearched(t *testing.T, d *testutil.TestDB, at time.Time, rs ...fakeRepo) {
	t.Helper()
	for _, r := range rs {
		repo, err := ghrepo.DecodeRepo([]byte(r.json()))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ghrepo.StoreSearched(context.Background(), d.Conn, repo, at); err != nil {
			t.Fatal(err)
		}
	}
}

// refreshOpts: a run with no search part.
func refreshOpts(f *fakeCore, token string, sleep func(context.Context, time.Duration) error) ghrepo.DiscoverOptions {
	return ghrepo.DiscoverOptions{Client: f.Client(token), Now: func() time.Time { return now0 }, Sleep: sleep, Logger: quiet,
		ScanPages: -1, HotCVEs: -1}
}

func stars(t *testing.T, d *testutil.TestDB, gid int) int {
	t.Helper()
	return count(t, d, `SELECT COALESCE(stars, -1) FROM github_repo WHERE github_id = $1`, gid)
}

func fetchedNow(t *testing.T, d *testutil.TestDB, gid int) bool {
	t.Helper()
	return count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = $1 AND fetched_at = $2`, gid, now0) == 1
}

// One run refreshes every unverified 'ok' row fetched more than
// RefreshUnverifiedAfter ago, oldest first, by id; a row refreshed within
// it, trusted, rejected and gone rows are left alone. A 304 only stamps
// fetched_at; a 404 by id makes the row 'gone' (markGone); a rename by id
// is the same identity under its new name.
func TestReviewRefresh(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	c := func(id int, full string, stars int) fakeRepo {
		return fakeRepo{id: id, full: full, created: old, stars: stars}
	}
	stale := now0.Add(-2 * time.Hour)
	seedSearched(t, d, stale.Add(-time.Hour), c(1, "a/CVE-2026-0001-poc", 1))
	seedSearched(t, d, stale, c(2, "b/CVE-2026-0002-poc", 2), c(3, "c/CVE-2026-0003-poc", 3), c(4, "d/CVE-2026-0004-poc", 4),
		c(5, "e/CVE-2026-0005-poc", 5), c(6, "f/CVE-2026-0006-poc", 6), c(7, "g/CVE-2026-0007-poc", 7), c(8, "h/CVE-2026-0008-poc", 8))
	seedSearched(t, d, now0.Add(-10*time.Minute), c(9, "i/CVE-2026-0009-poc", 9))
	exec(t, d, `UPDATE github_repo SET status = 'trusted', status_by = 'admin', status_at = now() WHERE github_id = 5`)
	exec(t, d, `UPDATE github_repo SET status = 'rejected', status_by = 'admin', status_at = now() WHERE github_id = 6`)
	exec(t, d, `UPDATE github_repo SET state = 'gone' WHERE github_id = 7`)
	exec(t, d, `UPDATE github_repo SET etag = '"old3"' WHERE github_id = 3`)
	f := newFakeCore(t, fakeRepo{},
		c(1, "a/CVE-2026-0001-poc", 100), c(2, "b/CVE-2026-0002-renamed", 200), c(3, "c/CVE-2026-0003-poc", 300),
		c(5, "e/CVE-2026-0005-poc", 500), c(6, "f/CVE-2026-0006-poc", 600), c(7, "g/CVE-2026-0007-poc", 700),
		c(8, "h/CVE-2026-0008-poc", 800), c(9, "i/CVE-2026-0009-poc", 900))
	// 4 is unknown (404); 3 answers 304
	f.status = func(_ int, p string) int {
		if p == "/repositories/3" {
			return http.StatusNotModified
		}
		return 0
	}
	sl := &sleeps{}
	res, err := ghrepo.Discover(ctx, d.Conn, refreshOpts(f, "", sl.sleep))
	if err != nil {
		t.Fatal(err)
	}
	r := res.Refresh
	if r.Candidates != 5 || r.Requests != 5 || r.OK != 3 || r.NotModified != 1 || r.Gone != 1 || r.Failed != 0 ||
		r.RateLimited || r.Capped || r.TimedOut || r.Remaining != -1 || res.Requests != 0 {
		t.Fatalf("%+v", res)
	}
	if got := strings.Join(f.paths(), " "); got != "/repositories/1 /repositories/2 /repositories/3 /repositories/4 /repositories/8" {
		t.Errorf("order: %s", got)
	}
	if f.inm[2] != `"old3"` || f.inm[0] != "" {
		t.Errorf("If-None-Match %q", f.inm)
	}
	if len(sl.d) != 4 || sl.d[0] != ghrepo.RefreshSpacingAnon {
		t.Errorf("spacing %v", sl.d)
	}
	for gid, want := range map[int]int{1: 100, 2: 200, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 800, 9: 9} {
		if got := stars(t, d, gid); got != want {
			t.Errorf("%d: stars %d, want %d", gid, got, want)
		}
	}
	for _, gid := range []int{1, 2, 3, 4, 8} {
		if !fetchedNow(t, d, gid) {
			t.Errorf("%d: fetched_at not stamped", gid)
		}
	}
	for _, gid := range []int{5, 6, 7, 9} {
		if fetchedNow(t, d, gid) {
			t.Errorf("%d: touched", gid)
		}
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 4 AND state = 'gone' AND status = 'unverified'`); n != 1 {
		t.Error("404 by id is not gone")
	}
	if status(t, d, "b/cve-2026-0002-renamed") != "unverified/" {
		t.Error("rename")
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo_name WHERE name_key = 'b/cve-2026-0002-poc'`); n != 0 {
		t.Error("old name still held")
	}
	// the next run within the threshold asks nothing
	res, err = ghrepo.Discover(ctx, d.Conn, refreshOpts(f, "", sl.sleep))
	if err != nil || res.Refresh.Candidates != 0 || res.Refresh.Requests != 0 {
		t.Errorf("again: %+v %v", res.Refresh, err)
	}
	// RefreshLimit < 0: none
	o := refreshOpts(f, "", sl.sleep)
	o.Now, o.RefreshLimit = func() time.Time { return now0.Add(2 * time.Hour) }, -1
	if res, err := ghrepo.Discover(ctx, d.Conn, o); err != nil || res.Refresh.Requests != 0 || len(f.paths()) != 5 {
		t.Errorf("off: %+v %v", res.Refresh, err)
	}
}

// seedStale stores n unverified rows (GitHub ids 101..), each a minute
// older than the next, all fetched more than RefreshUnverifiedAfter ago.
func seedStale(t *testing.T, d *testutil.TestDB, n int) []fakeRepo {
	var rs []fakeRepo
	for i := range n {
		r := fakeRepo{id: 101 + i, full: fmt.Sprintf("o/CVE-2026-%04d-poc", 1000+i), created: old, stars: 1}
		seedSearched(t, d, now0.Add(-3*time.Hour+time.Duration(i)*time.Minute), r)
		r.stars = 50
		rs = append(rs, r)
	}
	return rs
}

// The stops: the cap, the reserve, a 429, a bare 403 and the run time each
// end the refresh cleanly with their flag; the search part before it is
// recorded either way.
func TestReviewRefreshStops(t *testing.T) {
	t.Parallel()
	hit := fakeRepo{id: 900, full: "s/CVE-2026-0105-exploit", created: old, stars: 3}
	type tc struct {
		name   string
		token  string
		limit  int
		remain int
		status func(n int, path string) int
		run    time.Duration
		block  bool // the second refresh request waits for the run's end
		check  func(r ghrepo.RefreshResult) bool
		asked  int
		failed int
	}
	cases := []tc{
		{name: "cap", limit: 2, asked: 2,
			check: func(r ghrepo.RefreshResult) bool { return r.Capped && !r.RateLimited && !r.TimedOut && r.OK == 2 }},
		{name: "reserve", token: "tok", remain: 501, asked: 2,
			check: func(r ghrepo.RefreshResult) bool {
				return r.RateLimited && !r.Capped && r.OK == 2 && r.Remaining == 499
			}},
		{name: "429", asked: 1, status: func(n int, _ string) int {
			if n == 2 {
				return http.StatusTooManyRequests
			}
			return 0
		}, check: func(r ghrepo.RefreshResult) bool {
			return r.RateLimited && r.OK == 1 && r.Failed == 0 && r.Requests == 2
		}},
		{name: "403", asked: 2, failed: 1, status: func(n int, _ string) int {
			if n == 2 {
				return http.StatusForbidden
			}
			return 0
		}, check: func(r ghrepo.RefreshResult) bool {
			return r.RateLimited && r.OK == 1 && r.Failed == 1 && r.Requests == 2
		}},
		{name: "time", run: 600 * time.Millisecond, block: true, asked: 1,
			check: func(r ghrepo.RefreshResult) bool { return r.TimedOut && !r.RateLimited && r.OK == 1 && r.Requests == 1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := testutil.NewMigratedDB(t)
			ctx := context.Background()
			seedHot(t, d)
			rs := seedStale(t, d, 4)
			f := newFakeCore(t, hit, rs...)
			f.remaining, f.status = c.remain, c.status
			sleep := noSleep
			if c.block {
				sleep = func(ctx context.Context, d time.Duration) error {
					if d == ghrepo.RefreshSpacingAnon {
						<-ctx.Done()
						return ctx.Err()
					}
					return nil
				}
			}
			o := refreshOpts(f, c.token, sleep)
			o.HotCVEs, o.MaxRequests, o.RefreshLimit, o.RunTime = 1, 1, c.limit, c.run
			res, err := ghrepo.Discover(ctx, d.Conn, o)
			if err != nil || !c.check(res.Refresh) || res.Refresh.Candidates != 4 {
				t.Fatalf("%+v %v", res.Refresh, err)
			}
			// the search part is recorded
			if res.CVEs != 1 || res.Added != 1 || stars(t, d, 900) != 3 {
				t.Errorf("search: %+v", res)
			}
			// the oldest rows were asked; only answered ones changed
			n := 0
			for i, r := range rs {
				if stars(t, d, r.id) == 50 {
					n++
					if i >= c.asked {
						t.Errorf("row %d refreshed out of order", i)
					}
				}
			}
			if n+c.failed != c.asked {
				t.Errorf("%d refreshed, want %d", n, c.asked-c.failed)
			}
			if c.failed > 0 && !fetchedNow(t, d, rs[1].id) {
				t.Error("a bare 403 is not written as a transient failure")
			}
			if c.name == "429" && fetchedNow(t, d, rs[1].id) {
				t.Error("a 429 wrote something")
			}
		})
	}
}

// Without a token a run refreshes at most RefreshUnverifiedAnonLimit rows,
// RefreshSpacingAnon apart; with one, up to RefreshUnverifiedLimit.
func TestReviewRefreshAnonymous(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	rs := seedStale(t, d, ghrepo.RefreshUnverifiedAnonLimit+5)
	f := newFakeCore(t, fakeRepo{}, rs...)
	res, err := ghrepo.Discover(ctx, d.Conn, refreshOpts(f, "", noSleep))
	r := res.Refresh
	if err != nil || r.Candidates != len(rs) || r.Requests != ghrepo.RefreshUnverifiedAnonLimit || r.OK != r.Requests || !r.Capped {
		t.Fatalf("%+v %v", r, err)
	}
	sl := &sleeps{}
	res, err = ghrepo.Discover(ctx, d.Conn, refreshOpts(f, "tok", sl.sleep))
	r = res.Refresh
	if err != nil || r.Candidates != 5 || r.Requests != 5 || r.Capped || len(sl.d) != 4 || sl.d[0] != ghrepo.RefreshSpacingAuth {
		t.Fatalf("token: %+v %v %v", r, err, sl.d)
	}
	if ghrepo.MaxRunTime-ghrepo.RefreshMinTime < 5*time.Minute {
		t.Error("the search part's share is too small")
	}
}
