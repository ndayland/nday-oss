package ghrepo_test

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
)

// fakeRepo is a repository the fake search knows.
type fakeRepo struct {
	id      int
	full    string
	desc    string
	created time.Time
	fork    bool
	private bool
	stars   int
	owner   int // the owner's GitHub id (0 = not sent)
}

func (r fakeRepo) json() string {
	vis := "public"
	if r.private {
		vis = "private"
	}
	owner := ""
	if r.owner > 0 {
		owner = fmt.Sprintf(`, "id": %d`, r.owner)
	}
	return fmt.Sprintf(`{"id": %d, "full_name": %q, "private": %t, "visibility": %q, "owner": {"login": %q, "type": "User"%s},
        "description": %q, "stargazers_count": %d, "forks_count": 0, "language": null, "topics": [], "fork": %t, "archived": false,
        "created_at": %q, "pushed_at": %q, "score": 1.0}`, r.id, r.full, r.private, vis, strings.Split(r.full, "/")[0], owner, r.desc, r.stars, r.fork,
		r.created.Format(time.RFC3339), r.created.Format(time.RFC3339))
}

// fakeSearch answers GET /search/repositories from repos: the scan query
// (CVE-<year> in:name ... created:lo..hi) by name and creation time, the
// CVE query by name or description; 100 per page, at most 10 pages.
// refuse(n) may answer the n-th request (1-based) with a status, with or
// without rate-limit headers. GET /repos/{owner}/{name} and GET
// /repositories/{id} answer from repos too (the core API of FetchPending:
// by name, case-insensitive, and by id), and are recorded in core.
// incomplete and total, when set, change incomplete_results and
// total_count of a search page.
type fakeSearch struct {
	mu         sync.Mutex
	repos      []fakeRepo
	queries    []string // "q|sort|page"
	core       []string // paths of the core requests
	refuse     func(n int) (status int, headers bool)
	coreStatus func(path string) int // a status other than 0 answers that core request
	incomplete func(q string, page int) bool
	total      func(q string, page, n int) int
	// GET /users/{login}: users maps a lower-cased login to its id
	// (answered with the login as the key spells it); userStatus, when
	// set, answers every user request with that status instead
	users      map[string]int
	userStatus int
	inm        []string // If-None-Match of each core request ("" = none)
	*ghrepo.TestServer
}

var scanRe = regexp.MustCompile(`^CVE-([0-9]{4}) in:name fork:true created:(\S+)\.\.(\S+)$`)
var cveRe = regexp.MustCompile(`^((?:CVE-[0-9]{4}-[0-9]+)|(?:GHSA(?:-[0-9a-z]{4}){3})) in:name,description fork:true$`)
var ghsaScanRe = regexp.MustCompile(`^GHSA in:name fork:true created:(\S+)\.\.(\S+)$`)

func newFakeSearch(t *testing.T, repos ...fakeRepo) *fakeSearch {
	f := &fakeSearch{repos: repos}
	f.TestServer = ghrepo.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if login, ok := strings.CutPrefix(r.URL.Path, "/users/"); ok {
			if f.userStatus != 0 {
				w.WriteHeader(f.userStatus)
				return
			}
			for k, id := range f.users {
				if strings.EqualFold(k, login) {
					fmt.Fprintf(w, `{"login": %q, "id": %d, "type": "User"}`, k, id)
					return
				}
			}
			w.WriteHeader(404)
			return
		}
		name, byName := strings.CutPrefix(r.URL.Path, "/repos/")
		id, byID := strings.CutPrefix(r.URL.Path, "/repositories/")
		if byName || byID {
			f.core = append(f.core, r.URL.Path)
			f.inm = append(f.inm, r.Header.Get("If-None-Match"))
			if f.coreStatus != nil {
				if st := f.coreStatus(r.URL.Path); st != 0 {
					w.WriteHeader(st)
					return
				}
			}
			for _, x := range f.repos {
				if (byName && strings.EqualFold(x.full, name)) || (byID && strconv.Itoa(x.id) == id) {
					w.Write([]byte(x.json()))
					return
				}
			}
			w.WriteHeader(404)
			return
		}
		q := r.URL.Query()
		f.queries = append(f.queries, q.Get("q")+"|"+q.Get("sort")+"|"+q.Get("page"))
		if f.refuse != nil {
			if st, headers := f.refuse(len(f.queries)); st != 0 {
				if headers {
					w.Header().Set("X-RateLimit-Resource", "search")
					w.Header().Set("X-RateLimit-Remaining", "0")
				}
				if st/100 == 3 {
					w.Header().Set("Location", "https://api.github.com/search/repositories?q=x")
				}
				w.WriteHeader(st)
				return
			}
		}
		w.Header().Set("X-RateLimit-Resource", "search")
		w.Header().Set("X-RateLimit-Remaining", "9")
		if r.URL.Path != "/search/repositories" || q.Get("per_page") != "100" {
			w.WriteHeader(422)
			return
		}
		var hits []fakeRepo
		if m := scanRe.FindStringSubmatch(q.Get("q")); m != nil {
			lo, err1 := time.Parse(time.RFC3339, m[2])
			hi, err2 := time.Parse(time.RFC3339, m[3])
			if err1 != nil || err2 != nil {
				w.WriteHeader(422)
				return
			}
			for _, x := range f.repos {
				if strings.Contains(strings.ToUpper(x.full), "CVE-"+m[1]) && !x.created.Before(lo) && !x.created.After(hi) {
					hits = append(hits, x)
				}
			}
		} else if m := ghsaScanRe.FindStringSubmatch(q.Get("q")); m != nil {
			lo, err1 := time.Parse(time.RFC3339, m[1])
			hi, err2 := time.Parse(time.RFC3339, m[2])
			if err1 != nil || err2 != nil {
				w.WriteHeader(422)
				return
			}
			for _, x := range f.repos {
				if strings.Contains(strings.ToUpper(x.full), "GHSA") && !x.created.Before(lo) && !x.created.After(hi) {
					hits = append(hits, x)
				}
			}
		} else if m := cveRe.FindStringSubmatch(q.Get("q")); m != nil {
			for _, x := range f.repos {
				if strings.Contains(strings.ToUpper(x.full+" "+x.desc), strings.ToUpper(m[1])) {
					hits = append(hits, x)
				}
			}
		} else {
			w.WriteHeader(422)
			return
		}
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].id < hits[j].id })
		page, _ := strconv.Atoi(q.Get("page"))
		if page > 10 {
			w.WriteHeader(422)
			return
		}
		from := (page - 1) * 100
		var items []string
		for i := from; i < len(hits) && i < from+100; i++ {
			items = append(items, hits[i].json())
		}
		total, inc := len(hits), false
		if f.total != nil {
			total = f.total(q.Get("q"), page, total)
		}
		if f.incomplete != nil {
			inc = f.incomplete(q.Get("q"), page)
		}
		fmt.Fprintf(w, `{"total_count": %d, "incomplete_results": %t, "items": [%s]}`, total, inc, strings.Join(items, ","))
	})
	return f
}

// set replaces the repositories GitHub has.
func (f *fakeSearch) set(repos ...fakeRepo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.repos = repos
}

// takeCore returns and clears the recorded core request paths.
func (f *fakeSearch) takeCore() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.core
	f.core = nil
	return c
}

func (f *fakeSearch) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := f.queries
	f.queries = nil
	return q
}

// now0 is the clock of the discovery tests.
var now0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// old and future are repository creation times before and after any
// link of a test (x_post_link.created_at is the database's now()).
var (
	old    = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	future = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
)

type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
	return nil
}

// discoverOpts: a run without the GHSA name scan (TestGHSAScan turns it on).
func discoverOpts(f *fakeSearch, now time.Time, sl *sleeps) ghrepo.DiscoverOptions {
	return ghrepo.DiscoverOptions{Client: f.Client(""), Now: func() time.Time { return now }, Sleep: sl.sleep, Logger: quiet, ScanGHSA: -1}
}

func fetchOpts(f *fakeSearch) ghrepo.Options {
	return ghrepo.Options{Client: f.Client(""), Now: func() time.Time { return now0 }, Logger: quiet, Sleep: noSleep}
}

// scanState is "created_after|window_end|next_page" of a scan key ("" = none).
func scanState(t *testing.T, d *testutil.TestDB, key string) string {
	t.Helper()
	var s string
	if err := d.Conn.QueryRow(context.Background(), `SELECT COALESCE((SELECT to_char(created_after AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') || '|' ||
        COALESCE(to_char(window_end AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'), '') || '|' || next_page
        FROM github_search_scan WHERE scan_key = $1), '')`, key).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func cursor(t *testing.T, d *testutil.TestDB, key string) string {
	t.Helper()
	s, _, _ := strings.Cut(scanState(t, d, key), "|")
	return s
}

// status is "status/status_by" of the row a name key points at.
func status(t *testing.T, d *testutil.TestDB, name string) string {
	t.Helper()
	var s string
	if err := d.Conn.QueryRow(context.Background(), `SELECT r.status || '/' || COALESCE(r.status_by, '') FROM github_repo r
        JOIN github_repo_name n ON n.repo_id = r.id WHERE n.name_key = $1`, name).Scan(&s); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s
}

func idOf(t *testing.T, d *testutil.TestDB, name string) int64 {
	t.Helper()
	var id int64
	if err := d.Conn.QueryRow(context.Background(), `SELECT repo_id FROM github_repo_name WHERE name_key = $1`, name).Scan(&id); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return id
}

// The new-repository scan walks forward from its cursor: the first run
// reads the bootstrap window to now-ScanLag (narrowed until a window fits
// one page), a second run at the same time
// makes no request, a later run reads only the new window. Stored rows are
// 'unverified', first_source 'search'; forks are stored with is_fork;
// private repositories and ones without a CVE id are skipped.
func TestDiscoverScan(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	var repos []fakeRepo
	for i := 0; i < 150; i++ { // spread over the bootstrap window
		repos = append(repos, fakeRepo{id: 1000 + i, full: fmt.Sprintf("u%d/CVE-2026-%d-poc", i, 50000+i),
			created: now0.Add(-ghrepo.ScanLag - ghrepo.ScanBootstrap + time.Duration(i)*25*time.Minute)})
	}
	repos = append(repos,
		fakeRepo{id: 2001, full: "f/CVE-2026-60001", created: now0.Add(-5 * time.Hour), fork: true, stars: 10},
		fakeRepo{id: 2002, full: "p/CVE-2026-60002", created: now0.Add(-5 * time.Hour), private: true},
		fakeRepo{id: 2003, full: "n/cve-2026-tools", created: now0.Add(-5 * time.Hour)}, // no CVE id
		fakeRepo{id: 2004, full: "old/CVE-2025-1234_exp", created: now0.Add(-6 * time.Hour)},
		fakeRepo{id: 2005, full: "late/CVE-2026-60005", created: now0.Add(-30 * time.Minute)}, // inside ScanLag
	)
	f := newFakeSearch(t, repos...)
	sl := &sleeps{}
	o := discoverOpts(f, now0, sl)
	o.HotCVEs = -1
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	// 2026: the 3-day window holds 153 results (more than a page): halved;
	// its first half (87) and the rest (66) fit a page each. 2025: one page.
	if err != nil || res.Requests != 4 || res.ScanPages != 4 || res.ScanWindows != 3 || res.Added != 152 || res.Skipped != 2 ||
		res.RateLimited || res.Locked {
		t.Fatalf("%+v %v", res, err)
	}
	q := f.take()
	if strings.Join(q, " ; ") != "CVE-2026 in:name fork:true created:2026-11-13T11:00:00Z..2026-11-16T11:00:00Z|updated|1 ; "+
		"CVE-2026 in:name fork:true created:2026-11-13T11:00:00Z..2026-11-14T23:00:00Z|updated|1 ; "+
		"CVE-2026 in:name fork:true created:2026-11-14T23:00:00Z..2026-11-16T11:00:00Z|updated|1 ; "+
		"CVE-2025 in:name fork:true created:2026-11-13T11:00:00Z..2026-11-16T11:00:00Z|updated|1" {
		t.Errorf("queries %q", q)
	}
	if c := cursor(t, d, "name:CVE-2026"); c != "2026-11-16T11:00:00" {
		t.Errorf("cursor %s", c)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE first_source = 'search' AND status = 'unverified' AND status_by IS NULL
        AND state = 'ok' AND seen_at = $1`, now0); n != 152 {
		t.Errorf("%d unverified", n)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 2001 AND is_fork`); n != 1 {
		t.Error("fork not stored")
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id IN (2002, 2003, 2005)`); n != 0 {
		t.Error("private / no CVE / too new stored")
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo_cve c JOIN github_repo r ON r.id = c.repo_id WHERE r.github_id = 2004 AND c.cve_id = 'CVE-2025-1234' AND basis = 'name'`); n != 1 {
		t.Error("CVE-2025-1234 association")
	}
	if len(sl.d) != 3 || sl.d[0] != ghrepo.SearchSpacingAnon || sl.d[1] != ghrepo.SearchSpacingAnon {
		t.Errorf("sleeps %v", sl.d)
	}
	if res, err := ghrepo.Discover(ctx, d.Conn, o); err != nil || res.Requests != 0 {
		t.Errorf("again: %+v %v", res, err)
	}
	o = discoverOpts(f, now0.Add(time.Hour), &sleeps{})
	o.HotCVEs = -1
	res, err = ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || res.Requests != 2 || res.Added != 1 || res.Updated != 0 {
		t.Errorf("later: %+v %v", res, err)
	}
	if q := f.take(); len(q) != 2 || q[0] != "CVE-2026 in:name fork:true created:2026-11-16T11:00:00Z..2026-11-16T12:00:00Z|updated|1" {
		t.Errorf("later queries %q", q)
	}
	// search later reports a known repository as private: no longer listed
	f.mu.Lock()
	f.repos = append(f.repos, fakeRepo{id: 1000, full: "u0/CVE-2026-50000-poc", created: now0.Add(-90 * time.Minute), private: true})
	f.repos[0].created = now0.Add(-90 * time.Minute)
	f.repos = f.repos[1:]
	f.mu.Unlock()
	o = discoverOpts(f, now0.Add(time.Hour), &sleeps{})
	o.HotCVEs = -1
	if _, err := d.Conn.Exec(ctx, `UPDATE github_search_scan SET created_after = $1, window_end = NULL, next_page = 1`, now0.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if res, err := ghrepo.Discover(ctx, d.Conn, o); err != nil || res.Hidden != 1 {
		t.Errorf("hidden: %+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 1000 AND state = 'gone'`); n != 1 {
		t.Error("private repository still ok")
	}
}

// C1: a window whose pages do not fit the budget is halved, and the halved
// window persists: the next run continues with it instead of starting over
// from now-ScanLag, so a backlog converges; the cursor moves only past
// windows read to the end.
func TestDiscoverScanConverges(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	var repos []fakeRepo
	for i := 0; i < 250; i++ {
		repos = append(repos, fakeRepo{id: 1000 + i, full: fmt.Sprintf("u%d/CVE-2026-%d", i, 50000+i),
			created: now0.Add(-ghrepo.ScanLag - ghrepo.ScanBootstrap + time.Duration(i)*17*time.Minute)})
	}
	f := newFakeSearch(t, repos...)
	run := func(pages int) ghrepo.DiscoverResult {
		t.Helper()
		o := discoverOpts(f, now0, &sleeps{})
		o.HotCVEs, o.ScanPages = -1, pages
		res, err := ghrepo.Discover(ctx, d.Conn, o)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// 3 pages a run, 2 for 2026: probe of 3 days (3 pages, 1 left): halve;
	// probe of 1.5 days (2 pages, 0 left): halve, saved
	if res := run(3); res.ScanWindows != 1 { // only 2025's (empty) window
		t.Fatalf("%+v", res)
	}
	q := f.take()
	if len(q) < 2 || q[1] != "CVE-2026 in:name fork:true created:2026-11-13T11:00:00Z..2026-11-14T23:00:00Z|updated|1" {
		t.Errorf("%q", q)
	}
	if s := scanState(t, d, "name:CVE-2026"); s != "2026-11-13T11:00:00|2026-11-14T05:00:00|1" {
		t.Errorf("state %s", s)
	}
	// the next run starts at the saved window, not at now-ScanLag again
	run(3)
	if q := f.take(); q[0] != "CVE-2026 in:name fork:true created:2026-11-13T11:00:00Z..2026-11-14T05:00:00Z|updated|1" {
		t.Errorf("restart: %q", q)
	}
	for i := 0; i < 20 && cursor(t, d, "name:CVE-2026") != "2026-11-16T11:00:00"; i++ {
		run(3)
	}
	if c := cursor(t, d, "name:CVE-2026"); c != "2026-11-16T11:00:00" {
		t.Errorf("did not converge: %s", scanState(t, d, "name:CVE-2026"))
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE first_source = 'search'`); n != 250 {
		t.Errorf("%d stored", n)
	}
}

// C2: a minimal window is never skipped: when the budget runs out inside
// it, the next run resumes at the next page; only a minimal window with
// more than 1,000 results moves on, after its 10 retrievable pages.
func TestDiscoverScanMinimalWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := now0.Add(-6 * time.Hour)
	for _, n := range []int{250, 1050} {
		d := testutil.NewMigratedDB(t)
		var repos []fakeRepo
		for i := 0; i < n; i++ {
			repos = append(repos, fakeRepo{id: 1000 + i, full: fmt.Sprintf("u%d/CVE-2026-%d", i, 50000+i), created: t0.Add(time.Duration(i%60) * time.Second)})
		}
		f := newFakeSearch(t, repos...)
		if _, err := d.Conn.Exec(ctx, `INSERT INTO github_search_scan (scan_key, created_after, window_end, next_page) VALUES ('name:CVE-2026', $1, $2, 1)`,
			t0, t0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		o := discoverOpts(f, now0, &sleeps{})
		o.HotCVEs, o.ScanPages = -1, 3 // 2 for 2026
		res, err := ghrepo.Discover(ctx, d.Conn, o)
		if err != nil || res.ScanWindows != 1 { // only 2025's (empty) window
			t.Fatalf("%d: %+v %v", n, res, err)
		}
		if s := scanState(t, d, "name:CVE-2026"); s != "2026-11-16T06:00:00|2026-11-16T06:01:00|3" {
			t.Errorf("%d: not resumable: %s", n, s)
		}
		f.take()
		o.ScanPages = 15 // 10 for 2026
		res, err = ghrepo.Discover(ctx, d.Conn, o)
		if err != nil {
			t.Fatal(err)
		}
		if q := f.take(); q[0] != "CVE-2026 in:name fork:true created:2026-11-16T06:00:00Z..2026-11-16T06:01:00Z|updated|3" {
			t.Errorf("%d: did not resume at page 3: %q", n, q[0])
		}
		stored := count(t, d, `SELECT count(*) FROM github_repo`)
		moved := !strings.HasPrefix(scanState(t, d, "name:CVE-2026"), "2026-11-16T06:00:00|")
		switch n {
		case 250:
			if res.ScanDropped != 0 || stored != 250 || !moved {
				t.Errorf("250: %+v %d %s", res, stored, scanState(t, d, "name:CVE-2026"))
			}
		case 1050:
			// pages 3..10 read, then moved on with 50 passed over
			if res.ScanDropped != 50 || stored != 1000 || !moved {
				t.Errorf("1050: %+v %d %s", res, stored, scanState(t, d, "name:CVE-2026"))
			}
		}
	}
}

// S2: paging a search sorted by "updated" is not stable, so a window that
// holds more than one page is halved while it is wider than the minimum;
// only a window of the minimum width (one minute) is read page by page.
func TestScanSinglePageWindows(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	start := now0.Add(-ghrepo.ScanLag - ghrepo.ScanBootstrap)
	var repos []fakeRepo
	for i := 0; i < 260; i++ { // spread over the first 13 hours
		repos = append(repos, fakeRepo{id: 1000 + i, full: fmt.Sprintf("u%d/CVE-2026-%d", i, 50000+i), created: start.Add(time.Duration(i) * 3 * time.Minute)})
	}
	for i := 0; i < 230; i++ { // a burst inside one minute, two days in
		repos = append(repos, fakeRepo{id: 5000 + i, full: fmt.Sprintf("b%d/CVE-2026-%d", i, 60000+i),
			created: start.Add(48*time.Hour + time.Duration(i%50)*time.Second)})
	}
	f := newFakeSearch(t, repos...)
	paged := 0
	for run := 0; run < 40 && cursor(t, d, "name:CVE-2026") != "2026-11-16T11:00:00"; run++ {
		o := discoverOpts(f, now0, &sleeps{})
		o.HotCVEs = -1
		if _, err := ghrepo.Discover(ctx, d.Conn, o); err != nil {
			t.Fatal(err)
		}
		for _, q := range f.take() {
			parts := strings.Split(q, "|")
			m := scanRe.FindStringSubmatch(parts[0])
			if m == nil || len(parts) != 3 {
				t.Fatalf("query %q", q)
			}
			lo, _ := time.Parse(time.RFC3339, m[2])
			hi, _ := time.Parse(time.RFC3339, m[3])
			if parts[2] != "1" {
				paged++
				if hi.Sub(lo) > time.Minute {
					t.Errorf("page %s of a window %s wide: %s", parts[2], hi.Sub(lo), q)
				}
			}
		}
	}
	if c := cursor(t, d, "name:CVE-2026"); c != "2026-11-16T11:00:00" {
		t.Fatalf("did not converge: %s", scanState(t, d, "name:CVE-2026"))
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo`); n != 490 || paged == 0 {
		t.Errorf("%d stored, %d requests for a page after the first (the burst needs them)", n, paged)
	}
}

// S1: whether a window was read cleanly is decided over ALL its pages,
// also across runs: incomplete_results on a later page keeps the cursor
// where it is (the window is read again), and a total that grows past the
// 1,000 cap on a later page is what the passed-over count and the number
// of pages are taken from.
func TestScanTracksAllPages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := now0.Add(-6 * time.Hour)
	seed := func() (*testutil.TestDB, *fakeSearch) {
		d := testutil.NewMigratedDB(t)
		var repos []fakeRepo
		for i := 0; i < 250; i++ {
			repos = append(repos, fakeRepo{id: 1000 + i, full: fmt.Sprintf("u%d/CVE-2026-%d", i, 50000+i), created: t0.Add(time.Duration(i%60) * time.Second)})
		}
		exec(t, d, `INSERT INTO github_search_scan (scan_key, created_after, window_end, next_page) VALUES ('name:CVE-2026', $1, $2, 1)`, t0, t0.Add(time.Minute))
		return d, newFakeSearch(t, repos...)
	}
	run := func(d *testutil.TestDB, f *fakeSearch, pages int) ghrepo.DiscoverResult {
		t.Helper()
		o := discoverOpts(f, now0, &sleeps{})
		o.HotCVEs, o.ScanPages = -1, pages
		res, err := ghrepo.Discover(ctx, d.Conn, o)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	const window = "2026-11-16T06:00:00|2026-11-16T06:01:00|"
	// page 2 of 3 comes back incomplete; the run's budget ends after it
	d, f := seed()
	f.incomplete = func(q string, page int) bool { return strings.HasPrefix(q, "CVE-2026 ") && page == 2 }
	if res := run(d, f, 3); res.Incomplete != 1 || scanState(t, d, "name:CVE-2026") != window+"3" { // 2 requests for 2026
		t.Fatalf("%+v %s", res, scanState(t, d, "name:CVE-2026"))
	}
	// the next run reads page 3, the last one: the window was not read
	// cleanly, the cursor stays and the window starts over
	f.take()
	if res := run(d, f, 15); res.ScanWindows != 0 || res.Requests != 1 || scanState(t, d, "name:CVE-2026") != window+"1" {
		t.Errorf("after the last page of an incomplete window: %+v %s", res, scanState(t, d, "name:CVE-2026"))
	}
	if q := f.take(); len(q) != 1 || !strings.HasSuffix(q[0], "|3") {
		t.Errorf("queries %q", q)
	}
	// read again, cleanly this time: the cursor moves
	f.incomplete = nil
	if res := run(d, f, 15); res.ScanWindows == 0 || strings.HasPrefix(scanState(t, d, "name:CVE-2026"), "2026-11-16T06:00:00|") {
		t.Errorf("clean read: %+v %s", res, scanState(t, d, "name:CVE-2026"))
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo`); n != 250 {
		t.Errorf("%d stored", n)
	}
	// a total that grows past the cap after page 1: all 10 retrievable
	// pages are asked for, and the passed-over count comes from the largest total
	d, f = seed()
	f.total = func(q string, page, n int) int {
		if strings.HasPrefix(q, "CVE-2026 ") && page >= 2 {
			return 1200
		}
		return n
	}
	res := run(d, f, 15) // 10 requests for 2026
	var pages []string
	for _, q := range f.take() {
		if strings.HasPrefix(q, "CVE-2026 ") && strings.Contains(q, "2026-11-16T06:00:00Z..2026-11-16T06:01:00Z") {
			pages = append(pages, q[strings.LastIndex(q, "|")+1:])
		}
	}
	if res.ScanDropped != 200 || strings.Join(pages, ",") != "1,2,3,4,5,6,7,8,9,10" || strings.HasPrefix(scanState(t, d, "name:CVE-2026"), "2026-11-16T06:00:00|") {
		t.Errorf("growing total: %+v pages %v %s", res, pages, scanState(t, d, "name:CVE-2026"))
	}
}

// C1: the previous year is not starved by a current-year backlog.
func TestDiscoverScanYears(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	var repos []fakeRepo
	for i := 0; i < 900; i++ {
		repos = append(repos, fakeRepo{id: 1000 + i, full: fmt.Sprintf("u%d/CVE-2026-%d", i, 50000+i),
			created: now0.Add(-ghrepo.ScanLag - ghrepo.ScanBootstrap + time.Duration(i)*4*time.Minute)})
	}
	repos = append(repos, fakeRepo{id: 9, full: "p/CVE-2025-0009", created: now0.Add(-2 * time.Hour)})
	f := newFakeSearch(t, repos...)
	o := discoverOpts(f, now0, &sleeps{})
	o.HotCVEs = -1
	if _, err := ghrepo.Discover(ctx, d.Conn, o); err != nil {
		t.Fatal(err)
	}
	var y25 int
	for _, q := range f.take() {
		if strings.HasPrefix(q, "CVE-2025 ") {
			y25++
		}
	}
	if y25 == 0 || count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 9`) != 1 {
		t.Errorf("previous year starved (%d requests)", y25)
	}
}

// D1: a 403 without rate-limit headers (a secondary limit) stops the run;
// the CVE is not recorded as searched but its failure is counted (backoff);
// a 429 with headers stops the run and records nothing.
func TestDiscoverRateLimit(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	seedHot(t, d)
	f := newFakeSearch(t)
	f.refuse = func(n int) (int, bool) {
		if n == 1 {
			return 403, false
		}
		return 0, false
	}
	o := discoverOpts(f, now0, &sleeps{})
	o.ScanPages = -1
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || !res.RateLimited || res.Requests != 1 || res.CVEs != 0 || res.CVEFailed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_search_cve WHERE searched_at IS NULL AND failures = 1 AND cve_id = 'CVE-2026-0105'`); n != 1 {
		t.Error("bare 403: failure not counted, or recorded as searched")
	}
	// within its backoff the CVE waits; the others go first
	if got, _ := ghrepo.HotCVEs(ctx, d.Conn, now0.Add(30*time.Minute), 30); strings.Contains(strings.Join(got, " "), "0105") {
		t.Errorf("backoff: %v", got)
	}
	if got, _ := ghrepo.HotCVEs(ctx, d.Conn, now0.Add(61*time.Minute), 30); strings.Join(got, " ") != "CVE-2026-0101 CVE-2026-0102 CVE-2026-0105" {
		t.Errorf("after backoff: %v", got)
	}
	f.refuse = func(n int) (int, bool) { return 429, true }
	f.take()
	res, err = ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || !res.RateLimited || res.Requests != 1 || res.CVEFailed != 0 {
		t.Fatalf("429: %+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_search_cve`); n != 1 {
		t.Error("a 429 was recorded")
	}
	// a scan stopped by a 403 keeps its cursor
	f.refuse = func(n int) (int, bool) { return 403, false }
	o = discoverOpts(f, now0, &sleeps{})
	o.HotCVEs = -1
	if res, err := ghrepo.Discover(ctx, d.Conn, o); err != nil || res.Requests != 1 || cursor(t, d, "name:CVE-2026") != "2026-11-13T11:00:00" {
		t.Errorf("scan: %+v %v %s", res, err, scanState(t, d, "name:CVE-2026"))
	}
}

// D2: Search follows no redirect: a 3xx is a failed request, the Location
// is never requested.
func TestDiscoverRedirect(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	seedHot(t, d)
	f := newFakeSearch(t)
	f.refuse = func(n int) (int, bool) { return 302, false }
	o := discoverOpts(f, now0, &sleeps{})
	o.ScanPages, o.HotCVEs = -1, 1
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || res.Requests != 1 || res.Failed != 1 || res.CVEs != 0 || len(f.take()) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_search_cve WHERE searched_at IS NOT NULL`); n != 0 {
		t.Error("recorded as searched")
	}
}

// D4: the run stops cleanly at its run time.
func TestDiscoverRunTime(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	seedHot(t, d)
	f := newFakeSearch(t)
	o := discoverOpts(f, now0, nil)
	o.ScanPages, o.RunTime = -1, 50*time.Millisecond
	o.Sleep = func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || !res.TimedOut || res.Requests != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if ghrepo.MaxRunTime >= 20*time.Minute-time.Minute {
		t.Error("MaxRunTime does not leave room under the unit's TimeoutStartSec=20min")
	}
}

// D3: Discover and FetchPending share one lock: while it is held neither
// does anything; each releases it when done.
func TestGitHubPassLock(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	seedHot(t, d)
	if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo (queued_name, first_source) VALUES ('o/r', 'xposts')`); err != nil {
		t.Fatal(err)
	}
	f := newFakeSearch(t, fakeRepo{id: 1, full: "o/r", created: old})
	other, err := testutil.Connect(ctx, d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	tryOther := func() bool {
		t.Helper()
		var ok bool
		if err := other.QueryRow(ctx, `SELECT pg_try_advisory_lock($1, hashtext(current_schema()))`, ghrepo.DiscoverLockID).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !tryOther() {
		t.Fatal("lock")
	}
	o := discoverOpts(f, now0, &sleeps{})
	if res, err := ghrepo.Discover(ctx, d.Conn, o); err != nil || !res.Locked || res.Requests != 0 {
		t.Errorf("discover while locked: %+v %v", res, err)
	}
	if res, err := ghrepo.FetchPending(ctx, d.Conn, fetchOpts(f)); err != nil || !res.Locked || res.Requests != 0 {
		t.Errorf("fetch while locked: %+v %v", res, err)
	}
	if _, err := other.Exec(ctx, `SELECT pg_advisory_unlock($1, hashtext(current_schema()))`, ghrepo.DiscoverLockID); err != nil {
		t.Fatal(err)
	}
	if res, err := ghrepo.FetchPending(ctx, d.Conn, fetchOpts(f)); err != nil || res.Locked || res.OK != 1 {
		t.Errorf("fetch: %+v %v", res, err)
	}
	if !tryOther() { // released by FetchPending
		t.Fatal("FetchPending kept the lock")
	}
	if res, err := ghrepo.FetchPending(ctx, d.Conn, fetchOpts(f)); err != nil || !res.Locked {
		t.Errorf("fetch while Discover-side holds it: %+v %v", res, err)
	}
	if _, err := other.Exec(ctx, `SELECT pg_advisory_unlock($1, hashtext(current_schema()))`, ghrepo.DiscoverLockID); err != nil {
		t.Fatal(err)
	}
	if res, err := ghrepo.Discover(ctx, d.Conn, o); err != nil || res.Locked {
		t.Errorf("discover: %+v %v", res, err)
	}
	if !tryOther() {
		t.Fatal("Discover kept the lock")
	}
}

// seedHot: CVE-2026-0105 discussed by two enabled researchers, 0106 only by a
// disabled one; 0101 KEV and 0102 patched in the window (hot list), 0103
// only disclosed, 0104 patched before the window.
func seedHot(t *testing.T, d *testutil.TestDB) {
	t.Helper()
	ctx := context.Background()
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	for _, c := range []string{"0101", "0102", "0103", "0104", "0105", "0106"} {
		s.Vuln("CVE-2026-"+c, nil)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('1001', 'a', true), ('1002', 'b', true), ('1003', 'c', false)`); err != nil {
		t.Fatal(err)
	}
	ev := func(cve, typ, src string, at time.Time, key, detail string) {
		s.Event(sitetest.Ev{CVE: "CVE-2026-" + cve, Type: typ, Source: src, Occurred: sitetest.P(at), Observed: at, Key: key, Detail: detail})
	}
	ev("0101", "disclosed", "cvelist", now0.Add(-48*time.Hour), "d1", "")
	ev("0101", "kev_added", "kev", now0.Add(-24*time.Hour), "k1", "")
	ev("0102", "patch_released", "ghsa", now0.Add(-48*time.Hour), "p2", "")
	ev("0103", "disclosed", "cvelist", now0.Add(-24*time.Hour), "d3", "")
	ev("0104", "patch_released", "ghsa", now0.Add(-10*24*time.Hour), "p4", "")
	for i, a := range []string{"1001", "1002"} {
		ev("0105", "social_post", "xposts", now0.Add(-time.Hour), fmt.Sprintf("200000000000000010%d", i), `{"author_id": "`+a+`"}`)
	}
	ev("0106", "social_post", "xposts", now0.Add(-time.Hour), "2000000000000000109", `{"author_id": "1003"}`)
	s.Refresh()
}

// HotCVEs: discussed first, then the hot list; never searched before least
// recently searched; nothing searched within ResearchAfter.
func TestHotCVEs(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	seedHot(t, d)
	got, err := ghrepo.HotCVEs(ctx, d.Conn, now0, 30)
	if err != nil || strings.Join(got, " ") != "CVE-2026-0105 CVE-2026-0101 CVE-2026-0102" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO github_search_cve (cve_id, searched_at, total_count) VALUES
        ('CVE-2026-0105', $1, 3), ('CVE-2026-0101', $2, 0)`, now0.Add(-time.Hour), now0.Add(-ghrepo.ResearchAfter-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err = ghrepo.HotCVEs(ctx, d.Conn, now0, 30)
	if err != nil || strings.Join(got, " ") != "CVE-2026-0102 CVE-2026-0101" {
		t.Errorf("%v %v", got, err)
	}
	if got, err := ghrepo.HotCVEs(ctx, d.Conn, now0, 1); err != nil || strings.Join(got, " ") != "CVE-2026-0102" {
		t.Errorf("limit: %v %v", got, err)
	}
}

// The targeted search: one request per hot CVE (by stars), results stored,
// the CVE recorded; a second run within ResearchAfter searches nothing; the
// run's request cap holds.
func TestDiscoverTargeted(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	seedHot(t, d)
	f := newFakeSearch(t,
		fakeRepo{id: 1, full: "a/CVE-2026-0105-exploit", created: now0.Add(-10 * 24 * time.Hour), stars: 9},
		fakeRepo{id: 2, full: "b/scanner", desc: "Checks CVE-2026-0101", created: now0.Add(-10 * 24 * time.Hour)},
		fakeRepo{id: 3, full: "c/x", desc: "nothing", created: now0})
	sl := &sleeps{}
	o := discoverOpts(f, now0, sl)
	o.ScanPages = -1
	o.Client = f.Client("tok")
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || res.Requests != 3 || res.CVEs != 3 || res.Added != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	q := f.take()
	if strings.Join(q, " ; ") != "CVE-2026-0105 in:name,description fork:true|stars|1 ; CVE-2026-0101 in:name,description fork:true|stars|1 ; "+
		"CVE-2026-0102 in:name,description fork:true|stars|1" {
		t.Errorf("%q", q)
	}
	if len(sl.d) != 2 || sl.d[0] != ghrepo.SearchSpacingAuth {
		t.Errorf("authenticated spacing %v", sl.d)
	}
	if n := count(t, d, `SELECT count(*) FROM github_search_cve WHERE searched_at = $1 AND total_count IS NOT NULL AND failures = 0`, now0); n != 3 {
		t.Errorf("%d recorded", n)
	}
	if res, err := ghrepo.Discover(ctx, d.Conn, o); err != nil || res.Requests != 0 {
		t.Errorf("again: %+v %v", res, err)
	}
	o = discoverOpts(f, now0.Add(ghrepo.ResearchAfter+time.Minute), &sleeps{})
	o.ScanPages, o.MaxRequests = -1, 2
	if res, err := ghrepo.Discover(ctx, d.Conn, o); err != nil || res.Requests != 2 || res.Updated != 2 || res.Added != 0 {
		t.Errorf("capped: %+v %v", res, err)
	}
}

// A malformed page is a failed request: no rows, the CVE not marked
// searched, a failure counted.
func TestDiscoverMalformed(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	seedHot(t, d)
	f := newFakeSearch(t)
	o := discoverOpts(f, now0, &sleeps{})
	o.ScanPages, o.HotCVEs = -1, 1
	ghrepo.SetSearchDecode(&o, func([]byte) (*ghrepo.SearchPage, error) { return nil, fmt.Errorf("bad") })
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || res.Failed != 1 || res.Malformed != 1 || res.CVEs != 0 || res.CVEFailed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_search_cve WHERE searched_at IS NULL AND failures = 1`); n != 1 {
		t.Error("failure not recorded as such")
	}
}
