package ghrepo_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
)

// GHSA ids as the second id (docs/github.md "GHSA ids"): B1 extraction and
// storage as found, B2 resolution in the review list, B3 both ids in the
// targeted search, B4 the GHSA name scan, B5 advisory links are not swept.
// (The public page's resolution is tested in internal/site.)

const (
	ghsaAlias105 = "GHSA-2222-3333-4444" // alias of CVE-2026-0105
	ghsaAlias102 = "GHSA-gpwc-27cw-rh9r" // alias of CVE-2026-0102
	ghsaKeyed    = "GHSA-cccc-ffff-gggg" // a vulnerability without a CVE
	ghsaUnknown  = "GHSA-xxxx-xxxx-xxxx" // an id we have no record of
)

// B1: GHSA ids in a repository's name, description and topics are found
// whatever their case and stored in the canonical form, next to CVE ids,
// with the same bases; ids that are not GitHub advisory ids are ignored.
func TestAssociationsGHSA(t *testing.T) {
	t.Parallel()
	r, err := ghrepo.DecodeRepo([]byte(`{"id": 5, "full_name": "o/ghsa-GPWC-27cw-RH9R_CVE-2026-0001_poc", "private": false, "fork": false, "archived": false,
        "description": "PoC for GHSA-2222-3333-4444 (and Ghsa-Cccc-Ffff-Gggg); not GHSA-aaaa-bbbb-cccc, not GHSA-2222-3333",
        "topics": ["ghsa-xxxx-xxxx-xxxx", "cve-2026-0002", "ghsa"]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := r.Associations()
	if s := fmt.Sprint(got["name"], got["description"], got["topic"]); s != "[CVE-2026-0001 GHSA-gpwc-27cw-rh9r] [GHSA-2222-3333-4444 GHSA-cccc-ffff-gggg] [CVE-2026-0002 GHSA-xxxx-xxxx-xxxx]" {
		t.Errorf("%s", s)
	}
	// stored as found, no resolution at write time (the alias exists)
	d := testutil.NewMigratedDB(t)
	exec(t, d, `INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0105')`)
	exec(t, d, `INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ('CVE-2026-0105', $1, 'ghsa')`, ghsaAlias105)
	if _, _, err := ghrepo.StoreSearched(context.Background(), d.Conn, r, now0); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(assoc(t, d, 5), " "); got != "CVE-2026-0001:name CVE-2026-0002:topic GHSA-2222-3333-4444:description "+
		"GHSA-cccc-ffff-gggg:description GHSA-gpwc-27cw-rh9r:name GHSA-xxxx-xxxx-xxxx:topic" {
		t.Errorf("stored: %s", got)
	}
	// a post about a GHSA-keyed vulnerability gives a 'post' association under that id
	exec(t, d, `INSERT INTO vuln (cve_id) VALUES ($1)`, ghsaKeyed)
	exec(t, d, `INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, dedupe_key) VALUES
        ($1, 'social_post', now(), now(), 'xposts', '{}', $2)`, ghsaKeyed, post1)
	link(post1, 0, "https://github.com/p/tool", "code")(t, d)
	// B5: an advisory link (xlinks kind 'advisory') is not a repository for the sweep
	link(post1, 1, "https://github.com/p/tool/security/advisories/"+ghsaKeyed, "advisory")(t, d)
	if res := sweep(t, d); res.Candidates != 1 || res.Added != 1 || res.PostCVEs != 1 {
		t.Fatalf("%+v", res)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo_cve c JOIN github_repo_name n ON n.repo_id = c.repo_id
        WHERE n.name_key = 'p/tool' AND c.cve_id = $1 AND c.basis = 'post'`, ghsaKeyed); n != 1 {
		t.Error("post association under the GHSA id")
	}
	if n := count(t, d, `SELECT count(*) FROM x_post_link WHERE pos = 1 AND (repo_swept_url IS NOT NULL OR repo_root_key IS NOT NULL)`); n != 0 {
		t.Error("the advisory link was swept")
	}
}

// B2 (admin list): associations are shown by main id — the CVE when the
// GHSA id is its alias — and counted per vulnerability: a CVE and its own
// GHSA alias are one, an unresolvable GHSA id counts on its own.
func TestReviewResolvesGHSA(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO vuln (cve_id, published_at) VALUES ('CVE-2026-0105', '2026-05-01'), ('CVE-2025-0005', NULL), ('` + ghsaKeyed + `', '2026-06-01')`,
		`INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ('CVE-2026-0105', '` + ghsaAlias105 + `', 'ghsa')`,
	} {
		exec(t, d, q)
	}
	// 3 vulnerabilities: the CVE (by name) and its alias (by description) are one
	found(t, d, fakeRepo{id: 1, full: "o/CVE-2026-0105-" + ghsaKeyed, desc: ghsaAlias105 + " CVE-2025-0005", created: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)})
	// 4: one more, a GHSA id we cannot resolve
	found(t, d, fakeRepo{id: 2, full: "o/" + ghsaAlias105, desc: "CVE-2025-0005 " + ghsaKeyed + " " + ghsaUnknown, created: old})
	exec(t, d, `UPDATE github_repo SET created_at = now() - github_id * interval '1 minute'`)
	items, err := ghrepo.ListReview(ctx, d.Conn, "", 10, 0)
	if err != nil || len(items) != 2 {
		t.Fatalf("%+v %v", items, err)
	}
	a, b := items[0], items[1]
	if got := fmt.Sprint(a.CVEs); got != "[{CVE-2026-0105 [description name]} {CVE-2025-0005 [description]} {GHSA-cccc-ffff-gggg [name]}]" ||
		a.CVECount != 3 || a.Collection || !a.Predates {
		t.Errorf("a: %s count %d collection %v predates %v", got, a.CVECount, a.Collection, a.Predates)
	}
	if got := fmt.Sprint(b.CVEs); got != "[{CVE-2026-0105 [name]} {CVE-2025-0005 [description]} {GHSA-cccc-ffff-gggg [description]} {GHSA-xxxx-xxxx-xxxx [description]}]" ||
		b.CVECount != 4 || !b.Collection {
		t.Errorf("b: %s count %d collection %v", got, b.CVECount, b.Collection)
	}
}

// seedHotGHSA is seedHot plus: GHSA aliases of 0105 (discussed) and 0102
// (hot), and a GHSA-keyed vulnerability patched in the window (hot, between
// 0101 and 0102).
func seedHotGHSA(t *testing.T, d *testutil.TestDB) {
	t.Helper()
	seedHot(t, d)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	s.Alias("CVE-2026-0105", ghsaAlias105, "ghsa")
	s.Alias("CVE-2026-0102", ghsaAlias102, "ghsa")
	s.Alias("CVE-2026-0102", "VENDOR-1", "vendor")
	s.Vuln(ghsaKeyed, nil)
	at := now0.Add(-36 * time.Hour)
	s.Event(sitetest.Ev{CVE: ghsaKeyed, Type: "patch_released", Source: "ghsa", Occurred: sitetest.P(at), Observed: at, Key: ghsaKeyed})
	s.Refresh()
}

// B3: both ids are searched. A CVE-keyed hot vulnerability gives its CVE id
// and each GHSA alias id, a GHSA-keyed one its GHSA id; all due CVE ids come
// first, so inside the run's cap the second id never takes a request from a
// main id; each id has its own row, searched-at and failure count.
func TestHotIDsBoth(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	seedHotGHSA(t, d)
	all := "CVE-2026-0105 CVE-2026-0101 CVE-2026-0102 " + ghsaAlias105 + " " + ghsaKeyed + " " + ghsaAlias102
	got, err := ghrepo.HotCVEs(ctx, d.Conn, now0, 30)
	if err != nil || strings.Join(got, " ") != all {
		t.Fatalf("%v %v", got, err)
	}
	if got, _ := ghrepo.HotCVEs(ctx, d.Conn, now0, 4); strings.Join(got, " ") != "CVE-2026-0105 CVE-2026-0101 CVE-2026-0102 "+ghsaAlias105 {
		t.Errorf("cap 4: %v", got)
	}
	// a CVE id that is due again goes before GHSA ids never searched
	exec(t, d, `INSERT INTO github_search_cve (cve_id, searched_at, total_count) VALUES ('CVE-2026-0101', $1, 0), ('CVE-2026-0105', $2, 0)`,
		now0.Add(-ghrepo.ResearchAfter-time.Hour), now0.Add(-time.Hour))
	if got, _ := ghrepo.HotCVEs(ctx, d.Conn, now0, 2); strings.Join(got, " ") != "CVE-2026-0102 CVE-2026-0101" {
		t.Errorf("due CVE before new GHSA: %v", got)
	}
	exec(t, d, `DELETE FROM github_search_cve`)
	// one run: six searches in that order; the fifth (the GHSA-keyed id) fails
	f := newFakeSearch(t,
		fakeRepo{id: 1, full: "a/CVE-2026-0105-exploit", created: old},
		fakeRepo{id: 2, full: "b/" + strings.ToUpper(ghsaAlias105) + "-poc", created: old},
		fakeRepo{id: 3, full: "c/tool", desc: "fix for ghsa-GPWC-27cw-rh9r", created: old})
	f.refuse = func(n int) (int, bool) {
		if n == 5 {
			return 500, false
		}
		return 0, false
	}
	o := discoverOpts(f, now0, &sleeps{})
	o.ScanPages = -1
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || res.Requests != 6 || res.CVEs != 5 || res.CVEFailed != 1 || res.Added != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	var qs []string
	for _, q := range f.take() {
		qs = append(qs, strings.TrimSuffix(q, " in:name,description fork:true|stars|1"))
	}
	if strings.Join(qs, " ") != all {
		t.Errorf("queries %q", qs)
	}
	if got := strings.Join(assoc(t, d, 2), " ") + " | " + strings.Join(assoc(t, d, 3), " "); got != ghsaAlias105+":name | "+ghsaAlias102+":description" {
		t.Errorf("stored: %s", got)
	}
	// separate bookkeeping: six rows; only the failed id waits for its backoff
	if n := count(t, d, `SELECT count(*) FROM github_search_cve WHERE searched_at = $1 AND failures = 0`, now0); n != 5 {
		t.Errorf("%d searched", n)
	}
	if n := count(t, d, `SELECT count(*) FROM github_search_cve WHERE cve_id = $1 AND searched_at IS NULL AND failures = 1`, ghsaKeyed); n != 1 {
		t.Error("the failed GHSA search")
	}
	if got, _ := ghrepo.HotCVEs(ctx, d.Conn, now0.Add(2*time.Hour), 30); strings.Join(got, " ") != ghsaKeyed {
		t.Errorf("after the backoff: %v", got)
	}
}

// B4: the scan for names with "GHSA" gets exactly one request of a run's
// scan budget — whatever the CVE-year scans need, and never more, also when
// it has a backlog of its own; with a scan budget under 3 it runs every
// third hour. Repositories without a full GHSA (or CVE) id are not stored.
func TestGHSAScan(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	start := now0.Add(-ghrepo.ScanLag - ghrepo.ScanBootstrap)
	var repos []fakeRepo
	for i := 0; i < 900; i++ { // a CVE-year backlog that takes every request it can get
		repos = append(repos, fakeRepo{id: 1000 + i, full: fmt.Sprintf("u%d/CVE-2026-%d", i, 50000+i), created: start.Add(time.Duration(i) * 4 * time.Minute)})
	}
	groups := "23456789cfghjmpqrvwx"
	for i := 0; i < 230; i++ { // a GHSA backlog: more than a page in the bootstrap window
		id := fmt.Sprintf("GHSA-%c%c%c%c-2222-3333", groups[i%20], groups[i/20%20], groups[0], groups[1])
		repos = append(repos, fakeRepo{id: 5000 + i, full: fmt.Sprintf("g%d/%s-poc", i, id), created: start.Add(time.Duration(i) * 15 * time.Minute)})
	}
	repos = append(repos, fakeRepo{id: 9000, full: "g/ghsa-tools", created: start.Add(time.Hour)}) // no id: not stored
	f := newFakeSearch(t, repos...)
	split := func(o ghrepo.DiscoverOptions) (ghsa, years int) {
		t.Helper()
		o.HotCVEs = -1
		if _, err := ghrepo.Discover(ctx, d.Conn, o); err != nil {
			t.Fatal(err)
		}
		for _, q := range f.take() {
			if strings.HasPrefix(q, "GHSA in:name fork:true created:") {
				ghsa++
			} else {
				years++
			}
		}
		return
	}
	opts := func(now time.Time) ghrepo.DiscoverOptions {
		o := discoverOpts(f, now, &sleeps{})
		o.ScanGHSA = 0
		return o
	}
	for run := 0; run < 6; run++ {
		// (the year scans keep the other 9: they use what their backlog needs)
		if g, y := split(opts(now0)); g != 1 || y > ghrepo.DefaultScanPages-1 || (run == 0 && y != 7) {
			t.Fatalf("run %d: %d GHSA requests, %d year requests", run, g, y)
		}
	}
	// it converges on its own budget
	for run := 0; run < 40 && cursor(t, d, "name:GHSA") != "2026-11-16T11:00:00"; run++ {
		split(opts(now0))
	}
	if c := cursor(t, d, "name:GHSA"); c != "2026-11-16T11:00:00" {
		t.Errorf("GHSA scan did not converge: %s", scanState(t, d, "name:GHSA"))
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id >= 5000 AND github_id < 9000`); n != 230 {
		t.Errorf("%d GHSA repositories stored", n)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 9000`); n != 0 {
		t.Error("a repository without an id was stored")
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo_cve c JOIN github_repo r ON r.id = c.repo_id
        WHERE r.github_id = 5000 AND c.cve_id = 'GHSA-2223-2222-3333' AND c.basis = 'name'`); n != 1 {
		t.Error("association of a scanned GHSA repository")
	}
	// a scan budget of 2: the year scans keep it, except every third hour
	exec(t, d, `DELETE FROM github_search_scan WHERE scan_key = 'name:GHSA'`)
	small := func(hour int) (int, int) {
		o := opts(time.Date(2026, 11, 17, hour, 0, 0, 0, time.UTC)) // the next day: every scan has something to read
		o.ScanPages = 2
		return split(o)
	}
	if g, y := small(12); g != 0 || y == 0 || y > 2 {
		t.Errorf("hour 12: %d %d", g, y)
	}
	if g, y := small(14); g != 1 || y != 1 {
		t.Errorf("hour 14: %d %d", g, y)
	}
	// turned off
	o := opts(now0)
	o.ScanGHSA = -1
	if g, _ := split(o); g != 0 {
		t.Errorf("ScanGHSA -1: %d", g)
	}
}
