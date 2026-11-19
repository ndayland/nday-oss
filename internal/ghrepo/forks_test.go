package ghrepo_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/jobrun"
	"nday.land/nday/internal/testutil"
)

// Skipped forks (docs/github.md "Skipped forks"): a fork with fewer than
// ghrepo.MinForkStars stars isn't collected.

// reviewIDs is the GitHub ids ListReview shows for status, in its order,
// and checks CountReview agrees.
func reviewIDs(t *testing.T, d *testutil.TestDB, status string) []int64 {
	t.Helper()
	ctx := context.Background()
	items, err := ghrepo.ListReview(ctx, d.Conn, status, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ghrepo.CountReview(ctx, d.Conn, status)
	if err != nil || n != len(items) {
		t.Fatalf("count %d %v, list %d", n, err, len(items))
	}
	var out []int64
	for _, it := range items {
		var gh int64
		if err := d.Conn.QueryRow(ctx, `SELECT github_id FROM github_repo WHERE id = $1`, it.ID).Scan(&gh); err != nil {
			t.Fatal(err)
		}
		out = append(out, gh)
	}
	return out
}

func has(ids []int64, id int64) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestSkippedForkPredicate(t *testing.T) {
	for _, c := range []struct {
		r    ghrepo.Repo
		want bool
	}{
		{ghrepo.Repo{Fork: true, StarsKnown: true, Stars: 9}, true},
		{ghrepo.Repo{Fork: true, StarsKnown: true, Stars: 0}, true},
		{ghrepo.Repo{Fork: true, StarsKnown: true, Stars: 10}, false},
		{ghrepo.Repo{Fork: false, StarsKnown: true, Stars: 0}, false},
		{ghrepo.Repo{Fork: true, StarsKnown: false}, false}, // unknown stars never skip
	} {
		if got := c.r.SkippedFork(); got != c.want {
			t.Errorf("%+v: %v", c.r, got)
		}
	}
	if ghrepo.MinForkStars != 10 {
		t.Errorf("MinForkStars %d", ghrepo.MinForkStars)
	}
}

// Search: a fork under 10 stars that we have no row for is not stored at
// all (no row, name, association; a placeholder queued under its name is
// left alone) and is counted in SkippedForks, which the job record carries.
// A fork with 10 stars and a non-fork with 0 come in. A known fork (here
// admin-rejected) is refreshed as before and keeps its decision.
func TestSkippedForksSearch(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	at := now0.Add(-5 * time.Hour)
	// known before: found with 20 stars, then rejected by an admin
	found(t, d, fakeRepo{id: 4004, full: "adm/CVE-2026-80004", created: at, fork: true, stars: 20})
	decide(t, d, 4004, ghrepo.StatusRejected)
	// a post link queued a name search will also see
	if _, _, err := ghrepo.Queue(ctx, d.Conn, "pl/cve-2026-80005", ghrepo.Source); err != nil {
		t.Fatal(err)
	}
	f := newFakeSearch(t,
		fakeRepo{id: 4001, full: "lo/CVE-2026-80001", created: at, fork: true, stars: 9},
		fakeRepo{id: 4002, full: "ten/CVE-2026-80002", created: at, fork: true, stars: 10},
		fakeRepo{id: 4003, full: "nf/CVE-2026-80003", created: at, stars: 0},
		fakeRepo{id: 4004, full: "adm/CVE-2026-80004", created: at, fork: true, stars: 2},
		fakeRepo{id: 4005, full: "pl/CVE-2026-80005", created: at, fork: true, stars: 3})
	o := discoverOpts(f, now0, &sleeps{})
	o.HotCVEs = -1
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || res.SkippedForks != 2 || res.Added != 2 || res.Updated != 1 || res.Skipped != 0 || res.Items != 5 {
		t.Fatalf("%+v %v", res, err)
	}
	// the query still asks for forks (fork:true), unchanged
	for _, q := range f.take() {
		if !strings.Contains(q, " fork:true ") {
			t.Errorf("query %q", q)
		}
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id IN (4001, 4005)`); n != 0 {
		t.Errorf("%d skipped forks stored", n)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo_name WHERE name_key = 'lo/cve-2026-80001'`); n != 0 {
		t.Error("skipped fork's name stored")
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo_cve WHERE cve_id IN ('CVE-2026-80001', 'CVE-2026-80005')`); n != 0 {
		t.Error("skipped fork's associations stored")
	}
	if got := holder(t, d, "pl/cve-2026-80005"); got != "placeholder" {
		t.Errorf("placeholder: %s", got)
	}
	if got := gh(t, d, 4002); got != "unverified/- ok [ten/cve-2026-80002]" {
		t.Errorf("10 stars: %s", got)
	}
	if got := gh(t, d, 4003); got != "unverified/- ok [nf/cve-2026-80003]" {
		t.Errorf("non-fork: %s", got)
	}
	if got := gh(t, d, 4004); got != "rejected/admin ok [adm/cve-2026-80004]" {
		t.Errorf("rejected fork: %s", got)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 4004 AND stars = 2`); n != 1 {
		t.Error("known fork not refreshed")
	}
	if got := reviewIDs(t, d, ""); len(got) != 2 || !has(got, 4002) || !has(got, 4003) {
		t.Errorf("queue %v", got)
	}
	if got := reviewIDs(t, d, ghrepo.StatusRejected); len(got) != 1 || got[0] != 4004 {
		t.Errorf("rejected %v", got)
	}
	// nothing queued for the skipped one: the fetch pass asks only the
	// post link's placeholder, by its name
	f.takeCore()
	pass(t, d, f)
	if got := f.takeCore(); len(got) != 1 || got[0] != "/repos/pl/cve-2026-80005" {
		t.Errorf("core requests %v", got)
	}
	// that one is a fork with 3 stars nobody decided about: stored, but
	// not in the queue
	if got := gh(t, d, 4005); got != "unverified/- ok [pl/cve-2026-80005]" {
		t.Errorf("post fork: %s", got)
	}
	if got := reviewIDs(t, d, ""); len(got) != 2 || has(got, 4005) {
		t.Errorf("queue after fetch %v", got)
	}
	// the run's record on /admin/system carries the counter
	run := jobrun.Start(ctx, d.Conn, jobrun.GitHubDiscover, func() time.Time { return now0 })
	run.Finish(ctx, nil, res)
	var det string
	if err := d.Conn.QueryRow(ctx, `SELECT detail->>'skipped_forks' FROM job_run WHERE name = $1`, jobrun.GitHubDiscover).Scan(&det); err != nil || det != "2" {
		t.Errorf("job detail skipped_forks %q %v", det, err)
	}
}

// Unknown is not skipped: an answer without stargazers_count is stored
// (stars NULL) and listed; a row whose is_fork or stars is NULL is listed.
// An answer without the fork flag doesn't decode at all (DecodeRepo needs
// it), so search never sees an unknown fork flag.
func TestSkippedForkUnknown(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	r, err := ghrepo.DecodeRepo([]byte(`{"id": 4101, "full_name": "u/CVE-2026-81001", "private": false, "fork": true, "archived": false}`))
	if err != nil || r.StarsKnown || r.SkippedFork() {
		t.Fatalf("%+v %v", r, err)
	}
	added, skipped, err := ghrepo.StoreSearched(ctx, d.Conn, r, now0)
	if err != nil || !added || skipped {
		t.Fatalf("%v %v %v", added, skipped, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 4101 AND is_fork AND stars IS NULL`); n != 1 {
		t.Error("unknown stars not stored as NULL")
	}
	if _, err := ghrepo.DecodeRepo([]byte(`{"id": 4102, "full_name": "u/x", "private": false, "archived": false, "stargazers_count": 1}`)); err == nil {
		t.Error("no fork flag decoded")
	}
	exec(t, d, `INSERT INTO github_repo (github_id, queued_name, full_name, stars, is_fork, state, first_source) VALUES
        (4103, 'u/nullfork', 'u/nullfork', 3, NULL, 'ok', 'search'),
        (4104, 'u/lowfork', 'u/lowfork', 3, true, 'ok', 'search')`)
	got := reviewIDs(t, d, "")
	if len(got) != 2 || !has(got, 4101) || !has(got, 4103) {
		t.Errorf("queue %v", got)
	}
}

// A fork first seen through a post link is fetched once (that's how we
// learn it's a fork). Not stamped (created after the link) and with 3
// stars, nobody decided about it: not in the queue, not asked again before
// its normal refresh; when its refresh finds 12 stars it comes in. A
// stamped one is trusted by the post rule and stays so.
func TestSkippedForkFromPost(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := newFakeSearch(t,
		fakeRepo{id: 5001, full: "pf/tool", created: future, fork: true, stars: 3},
		fakeRepo{id: 5002, full: "pr/tool", created: old, fork: true, stars: 3})
	link(post1, 0, "https://github.com/pf/tool", "code")(t, d)
	link(post1, 1, "https://github.com/pr/tool", "code")(t, d)
	sweep(t, d)
	pass(t, d, f)
	if got := f.takeCore(); len(got) != 2 {
		t.Fatalf("core %v", got)
	}
	if got := gh(t, d, 5001); got != "unverified/- ok [pf/tool]" {
		t.Errorf("unstamped fork: %s", got)
	}
	if got := gh(t, d, 5002); got != "trusted/rule ok [pr/tool]" {
		t.Errorf("stamped fork: %s", got)
	}
	if got := reviewIDs(t, d, ""); len(got) != 0 {
		t.Errorf("queue %v", got)
	}
	if got := reviewIDs(t, d, ghrepo.StatusTrusted); len(got) != 1 || got[0] != 5002 {
		t.Errorf("trusted %v", got)
	}
	// next run: nothing due, so no request for it
	pass(t, d, f)
	if got := f.takeCore(); len(got) != 0 {
		t.Errorf("asked again early: %v", got)
	}
	// a week on, its refresh finds 12 stars: in the queue, no write needed
	// beyond the refresh itself
	f.set(fakeRepo{id: 5001, full: "pf/tool", created: future, fork: true, stars: 12},
		fakeRepo{id: 5002, full: "pr/tool", created: old, fork: true, stars: 3})
	due(t, d)
	pass(t, d, f)
	if got := gh(t, d, 5001); got != "unverified/- ok [pf/tool]" {
		t.Errorf("after refresh: %s", got)
	}
	if got := reviewIDs(t, d, ""); len(got) != 1 || got[0] != 5001 {
		t.Errorf("queue after 12 stars %v", got)
	}
	if got := gh(t, d, 5002); got != "trusted/rule ok [pr/tool]" {
		t.Errorf("stamped fork after refresh: %s", got)
	}
}

// Decided rows are left alone whatever their stars: admin-trusted,
// admin-rejected, rule-trusted, owner-trusted and an admin's reset stay
// where they are listed, and search refreshing them changes no status and
// skips nothing.
func TestSkippedForkDecidedUntouched(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	exec(t, d, `INSERT INTO github_repo (github_id, queued_name, full_name, stars, is_fork, state, first_source, status, status_by, status_at, seen_at) VALUES
        (6001, 'at/cve-2026-82001', 'at/CVE-2026-82001', 2, true, 'ok', 'search', 'trusted', 'admin', now(), now()),
        (6002, 'ar/cve-2026-82002', 'ar/CVE-2026-82002', 2, true, 'ok', 'search', 'rejected', 'admin', now(), now()),
        (6003, 'rt/cve-2026-82003', 'rt/CVE-2026-82003', 2, true, 'ok', 'xposts', 'trusted', 'rule', now(), now()),
        (6004, 'ot/forktool', 'ot/forktool', 2, true, 'ok', 'xposts', 'trusted', 'owner', now(), now()),
        (6005, 'au/cve-2026-82005', 'au/CVE-2026-82005', 2, true, 'ok', 'search', 'unverified', 'admin', now(), now())`)
	exec(t, d, `INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo`)
	exec(t, d, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status, repo_root_key, repo_github_id, repo_checked_at)
        VALUES ($1, 0, 'https://t.co/x', 'https://github.com/rt/CVE-2026-82003', 'https://github.com/rt/CVE-2026-82003', 'github.com', 'code', 'api', 'ok',
        'rt/cve-2026-82003', 6003, now())`, post1)
	check := func(when string) {
		t.Helper()
		want := map[string][]int64{"": {6005}, ghrepo.StatusTrusted: {6001, 6003, 6004}, ghrepo.StatusRejected: {6002}}
		for st, ids := range want {
			got := reviewIDs(t, d, st)
			if len(got) != len(ids) {
				t.Errorf("%s %q: %v want %v", when, st, got, ids)
				continue
			}
			for _, id := range ids {
				if !has(got, id) {
					t.Errorf("%s %q: %v want %v", when, st, got, ids)
				}
			}
		}
	}
	check("before")
	at := now0.Add(-5 * time.Hour)
	f := newFakeSearch(t,
		fakeRepo{id: 6001, full: "at/CVE-2026-82001", created: at, fork: true, stars: 1},
		fakeRepo{id: 6002, full: "ar/CVE-2026-82002", created: at, fork: true, stars: 1},
		fakeRepo{id: 6003, full: "rt/CVE-2026-82003", created: at, fork: true, stars: 1},
		fakeRepo{id: 6005, full: "au/CVE-2026-82005", created: at, fork: true, stars: 1})
	o := discoverOpts(f, now0, &sleeps{})
	o.HotCVEs = -1
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || res.SkippedForks != 0 || res.Updated != 4 || res.Added != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	for id, want := range map[int]string{6001: "trusted/admin", 6002: "rejected/admin", 6003: "trusted/rule", 6004: "trusted/owner", 6005: "unverified/admin"} {
		if got := gh(t, d, id); !strings.HasPrefix(got, want+" ok") {
			t.Errorf("%d: %s, want %s", id, got, want)
		}
	}
	check("after search")
	if n := count(t, d, `SELECT count(*) FROM github_rejected_name WHERE repo_id <> (SELECT id FROM github_repo WHERE github_id = 6002)`); n != 0 {
		t.Errorf("%d rejected names added", n)
	}
}

// The trusted-account refetch (owner_id NULL, login of a listed account)
// asks a skipped fork once; forks are never owner-trusted, so it stays out
// of the queue and isn't asked again. A search hit for the same account's
// low-star fork stores nothing, so there's nothing to refetch.
func TestSkippedForkOwnerRefetch(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	f := newFakeSearch(t, fakeRepo{id: 7001, full: "olga/tool", created: future, fork: true, stars: 3})
	link(post1, 0, "https://github.com/olga/tool", "code")(t, d)
	sweep(t, d)
	pass(t, d, f)
	f.takeCore()
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 7001 AND owner_id IS NULL AND owner_login = 'olga'`); n != 1 {
		t.Fatal("setup: owner id stored")
	}
	addOwner(t, d, "olga", 701)
	f.set(fakeRepo{id: 7001, full: "olga/tool", created: future, fork: true, stars: 3, owner: 701},
		fakeRepo{id: 7002, full: "olga/CVE-2026-83002", created: now0.Add(-5 * time.Hour), fork: true, stars: 1, owner: 701})
	pass(t, d, f)
	if got := f.takeCore(); len(got) != 1 || got[0] != "/repositories/7001" {
		t.Errorf("refetch %v", got)
	}
	if got := gh(t, d, 7001); got != "unverified/- ok [olga/tool]" {
		t.Errorf("after refetch: %s", got)
	}
	if got := reviewIDs(t, d, ""); len(got) != 0 {
		t.Errorf("queue %v", got)
	}
	pass(t, d, f)
	if got := f.takeCore(); len(got) != 0 {
		t.Errorf("asked again: %v", got)
	}
	o := discoverOpts(f, now0, &sleeps{})
	o.HotCVEs = -1
	res, err := ghrepo.Discover(ctx, d.Conn, o)
	if err != nil || res.SkippedForks != 1 || res.Added != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := gh(t, d, 7002); got != "none" {
		t.Errorf("searched fork: %s", got)
	}
	pass(t, d, f)
	if got := f.takeCore(); len(got) != 0 {
		t.Errorf("after search: %v", got)
	}
	if got := reviewIDs(t, d, ""); len(got) != 0 {
		t.Errorf("queue at the end %v", got)
	}
}
