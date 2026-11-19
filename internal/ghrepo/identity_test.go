package ghrepo_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/testutil"
)

// Tests of the data model (docs/github.md "Identity, names, links"): one
// test per invariant I1..I5, I7, I8, I10 (I6 is internal/site, I9
// TestMigrationBackfill). The reviewers' sequences that broke the earlier
// model are replayed where they belong.

// found stores r as a search result (storeSearched).
func found(t *testing.T, d *testutil.TestDB, r fakeRepo) bool {
	t.Helper()
	rr, err := ghrepo.DecodeRepo([]byte(r.json()))
	if err != nil {
		t.Fatal(err)
	}
	added, _, err := ghrepo.StoreSearched(context.Background(), d.Conn, rr, now0)
	if err != nil {
		t.Fatal(err)
	}
	return added
}

// gh describes the identity with GitHub id: "status/by state [name keys]",
// "none" when no row has that id.
func gh(t *testing.T, d *testutil.TestDB, id int) string {
	t.Helper()
	var s string
	if err := d.Conn.QueryRow(context.Background(), `SELECT COALESCE((SELECT r.status || '/' || COALESCE(r.status_by, '-') || ' ' || r.state || ' [' ||
        COALESCE((SELECT string_agg(n.name_key, ',' ORDER BY n.name_key) FROM github_repo_name n WHERE n.repo_id = r.id), '') || ']'
        FROM github_repo r WHERE r.github_id = $1), 'none')`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// holder is the GitHub id of the row a name key points at: "placeholder"
// when it has none, "free" when no row holds the key.
func holder(t *testing.T, d *testutil.TestDB, key string) string {
	t.Helper()
	var s string
	if err := d.Conn.QueryRow(context.Background(), `SELECT COALESCE((SELECT COALESCE(r.github_id::text, 'placeholder') FROM github_repo_name n
        JOIN github_repo r ON r.id = n.repo_id WHERE n.name_key = $1), 'free')`, key).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// stamp is "root key|stamp|checked" of a link ("-" = NULL).
func stamp(t *testing.T, d *testutil.TestDB, post string, pos int) string {
	t.Helper()
	var s string
	if err := d.Conn.QueryRow(context.Background(), `SELECT COALESCE(repo_root_key, '-') || '|' || COALESCE(repo_github_id::text, '-') || '|' ||
        CASE WHEN repo_checked_at IS NULL THEN 'unchecked' ELSE 'checked' END FROM x_post_link WHERE post_id = $1 AND pos = $2`, post, pos).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// linkAt stores a code link with a given created_at (the time nday stored it).
func linkAt(t *testing.T, d *testutil.TestDB, post string, pos int, final string, created time.Time) {
	t.Helper()
	link(post, pos, final, "code")(t, d)
	exec(t, d, `UPDATE x_post_link SET created_at = $3 WHERE post_id = $1 AND pos = $2`, post, pos, created)
}

func exec(t *testing.T, d *testutil.TestDB, q string, args ...any) {
	t.Helper()
	if _, err := d.Conn.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func sweep(t *testing.T, d *testutil.TestDB) ghrepo.EnqueueResult {
	t.Helper()
	res, err := ghrepo.Enqueue(context.Background(), d.Conn, quiet)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func pass(t *testing.T, d *testutil.TestDB, f *fakeSearch) ghrepo.Result {
	t.Helper()
	res, err := ghrepo.FetchPending(context.Background(), d.Conn, fetchOpts(f))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// due makes every 'ok' row due for its refresh.
func due(t *testing.T, d *testutil.TestDB) {
	t.Helper()
	exec(t, d, `UPDATE github_repo SET fetched_at = $1 WHERE state = 'ok'`, now0.Add(-30*24*time.Hour))
}

func decide(t *testing.T, d *testutil.TestDB, ghID int, status string) {
	t.Helper()
	if ch, err := ghrepo.SetStatus(context.Background(), d.Conn, repoID(t, d, ghID), status); err != nil || !ch {
		t.Fatalf("SetStatus %d %s: %v %v", ghID, status, ch, err)
	}
}

const (
	post1 = "2000000000000000001"
	post2 = "2000000000000000002"
	post3 = "2000000000000000003"
)

// I1: a row with a GitHub id is that identity forever. The database
// refuses another id for it (and a status on a placeholder); a name that
// answers with another id — by name (reviewers' probe "repojack refresh"),
// from search ("search then refresh") or in an answer to a request by id —
// never rewrites the row: the other repository is another row. A
// placeholder is never an object of review.
func TestIdentityImmutable(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	found(t, d, fakeRepo{id: 10, full: "alice/CVE-2026-0001-poc", created: old})
	decide(t, d, 10, ghrepo.StatusTrusted)
	a := repoID(t, d, 10)
	wait, _, err := ghrepo.Queue(ctx, d.Conn, "p/wait", ghrepo.Source)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE github_repo SET github_id = 999 WHERE github_id = 10`,
		`UPDATE github_repo SET github_id = NULL, state = 'pending' WHERE github_id = 10`,
		`UPDATE github_repo SET status = 'trusted', status_by = 'admin', status_at = now() WHERE queued_name = 'p/wait'`,
		`UPDATE github_repo SET status = 'rejected', status_by = 'rule', status_at = now() WHERE queued_name = 'p/wait'`,
		`UPDATE github_repo SET status_by = 'admin', status_at = now() WHERE queued_name = 'p/wait'`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	// the name is registered again by repository 999; a researcher's root
	// link makes the pass ask for the name
	f := newFakeSearch(t, fakeRepo{id: 999, full: "alice/CVE-2026-0001-poc", created: future})
	link(post1, 0, "https://github.com/alice/CVE-2026-0001-poc", "code")(t, d)
	sweep(t, d)
	if res := pass(t, d, f); res.OK != 1 || res.LinkChecks != 1 {
		t.Fatalf("%+v", res)
	}
	if repoID(t, d, 10) != a || gh(t, d, 10) != "trusted/admin ok []" || gh(t, d, 999) != "unverified/- ok [alice/cve-2026-0001-poc]" {
		t.Errorf("by name: 10 = %s (row %d, was %d), 999 = %s", gh(t, d, 10), repoID(t, d, 10), a, gh(t, d, 999))
	}
	// search returns yet another id under that name
	if !found(t, d, fakeRepo{id: 1000, full: "Alice/CVE-2026-0001-poc", created: old}) {
		t.Error("search: not a new row")
	}
	if repoID(t, d, 10) != a || gh(t, d, 10) != "trusted/admin ok []" || gh(t, d, 999) != "unverified/- ok []" ||
		gh(t, d, 1000) != "unverified/- ok [alice/cve-2026-0001-poc]" {
		t.Errorf("search: %s | %s | %s", gh(t, d, 10), gh(t, d, 999), gh(t, d, 1000))
	}
	// an answer to a request by id that carries another id changes nothing
	bad := ghrepo.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fakeRepo{id: 555, full: "x/CVE-2026-0555", created: old}.json()))
	})
	due(t, d)
	o := fetchOpts(f)
	o.Client = bad.Client("")
	if res, err := ghrepo.FetchPending(ctx, d.Conn, o); err != nil || res.OK != 0 || res.Retry == 0 {
		t.Errorf("another id by id: %+v %v", res, err)
	}
	if repoID(t, d, 10) != a || gh(t, d, 555) != "none" || count(t, d, `SELECT count(*) FROM github_repo WHERE github_id IS NOT NULL`) != 3 {
		t.Errorf("another id by id: 10 is row %d, 555 = %s", repoID(t, d, 10), gh(t, d, 555))
	}
	// a placeholder: no decision possible, never listed
	if _, err := ghrepo.SetStatus(ctx, d.Conn, wait, ghrepo.StatusTrusted); !errors.Is(err, ghrepo.ErrRepoNotFound) {
		t.Errorf("SetStatus on a placeholder: %v", err)
	}
	for _, st := range []string{"unverified", "trusted", "rejected"} {
		items, err := ghrepo.ListReview(ctx, d.Conn, st, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if it.ID == wait || it.FullName == "" {
				t.Errorf("placeholder listed as %s", st)
			}
		}
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE github_id IS NULL AND (status <> 'unverified' OR status_by IS NOT NULL)`); n != 0 {
		t.Errorf("%d placeholders with a status", n)
	}
}

// I2: an identity is refreshed by id (GET /repositories/{id}), not by
// name: a changed full_name is a rename of the same row, whoever answers
// for the old name now; 404 by id makes it 'gone' with its status
// untouched.
func TestRefreshByID(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	found(t, d, fakeRepo{id: 20, full: "evil/CVE-2026-0777", created: old})
	decide(t, d, 20, ghrepo.StatusRejected)
	a := repoID(t, d, 20)
	// renamed; someone else registered the old name
	f := newFakeSearch(t, fakeRepo{id: 20, full: "evil/CVE-2026-0777-x", created: old, stars: 7},
		fakeRepo{id: 99, full: "evil/CVE-2026-0777", created: old})
	due(t, d)
	if res := pass(t, d, f); res.OK != 1 || res.Requests != 1 {
		t.Fatalf("%+v", res)
	}
	if c := f.takeCore(); len(c) != 1 || c[0] != "/repositories/20" {
		t.Errorf("requests %q", c)
	}
	if repoID(t, d, 20) != a || gh(t, d, 20) != "rejected/admin ok [evil/cve-2026-0777-x]" || gh(t, d, 99) != "none" ||
		holder(t, d, "evil/cve-2026-0777") != "free" ||
		count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 20 AND full_name = 'evil/CVE-2026-0777-x' AND stars = 7`) != 1 {
		t.Errorf("rename: %s, 99 = %s, old name %s", gh(t, d, 20), gh(t, d, 99), holder(t, d, "evil/cve-2026-0777"))
	}
	// deleted: gone, the decision stays, the name is released
	f.set(fakeRepo{id: 99, full: "evil/CVE-2026-0777-x", created: old})
	due(t, d)
	if res := pass(t, d, f); res.Gone != 1 {
		t.Fatalf("%+v", res)
	}
	if c := f.takeCore(); len(c) != 1 || c[0] != "/repositories/20" {
		t.Errorf("requests %q", c)
	}
	if repoID(t, d, 20) != a || gh(t, d, 20) != "rejected/admin gone []" || gh(t, d, 99) != "none" {
		t.Errorf("gone: %s, 99 = %s", gh(t, d, 20), gh(t, d, 99))
	}
}

// A name that answers 404 by name is released by the identity that held
// it; nothing else of that identity changes, and the next pass asks it by
// id: it learns its current name (or that it is gone).
func TestNameNotFoundReleasesKey(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	found(t, d, fakeRepo{id: 30, full: "moved/CVE-2026-0030", created: old})
	decide(t, d, 30, ghrepo.StatusTrusted)
	// renamed without a redirect left behind (the old name answers 404)
	f := newFakeSearch(t, fakeRepo{id: 30, full: "moved/CVE-2026-0030-new", created: old})
	link(post1, 0, "https://github.com/moved/CVE-2026-0030", "code")(t, d)
	sweep(t, d)
	if res := pass(t, d, f); res.Gone != 1 || res.LinkChecks != 1 {
		t.Fatalf("%+v", res)
	}
	if gh(t, d, 30) != "trusted/admin ok []" || stamp(t, d, post1, 0) != "moved/cve-2026-0030|-|checked" {
		t.Errorf("after the 404 by name: %s, %s", gh(t, d, 30), stamp(t, d, post1, 0))
	}
	f.takeCore()
	if res := pass(t, d, f); res.OK != 1 {
		t.Fatalf("%+v", res)
	}
	if c := f.takeCore(); len(c) != 1 || c[0] != "/repositories/30" || gh(t, d, 30) != "trusted/admin ok [moved/cve-2026-0030-new]" {
		t.Errorf("the refresh by id: %q, %s", c, gh(t, d, 30))
	}
	if res := pass(t, d, f); res.Requests != 0 {
		t.Errorf("idle: %+v", res)
	}
}

// I3: names. A placeholder whose name answers with an identity that has a
// row is folded into it (the key and its post associations move, the
// placeholder is deleted); otherwise the placeholder becomes the identity.
// An identity holds only its current name: a rename releases the old key.
// A key held by identity A that answers with another id leaves A as it is,
// without the key; two identities are never merged.
func TestNames(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	// 3 is known under its current name; old/name is queued with a post
	// association; GitHub redirects old/name to repository 3 (fakeGitHub)
	found(t, d, fakeRepo{id: 3, full: "acme/Name", desc: "CVE-2026-0003", created: old})
	three := repoID(t, d, 3)
	if _, _, err := ghrepo.Queue(ctx, d.Conn, "old/name", ghrepo.Source); err != nil {
		t.Fatal(err)
	}
	exec(t, d, `INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT repo_id, 'CVE-2026-0009', 'post' FROM github_repo_name WHERE name_key = 'old/name'`)
	// bob/tool is queued and new to us
	bob, _, err := ghrepo.Queue(ctx, d.Conn, "bob/tool", ghrepo.Source)
	if err != nil {
		t.Fatal(err)
	}
	a := fakeGitHub(t, 0, nil)
	o := ghrepo.Options{Client: a.Client(""), Now: func() time.Time { return now0 }, Logger: quiet, Sleep: noSleep}
	res, err := ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || res.OK != 2 || res.Merged != 1 || res.Requests != 3 { // 2 steps, one of them redirected
		t.Fatalf("%+v %v", res, err)
	}
	if repoID(t, d, 3) != three || gh(t, d, 3) != "unverified/- ok [acme/name]" || holder(t, d, "old/name") != "free" ||
		count(t, d, `SELECT count(*) FROM github_repo`) != 2 {
		t.Errorf("folded placeholder: %s, old/name %s, %d rows", gh(t, d, 3), holder(t, d, "old/name"), count(t, d, `SELECT count(*) FROM github_repo`))
	}
	if got := strings.Join(assoc(t, d, 3), " "); got != "CVE-2026-0009:post" { // the answer's description names no CVE
		t.Errorf("associations after the fold: %s", got)
	}
	if repoID(t, d, 2) != bob || gh(t, d, 2) != "unverified/- ok [bob/tool]" {
		t.Errorf("placeholder that became an identity: row %d (was %d) %s", repoID(t, d, 2), bob, gh(t, d, 2))
	}
	// a rename learned from search releases the old key
	found(t, d, fakeRepo{id: 2, full: "bob/tool2", desc: "CVE-2026-0002", created: old})
	if gh(t, d, 2) != "unverified/- ok [bob/tool2]" || holder(t, d, "bob/tool") != "free" {
		t.Errorf("rename: %s, old key %s", gh(t, d, 2), holder(t, d, "bob/tool"))
	}
	// acme/name answers with another id (search): 3 keeps everything but the key
	decide(t, d, 3, ghrepo.StatusTrusted)
	if !found(t, d, fakeRepo{id: 77, full: "Acme/name", desc: "CVE-2026-0003", created: old}) {
		t.Error("another id under a held name: not a new row")
	}
	if repoID(t, d, 3) != three || gh(t, d, 3) != "trusted/admin ok []" || gh(t, d, 77) != "unverified/- ok [acme/name]" ||
		count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 3 AND full_name = 'acme/Name'`) != 1 ||
		count(t, d, `SELECT count(*) FROM github_repo`) != 3 {
		t.Errorf("3 = %s, 77 = %s", gh(t, d, 3), gh(t, d, 77))
	}
	if n := count(t, d, `SELECT count(*) FROM (SELECT repo_id FROM github_repo_name n JOIN github_repo r ON r.id = n.repo_id
        WHERE r.github_id IS NOT NULL GROUP BY repo_id HAVING count(*) > 1) x`); n != 0 {
		t.Errorf("%d identities hold more than one name", n)
	}
}

// I4: vouching is recorded on the link, by identity, once: a root link is
// checked by a request for its key BY NAME made after the link exists, and
// stamped only when a public repository created no later than the link was
// stored answers. The sweep stamps nothing; a deep link is never stamped;
// a transient failure leaves the link unchecked; a 404 checks it without a
// stamp; another spelling of the same root keeps the stamp without a
// request; another root key resets it; a checked link is not looked at
// again, except when the key's 'gone' placeholder answers within its retry
// window, and then only under the same creation-time condition.
func TestLinkStamp(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := newFakeSearch(t,
		fakeRepo{id: 501, full: "bob/tool", created: old},
		fakeRepo{id: 502, full: "late/repo", created: future},
		fakeRepo{id: 503, full: "mid/repo", created: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		fakeRepo{id: 505, full: "dave/flaky", created: old})
	flaky := 502
	f.coreStatus = func(path string) int {
		if path == "/repos/dave/flaky" {
			return flaky
		}
		return 0
	}
	link(post1, 0, "https://github.com/bob/tool", "code")(t, d)
	link(post1, 1, "https://github.com/late/repo", "code")(t, d)
	link(post1, 2, "https://github.com/bob/tool/blob/main/x.py", "code")(t, d)
	link(post1, 3, "https://github.com/carol/missing", "code")(t, d)
	link(post1, 4, "https://github.com/dave/flaky", "code")(t, d)
	linkAt(t, d, post1, 5, "https://github.com/mid/repo", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))     // before the repository existed
	linkAt(t, d, post1, 6, "https://github.com/Mid/Repo.git", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) // after
	if res := sweep(t, d); res.Candidates != 7 || res.Added != 5 {
		t.Fatalf("%+v", res)
	}
	if n := count(t, d, `SELECT count(*) FROM x_post_link WHERE repo_github_id IS NOT NULL OR repo_checked_at IS NOT NULL`); n != 0 {
		t.Errorf("the sweep checked or stamped %d links", n)
	}
	res := pass(t, d, f)
	if res.Requests != 5 || res.OK != 3 || res.Gone != 1 || res.Retry != 1 || res.Stamped != 2 {
		t.Fatalf("%+v", res)
	}
	f.takeCore()
	for pos, want := range []string{"bob/tool|501|checked", "late/repo|-|checked", "-|-|unchecked", "carol/missing|-|checked",
		"dave/flaky|-|unchecked", "mid/repo|-|checked", "mid/repo|503|checked"} {
		if got := stamp(t, d, post1, pos); got != want {
			t.Errorf("link %d: %s, want %s", pos, got, want)
		}
	}
	for id, want := range map[int]string{501: "trusted/rule ok [bob/tool]", 502: "unverified/- ok [late/repo]", 503: "trusted/rule ok [mid/repo]"} {
		if got := gh(t, d, id); got != want {
			t.Errorf("%d: %s, want %s", id, got, want)
		}
	}
	// nothing checked is asked again: only the flaky placeholder is retried
	flaky = 0
	if res := pass(t, d, f); res.Requests != 1 || res.Stamped != 1 {
		t.Errorf("second pass: %+v", res)
	}
	if c := f.takeCore(); len(c) != 1 || c[0] != "/repos/dave/flaky" || stamp(t, d, post1, 4) != "dave/flaky|505|checked" {
		t.Errorf("second pass: %q, %s", c, stamp(t, d, post1, 4))
	}
	// another spelling of the same root: swept again, stamp kept, no request
	exec(t, d, `UPDATE x_post_link SET final_url = 'https://github.com/Bob/tool/' WHERE post_id = $1 AND pos = 0`, post1)
	if res := sweep(t, d); res.Candidates != 1 {
		t.Errorf("%+v", res)
	}
	if res := pass(t, d, f); res.Requests != 0 || stamp(t, d, post1, 0) != "bob/tool|501|checked" {
		t.Errorf("same root key: %+v, %s", res, stamp(t, d, post1, 0))
	}
	// another root key: the check and the stamp start over
	exec(t, d, `UPDATE x_post_link SET final_url = 'https://github.com/late/repo' WHERE post_id = $1 AND pos = 0`, post1)
	sweep(t, d)
	if got := stamp(t, d, post1, 0); got != "late/repo|-|unchecked" {
		t.Errorf("another root key: %s", got)
	}
	if res := pass(t, d, f); res.Requests != 1 || res.LinkChecks != 1 || res.Stamped != 0 || stamp(t, d, post1, 0) != "late/repo|-|checked" {
		t.Errorf("another root key, checked: %+v, %s", res, stamp(t, d, post1, 0))
	}
	f.takeCore()
	// a new root link to a repository we know is still checked by a request
	// for its own key, never from the stored row
	link(post2, 0, "https://github.com/bob/tool", "code")(t, d)
	sweep(t, d)
	if got := stamp(t, d, post2, 0); got != "bob/tool|-|unchecked" {
		t.Errorf("new link before the pass: %s", got)
	}
	if res := pass(t, d, f); res.Requests != 1 || res.Stamped != 1 {
		t.Errorf("new link: %+v", res)
	}
	if c := f.takeCore(); len(c) != 1 || c[0] != "/repos/bob/tool" || stamp(t, d, post2, 0) != "bob/tool|501|checked" {
		t.Errorf("new link: %q, %s", c, stamp(t, d, post2, 0))
	}
	// a link checked without a stamp is not looked at again: late/repo is
	// later registered by an older repository and linked by a new post
	f.set(fakeRepo{id: 600, full: "late/repo", created: old})
	link(post2, 1, "https://github.com/late/repo", "code")(t, d)
	sweep(t, d)
	if res := pass(t, d, f); res.Stamped != 1 {
		t.Errorf("late/repo again: %+v", res)
	}
	if stamp(t, d, post1, 1) != "late/repo|-|checked" || stamp(t, d, post1, 0) != "late/repo|-|checked" || stamp(t, d, post2, 1) != "late/repo|600|checked" ||
		gh(t, d, 600) != "trusted/rule ok [late/repo]" || gh(t, d, 502) != "unverified/- ok []" {
		t.Errorf("old links %s %s, new link %s, 600 = %s, 502 = %s", stamp(t, d, post1, 1), stamp(t, d, post1, 0), stamp(t, d, post2, 1),
			gh(t, d, 600), gh(t, d, 502))
	}
	// the 'gone' placeholder of carol/missing answers within its retry
	// window with a repository older than the link: the link is stamped
	// now. erin/missing answers with one created after its link: no stamp.
	link(post2, 2, "https://github.com/erin/missing", "code")(t, d)
	sweep(t, d)
	pass(t, d, f)
	if stamp(t, d, post2, 2) != "erin/missing|-|checked" {
		t.Fatalf("erin: %s", stamp(t, d, post2, 2))
	}
	exec(t, d, `UPDATE github_repo SET created_at = $1, fetched_at = $2 WHERE state = 'gone'`, now0, now0.Add(-25*time.Hour))
	f.set(fakeRepo{id: 504, full: "carol/missing", created: old}, fakeRepo{id: 506, full: "erin/missing", created: future})
	if res := pass(t, d, f); res.OK != 2 || res.Stamped != 1 {
		t.Errorf("gone retries: %+v", res)
	}
	if stamp(t, d, post1, 3) != "carol/missing|504|checked" || gh(t, d, 504) != "trusted/rule ok [carol/missing]" ||
		stamp(t, d, post2, 2) != "erin/missing|-|checked" || gh(t, d, 506) != "unverified/- ok [erin/missing]" {
		t.Errorf("carol %s %s, erin %s %s", stamp(t, d, post1, 3), gh(t, d, 504), stamp(t, d, post2, 2), gh(t, d, 506))
	}
}

// I5: rule trust comes from stamps and from nothing else. The sweep of a
// root link to a repository we already know grants nothing; a link to a
// name vouches for the repository that answers for the name now, not for
// one that held it before (reviewers' probe "stale alias"); a repository
// created after the link under the linked name gets nothing; a deep link
// never counts.
func TestRuleTrustOnlyFromStamps(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	// GA is found by search under att/CVE-2026-0001-poc, then renamed
	// (search returns it under its new name)
	found(t, d, fakeRepo{id: 700, full: "att/CVE-2026-0001-poc", created: old})
	found(t, d, fakeRepo{id: 700, full: "att/zzz", desc: "CVE-2026-0001", created: old})
	// eve and deep are found by search; ghost is found under a name that
	// will be registered again later
	found(t, d, fakeRepo{id: 502, full: "eve/CVE-2026-0003", created: old})
	found(t, d, fakeRepo{id: 504, full: "deep/CVE-2026-0005", created: old})
	found(t, d, fakeRepo{id: 800, full: "ghost/CVE-2026-0008", created: old})
	// researchers link the roots of the old name, of eve and of ghost, and
	// a file inside deep
	link(post1, 0, "https://github.com/att/CVE-2026-0001-poc", "code")(t, d)
	link(post1, 1, "https://github.com/eve/CVE-2026-0003", "code")(t, d)
	link(post1, 2, "https://github.com/deep/CVE-2026-0005/blob/main/x.py", "code")(t, d)
	link(post1, 3, "https://github.com/ghost/CVE-2026-0008", "code")(t, d)
	sweep(t, d)
	for _, id := range []int{700, 502, 504, 800} {
		if s := gh(t, d, id); !strings.HasPrefix(s, "unverified/- ") {
			t.Errorf("after the sweep alone, %d: %s", id, s)
		}
	}
	// GitHub now: GB (created before the link) answers for GA's old name;
	// ghost's name was registered again by a repository created after the link
	f := newFakeSearch(t, fakeRepo{id: 700, full: "att/zzz", created: old},
		fakeRepo{id: 701, full: "att/CVE-2026-0001-poc", created: time.Now().Add(-time.Hour)},
		fakeRepo{id: 502, full: "eve/CVE-2026-0003", created: old},
		fakeRepo{id: 504, full: "deep/CVE-2026-0005", created: old},
		fakeRepo{id: 801, full: "ghost/CVE-2026-0008", created: future})
	if res := pass(t, d, f); res.Stamped != 2 {
		t.Fatalf("%+v", res)
	}
	for id, want := range map[int]string{
		700: "unverified/- ok [att/zzz]",               // left the name: nothing
		701: "trusted/rule ok [att/cve-2026-0001-poc]", // answers for the linked name, older than the link
		502: "trusted/rule ok [eve/cve-2026-0003]",
		504: "unverified/- ok [deep/cve-2026-0005]",  // only a deep link
		800: "unverified/- ok []",                    // lost the name
		801: "unverified/- ok [ghost/cve-2026-0008]", // registered after the link
	} {
		if got := gh(t, d, id); got != want {
			t.Errorf("%d: %s, want %s", id, got, want)
		}
	}
	if got := stamp(t, d, post1, 0) + " " + stamp(t, d, post1, 3); got != "att/cve-2026-0001-poc|701|checked ghost/cve-2026-0008|-|checked" {
		t.Errorf("stamps: %s", got)
	}
	// later sweeps, searches and refreshes add no trust
	exec(t, d, `UPDATE x_post_link SET final_url = final_url || '/' WHERE post_id = $1 AND pos IN (0, 3)`, post1)
	sweep(t, d)
	found(t, d, fakeRepo{id: 801, full: "ghost/CVE-2026-0008", created: future})
	found(t, d, fakeRepo{id: 700, full: "att/zzz", desc: "CVE-2026-0001", created: old})
	due(t, d)
	pass(t, d, f)
	if gh(t, d, 801) != "unverified/- ok [ghost/cve-2026-0008]" || gh(t, d, 700) != "unverified/- ok [att/zzz]" || gh(t, d, 800) != "unverified/- gone []" {
		t.Errorf("afterwards: 801 %s, 700 %s, 800 %s", gh(t, d, 801), gh(t, d, 700), gh(t, d, 800))
	}
}

// Reviewers' probe "re-sweep": a link whose repository was replaced under
// the same name after the post does not vouch for the replacement when the
// link's URL changes spelling and is swept again.
func TestResweepGivesNoTrust(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	link(post1, 0, "https://github.com/v/poc", "code")(t, d)
	f := newFakeSearch(t, fakeRepo{id: 900, full: "v/poc", created: old})
	sweep(t, d)
	pass(t, d, f)
	if gh(t, d, 900) != "trusted/rule ok [v/poc]" {
		t.Fatalf("900: %s", gh(t, d, 900))
	}
	// deleted; a new repository under the name, created after the post
	f.set(fakeRepo{id: 901, full: "v/poc", created: future})
	due(t, d)
	pass(t, d, f)
	if gh(t, d, 900) != "trusted/rule gone []" || gh(t, d, 901) != "none" {
		t.Errorf("after the refresh: 900 %s, 901 %s", gh(t, d, 900), gh(t, d, 901))
	}
	exec(t, d, `UPDATE x_post_link SET final_url = 'https://github.com/v/poc/' WHERE post_id = $1`, post1)
	if res := sweep(t, d); res.Candidates != 1 {
		t.Fatalf("%+v", res)
	}
	pass(t, d, f) // the queued name is asked: 901 answers
	found(t, d, fakeRepo{id: 901, full: "v/poc", desc: "CVE-2026-0009", created: future})
	if s := gh(t, d, 901); s != "unverified/- ok [v/poc]" || stamp(t, d, post1, 0) != "v/poc|900|checked" {
		t.Errorf("after the re-sweep: 901 %s, link %s", s, stamp(t, d, post1, 0))
	}
}

// Reviewers' probe "gone, then created later": a post links a name that
// does not exist; a repository registered under it afterwards — found by
// search or by the retry of the name — is not trusted.
func TestGoneNameCreatedLater(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	link(post1, 0, "https://github.com/carol/missing", "code")(t, d)
	f := newFakeSearch(t)
	sweep(t, d)
	if res := pass(t, d, f); res.Gone != 1 || stamp(t, d, post1, 0) != "carol/missing|-|checked" {
		t.Fatalf("%+v %s", res, stamp(t, d, post1, 0))
	}
	ph := idOf(t, d, "carol/missing")
	if !strings.HasPrefix(status(t, d, "carol/missing"), "unverified/") {
		t.Errorf("gone placeholder: %s", status(t, d, "carol/missing"))
	}
	// search finds a repository under that name: a row of its own (A5: a
	// search result never becomes the placeholder a post link queued, so it
	// inherits no 'post' association and is no 'xposts' row); the
	// placeholder stays queued, without the name
	if !found(t, d, fakeRepo{id: 666, full: "carol/missing", desc: "CVE-2026-0002 exploit", created: future}) {
		t.Error("the search result took over the placeholder")
	}
	if repoID(t, d, 666) == ph || gh(t, d, 666) != "unverified/- ok [carol/missing]" || stamp(t, d, post1, 0) != "carol/missing|-|checked" ||
		count(t, d, `SELECT count(*) FROM github_repo WHERE id = $1 AND github_id IS NULL AND state = 'gone'`, ph) != 1 ||
		count(t, d, `SELECT count(*) FROM github_repo WHERE github_id = 666 AND first_source = 'search'`) != 1 ||
		count(t, d, `SELECT count(*) FROM github_repo_cve c JOIN github_repo r ON r.id = c.repo_id WHERE r.github_id = 666 AND c.basis = 'post'`) != 0 {
		t.Errorf("666: %s, link %s", gh(t, d, 666), stamp(t, d, post1, 0))
	}
	// a second post links it: the repository was created after that link
	// too (2099), so its check gives no stamp either
	link(post2, 0, "https://github.com/carol/missing", "code")(t, d)
	sweep(t, d)
	f.set(fakeRepo{id: 666, full: "carol/missing", created: future})
	pass(t, d, f)
	if gh(t, d, 666) != "unverified/- ok [carol/missing]" || stamp(t, d, post2, 0) != "carol/missing|-|checked" {
		t.Errorf("after a second link: %s, %s", gh(t, d, 666), stamp(t, d, post2, 0))
	}
	// the placeholder's own retry by name (inside its window) folds it into
	// the identity that answers: only then do its post associations move
	exec(t, d, `INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'CVE-2026-0002', 'post')`, ph)
	exec(t, d, `UPDATE github_repo SET created_at = $1, fetched_at = $2 WHERE id = $3`, now0, now0.Add(-25*time.Hour), ph)
	if res := pass(t, d, f); res.Merged != 1 || count(t, d, `SELECT count(*) FROM github_repo WHERE id = $1`, ph) != 0 ||
		count(t, d, `SELECT count(*) FROM github_repo_cve c JOIN github_repo r ON r.id = c.repo_id WHERE r.github_id = 666 AND c.basis = 'post'`) != 1 ||
		gh(t, d, 666) != "unverified/- ok [carol/missing]" {
		t.Errorf("the placeholder's retry: %+v %s", res, gh(t, d, 666))
	}
}

// I7: an admin's decision stays with the identity through everything
// automatic: a root link that stamps it, a rename learned from search or
// from its refresh, its name being registered again by another repository
// (which starts on its own), 'gone'.
func TestAdminDecisionSticks(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	found(t, d, fakeRepo{id: 1, full: "t/CVE-2026-0001", created: old})
	found(t, d, fakeRepo{id: 2, full: "r/CVE-2026-0002", created: old})
	found(t, d, fakeRepo{id: 3, full: "u/CVE-2026-0003", created: old})
	decide(t, d, 1, ghrepo.StatusTrusted)
	decide(t, d, 2, ghrepo.StatusRejected)
	decide(t, d, 3, ghrepo.StatusUnverified) // a reset is a decision too
	rows := map[int]int64{1: repoID(t, d, 1), 2: repoID(t, d, 2), 3: repoID(t, d, 3)}
	want := map[int]string{1: "trusted/admin", 2: "rejected/admin", 3: "unverified/admin"}
	check := func(step string) {
		t.Helper()
		for id, w := range want {
			if s := gh(t, d, id); !strings.HasPrefix(s, w+" ") || repoID(t, d, id) != rows[id] {
				t.Errorf("%s: %d is %s (row %d), want %s (row %d)", step, id, s, repoID(t, d, id), w, rows[id])
			}
		}
	}
	at := func(n int) time.Time {
		var at time.Time
		if err := d.Conn.QueryRow(context.Background(), `SELECT status_at FROM github_repo WHERE github_id = $1`, n).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	at3 := at(3)
	// researchers link all three roots: stamped, statuses unchanged
	f := newFakeSearch(t, fakeRepo{id: 1, full: "t/CVE-2026-0001", created: old}, fakeRepo{id: 2, full: "r/CVE-2026-0002", created: old},
		fakeRepo{id: 3, full: "u/CVE-2026-0003", created: old})
	for i, u := range []string{"https://github.com/t/CVE-2026-0001", "https://github.com/r/CVE-2026-0002", "https://github.com/u/CVE-2026-0003"} {
		link(post1, i, u, "code")(t, d)
	}
	sweep(t, d)
	if res := pass(t, d, f); res.Stamped != 3 {
		t.Fatalf("%+v", res)
	}
	check("stamped")
	if !at(3).Equal(at3) {
		t.Error("status_at of an admin decision rewritten")
	}
	// renamed; search finds them under the new names
	for _, r := range []fakeRepo{{id: 1, full: "t/CVE-2026-0001-b", created: old}, {id: 2, full: "r/CVE-2026-0002-b", created: old},
		{id: 3, full: "u/CVE-2026-0003-b", created: old}} {
		found(t, d, r)
	}
	check("renamed (search)")
	// the old names are registered again by other repositories, linked and found
	f.set(fakeRepo{id: 1, full: "t/CVE-2026-0001-c", created: old}, fakeRepo{id: 2, full: "r/CVE-2026-0002-c", created: old},
		fakeRepo{id: 11, full: "t/CVE-2026-0001", created: old}, fakeRepo{id: 13, full: "u/CVE-2026-0003", created: old})
	link(post2, 0, "https://github.com/t/CVE-2026-0001", "code")(t, d)
	sweep(t, d)
	found(t, d, fakeRepo{id: 13, full: "u/CVE-2026-0003", created: old})
	due(t, d)
	pass(t, d, f) // refreshes by id: 1 and 2 renamed again, 3 gone; the link check: 11
	check("renamed (refresh), names registered again")
	if gh(t, d, 1) != "trusted/admin ok [t/cve-2026-0001-c]" || gh(t, d, 3) != "unverified/admin gone []" ||
		gh(t, d, 11) != "trusted/rule ok [t/cve-2026-0001]" || gh(t, d, 13) != "unverified/- ok [u/cve-2026-0003]" {
		t.Errorf("1 %s | 3 %s | 11 %s | 13 %s", gh(t, d, 1), gh(t, d, 3), gh(t, d, 11), gh(t, d, 13))
	}
}

// I8: rejected names. A rejection is recorded for the name key the
// identity holds, and for every key it holds later while it stays
// rejected; an identity nobody decided about that turns up under such a
// key is rejected by rule, and an admin can still decide about it;
// lifting one identity's rejection removes only the keys it recorded.
// Replays the reviewers' sequences "rejected, renamed, name re-registered,
// refreshed, found again" and "rejected, renamed, recreated under the new
// name".
func TestRejectedNames(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	exec(t, d, `INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0777')`)
	found(t, d, fakeRepo{id: 770, full: "evil/CVE-2026-0777", created: old})
	decide(t, d, 770, ghrepo.StatusRejected)
	// the owner renames 770 to evil/CVE-2026-0777-x and plants 771 under
	// the old name before our refresh
	f := newFakeSearch(t, fakeRepo{id: 770, full: "evil/CVE-2026-0777-x", created: old}, fakeRepo{id: 771, full: "evil/CVE-2026-0777", created: old})
	due(t, d)
	pass(t, d, f)
	if gh(t, d, 770) != "rejected/admin ok [evil/cve-2026-0777-x]" || gh(t, d, 771) != "none" {
		t.Errorf("refresh: 770 %s, 771 %s", gh(t, d, 770), gh(t, d, 771))
	}
	// search finds both
	found(t, d, fakeRepo{id: 771, full: "evil/CVE-2026-0777", created: old})
	found(t, d, fakeRepo{id: 770, full: "evil/CVE-2026-0777-x", created: old})
	if gh(t, d, 770) != "rejected/admin ok [evil/cve-2026-0777-x]" || gh(t, d, 771) != "rejected/rule ok [evil/cve-2026-0777]" {
		t.Errorf("found again: 770 %s, 771 %s", gh(t, d, 770), gh(t, d, 771))
	}
	// neither passes the public listing's filter
	if n := count(t, d, `SELECT count(*) FROM github_repo r WHERE r.github_id IN (770, 771) AND r.state = 'ok' AND r.status <> 'rejected'`); n != 0 {
		t.Errorf("%d of them listable", n)
	}
	// 770 is deleted and recreated as 772 under its CURRENT name
	if !found(t, d, fakeRepo{id: 772, full: "evil/CVE-2026-0777-x", created: old}) || gh(t, d, 772) != "rejected/rule ok [evil/cve-2026-0777-x]" {
		t.Errorf("recreated under the new name: %s", gh(t, d, 772))
	}
	// a researcher's root link does not lift a rejection by rule
	link(post1, 0, "https://github.com/evil/CVE-2026-0777", "code")(t, d)
	sweep(t, d)
	pass(t, d, f)
	if stamp(t, d, post1, 0) != "evil/cve-2026-0777|771|checked" || gh(t, d, 771) != "rejected/rule ok [evil/cve-2026-0777]" {
		t.Errorf("linked: %s %s", stamp(t, d, post1, 0), gh(t, d, 771))
	}
	// an existing identity nobody decided about that moves under a rejected name
	found(t, d, fakeRepo{id: 780, full: "evil/other", desc: "CVE-2026-0777", created: old})
	found(t, d, fakeRepo{id: 780, full: "evil/CVE-2026-0777", desc: "CVE-2026-0777", created: old})
	if gh(t, d, 780) != "rejected/rule ok [evil/cve-2026-0777]" {
		t.Errorf("renamed into a rejected name: %s", gh(t, d, 780))
	}
	// an admin decides about 771 explicitly: a change (audited by the caller)
	if ch, err := ghrepo.SetStatus(ctx, d.Conn, repoID(t, d, 771), ghrepo.StatusRejected); err != nil || !ch {
		t.Errorf("explicit rejection of a rule-rejected identity: %v %v", ch, err)
	}
	if ch, err := ghrepo.SetStatus(ctx, d.Conn, repoID(t, d, 771), ghrepo.StatusRejected); err != nil || ch {
		t.Errorf("again: %v %v", ch, err)
	}
	// two identities recorded keys; lifting 770's rejection removes only its own
	found(t, d, fakeRepo{id: 771, full: "evil/CVE-2026-0777-y", created: old}) // 771 (admin-rejected) holds a key of its own now
	var keys string
	names := func() string {
		if err := d.Conn.QueryRow(ctx, `SELECT COALESCE(string_agg(j.name_key || '@' || r.github_id, ' ' ORDER BY j.name_key, r.github_id), '')
            FROM github_rejected_name j JOIN github_repo r ON r.id = j.repo_id`).Scan(&keys); err != nil {
			t.Fatal(err)
		}
		return keys
	}
	// (771 held no key when it was rejected — 780 had taken its name — so
	// the key of its stored full name was recorded for it: A1)
	if got := names(); got != "evil/cve-2026-0777@770 evil/cve-2026-0777@771 evil/cve-2026-0777-x@770 evil/cve-2026-0777-y@771" {
		t.Errorf("recorded: %s", got)
	}
	decide(t, d, 770, ghrepo.StatusUnverified)
	if got := names(); got != "evil/cve-2026-0777@771 evil/cve-2026-0777-y@771" {
		t.Errorf("after lifting 770's: %s", got)
	}
	// a new identity under a key only 770 had recorded starts unverified;
	// one under a key 771 recorded is rejected by rule
	found(t, d, fakeRepo{id: 790, full: "evil/CVE-2026-0777-x", created: old})
	found(t, d, fakeRepo{id: 771, full: "evil/CVE-2026-0777-z", created: old})
	found(t, d, fakeRepo{id: 791, full: "evil/CVE-2026-0777-y", created: old})
	found(t, d, fakeRepo{id: 792, full: "evil/CVE-2026-0777", created: old})
	if gh(t, d, 790) != "unverified/- ok [evil/cve-2026-0777-x]" || gh(t, d, 791) != "rejected/rule ok [evil/cve-2026-0777-y]" ||
		gh(t, d, 792) != "rejected/rule ok [evil/cve-2026-0777]" {
		t.Errorf("790 %s, 791 %s, 792 %s", gh(t, d, 790), gh(t, d, 791), gh(t, d, 792))
	}
	// I7: identities an admin decided about keep the decision when they
	// move under a rejected name (trusted, and reset to unverified)
	found(t, d, fakeRepo{id: 795, full: "ok/CVE-2026-0795", created: old})
	found(t, d, fakeRepo{id: 796, full: "ok/CVE-2026-0796", created: old})
	decide(t, d, 795, ghrepo.StatusTrusted)
	decide(t, d, 796, ghrepo.StatusUnverified)
	found(t, d, fakeRepo{id: 795, full: "evil/CVE-2026-0777-y", created: old})
	found(t, d, fakeRepo{id: 796, full: "evil/CVE-2026-0777-z", created: old})
	if gh(t, d, 795) != "trusted/admin ok [evil/cve-2026-0777-y]" || gh(t, d, 796) != "unverified/admin ok [evil/cve-2026-0777-z]" {
		t.Errorf("admin decisions under rejected names: 795 %s, 796 %s", gh(t, d, 795), gh(t, d, 796))
	}
}

// I10: Enqueue next to a transaction that creates the same name key (a
// discovery pass storing a result under it): no unique violation; the
// sweep waits, then uses the row that won.
func TestEnqueueConcurrentName(t *testing.T) {
	t.Parallel()
	d := seedPostLinks(t)
	ctx := context.Background()
	other, err := testutil.Connect(ctx, d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	tx, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO github_repo (github_id, queued_name, full_name, state, first_source)
        VALUES (2, 'bob/tool', 'bob/tool', 'ok', 'search') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO github_repo_name (name_key, repo_id) VALUES ('bob/tool', $1)`, id); err != nil {
		t.Fatal(err)
	}
	type out struct {
		res ghrepo.EnqueueResult
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := ghrepo.Enqueue(ctx, d.Conn, quiet)
		done <- out{res, err}
	}()
	select {
	case o := <-done:
		t.Fatalf("the sweep did not wait for the concurrent name: %+v %v", o.res, o.err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	o := <-done
	if o.err != nil || o.res.Candidates != 8 || o.res.Added != 5 {
		t.Fatalf("%+v %v", o.res, o.err)
	}
	if holder(t, d, "bob/tool") != "2" || count(t, d, `SELECT count(*) FROM github_repo WHERE queued_name = 'bob/tool'`) != 1 {
		t.Errorf("bob/tool: %s, %d rows", holder(t, d, "bob/tool"), count(t, d, `SELECT count(*) FROM github_repo WHERE queued_name = 'bob/tool'`))
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo_cve WHERE repo_id = $1 AND basis = 'post'`, id); n != 2 {
		t.Errorf("post associations on the row that won: %d", n)
	}
}
