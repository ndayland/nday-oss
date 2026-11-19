package ghrepo_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/testutil"
)

// ownerRepo inserts a fetched repository of owner login (ownerID 0 = id not
// known, as for rows fetched before migration 0036) with a status.
func ownerRepo(t *testing.T, d *testutil.TestDB, gh int64, full, login string, ownerID int64, status, by string) int64 {
	t.Helper()
	var byArg, atArg, oid any
	if by != "" {
		byArg, atArg = by, time.Now()
	}
	if ownerID != 0 {
		oid = ownerID
	}
	var id int64
	if err := d.Conn.QueryRow(context.Background(), `INSERT INTO github_repo (github_id, queued_name, full_name, owner_login, owner_id,
        state, fetched_at, first_source, repo_created_at, status, status_by, status_at)
        VALUES ($1, lower($2), $2, $3, $4, 'ok', now() - interval '2 days', 'search', '2026-01-01', $5, $6, $7) RETURNING id`,
		gh, full, login, oid, status, byArg, atArg).Scan(&id); err != nil {
		t.Fatal(err)
	}
	exec(t, d, `INSERT INTO github_repo_name (name_key, repo_id) VALUES (lower($1), $2)`, full, id)
	return id
}

// ownerTx runs fn in a transaction with the store lock, then syncs owner trust.
func ownerTx(t *testing.T, d *testutil.TestDB, fn func(tx pgx.Tx) error) (granted, reverted int) {
	t.Helper()
	err := pgx.BeginFunc(context.Background(), d.Conn, func(tx pgx.Tx) error {
		ctx := context.Background()
		if err := ghrepo.LockOwners(ctx, tx); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		var err error
		granted, reverted, err = ghrepo.SyncOwners(ctx, tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return granted, reverted
}

// addOwner lists login with the owner id ownerID (0 = pending).
func addOwner(t *testing.T, d *testutil.TestDB, login string, ownerID int64) int64 {
	t.Helper()
	var id int64
	ownerTx(t, d, func(tx pgx.Tx) error {
		var err error
		id, err = ghrepo.AddOwner(context.Background(), tx, login, ownerID, "", "")
		return err
	})
	return id
}

func setOwner(t *testing.T, d *testutil.TestDB, id int64, on bool) (granted, reverted int) {
	t.Helper()
	return ownerTx(t, d, func(tx pgx.Tx) error {
		_, err := ghrepo.SetOwnerEnabled(context.Background(), tx, id, on)
		return err
	})
}

func statusOf(t *testing.T, d *testutil.TestDB, id int64) string {
	t.Helper()
	var s string
	if err := d.Conn.QueryRow(context.Background(), `SELECT status || '/' || COALESCE(status_by, '') FROM github_repo WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// stampBy stamps a root link to repository gh from a post by X account
// xid (enabled or not).
func stampBy(t *testing.T, d *testutil.TestDB, post string, gh int64, full, xid string, enabled bool) {
	t.Helper()
	exec(t, d, `INSERT INTO x_accounts (user_id, handle, enabled) VALUES ($1, 'h' || $1, $2) ON CONFLICT DO NOTHING`, xid, enabled)
	exec(t, d, `INSERT INTO x_post_no_cve (post_id, author_id, text, posted_at, url, observed_at) VALUES ($1, $2, 'x', now(), 'https://x.com/i/web/status/1', now())`,
		post, xid)
	exec(t, d, `INSERT INTO x_post_link (post_id, pos, short_url, kind, origin, status, repo_root_key, repo_checked_at, repo_github_id)
        VALUES ($1, 0, 'https://t.co/a', 'code', 'api', 'ok', lower($2), now(), $3)`, post, full, gh)
}

// Adding an account trusts the undecided repositories of that owner id —
// with or without a stamped post link — and nothing else: an admin's
// trust or rejection, the post rule's trust and a rejection by rule keep
// their origin; a fork and a collection wait for a person; a row of a
// previous holder of the login (another id) and a row without an id are
// not trusted. Disabling takes owner trust back: to 'rule' where the post
// rule's own test holds (a stamp, whoever posted it), else unverified.
func TestOwnerTrustAddDisable(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	const alice = 10
	plain := ownerRepo(t, d, 1, "alice/CVE-2026-1-poc", "alice", alice, "unverified", "")
	stampOff := ownerRepo(t, d, 2, "alice/lab", "alice", alice, "unverified", "")
	stampBy(t, d, "101", 2, "alice/lab", "501", false) // the poster was disabled since
	stampOn := ownerRepo(t, d, 3, "alice/lab2", "alice", alice, "unverified", "")
	stampBy(t, d, "102", 3, "alice/lab2", "502", true)
	rej := ownerRepo(t, d, 4, "alice/fake", "alice", alice, "rejected", "admin")
	adm := ownerRepo(t, d, 5, "alice/kept", "alice", alice, "trusted", "admin")
	rule := ownerRepo(t, d, 6, "alice/posted", "alice", alice, "trusted", "rule")
	stampBy(t, d, "103", 6, "alice/posted", "502", true)
	rrule := ownerRepo(t, d, 7, "alice/dup", "alice", alice, "rejected", "rule")
	fork := ownerRepo(t, d, 8, "alice/fork-of-junk", "alice", alice, "unverified", "")
	exec(t, d, `UPDATE github_repo SET is_fork = true WHERE id = $1`, fork)
	coll := ownerRepo(t, d, 9, "alice/cve-collection", "alice", alice, "unverified", "")
	for i := 1; i <= 4; i++ {
		exec(t, d, `INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, $2, 'name')`, coll, fmt.Sprintf("CVE-2026-%04d", 9000+i))
	}
	prev := ownerRepo(t, d, 11, "alice/old-thing", "alice", 99, "unverified", "")   // a previous holder of the login
	noID := ownerRepo(t, d, 12, "Alice/unfetched", "Alice", 0, "unverified", "")    // fetched before 0036
	other := ownerRepo(t, d, 13, "bob/CVE-2026-1-poc", "bob", 20, "unverified", "") // another owner

	id := addOwner(t, d, "alice", alice)
	want := map[int64]string{plain: "trusted/owner", stampOff: "trusted/owner", stampOn: "trusted/owner", rej: "rejected/admin",
		adm: "trusted/admin", rule: "trusted/rule", rrule: "rejected/rule", fork: "unverified/", coll: "unverified/",
		prev: "unverified/", noID: "unverified/", other: "unverified/"}
	for r, w := range want {
		if got := statusOf(t, d, r); got != w {
			t.Errorf("after add, row %d: %s, want %s", r, got, w)
		}
	}
	err := pgx.BeginFunc(context.Background(), d.Conn, func(tx pgx.Tx) error {
		got, err := ghrepo.AddOwner(context.Background(), tx, "ALICE", 0, "", "")
		if got != id {
			t.Errorf("duplicate names %d, want %d", got, id)
		}
		return err
	})
	if !errors.Is(err, ghrepo.ErrOwnerExists) {
		t.Errorf("duplicate login: %v", err)
	}
	if o, err := ghrepo.GetOwner(context.Background(), d.Conn, id, false); err != nil || o.Repos != 9 || o.Trusted != 3 || !o.Enabled {
		t.Errorf("listed: %+v %v", o, err)
	}

	if g, r := setOwner(t, d, id, false); g != 0 || r != 3 {
		t.Errorf("disable: granted %d reverted %d", g, r)
	}
	want[plain], want[stampOff], want[stampOn] = "unverified/", "trusted/rule", "trusted/rule"
	for r, w := range want {
		if got := statusOf(t, d, r); got != w {
			t.Errorf("after disable, row %d: %s, want %s", r, got, w)
		}
	}
	// a repository that becomes a fork loses owner trust
	exec(t, d, `UPDATE github_repo SET status = 'unverified', status_by = NULL, status_at = NULL WHERE id IN ($1, $2)`, stampOff, stampOn)
	setOwner(t, d, id, true)
	exec(t, d, `UPDATE github_repo SET is_fork = true WHERE id = $1`, plain)
	ownerTx(t, d, func(pgx.Tx) error { return nil })
	if got := statusOf(t, d, plain); got != "unverified/" {
		t.Errorf("became a fork: %s", got)
	}
}

// The owner's numeric id decides: a renamed owner keeps its trust and the
// account shows the new login; someone else who registers the old login
// is not trusted; a listed id is a duplicate whatever login is typed.
func TestOwnerTrustByID(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	id := addOwner(t, d, "alice", 77)
	renamed := ownerRepo(t, d, 12, "alice2/two", "alice2", 77, "unverified", "")
	exec(t, d, `UPDATE github_repo SET fetched_at = clock_timestamp() WHERE id = $1`, renamed) // fetched after the account was added
	squat := ownerRepo(t, d, 13, "alice/CVE-2026-9-poc", "alice", 99, "unverified", "")
	ownerTx(t, d, func(pgx.Tx) error { return nil })
	if got := statusOf(t, d, renamed); got != "trusted/owner" {
		t.Errorf("renamed owner's repository: %s", got)
	}
	if got := statusOf(t, d, squat); got != "unverified/" {
		t.Errorf("new holder of the old login: %s", got)
	}
	if o, _ := ghrepo.GetOwner(ctx, d.Conn, id, false); o.Login != "alice2" {
		t.Errorf("login after the rename: %q", o.Login)
	}
	err := pgx.BeginFunc(ctx, d.Conn, func(tx pgx.Tx) error {
		_, err := ghrepo.AddOwner(ctx, tx, "someone", 77, "", "")
		return err
	})
	if !errors.Is(err, ghrepo.ErrOwnerExists) {
		t.Errorf("listed id under another login: %v", err)
	}
}

// An account whose id could not be looked up trusts nothing — not even a
// row with its login and an id — until a fetch pass resolves it
// (GET /users/{login}); a failed lookup is retried by the next pass.
func TestOwnerPendingResolved(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	r := ownerRepo(t, d, 21, "carol/CVE-2026-2-poc", "carol", 55, "unverified", "")
	id := addOwner(t, d, "carol", 0)
	if got := statusOf(t, d, r); got != "unverified/" {
		t.Fatalf("pending account trusted: %s", got)
	}
	f := newFakeSearch(t)
	f.users = map[string]int{"Carol": 55}
	f.userStatus = 502
	res := pass(t, d, f)
	if res.OwnersPinned != 0 || res.Requests != 1 {
		t.Errorf("failed lookup: %+v", res)
	}
	if o, _ := ghrepo.GetOwner(ctx, d.Conn, id, false); o.OwnerID != 0 {
		t.Errorf("pinned after a failed lookup: %+v", o)
	}
	f.userStatus = 0
	res = pass(t, d, f)
	if res.OwnersPinned != 1 {
		t.Errorf("retry: %+v", res)
	}
	if o, _ := ghrepo.GetOwner(ctx, d.Conn, id, false); o.OwnerID != 55 || !strings.EqualFold(o.Login, "carol") {
		t.Errorf("after the lookup: %+v", o)
	}
	if got := statusOf(t, d, r); got != "trusted/owner" {
		t.Errorf("after the lookup: %s", got)
	}
	// nothing pending any more: no request
	if res := pass(t, d, f); res.OwnersPinned != 0 || res.Requests != 0 {
		t.Errorf("third pass: %+v", res)
	}
}

// LookupOwner: the id and GitHub's spelling; 404 is ErrLoginNotFound; a
// refusal or an answer for another login is an error to retry.
func TestLookupOwner(t *testing.T) {
	t.Parallel()
	f := newFakeSearch(t)
	f.users = map[string]int{"Dora": 42}
	ctx := context.Background()
	if id, login, err := ghrepo.LookupOwner(ctx, f.Client(""), "dora"); err != nil || id != 42 || login != "Dora" {
		t.Errorf("found: %d %q %v", id, login, err)
	}
	if _, _, err := ghrepo.LookupOwner(ctx, f.Client(""), "nobody"); !errors.Is(err, ghrepo.ErrLoginNotFound) {
		t.Errorf("404: %v", err)
	}
	f.userStatus = 429
	if _, _, err := ghrepo.LookupOwner(ctx, f.Client(""), "dora"); err == nil || errors.Is(err, ghrepo.ErrLoginNotFound) {
		t.Errorf("429: %v", err)
	}
}

// A row without an owner id whose stored login names a listed account is a
// candidate: the fetch pass asks it again without a validator (so the
// answer is a 200 with owner.id, even for an undecided row found by search
// that is otherwise never refreshed), and the answer decides.
func TestOwnerCandidateRefetch(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	same := ownerRepo(t, d, 31, "erin/CVE-2026-3-poc", "erin", 0, "unverified", "")
	moved := ownerRepo(t, d, 32, "erin/CVE-2026-4-poc", "erin", 0, "unverified", "")
	exec(t, d, `UPDATE github_repo SET etag = '"abc"', fetched_at = $1`, now0.Add(-24*time.Hour))
	addOwner(t, d, "erin", 66)
	if got := statusOf(t, d, same); got != "unverified/" {
		t.Fatalf("trusted by login: %s", got)
	}
	// the login now belongs to another account (id 67) for repository 32
	f := newFakeSearch(t,
		fakeRepo{id: 31, full: "erin/CVE-2026-3-poc", created: old, owner: 66},
		fakeRepo{id: 32, full: "erin/CVE-2026-4-poc", created: old, owner: 67})
	pass(t, d, f)
	if got := strings.Join(f.takeCore(), " "); got != "/repositories/31 /repositories/32" {
		t.Errorf("requests: %s", got)
	}
	for _, v := range f.inm {
		if v != "" {
			t.Errorf("conditional refetch: If-None-Match %q", v)
		}
	}
	if got := statusOf(t, d, same); got != "trusted/owner" {
		t.Errorf("same owner after the refetch: %s", got)
	}
	if got := statusOf(t, d, moved); got != "unverified/" {
		t.Errorf("another owner after the refetch: %s", got)
	}
	// once it has an id it is not asked again by this rule
	f.inm = nil
	pass(t, d, f)
	if got := f.takeCore(); len(got) != 0 {
		t.Errorf("asked again: %v", got)
	}
}

// A repository of a listed owner found later is trusted on arrival.
func TestOwnerTrustOnDiscovery(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	addOwner(t, d, "Carol", 501)
	f := newFakeSearch(t,
		fakeRepo{id: 3001, full: "carol/CVE-2026-70001-poc", created: now0.Add(-5 * time.Hour), owner: 501},
		fakeRepo{id: 3002, full: "dave/CVE-2026-70002-poc", created: now0.Add(-5 * time.Hour), owner: 502},
		fakeRepo{id: 3003, full: "carol/CVE-2026-70003-fork", created: now0.Add(-5 * time.Hour), owner: 501, fork: true, stars: 10})
	o := discoverOpts(f, now0, &sleeps{})
	o.HotCVEs = -1
	if _, err := ghrepo.Discover(ctx, d.Conn, o); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"carol/cve-2026-70001-poc": "trusted/owner", "dave/cve-2026-70002-poc": "unverified/",
		"carol/cve-2026-70003-fork": "unverified/"} {
		if got := status(t, d, name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
	var stored int64
	if err := d.Conn.QueryRow(ctx, `SELECT owner_id FROM github_repo WHERE github_id = 3002`).Scan(&stored); err != nil || stored != 502 {
		t.Errorf("owner_id stored: %d %v", stored, err)
	}
}

// PoC events of owner trust follow the post rule's conditions: name,
// description or topic only (a post alone is not enough), not created more
// than 30 days before the disclosure, live only when created recently;
// never for a fork or a collection; taking owner trust back removes them.
func TestOwnerTrustPoC(t *testing.T) {
	t.Parallel()
	p := newPoCDB(t)
	recent := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	for _, c := range []string{"CVE-2026-0701", "CVE-2026-0702", "CVE-2026-0703", "CVE-2026-0704", "CVE-2026-0705"} {
		p.vuln(c)
	}
	p.repo(71, "unverified", "", recent, "CVE-2026-0701", "name")                  // live
	p.repo(72, "unverified", "", recent, "CVE-2026-0702", "post")                  // post only
	p.repo(73, "unverified", "", "2025-11-01T00:00:00Z", "CVE-2026-0703", "name")  // 70 days before the disclosure
	p.repo(74, "unverified", "", "2026-01-05T00:00:00Z", "CVE-2026-0704", "topic") // 5 days before: at the disclosure, history
	p.repo(75, "unverified", "", recent, "CVE-2026-0705", "name")                  // a fork
	p.exec(`UPDATE github_repo SET owner_login = 'eve', owner_id = 7`)
	p.exec(`UPDATE github_repo SET is_fork = true WHERE github_id = 75`)
	d := &testutil.TestDB{Conn: p.conn}
	id := addOwner(t, d, "eve", 7)
	day := recent[:10] + " " + recent[11:16]
	want := "CVE-2026-0701 71 " + day + " false, CVE-2026-0704 74 2026-01-10 08:00 true"
	if got := p.events(); got != want {
		t.Errorf("owner-trusted events:\n got %s\nwant %s", got, want)
	}
	setOwner(t, d, id, false)
	if got := p.events(); got != "" {
		t.Errorf("after disable: %s", got)
	}
}

// Migration 0036 keeps the old origins and accepts 'owner' only on a
// trusted identity; login syntax.
func TestOwnerStatusCheck(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ownerRepo(t, d, 21, "a/rule", "a", 0, "trusted", "rule")
	ownerRepo(t, d, 22, "a/admin", "a", 0, "rejected", "admin")
	ownerRepo(t, d, 23, "a/owner", "a", 0, "trusted", "owner")
	for _, q := range []string{
		`UPDATE github_repo SET status_by = 'bogus' WHERE github_id = 21`,
		`UPDATE github_repo SET status = 'rejected' WHERE github_id = 23`,
		`INSERT INTO github_trusted_owner (login) VALUES ('-bad')`,
		`INSERT INTO github_trusted_owner (login) VALUES ('abcdefghijabcdefghijabcdefghijabcdefghij')`,
		`INSERT INTO github_trusted_owner (login) VALUES ('')`,
	} {
		if _, err := d.Conn.Exec(context.Background(), q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	if !ghrepo.ValidLogin("a-b") || ghrepo.ValidLogin("-ab") || ghrepo.ValidLogin("a_b") ||
		ghrepo.ValidLogin("abcdefghijabcdefghijabcdefghijabcdefghij") || !ghrepo.ValidLogin("abcdefghijabcdefghijabcdefghijabcdefghi") {
		t.Error("ValidLogin")
	}
}

// Both rules: a listed owner's repository found by search is trusted by
// 'owner'; when the post rule fires for it (a researcher's link stamped
// with it) it becomes 'rule'; when the link moves to another repository
// the stamp goes and owner trust comes back.
func TestOwnerTrustAndPostRule(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	addOwner(t, d, "bob", 61)
	r := fakeRepo{id: 601, full: "bob/CVE-2026-6001-poc", created: old, owner: 61}
	f := newFakeSearch(t, r, fakeRepo{id: 602, full: "zed/other", created: old})
	found(t, d, r)
	if got := gh(t, d, 601); got != "trusted/owner ok [bob/cve-2026-6001-poc]" {
		t.Fatalf("found by search: %s", got)
	}
	link(post1, 0, "https://github.com/bob/CVE-2026-6001-poc", "code")(t, d)
	sweep(t, d)
	pass(t, d, f)
	if got := gh(t, d, 601); got != "trusted/rule ok [bob/cve-2026-6001-poc]" {
		t.Errorf("after the stamp: %s", got)
	}
	exec(t, d, `UPDATE x_post_link SET final_url = 'https://github.com/zed/other' WHERE post_id = $1 AND pos = 0`, post1)
	sweep(t, d)
	if got := gh(t, d, 601); got != "trusted/owner ok [bob/cve-2026-6001-poc]" {
		t.Errorf("after the stamp went: %s", got)
	}
}

// owner.id is read when it is a positive number; any other value only
// drops the id, never the repository.
func TestDecodeOwnerID(t *testing.T) {
	for body, want := range map[string]int64{
		`{"id": 1, "full_name": "a/b", "fork": false, "archived": false, "owner": {"login": "a", "id": 42}}`:   42,
		`{"id": 1, "full_name": "a/b", "fork": false, "archived": false, "owner": {"login": "a", "id": "42"}}`: 0,
		`{"id": 1, "full_name": "a/b", "fork": false, "archived": false, "owner": {"login": "a", "id": -1}}`:   0,
		`{"id": 1, "full_name": "a/b", "fork": false, "archived": false, "owner": {"login": "-a", "id": 42}}`:  0,
	} {
		r, err := ghrepo.DecodeRepo([]byte(body))
		if err != nil || r.OwnerID != want {
			t.Errorf("%s: %+v %v", body, r, err)
		}
	}
}
