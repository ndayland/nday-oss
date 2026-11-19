package ghrepo_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/db"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/migrations"
)

// seedReview stores: 101 a search find with two CVEs by name and topic
// (created before CVE-2026-0001 was published: predates), 102 a
// collection (6 CVEs in its description), 103 a trusted post link, 104 a
// pending row (never listed).
func seedReview(t *testing.T) *testutil.TestDB {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO vuln (cve_id, published_at) VALUES ('CVE-2026-0001', '2026-05-01'), ('CVE-2026-0002', NULL)`,
		`INSERT INTO github_repo (github_id, queued_name, full_name, owner_login, description, stars, forks, topics, is_fork, is_archived,
            repo_created_at, pushed_at, state, first_source, created_at, status, status_by, status_at) OVERRIDING SYSTEM VALUE VALUES
            (101, 'a/cve-2026-0001', 'A/CVE-2026-0001', 'A', 'desc <b>', 15, 1, '{cve-2026-0002}', true, false, '2026-04-01', '2026-04-02', 'ok', 'search', '2026-11-16 03:00', 'unverified', NULL, NULL),
            (102, 'c/list', 'c/list', 'c', 'CVE-2026-1001 CVE-2026-1002 CVE-2026-1003 CVE-2026-1004 CVE-2026-1005 CVE-2026-1006', 50, 9, '{}', false, true, '2026-01-01', NULL, 'ok', 'search', '2026-11-16 02:00', 'unverified', NULL, NULL),
            (103, 'p/tool', 'p/tool', 'p', NULL, 1, 0, '{}', false, false, NULL, NULL, 'ok', 'xposts', '2026-11-16 01:00', 'trusted', 'rule', now()),
            (NULL, 'q/wait', NULL, NULL, NULL, NULL, NULL, '{}', NULL, NULL, NULL, NULL, 'pending', 'xposts', '2026-11-16 04:00', 'unverified', NULL, NULL)`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'CVE-2026-0001', 'name' FROM github_repo WHERE github_id = 101`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'CVE-2026-0002', 'topic' FROM github_repo WHERE github_id = 101`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'CVE-2026-0001', 'post' FROM github_repo WHERE github_id = 101`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'CVE-2026-100' || g, 'description' FROM github_repo, generate_series(1, 6) g WHERE github_id = 102`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'CVE-2026-0002', 'post' FROM github_repo WHERE github_id = 103`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	return d
}

func repoID(t *testing.T, d *testutil.TestDB, gh int) int64 {
	t.Helper()
	var id int64
	if err := d.Conn.QueryRow(context.Background(), `SELECT id FROM github_repo WHERE github_id = $1`, gh).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestReviewList(t *testing.T) {
	t.Parallel()
	d := seedReview(t)
	ctx := context.Background()
	items, err := ghrepo.ListReview(ctx, d.Conn, "", 10, 0)
	if err != nil || len(items) != 2 {
		t.Fatalf("%+v %v", items, err)
	}
	a, c := items[0], items[1]
	if a.FullName != "A/CVE-2026-0001" || a.OwnerLogin != "A" || a.Description != "desc <b>" || a.Stars != 15 || a.Forks != 1 ||
		!a.IsFork || a.IsArchived || a.Status != "unverified" || a.StatusBy != "" || a.StatusAt != nil || a.FirstSource != "search" ||
		a.Created == nil || !a.Created.Equal(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)) || a.Created.Location() != time.UTC || a.Pushed == nil ||
		a.Collection || !a.Predates || a.CVECount != 2 {
		t.Errorf("a: %+v", a)
	}
	if got := fmt.Sprint(a.CVEs); got != "[{CVE-2026-0002 [topic]} {CVE-2026-0001 [name post]}]" {
		t.Errorf("a CVEs: %s", got)
	}
	if !c.Collection || c.Predates || c.CVECount != 6 || len(c.CVEs) != 6 || c.CVEs[0].CVE != "CVE-2026-1006" || !c.IsArchived || c.Pushed != nil {
		t.Errorf("c: %+v", c)
	}
	if items, err := ghrepo.ListReview(ctx, d.Conn, "unverified", 1, 1); err != nil || len(items) != 1 || items[0].FullName != "c/list" {
		t.Errorf("page 2: %+v %v", items, err)
	}
	if items, err := ghrepo.ListReview(ctx, d.Conn, "trusted", 10, 0); err != nil || len(items) != 1 || items[0].StatusBy != "rule" ||
		items[0].StatusAt == nil || len(items[0].CVEs) != 1 {
		t.Errorf("trusted: %+v %v", items, err)
	}
	for st, want := range map[string]int{"": 2, "unverified": 2, "trusted": 1, "rejected": 0} {
		if n, err := ghrepo.CountReview(ctx, d.Conn, st); err != nil || n != want {
			t.Errorf("count %q: %d %v", st, n, err)
		}
	}
	for _, bad := range []string{"all", "ok", "TRUSTED"} {
		if _, err := ghrepo.ListReview(ctx, d.Conn, bad, 1, 0); err == nil {
			t.Errorf("list %q", bad)
		}
		if _, err := ghrepo.CountReview(ctx, d.Conn, bad); err == nil {
			t.Errorf("count %q", bad)
		}
	}
	if _, err := ghrepo.ListReview(ctx, d.Conn, "", -1, 0); err == nil {
		t.Error("negative limit")
	}
}

// B3: a collection is more than CollectionMin (3) CVEs by name,
// description or topic; 'post' associations do not count.
func TestReviewCollectionBoundary(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	if ghrepo.CollectionMin != 3 {
		t.Fatalf("CollectionMin %d", ghrepo.CollectionMin)
	}
	for _, q := range []string{
		`INSERT INTO github_repo (github_id, queued_name, full_name, state, first_source, created_at) OVERRIDING SYSTEM VALUE VALUES
            (3, 'o/three', 'o/three', 'ok', 'search', '2026-11-16 03:00'), (4, 'o/four', 'o/four', 'ok', 'search', '2026-11-16 02:00')`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT r.id, 'CVE-2026-100' || g, 'name' FROM github_repo r, generate_series(1, r.github_id::int) g`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT r.id, 'CVE-2026-200' || g, 'post' FROM github_repo r, generate_series(1, 5) g WHERE r.github_id = 3`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	items, err := ghrepo.ListReview(ctx, d.Conn, "", 10, 0)
	if err != nil || len(items) != 2 || items[0].FullName != "o/three" || items[0].Collection || !items[1].Collection {
		t.Errorf("%+v %v", items, err)
	}
}

func TestReviewSetStatus(t *testing.T) {
	t.Parallel()
	d := seedReview(t)
	ctx := context.Background()
	a, p := repoID(t, d, 101), repoID(t, d, 103)
	for _, step := range []struct {
		id      int64
		status  string
		changed bool
		want    string
	}{
		{a, "trusted", true, "trusted/admin"},
		{a, "trusted", false, "trusted/admin"},
		{a, "rejected", true, "rejected/admin"},
		{a, "unverified", true, "unverified/admin"},
		{p, "trusted", true, "trusted/admin"}, // confirming a rule makes it an admin decision
		{p, "trusted", false, "trusted/admin"},
	} {
		ch, err := ghrepo.SetStatus(ctx, d.Conn, step.id, step.status)
		var got string
		if err == nil {
			err = d.Conn.QueryRow(ctx, `SELECT status || '/' || status_by FROM github_repo WHERE id = $1 AND status_at IS NOT NULL`, step.id).Scan(&got)
		}
		if err != nil || ch != step.changed || got != step.want {
			t.Errorf("%+v: %v %s %v", step, ch, got, err)
		}
	}
	if _, err := ghrepo.SetStatus(ctx, d.Conn, 999999, "trusted"); !errors.Is(err, ghrepo.ErrRepoNotFound) {
		t.Errorf("missing: %v", err)
	}
	for _, bad := range []string{"", "ok", "admin"} {
		if _, err := ghrepo.SetStatus(ctx, d.Conn, a, bad); err == nil {
			t.Errorf("status %q accepted", bad)
		}
	}
	// GetForUpdate in a transaction
	err := pgx.BeginFunc(ctx, d.Conn, func(tx pgx.Tx) error {
		full, st, by, err := ghrepo.GetForUpdate(ctx, tx, a)
		if err != nil || full != "A/CVE-2026-0001" || st != "unverified" || by != "admin" {
			t.Errorf("%q %q %q %v", full, st, by, err)
		}
		var w int64
		if err := tx.QueryRow(ctx, `SELECT id FROM github_repo WHERE github_id IS NULL`).Scan(&w); err != nil {
			return err
		}
		if full, st, by, err := ghrepo.GetForUpdate(ctx, tx, w); err != nil || full != "" || st != "unverified" || by != "" {
			t.Errorf("pending: %q %q %q %v", full, st, by, err)
		}
		if _, _, _, err := ghrepo.GetForUpdate(ctx, tx, 999999); !errors.Is(err, ghrepo.ErrRepoNotFound) {
			t.Errorf("missing: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// migrationsUpTo is the embedded migrations whose name sorts before limit.
func migrationsUpTo(t *testing.T, limit string) fstest.MapFS {
	t.Helper()
	out := fstest.MapFS{}
	ents, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".sql") && e.Name() < limit {
			b, err := fs.ReadFile(migrations.FS, e.Name())
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = &fstest.MapFile{Data: b}
		}
	}
	return out
}

// I9 / A2: migration 0025 computes no root key and no trust in SQL. It adds
// the columns and drops the names an identity no longer answers for
// (phase-1 aliases, 'gone' identities). The phase-1 sweep marker
// (repo_queued_url) is left alone and not used: the new sweep has its own
// (repo_swept_url), so it sweeps every link once whatever a phase-1 binary
// marked before or after the migration; it then derives the root keys, and a phase-1
// repository becomes trusted by rule only when the fetch pass has checked
// its link (until then the link has no stamp: it renders plain). The new
// CHECKs and the github_id trigger hold.
func TestMigrationBackfill(t *testing.T) {
	t.Parallel()
	d := testutil.NewDB(t)
	ctx := context.Background()
	if _, err := db.Migrate(ctx, d.Conn, migrationsUpTo(t, "0025")); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO github_repo (github_id, queued_name, full_name, repo_created_at, state, first_source, fetched_at) VALUES
            (1, 'a/root', 'a/root', '2026-01-01', 'ok', 'xposts', '2026-07-01'),
            (2, 'a/git', 'A/Git', '2026-01-01', 'ok', 'xposts', '2026-07-01'),
            (3, 'a/deep', 'a/deep', '2026-01-01', 'ok', 'xposts', '2026-07-01'),
            (4, 'a/late', 'a/late', '2026-12-01', 'ok', 'xposts', '2026-07-01'),
            (5, 'old/alias', 'new/Name', '2026-01-01', 'ok', 'xposts', '2026-07-01'),
            (6, 'g/one', 'g/one', '2026-01-01', 'gone', 'xposts', '2026-07-01'),
            (NULL, 'a/gone', NULL, NULL, 'gone', 'xposts', '2026-07-01')`,
		`INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo`,
		`INSERT INTO github_repo_name (name_key, repo_id) SELECT 'new/name', id FROM github_repo WHERE github_id = 5`,
		`INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status, created_at, repo_queued_url) VALUES
            ('1', 0, 'https://t.co/a', 'x', 'https://github.com/a/root', 'github.com', 'code', 'api', 'ok', '2026-06-01', 'https://github.com/a/root'),
            ('1', 1, 'https://t.co/b', 'x', 'https://www.github.com/A/Git.git/', 'github.com', 'code', 'api', 'ok', '2026-06-01', 'https://www.github.com/A/Git.git/'),
            ('1', 2, 'https://t.co/c', 'x', 'https://github.com/a/deep/issues/1', 'github.com', 'code', 'api', 'ok', '2026-06-01', 'https://github.com/a/deep/issues/1'),
            ('1', 3, 'https://t.co/d', 'x', 'https://github.com/a/late', 'github.com', 'code', 'api', 'ok', '2026-06-01', 'https://github.com/a/late'),
            ('1', 4, 'https://t.co/e', 'x', 'https://github.com/a/gone', 'github.com', 'code', 'api', 'ok', '2026-06-01', 'https://github.com/a/gone'),
            ('1', 5, 'https://t.co/f', 'x', 'https://github.com/a/root?tab=readme', 'github.com', 'code', 'api', 'ok', '2026-06-01', 'https://github.com/a/root?tab=readme')`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	applied, err := db.Migrate(ctx, d.Conn, migrationsUpTo(t, "0026"))
	if err != nil || strings.Join(applied, ",") != "0025_github_discovery" {
		t.Fatalf("%v %v", applied, err)
	}
	// nothing is trusted, no root key is set, the phase-1 marker is untouched
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE status <> 'unverified' OR status_by IS NOT NULL`); n != 0 {
		t.Errorf("%d rows with a status right after the migration", n)
	}
	if n := count(t, d, `SELECT count(*) FROM x_post_link WHERE repo_queued_url IS DISTINCT FROM final_url OR repo_swept_url IS NOT NULL
        OR repo_root_key IS NOT NULL OR repo_github_id IS NOT NULL OR repo_checked_at IS NOT NULL`); n != 0 {
		t.Errorf("%d links changed by the migration", n)
	}
	// a phase-1 binary still running (a collector timer between the
	// migration and the binary swap) stores a new link and marks it swept
	exec(t, d, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status, created_at, repo_queued_url) VALUES
        ('2', 0, 'https://t.co/g', 'x', 'https://github.com/a/root/', 'github.com', 'code', 'api', 'ok', '2026-06-02', 'https://github.com/a/root/')`)
	// names: an identity keeps only its current name, a 'gone' identity none; placeholders keep theirs
	var names string
	if err := d.Conn.QueryRow(ctx, `SELECT string_agg(name_key, ' ' ORDER BY name_key) FROM github_repo_name`).Scan(&names); err != nil ||
		names != "a/deep a/git a/gone a/late a/root new/name" {
		t.Errorf("names: %s %v", names, err)
	}
	// this code needs the later migrations too (owner_id, 0036): the binary
	// of this release runs only on the full schema
	if _, err := db.Migrate(ctx, d.Conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	// the Go sweep derives the root keys (no revival: the links are older than the last request)
	res, err := ghrepo.Enqueue(ctx, d.Conn, quiet)
	if err != nil || res.Candidates != 7 || res.Added != 0 || res.Revived != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	var keys string
	if err := d.Conn.QueryRow(ctx, `SELECT string_agg(COALESCE(repo_root_key, '-'), ' ' ORDER BY post_id, pos) FROM x_post_link`).Scan(&keys); err != nil ||
		keys != "a/root a/git - a/late a/gone - a/root" {
		t.Errorf("root keys: %s %v", keys, err)
	}
	if res, err := ghrepo.Enqueue(ctx, d.Conn, quiet); err != nil || res.Candidates != 0 {
		t.Errorf("second sweep: %+v %v", res, err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE status <> 'unverified'`); n != 0 {
		t.Errorf("%d rows trusted by the sweep", n)
	}
	// the fetch pass checks the links: one request per root key
	f := newFakeSearch(t, fakeRepo{id: 1, full: "a/root", created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		fakeRepo{id: 2, full: "A/Git", created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		fakeRepo{id: 4, full: "a/late", created: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)})
	o := fetchOpts(f)
	o.RefreshLimit = -1
	pres, err := ghrepo.FetchPending(ctx, d.Conn, o)
	if err != nil || pres.Requests != 4 || pres.LinkChecks != 4 || pres.Stamped != 3 {
		t.Fatalf("%+v %v", pres, err)
	}
	var got string
	if err := d.Conn.QueryRow(ctx, `SELECT string_agg(queued_name || '=' || status || '/' || COALESCE(status_by, ''), ' ' ORDER BY queued_name)
        FROM github_repo`).Scan(&got); err != nil ||
		got != "a/deep=unverified/ a/git=trusted/rule a/gone=unverified/ a/late=unverified/ a/root=trusted/rule g/one=unverified/ old/alias=unverified/" {
		t.Errorf("after the pass: %s %v", got, err)
	}
	// new rows default to unverified; the CHECKs and the trigger hold
	if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo (queued_name, first_source) VALUES ('e/f', 'search')`); err != nil {
		t.Fatal(err)
	}
	if n := count(t, d, `SELECT count(*) FROM github_repo WHERE queued_name = 'e/f' AND status = 'unverified' AND status_by IS NULL`); n != 1 {
		t.Error("default")
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE github_repo SET status = 'rejected', status_by = 'rule', status_at = now() WHERE queued_name = 'a/deep'`); err != nil {
		t.Errorf("rejected by rule on an identity: %v", err)
	}
	// B1: both id forms, exactly as vuln.cve_id; a placeholder may be deleted
	for _, q := range []string{
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'GHSA-gpwc-27cw-rh9r', 'name' FROM github_repo WHERE queued_name = 'a/root'`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'CVE-2026-123456789012345678901', 'name' FROM github_repo WHERE queued_name = 'a/root'`,
		`INSERT INTO github_search_cve (cve_id) VALUES ('GHSA-gpwc-27cw-rh9r'), ('CVE-2026-0001')`,
		`INSERT INTO github_search_scan (scan_key, created_after) VALUES ('name:GHSA', now()), ('name:CVE-2026', now())`,
		`DELETE FROM github_repo WHERE queued_name = 'e/f'`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Errorf("refused: %s: %v", q, err)
		}
	}
	for _, q := range []string{
		`UPDATE github_repo SET status = 'trusted' WHERE queued_name = 'a/late'`,                                        // no status_by
		`UPDATE github_repo SET status_by = NULL, status_at = NULL WHERE queued_name = 'a/deep'`,                        // rejected, nobody decided
		`UPDATE github_repo SET status_at = NULL WHERE queued_name = 'a/deep'`,                                          // no status_at
		`UPDATE github_repo SET status = 'maybe' WHERE queued_name = 'a/deep'`,                                          // unknown status
		`UPDATE github_repo SET status = 'trusted', status_by = 'rule', status_at = now() WHERE queued_name = 'a/gone'`, // a placeholder holds no status
		`UPDATE github_repo SET status = 'trusted', status_by = 'admin', status_at = now() WHERE queued_name = 'a/gone'`,
		`UPDATE github_repo SET github_id = 99 WHERE queued_name = 'a/root'`, // an identity keeps its id
		`DELETE FROM github_repo WHERE queued_name = 'a/deep'`,               // and is never deleted (a phase-1 rename merge)
		`INSERT INTO github_search_scan (scan_key, created_after) VALUES ('name:GHSA-x', now())`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'GHSA-GPWC-27CW-RH9R', 'name' FROM github_repo WHERE queued_name = 'a/root'`, // not the canonical form
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'GHSA-aaaa-27cw-rh9r', 'name' FROM github_repo WHERE queued_name = 'a/root'`, // not GitHub's alphabet
		`INSERT INTO github_search_cve (cve_id) VALUES ('ghsa-gpwc-27cw-rh9r')`,
		`UPDATE x_post_link SET repo_github_id = 1 WHERE pos = 2`,     // a stamp needs a root key and a check
		`UPDATE x_post_link SET repo_github_id = 12345 WHERE pos = 0`, // a stamp names a known identity
		`INSERT INTO github_search_scan (scan_key, created_after) VALUES ('name:CVE-26', now())`,
		`INSERT INTO github_search_cve (cve_id, searched_at) VALUES ('CVE-2026-1 OR x', now())`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
}
