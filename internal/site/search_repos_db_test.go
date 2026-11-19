package site_test

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"nday.land/nday/internal/db"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/migrations"
)

// B5: before migration 0025 (no review status) a repository post link is
// decorated as in phase 1 (no mark, stars), nothing else is listed.
func TestResourcesBefore0025(t *testing.T) {
	t.Parallel()
	d := testutil.NewDB(t)
	before := fstest.MapFS{}
	ents, _ := fs.ReadDir(migrations.FS, ".")
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".sql") && e.Name() < "0025" {
			b, _ := fs.ReadFile(migrations.FS, e.Name())
			before[e.Name()] = &fstest.MapFile{Data: b}
		}
	}
	if _, err := db.Migrate(ctx, d.Conn, before); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('1001', 'a', true)`,
		`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0001')`,
		`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, dedupe_key) VALUES
            ('CVE-2026-0001', 'social_post', '2026-11-12', '2026-11-12', 'xposts', '{"author_id": "1001"}', '2000000000000000001')`,
		`INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status) VALUES
            ('2000000000000000001', 0, 'https://t.co/a', 'https://github.com/o/r', 'https://github.com/o/r', 'github.com', 'code', 'api', 'ok')`,
		`INSERT INTO github_repo (github_id, queued_name, full_name, stars, repo_created_at, state, first_source) VALUES
            (1, 'o/r', 'o/r', 12, '2026-01-01', 'ok', 'xposts'), (2, 'x/cve-2026-0001', 'x/CVE-2026-0001', 5, '2026-01-01', 'ok', 'xposts')`,
		`INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'CVE-2026-0001', 'name' FROM github_repo`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	st := site.New(site.SingleConn(d.Conn)).WithClock(func() time.Time { return sitetest.Now })
	rs, err := st.Resources(ctx, "CVE-2026-0001")
	if err != nil || len(rs) != 1 || rs[0].Repo == nil || rs[0].Kind != "poc" || rs[0].Repo.Stars != 12 || rs[0].Repo.Unverified {
		t.Errorf("%+v %v", rs, err)
	}
}

// TestResourcesSearchRepos: on the page of a post whose root link is
// stamped with a repository named after the CVE, it is under poc; it does
// not count here (rule trust, but created long before the disclosure), so
// it shows without stars like one an admin reset to unverified; a rejected
// one renders plain. Repositories associated with the page's CVE by name,
// description or topic and not shown through a post link are listed under
// PoC after the post links: the counted ones first (here the admin-trusted:
// stars desc; forks and stale rows included), then up to
// site.MaxUnverifiedRepos others — rule-trusted ones that do not count here
// included (A3) — without stars, ordered by min(stars, 50) desc then oldest
// first (B1); never a fork, a collection (more than 3 CVEs; exactly 3 is
// fine, B3), a row not seen for 14 days (B4), a rejected, gone or post-only
// one.
func TestResourcesSearchRepos(t *testing.T) {
	st, d, _ := seeded(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	seedLinks(t, s)
	gpu := sitetest.GPU
	s.Event(sitetest.Ev{CVE: gpu, Type: "social_post", Source: "xposts", Occurred: sitetest.P(sitetest.Ago(1)), Observed: sitetest.Ago(1),
		Key: "2000000000000000031", Detail: `{"post_id": "2000000000000000031", "author_id": "1002", "text": "x", "lang": "en"}`})
	for i, u := range []string{"https://github.com/post/linked", "https://github.com/post/rejected", "https://github.com/post/unverified"} {
		if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status)
            VALUES ('2000000000000000031', $1, 'https://t.co/r', $2, $2, 'github.com', 'code', 'api', 'ok')`, i, u); err != nil {
			t.Fatal(err)
		}
	}
	const fresh, stale = "2026-11-12", "2026-10-01" // the store's clock: 2026-11-13
	type row struct {
		gh               int
		full, status, by string
		stars            int
		created, seen    string
		fork, gone       bool
		cves             int // CVEs by name besides the page's
		basis            string
	}
	rows := []row{
		{gh: 1, full: "post/linked", status: "trusted", by: "rule", stars: 1, created: "2026-01-01", seen: fresh, basis: "name"},
		{gh: 2, full: "post/rejected", status: "rejected", by: "admin", stars: 1, created: "2026-01-01", seen: fresh, basis: "name"},
		{gh: 3, full: "post/unverified", status: "unverified", by: "admin", stars: 2, created: "2026-01-02", seen: fresh, basis: "name"},
		{gh: 10, full: "T/admin-low", status: "trusted", by: "admin", stars: 0, created: "2026-02-01", basis: "description"}, // never seen: admin
		{gh: 11, full: "T/admin-fork", status: "trusted", by: "admin", stars: 3, created: "2026-02-01", seen: stale, basis: "name", fork: true},
		{gh: 12, full: "R/rule-elsewhere", status: "trusted", by: "rule", stars: 999, created: "2026-03-10", seen: fresh, basis: "name"},
		{gh: 20, full: "u/a", status: "unverified", stars: 50, created: "2026-03-05", seen: fresh, basis: "name"},
		{gh: 21, full: "u/b", status: "unverified", stars: 500, created: "2026-03-06", seen: fresh, basis: "topic"},
		{gh: 22, full: "u/c", status: "unverified", stars: 9, created: "2026-03-02", seen: fresh, basis: "description"},
		{gh: 23, full: "u/d-over-cap", status: "unverified", stars: 8, created: "2026-03-01", seen: fresh, basis: "name"},
		{gh: 24, full: "u/coll3", status: "unverified", stars: 60, created: "2026-03-01", seen: fresh, basis: "name", cves: 2},
		{gh: 25, full: "u/coll4", status: "unverified", stars: 999, created: "2026-03-01", seen: fresh, basis: "name", cves: 3},
		{gh: 26, full: "u/fork", status: "unverified", stars: 999, created: "2026-03-01", seen: fresh, basis: "name", fork: true},
		{gh: 27, full: "u/rule-fork", status: "trusted", by: "rule", stars: 999, created: "2026-03-01", seen: fresh, basis: "name", fork: true},
		{gh: 28, full: "u/stale", status: "unverified", stars: 999, created: "2026-03-01", seen: stale, basis: "name"},
		{gh: 29, full: "u/rejected", status: "rejected", by: "admin", stars: 999, created: "2026-03-01", seen: fresh, basis: "name"},
		{gh: 30, full: "u/gone", status: "unverified", stars: 999, created: "2026-03-01", seen: fresh, basis: "name", gone: true},
		{gh: 31, full: "u/post-only", status: "trusted", by: "rule", stars: 999, created: "2026-03-01", seen: fresh, basis: "post"},
	}
	for _, r := range rows {
		state := "ok"
		if r.gone {
			state = "gone"
		}
		var by, seen any
		if r.by != "" {
			by = r.by
		}
		if r.seen != "" {
			seen = r.seen
		}
		if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo (github_id, queued_name, full_name, owner_login, description, stars, is_fork,
            repo_created_at, state, first_source, status, status_by, status_at, seen_at) VALUES ($1, lower($2), $2, 'QZREPOOWNER', 'QZREPODESC', $3, $4,
            $5::date, $6, 'search', $7, $8, CASE WHEN $8::text IS NULL THEN NULL ELSE now() END, $9::timestamptz)`,
			r.gh, r.full, r.stars, r.fork, r.created, state, r.status, by, seen); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo WHERE github_id = $1`, r.gh); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, $2, $3 FROM github_repo WHERE github_id = $1`,
			r.gh, gpu, r.basis); err != nil {
			t.Fatal(err)
		}
		if r.cves > 0 {
			if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo_cve (repo_id, cve_id, basis)
                SELECT id, 'CVE-2025-' || (1000 + g), 'name' FROM github_repo, generate_series(1, $2::int) g WHERE github_id = $1`, r.gh, r.cves); err != nil {
				t.Fatal(err)
			}
		}
	}
	// the three post links were checked and stamped by the fetch pass
	if _, err := d.Conn.Exec(ctx, `UPDATE x_post_link l SET repo_root_key = lower(r.full_name), repo_github_id = r.github_id, repo_checked_at = now()
        FROM github_repo r WHERE l.post_id = '2000000000000000031' AND l.final_url = 'https://github.com/' || r.full_name`); err != nil {
		t.Fatal(err)
	}
	rs, err := st.Resources(ctx, gpu)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs {
		if !strings.Contains(r.URL, "github.com/post/") && !strings.Contains(r.URL, "github.com/T/") && !strings.Contains(r.URL, "github.com/u/") &&
			!strings.Contains(r.URL, "github.com/R/") {
			continue
		}
		line := fmt.Sprintf("%s|%s|%d", r.Kind, r.URL, r.Researchers)
		if r.Repo != nil {
			line += fmt.Sprintf("|%s|%d|%s|%v", r.Repo.FullName, r.Repo.Stars, r.Repo.Created, r.Repo.Unverified)
		}
		got = append(got, line)
	}
	want := []string{
		"poc|https://github.com/post/linked|1|post/linked|0|2026-01-01|true",
		"poc|https://github.com/post/unverified|1|post/unverified|0|2026-01-02|true",
		"poc|https://github.com/T/admin-fork|0|T/admin-fork|3|2026-02-01|false",
		"poc|https://github.com/T/admin-low|0|T/admin-low|0|2026-02-01|false",
		"poc|https://github.com/u/coll3|0|u/coll3|0|2026-03-01|true",
		"poc|https://github.com/u/a|0|u/a|0|2026-03-05|true",
		"poc|https://github.com/u/b|0|u/b|0|2026-03-06|true",
		"poc|https://github.com/R/rule-elsewhere|0|R/rule-elsewhere|0|2026-03-10|true",
		"poc|https://github.com/u/c|0|u/c|0|2026-03-02|true",
		"poc|https://github.com/u/d-over-cap|0|u/d-over-cap|0|2026-03-01|true",
		"code|https://github.com/post/rejected|1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("resources:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range rs {
		if s := fmt.Sprintf("%+v %+v", r, r.Repo); strings.Contains(strings.ToUpper(s), "QZREPO") || strings.Contains(s, "admin") && !strings.Contains(r.URL, "admin-") {
			t.Errorf("non-public repository data: %s", s)
		}
	}
	// the page of a post that links R/rule-elsewhere shows it trusted
	s.Event(sitetest.Ev{CVE: "CVE-2026-1001", Type: "social_post", Source: "xposts", Occurred: sitetest.P(sitetest.Ago(1)), Observed: sitetest.Ago(1),
		Key: "2000000000000000032", Detail: `{"post_id": "2000000000000000032", "author_id": "1002", "text": "x", "lang": "en"}`})
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status)
        VALUES ('2000000000000000032', 0, 'https://t.co/r', 'https://github.com/R/rule-elsewhere', 'https://github.com/R/rule-elsewhere', 'github.com', 'code', 'api', 'ok')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE x_post_link SET repo_root_key = 'r/rule-elsewhere', repo_github_id = 12, repo_checked_at = now()
        WHERE post_id = '2000000000000000032'`); err != nil {
		t.Fatal(err)
	}
	rs, err = st.Resources(ctx, "CVE-2026-1001")
	var line string
	for _, r := range rs {
		if r.Repo != nil && r.Repo.FullName == "R/rule-elsewhere" {
			line = fmt.Sprintf("%s|%d|%v", r.Kind, r.Repo.Stars, r.Repo.Unverified)
		}
	}
	if err != nil || line != "code|999|false" {
		t.Errorf("on its post's page: %q %v", line, err)
	}
}

func TestAddSearchRepos(t *testing.T) {
	rs := []site.Resource{
		{URL: "https://x.example/poc", Kind: "poc", Researchers: 1},
		{URL: "https://github.com/a/b", Kind: "poc", Researchers: 1, Repo: &site.ResourceRepo{FullName: "a/b"}},
		{URL: "https://github.com/o/plain", Kind: "code", Researchers: 1},
		{URL: "https://github.com/Root/Linked.git", Kind: "code", Researchers: 1}, // a plain root link, another spelling
	}
	found := []site.SearchRepo{
		{ID: 1, Repo: site.ResourceRepo{FullName: "a/b"}, Status: "unverified"},                                                      // shown by a post link
		{ID: 2, Repo: site.ResourceRepo{FullName: "o/plain"}, Status: "unverified"},                                                  // same URL as a post link
		{ID: 3, Repo: site.ResourceRepo{FullName: "bad name/x"}, Status: "trusted", StatusBy: "admin"},                               // invalid
		{ID: 4, Repo: site.ResourceRepo{FullName: "t/t", Stars: 7}, Status: "trusted", StatusBy: "admin", Fork: true, Counted: true}, // admin: listed
		{ID: 5, Repo: site.ResourceRepo{FullName: "r/r"}, Status: "rejected", StatusBy: "admin"},
		{ID: 6, Repo: site.ResourceRepo{FullName: "u/1", Stars: 9}, Status: "unverified"},
		{ID: 7, Repo: site.ResourceRepo{FullName: "u/2"}, Status: "unverified", Collection: true},
		{ID: 8, Repo: site.ResourceRepo{FullName: "u/3"}, Status: ""},
		{ID: 9, Repo: site.ResourceRepo{FullName: "u/rule", Stars: 5}, Status: "trusted", StatusBy: "rule"},
		{ID: 10, Repo: site.ResourceRepo{FullName: "u/rulefork"}, Status: "trusted", StatusBy: "rule", Fork: true},
		{ID: 12, Repo: site.ResourceRepo{FullName: "u/rulecountfork"}, Status: "trusted", StatusBy: "rule", Fork: true, Counted: true}, // a fork all the same
		{ID: 13, Repo: site.ResourceRepo{FullName: "c/owner", Stars: 4}, Status: "trusted", StatusBy: "owner", Counted: true},          // counted: stars, like admin
		{ID: 14, Repo: site.ResourceRepo{FullName: "c/admin-nc", Stars: 6}, Status: "trusted", StatusBy: "admin"},                      // admin, not counting here
		{ID: 11, Repo: site.ResourceRepo{FullName: "root/linked"}, Status: "trusted", StatusBy: "admin"},                               // its root is linked: once on the page
		{ID: 6, Repo: site.ResourceRepo{FullName: "U/1", Stars: 9}, Status: "unverified"},                                              // the same identity again
	}
	out := site.AddSearchRepos(rs, map[int64]bool{1: true}, found)
	var got []string
	for _, r := range out {
		s := r.Kind + "|" + r.URL
		if r.Repo != nil {
			s += fmt.Sprintf("|%d|%v|%v", r.Repo.Stars, r.Repo.Unverified, r.Repo.Counted)
		}
		got = append(got, s)
	}
	// counted first (stars, whoever trusted them), then the rest (no stars)
	if strings.Join(got, " ") != "poc|https://x.example/poc poc|https://github.com/a/b|0|false|false poc|https://github.com/t/t|7|false|true "+
		"poc|https://github.com/c/owner|4|false|true poc|https://github.com/u/1|0|true|false poc|https://github.com/u/rule|0|true|false "+
		"poc|https://github.com/c/admin-nc|0|true|false code|https://github.com/o/plain code|https://github.com/Root/Linked.git" {
		t.Errorf("%s", strings.Join(got, " "))
	}
	if rs[1].Repo.Unverified {
		t.Error("input modified")
	}
	// the cap: at most MaxUnverifiedRepos that do not count; counted ones are not capped here
	var many []site.SearchRepo
	for i := 0; i < site.MaxUnverifiedRepos+3; i++ {
		many = append(many, site.SearchRepo{ID: int64(100 + i), Repo: site.ResourceRepo{FullName: fmt.Sprintf("m/%d", i)}, Status: "unverified"})
	}
	if n := len(site.AddSearchRepos(nil, nil, many)); n != site.MaxUnverifiedRepos {
		t.Errorf("cap: %d", n)
	}
	for i := 0; i < 5; i++ {
		many = append(many, site.SearchRepo{ID: int64(900 + i), Repo: site.ResourceRepo{FullName: fmt.Sprintf("k/%d", i)}, Status: "trusted", StatusBy: "rule", Counted: true})
	}
	if n := len(site.AddSearchRepos(nil, nil, many)); n != site.MaxUnverifiedRepos+5 {
		t.Errorf("cap with counted: %d", n)
	}
	if len(site.AddSearchRepos(nil, nil, nil)) != 0 {
		t.Error("empty")
	}
}
