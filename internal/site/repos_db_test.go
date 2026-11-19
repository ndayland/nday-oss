package site_test

import (
	"fmt"
	"strings"
	"testing"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// TestResourcesRepos (I6): a root code link on github.com is decorated only
// when it is stamped with a repository (x_post_link.repo_github_id) that is
// 'ok' and still holds the link's name; then it carries only the public
// repository fields (full name, stars, creation day) and moves to poc only
// when the repository's name, description or topics name the page's CVE (a
// 'post' association does not count). Plain: a deep link, an unstamped
// link (not checked yet, or checked without a stamp), a 'gone' or pending
// repository, a name the stamped repository was renamed away from or lost
// to another repository. A repository whose root is linked is not listed a
// second time among the found ones, whatever the link's spelling.
func TestResourcesRepos(t *testing.T) {
	st, d, _ := seeded(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	seedLinks(t, s)
	gpu := sitetest.GPU
	s.Event(sitetest.Ev{CVE: gpu, Type: "social_post", Source: "xposts", Occurred: sitetest.P(sitetest.Ago(1)), Observed: sitetest.Ago(1),
		Key: "2000000000000000021", Detail: `{"post_id": "2000000000000000021", "author_id": "1002", "text": "x", "lang": "en"}`})
	for i, u := range []string{"https://github.com/O/R/blob/main/x.py", "https://github.com/gone/repo", "https://github.com/plain/tool",
		"https://github.com/wait/repo", "https://github.com/old/tool", "https://github.com/renamed/tool",
		"https://github.com/NoStamp/Repo.git", "https://github.com/lost/name"} {
		if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status)
            VALUES ('2000000000000000021', $1, 'https://t.co/r', $2, $2, 'github.com', 'code', 'api', 'ok')`, i, u); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO github_repo (github_id, queued_name, full_name, owner_type, description, stars, topics, language, repo_created_at, state, first_source)
            OVERRIDING SYSTEM VALUE VALUES
            (1, 'o/r', 'O/R', 'User', 'QZREPODESC', 1234567, '{qzrepotopic}', 'QZREPOLANG', '2026-02-03 23:30:00+00', 'ok', 'xposts'),
            (2, 'gone/repo', 'gone/repo', 'User', 'QZREPODESC', 5, '{}', NULL, '2026-01-01', 'gone', 'xposts'),
            (3, 'plain/tool', 'Plain/Tool', 'Organization', 'QZREPODESC', 0, '{}', NULL, NULL, 'ok', 'xposts'),
            (NULL, 'wait/repo', NULL, NULL, NULL, NULL, '{}', NULL, NULL, 'pending', 'xposts'),
            (5, 'renamed/tool', 'Renamed/Tool', 'User', NULL, 7, '{}', NULL, '2026-05-06', 'ok', 'xposts'),
            (6, 'nostamp/repo', 'nostamp/repo', 'User', NULL, 9, '{}', NULL, '2026-05-07', 'ok', 'search'),
            (7, 'lost/name', 'lost/name', 'User', NULL, 9, '{}', NULL, '2026-05-08', 'ok', 'xposts'),
            (8, 'lost/name', 'Lost/Name', 'User', NULL, 9, '{}', NULL, '2026-05-09', 'ok', 'search'),
            (9, 'stale/name', 'stale/name', 'User', NULL, 9, '{}', NULL, '2026-05-10', 'ok', 'search')`,
		// every identity holds its current name, except 7 (8 answered for lost/name since) and 9 (holds none)
		`INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo WHERE github_id IS DISTINCT FROM 7 AND github_id IS DISTINCT FROM 9`,
		// linked from posts and stamped: trusted by rule, seen recently (migration 0025)
		`UPDATE github_repo SET status = 'trusted', status_by = 'rule', status_at = now() WHERE github_id IN (1, 2, 3, 5, 7)`,
		`UPDATE github_repo SET seen_at = '2026-11-12' WHERE github_id IS NOT NULL`,
		// the links as the sweep and the fetch pass left them: root keys;
		// stamps for o/r, gone/repo, plain/tool, renamed/tool, lost/name (7,
		// before it lost the name) and old/tool (5, before its rename);
		// NoStamp/Repo.git checked without a stamp; wait/repo not checked yet
		`UPDATE x_post_link l SET repo_root_key = x.k, repo_github_id = x.g, repo_checked_at = CASE WHEN x.c THEN now() END
         FROM (VALUES ('https://github.com/o/r', 'o/r', 1, true), ('https://github.com/gone/repo', 'gone/repo', 2, true),
                      ('https://github.com/plain/tool', 'plain/tool', 3, true), ('https://github.com/wait/repo', 'wait/repo', NULL, false),
                      ('https://github.com/old/tool', 'old/tool', 5, true), ('https://github.com/renamed/tool', 'renamed/tool', 5, true),
                      ('https://github.com/NoStamp/Repo.git', 'nostamp/repo', NULL, true), ('https://github.com/lost/name', 'lost/name', 7, true)
              ) AS x(u, k, g, c) WHERE l.final_url = x.u`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, '` + gpu + `', 'name' FROM github_repo WHERE github_id IN (1, 2, 5, 6, 7, 9)`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, '` + gpu + `', 'post' FROM github_repo WHERE github_id = 3`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, 'CVE-2026-1001', 'topic' FROM github_repo WHERE github_id = 3`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	rs, err := st.Resources(ctx, gpu)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs {
		line := fmt.Sprintf("%s|%s|%d", r.Kind, r.URL, r.Researchers)
		if r.Repo != nil {
			line += fmt.Sprintf("|%s|%d|%s", r.Repo.FullName, r.Repo.Stars, r.Repo.Created)
		}
		got = append(got, line)
	}
	want := []string{
		"poc|https://www.exploit-db.com/exploits/1|1",
		"poc|https://exploit-db.com/exploits/2|1",
		// named after the CVE but not counting (rule trust, created long
		// before the disclosure): under poc, stars hidden
		"poc|https://github.com/o/r|1|O/R|0|2026-02-03",
		"poc|https://github.com/renamed/tool|1|Renamed/Tool|0|2026-05-06", // the current name: decorated
		"patch|https://github.com/o/r/commit/abc|2",
		"advisory|https://msrc.microsoft.com/update-guide/x|1",
		"code|https://github.com/O/R/blob/main/x.py|1", // a deep link: plain, kept next to the root link
		"code|https://github.com/gone/repo|1",          // stamped, was 'ok', now 'gone': plain
		"code|https://github.com/plain/tool|1|Plain/Tool|0|",
		"code|https://github.com/wait/repo|1",
		"code|https://github.com/old/tool|1",         // stamped with Renamed/Tool, which left that name: plain, not regrouped
		"code|https://github.com/NoStamp/Repo.git|1", // checked without a stamp: plain; nostamp/repo is not listed a second time
		"code|https://github.com/lost/name|1",        // stamped with a repository that lost the name to another: plain
		"other|https://example.com/post#frag|2",
		"other|https://example.com/a|1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("resources:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// only the public fields: nothing else of github_repo
	for _, r := range rs {
		if s := fmt.Sprintf("%+v %+v", r, r.Repo); strings.Contains(strings.ToUpper(s), "QZREPO") || strings.Contains(s, "User") || strings.Contains(s, "Organization") {
			t.Errorf("non-public repository data: %s", s)
		}
	}
	// another CVE's page: o/r is not a PoC of it; Plain/Tool (topic;
	// trusted by rule, its post is not on this page, creation time unknown
	// so not "old") counts as a PoC source of it (a github event): listed
	// counted, not marked, whatever trusted it
	rs, err = st.Resources(ctx, "CVE-2026-1001")
	if err != nil || len(rs) != 2 || rs[0].Repo == nil || rs[0].URL != "https://github.com/Plain/Tool" || rs[0].Kind != "poc" ||
		rs[0].Repo.Unverified || !rs[0].Repo.Counted || rs[1].Repo != nil {
		t.Errorf("other CVE: %+v %v", rs, err)
	}
}

func TestApplyRepos(t *testing.T) {
	rs := []site.Resource{
		{URL: "https://github.com/a/b", Kind: "code", Researchers: 1},
		{URL: "https://github.com/a/b/tree/x", Kind: "code", Researchers: 3},
		{URL: "https://github.com/a/b/issues/3", Kind: "code", Researchers: 1},
		{URL: "https://github.com/a/b/commit/1", Kind: "patch", Researchers: 1},
		{URL: "https://gist.github.com/a/b", Kind: "code", Researchers: 1},
		{URL: "https://github.com/c/d.git", Kind: "code", Researchers: 1},
		{URL: "https://github.com/old/x", Kind: "code", Researchers: 2},
	}
	m := map[string]site.RepoMatch{"a/b": {ID: 1, Repo: site.ResourceRepo{FullName: "A/B", Stars: 2}, PoC: true},
		"c/d":   {ID: 2, Repo: site.ResourceRepo{FullName: "c/D"}},
		"old/x": {ID: 3, Repo: site.ResourceRepo{FullName: "new/x"}, PoC: true}} // reached through an alias
	out := site.ApplyRepos(rs, m)
	var got []string
	for _, r := range out {
		got = append(got, fmt.Sprintf("%s|%s|%d|%v", r.Kind, r.URL, r.Researchers, r.Repo != nil))
	}
	want := "poc|https://github.com/a/b|1|true patch|https://github.com/a/b/commit/1|1|false code|https://github.com/a/b/tree/x|3|false " +
		"code|https://github.com/a/b/issues/3|1|false code|https://gist.github.com/a/b|1|false code|https://github.com/c/d.git|1|true " +
		"code|https://github.com/old/x|2|false"
	if strings.Join(got, " ") != want {
		t.Errorf("got %s", strings.Join(got, " "))
	}
	if site.ApplyRepos(rs, nil)[0].Kind != "code" {
		t.Error("no repos")
	}
}
