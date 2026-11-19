package site_test

import (
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
)

// A fork under ghrepo.MinForkStars stars that nobody decided about is not
// collected (docs/github.md "Skipped forks"): a post's root link stamped
// with it stays plain, and it's never listed among the found repositories.
// With 10+ stars, or decided by staff, the post rule or a trusted account,
// it's shown as before (the found listing still drops forks an admin
// didn't trust, as before this rule).
func TestResourcesSkippedForks(t *testing.T) {
	st, d, _ := seeded(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	gpu := sitetest.GPU
	const post = "2000000000000000031"
	s.Event(sitetest.Ev{CVE: gpu, Type: "social_post", Source: "xposts", Occurred: sitetest.P(sitetest.Ago(1)), Observed: sitetest.Ago(1),
		Key: post, Detail: `{"post_id": "` + post + `", "author_id": "1009", "text": "x", "lang": "en"}`})
	links := []string{"https://github.com/fk/low", "https://github.com/fk/high", "https://github.com/fk/adm", "https://github.com/fk/rule"}
	for i, u := range links {
		if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status)
            VALUES ($1, $2, 'https://t.co/f', $3, $3, 'github.com', 'code', 'api', 'ok')`, post, i, u); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('1009', 'resF', true)`,
		`INSERT INTO github_repo (github_id, queued_name, full_name, stars, is_fork, repo_created_at, state, first_source, status, status_by, status_at, seen_at)
            OVERRIDING SYSTEM VALUE VALUES
            (901, 'fk/low', 'fk/low', 3, true, '2026-05-01', 'ok', 'xposts', 'unverified', NULL, NULL, '2026-11-12'),
            (902, 'fk/high', 'fk/high', 12, true, '2026-05-01', 'ok', 'xposts', 'unverified', NULL, NULL, '2026-11-12'),
            (903, 'fk/adm', 'fk/adm', 3, true, '2026-05-01', 'ok', 'xposts', 'trusted', 'admin', now(), '2026-11-12'),
            (904, 'fk/rule', 'fk/rule', 3, true, '2026-05-01', 'ok', 'xposts', 'trusted', 'rule', now(), '2026-11-12'),
            (905, 'fs/low', 'fs/low', 3, true, '2026-05-01', 'ok', 'search', 'unverified', NULL, NULL, '2026-11-12'),
            (906, 'fs/adm', 'fs/adm', 2, true, '2026-05-01', 'ok', 'search', 'trusted', 'admin', now(), '2026-11-12')`,
		`INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo WHERE github_id BETWEEN 901 AND 906`,
		`UPDATE x_post_link l SET repo_root_key = lower(substr(l.final_url, 20)), repo_checked_at = now(),
            repo_github_id = (SELECT r.github_id FROM github_repo r WHERE r.queued_name = lower(substr(l.final_url, 20)))
         WHERE l.post_id = '` + post + `'`,
		`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, '` + gpu + `', 'name' FROM github_repo WHERE github_id BETWEEN 901 AND 906`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	rs, err := st.Resources(ctx, gpu)
	if err != nil {
		t.Fatal(err)
	}
	decorated := map[string]bool{}
	seen := map[string]bool{}
	for _, r := range rs {
		u := strings.ToLower(r.URL)
		seen[u] = true
		if r.Repo != nil {
			decorated[u] = true
		}
	}
	for u, want := range map[string]bool{"https://github.com/fk/low": false, "https://github.com/fk/high": true,
		"https://github.com/fk/adm": true, "https://github.com/fk/rule": true} {
		if !seen[u] || decorated[u] != want {
			t.Errorf("%s: shown %v, decorated %v, want %v", u, seen[u], decorated[u], want)
		}
	}
	if seen["https://github.com/fs/low"] || !seen["https://github.com/fs/adm"] {
		t.Errorf("found listing: %v", seen)
	}
}
