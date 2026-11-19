package site_test

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/site/sitetest"
)

// TestResourcesReposGHSA: "CVE is the main id, GHSA the second id" for
// repositories (docs/github.md "GHSA ids"). Associations keep the id found
// in the repository (github_repo_cve); the page resolves:
//   - on a CVE's page, a repository associated with the CVE id or with a
//     GHSA id that is the CVE's alias (the found listing, and the PoC
//     grouping of a stamped post link);
//   - on the page of a GHSA-keyed vulnerability, one associated with that
//     GHSA id;
//   - a CVE and its own GHSA alias count as one vulnerability for the
//     collection rule, a GHSA id nobody knows counts on its own;
//   - when the GHSA-keyed vulnerability gets its CVE (pipeline mergeVuln),
//     its repositories are on the CVE's page with no row of theirs changed.
func TestResourcesReposGHSA(t *testing.T) {
	st, d, _ := seeded(t)
	sitetest.SeedGHSA(t, d.Conn)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	seedLinks(t, s)
	const cve, keyed, alias = "CVE-2026-1004", sitetest.GHSA, sitetest.GHSAAlias
	for i, p := range []struct{ id, vuln, url string }{
		{"2000000000000000041", cve, "https://github.com/p/alias-linked"},
		{"2000000000000000042", keyed, "https://github.com/p/keyed-linked"},
	} {
		s.Event(sitetest.Ev{CVE: p.vuln, Type: "social_post", Source: "xposts", Occurred: sitetest.P(sitetest.Ago(1)), Observed: sitetest.Ago(1),
			Key: p.id, Detail: `{"post_id": "` + p.id + `", "author_id": "1002", "text": "x", "lang": "en"}`})
		if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status)
            VALUES ($1, 0, $2, $3, $3, 'github.com', 'code', 'api', 'ok')`, p.id, fmt.Sprintf("https://t.co/g%d", i), p.url); err != nil {
			t.Fatal(err)
		}
	}
	type row struct {
		gh   int
		full string
		ids  []string // associations by name
	}
	for _, r := range []row{
		{101, "f/found-alias", []string{alias}},
		{102, "f/found-cve", []string{cve}},
		{103, "f/found-keyed", []string{keyed}},
		{104, "f/three", []string{cve, alias, "CVE-2025-1001", "CVE-2025-1002"}},                        // 3 vulnerabilities: listed
		{105, "f/four", []string{cve, "CVE-2025-1001", "CVE-2025-1002", "GHSA-xxxx-xxxx-xxxx"}},         // 4: a collection
		{106, "f/keyed-four", []string{keyed, "CVE-2025-1001", "CVE-2025-1002", "GHSA-xxxx-xxxx-xxxx"}}, // 4: a collection
		{107, "p/alias-linked", []string{alias}},
		{108, "p/keyed-linked", []string{keyed}},
		{109, "f/other-ghsa", []string{"GHSA-xxxx-xxxx-xxxx"}},
	} {
		if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo (github_id, queued_name, full_name, stars, repo_created_at, state, first_source, seen_at)
            VALUES ($1, lower($2), $2, $3, '2026-03-01', 'ok', 'search', '2026-11-12')`, r.gh, r.full, 200-r.gh); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo WHERE github_id = $1`, r.gh); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Conn.Exec(ctx, `INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, unnest($2::text[]), 'name' FROM github_repo WHERE github_id = $1`,
			r.gh, r.ids); err != nil {
			t.Fatal(err)
		}
	}
	// the two post links are stamped (the fetch pass) and their repositories trusted by rule
	if _, err := d.Conn.Exec(ctx, `UPDATE x_post_link l SET repo_root_key = lower(r.full_name), repo_github_id = r.github_id, repo_checked_at = now()
        FROM github_repo r WHERE l.final_url = 'https://github.com/' || r.full_name AND r.github_id IN (107, 108)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE github_repo SET status = 'trusted', status_by = 'rule', status_at = now() WHERE github_id IN (107, 108)`); err != nil {
		t.Fatal(err)
	}
	page := func(id string) string {
		t.Helper()
		rs, err := st.Resources(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rs {
			if r.Repo != nil {
				got = append(got, fmt.Sprintf("%s|%s|%v", r.Kind, r.Repo.FullName, r.Repo.Unverified))
			}
		}
		return strings.Join(got, " ")
	}
	// p/*-linked are rule-trusted but created long before the disclosure:
	// they do not count, so they show like the unverified ones
	const onCVE = "poc|p/alias-linked|true poc|f/found-alias|true poc|f/found-cve|true poc|f/three|true"
	if got := page(cve); got != onCVE {
		t.Errorf("CVE page:\n%s\nwant\n%s", got, onCVE)
	}
	const onKeyed = "poc|p/keyed-linked|true poc|f/found-keyed|true"
	if got := page(keyed); got != onKeyed {
		t.Errorf("GHSA-keyed page:\n%s\nwant\n%s", got, onKeyed)
	}
	// upstream assigns CVE-2026-1999 to the GHSA-keyed vulnerability: the
	// alias is written and the row moves (pipeline); github_repo_cve does not
	var before string
	sum := `SELECT md5(string_agg(repo_id || ':' || cve_id || ':' || basis, ',' ORDER BY repo_id, cve_id, basis)) FROM github_repo_cve`
	if err := d.Conn.QueryRow(ctx, sum).Scan(&before); err != nil {
		t.Fatal(err)
	}
	const newCVE = "CVE-2026-1999"
	err := pgx.BeginFunc(ctx, d.Conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1)`, newCVE); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ($1, $2, 'ghsa')`, newCVE, keyed); err != nil {
			return err
		}
		mc, err := pipeline.MergeVulnID(ctx, tx, keyed, newCVE, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err == nil && !mc.Merged {
			err = fmt.Errorf("not merged: %+v", mc)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var after string
	if err := d.Conn.QueryRow(ctx, sum).Scan(&after); err != nil || after != before {
		t.Errorf("github_repo_cve changed by the merge: %v", err)
	}
	if got := page(newCVE); got != onKeyed {
		t.Errorf("after the merge, the CVE's page:\n%s\nwant\n%s", got, onKeyed)
	}
}
