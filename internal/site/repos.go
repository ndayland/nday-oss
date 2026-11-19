package site

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/xlinks"
)

// ResourceRepo is the public part of a fetched GitHub repository (see the
// comment at the top of public.go): nothing else of github_repo reaches a
// page.
type ResourceRepo struct {
	FullName string `json:"full_name"` // "Owner/Name" as GitHub returns it (ghrepo.ValidFullName)
	Stars    int    `json:"stars"`     // 0 (and not shown) when Unverified
	Created  string `json:"created"`   // YYYY-MM-DD (UTC); "" = unknown
	// Unverified: shown without its star count (stars are cheap to buy): a
	// repository nobody vouches for, and every repository under poc that
	// does not count (Counted false). Pages list the latter in their own
	// collapsed group, without a per-row mark; elsewhere (code) it is marked.
	Unverified bool `json:"unverified,omitempty"`
	// Counted: the repository is a PoC source of the page's vulnerability,
	// i.e. it has a poc_published event of source github for it (the set
	// github_poc_want keeps, docs/github.md "PoC events"). It says nothing
	// about why it is trusted. Only these repositories sit in the PoC group
	// proper and get a dot on the chart; the other poc repositories are the
	// "unreviewed" group.
	Counted bool `json:"counted,omitempty"`
}

// RepoMatch is the repository a root post link of the page is stamped
// with (x_post_link.repo_github_id), as repoResources reads it for one
// CVE: its row id, public fields, whether its name, description or
// topics name the CVE (github_repo_cve basis name / description / topic),
// its review status (ghrepo.Status*; "" = unknown, shown as before
// review existed; StatusBy "" = nobody decided), and whether it counts as a
// PoC source of the CVE (ResourceRepo.Counted).
type RepoMatch struct {
	ID       int64
	Repo     ResourceRepo
	PoC      bool
	Status   string
	StatusBy string
	Counted  bool
}

// SearchRepo is a fetched repository associated with a page's CVE by
// name, description or topic, as repoResources reads it for the listing of
// AddSearchRepos (forks, collections and stale rows that an admin did not
// trust are already left out by the query).
type SearchRepo struct {
	ID       int64
	Repo     ResourceRepo
	Status   string // ghrepo.Status*
	StatusBy string // ghrepo.StatusBy*, "" = nobody decided
	// Fork, Collection (ghrepo.CollectionMin): never listed unless an
	// admin trusted the repository.
	Fork       bool
	Collection bool
	// Counted: a PoC source of the page's vulnerability (ResourceRepo.Counted).
	Counted bool
}

// MaxUnverifiedRepos caps the repositories AddSearchRepos lists on one page
// that do not count (the "unreviewed" group, paged on the page); the
// counted ones are capped only by searchRepoScan.
const MaxUnverifiedRepos = 100

// SearchStaleAfter: a repository an admin did not trust is listed by
// AddSearchRepos only when search or a fetch returned it this recently
// (github_repo.seen_at).
const SearchStaleAfter = 14 * 24 * time.Hour

// unverifiedStarCap: the listing orders marked repositories by
// min(stars, unverifiedStarCap), so buying more stars gains nothing.
const unverifiedStarCap = 50

// adminTrusted reports an admin's trust (the only trust that counts
// outside the page of the post that links a repository).
func adminTrusted(status, by string) bool {
	return status == ghrepo.StatusTrusted && by == ghrepo.StatusByAdmin
}

// AddSearchRepos lists repositories of the page's CVE that no post link of
// rs shows (shown: the row ids of decorated links) under poc, after the poc
// links of rs, each as a link to https://github.com/<full name>: first the
// counted ones (a PoC source of the CVE, whoever trusted them; with stars,
// Counted), then at most MaxUnverifiedRepos others (unverified, or trusted
// but not counting here) without stars (Unverified), each in the order of
// found. Counted and not counted look the same whatever the trust came from
// (admin, post rule, trusted account). Never a rejected repository, never a
// fork or a collection unless an admin trusted it. A repository is on the
// page once: not when rs already has its URL, nor when rs has a root link
// to its name (decorated or plain, whatever the spelling), nor twice from
// found. rs must be in display order (ApplyRepos).
func AddSearchRepos(rs []Resource, shown map[int64]bool, found []SearchRepo) []Resource {
	have := map[string]bool{}
	roots := map[string]bool{}
	for _, r := range rs {
		if k, ok := ResourceKey(r.URL); ok {
			have[k] = true
		}
		if k, ok := ghrepo.RootKeyOf(r.URL); ok {
			roots[k] = true
		}
	}
	listed := map[int64]bool{}
	var counted, rest []Resource
	for _, f := range found {
		if shown[f.ID] || listed[f.ID] || !ghrepo.ValidFullName(f.Repo.FullName) || f.Status == ghrepo.StatusRejected ||
			(f.Status != ghrepo.StatusTrusted && f.Status != ghrepo.StatusUnverified) || roots[strings.ToLower(f.Repo.FullName)] {
			continue
		}
		admin := adminTrusted(f.Status, f.StatusBy)
		if !admin && (f.Fork || f.Collection) || !f.Counted && len(rest) >= MaxUnverifiedRepos {
			continue
		}
		u := "https://github.com/" + f.Repo.FullName
		k, ok := ResourceKey(u)
		if !ok || have[k] {
			continue
		}
		have[k] = true
		listed[f.ID] = true
		repo := f.Repo
		repo.Counted, repo.Unverified = f.Counted, !f.Counted
		if repo.Unverified {
			repo.Stars = 0
		}
		r := Resource{URL: u, Host: "github.com", Kind: xlinks.KindPoC, Repo: &repo}
		if f.Counted {
			counted = append(counted, r)
		} else {
			rest = append(rest, r)
		}
	}
	if len(counted)+len(rest) == 0 {
		return rs
	}
	i := 0
	for i < len(rs) && rs[i].Kind == xlinks.KindPoC {
		i++
	}
	out := make([]Resource, 0, len(rs)+len(counted)+len(rest))
	out = append(out, rs[:i]...)
	out = append(out, counted...)
	out = append(out, rest...)
	return append(out, rs[i:]...)
}

// ApplyRepos decorates code links on github.com of rs (ResourcesFor's
// order) with their repository, byKey mapping the root key of a stamped
// link to the identity it is stamped with (repoResources reads only
// stamped links whose identity is 'ok' and still holds that name). A link
// is decorated ONLY when it is a link to the repository root
// (ghrepo.RootKeyOf) AND its own key equals the lower-cased full name of
// that identity: a link to a name the repository was renamed away from
// (which someone else may have registered since) and every deep link
// (issues, blob, tree, releases, advisories, ...) keep their plain
// rendering and their Classify group. A rejected repository decorates
// nothing (its links stay plain in their Classify group). A decorated link
// gets Repo (with Counted), and Kind poc when its name, description or
// topics name the CVE or when it counts as a PoC source of it; its stars
// are hidden (Repo.Unverified) when its status is unverified (an admin
// reset it) or when it is under poc without counting. No link is dropped
// or merged. The result is re-sorted by kind, stable.
func ApplyRepos(rs []Resource, byKey map[string]RepoMatch) []Resource {
	if len(byKey) == 0 {
		return rs
	}
	out := make([]Resource, 0, len(rs))
	for _, r := range rs {
		if r.Kind == xlinks.KindCode {
			if k, ok := ghrepo.RootKeyOf(r.URL); ok {
				if m, ok := byKey[k]; ok && strings.ToLower(m.Repo.FullName) == k && m.Status != ghrepo.StatusRejected {
					repo := m.Repo
					repo.Counted = m.Counted
					if m.PoC || m.Counted {
						r.Kind = xlinks.KindPoC
					}
					if m.Status == ghrepo.StatusUnverified || r.Kind == xlinks.KindPoC && !m.Counted {
						repo.Unverified, repo.Stars = true, 0
					}
					r.Repo = &repo
				}
			}
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return resourceRank(out[i].Kind) < resourceRank(out[j].Kind) })
	return out
}

// searchRepoScan bounds the counted repositories repoResources reads for
// one page; the others are read up to MaxUnverifiedRepos plus this slack
// (rows dropped as duplicates of post links).
const (
	searchRepoScan  = 200
	searchRepoSlack = 10
)

// vulnMatch1 / vulnMatch2 are the condition "association row c is about
// the page's vulnerability" with the page's id in $1 / $2: the id itself
// (a CVE id, or the GHSA id of a GHSA-keyed vulnerability), or a GHSA id
// that is a 'ghsa' alias of it. Associations store ids as found; this is
// the read-time resolution (ghrepo.VulnOfSQL is its other direction), so
// the repositories of a GHSA-keyed vulnerability stay on its page when it
// moves to its CVE.
const (
	vulnMatch1 = `(c.cve_id = $1 OR c.cve_id IN (SELECT a.alias FROM vuln_alias a WHERE a.cve_id = $1 AND a.alias_type = 'ghsa'))`
	vulnMatch2 = `(c.cve_id = $2 OR c.cve_id IN (SELECT a.alias FROM vuln_alias a WHERE a.cve_id = $2 AND a.alias_type = 'ghsa'))`
)

// postRepoSQL reads, for the root keys $1 of the page of vulnerability $2, the
// identity that a link of a post about that CVE is stamped with
// (x_post_link.repo_github_id: a fresh answer of the GitHub API for the
// link's own key, never a name join), when that identity is 'ok' and still
// holds the key (github_repo_name: its current lower-cased full name). An
// unchecked or unstamped link, a renamed, gone or replaced repository give
// no row: the link stays plain. So does a fork under ghrepo.MinForkStars
// stars that nobody decided about (ghrepo.SkippedForkSQL: not collected).
// postRepoSQL0023 is the read before migration 0025 (no stamps, no review status: every fetched repository
// of the name is shown as before review existed, a poc one as counted).
const (
	postRepoSQL = `SELECT DISTINCT l.repo_root_key, r.id, r.full_name, COALESCE(r.stars, 0),
    COALESCE(to_char(r.repo_created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'), ''),
    EXISTS (SELECT 1 FROM github_repo_cve c WHERE c.repo_id = r.id AND ` + vulnMatch2 + ` AND c.basis IN ('name', 'description', 'topic')),
    r.status, COALESCE(r.status_by, ''), ` + countedSQL2 + `
FROM x_post_link l
JOIN event p ON p.dedupe_key = l.post_id AND p.source = 'xposts' AND p.type = 'social_post' AND p.cve_id = $2
JOIN github_repo r ON r.github_id = l.repo_github_id
JOIN github_repo_name n ON n.name_key = l.repo_root_key AND n.repo_id = r.id
WHERE l.repo_root_key = ANY($1) AND l.status = 'ok' AND r.state = 'ok' AND r.full_name IS NOT NULL AND lower(r.full_name) = l.repo_root_key
  AND NOT ` + ghrepo.SkippedForkSQL
	postRepoSQL0023 = `SELECT n.name_key, r.id, r.full_name, COALESCE(r.stars, 0),
    COALESCE(to_char(r.repo_created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'), ''),
    EXISTS (SELECT 1 FROM github_repo_cve c WHERE c.repo_id = r.id AND c.cve_id = $2 AND c.basis IN ('name', 'description', 'topic')),
    'trusted', '',
    EXISTS (SELECT 1 FROM github_repo_cve c WHERE c.repo_id = r.id AND c.cve_id = $2 AND c.basis IN ('name', 'description', 'topic'))
FROM github_repo_name n JOIN github_repo r ON r.id = n.repo_id
WHERE n.name_key = ANY($1) AND r.state = 'ok' AND r.full_name IS NOT NULL AND lower(r.full_name) = n.name_key`
)

// countedSQL1 / countedSQL2: repository r counts as a PoC source of the
// vulnerability $1 / $2 — it has that vulnerability's poc_published event
// of source github (keyed by its GitHub id; github_poc_sync keeps exactly
// the github_poc_want set). One probe of event_github_idx.
const (
	countedSQL1 = `EXISTS (SELECT 1 FROM event e WHERE e.source = 'github' AND e.dedupe_key = r.github_id::text AND e.cve_id = $1 AND e.type = 'poc_published')`
	countedSQL2 = `EXISTS (SELECT 1 FROM event e WHERE e.source = 'github' AND e.dedupe_key = r.github_id::text AND e.cve_id = $2 AND e.type = 'poc_published')`
)

// searchRepoSQL reads repositories of vulnerability $1 not shown by a post
// link ($3 row ids), not rejected, still holding their name
// (github_repo_name: a repository whose name another one answered for since
// is not listed under it), whether each is a fork or a collection (more
// than ghrepo.CollectionMin vulnerabilities, $2: distinct by
// ghrepo.VulnOfSQL, so a CVE and its own GHSA alias are one), with the
// class appended:
//   - searchCountedWhere: the counted ones (a github PoC event of $1, read
//     from the event side by the vulnerability's id), stars desc, oldest
//     first, whatever their association basis or seen_at;
//   - searchOtherWhere: the others associated with $1 (vulnMatch1) by
//     name, description or topic — admin-trusted ones, or ones not forks,
//     not collections and seen since $4 — by min(stars, $5) desc, oldest
//     first, id.
//
// At most $6 each.
const searchRepoSQL = `SELECT r.id, r.full_name, COALESCE(r.stars, 0),
    COALESCE(to_char(r.repo_created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'), ''), r.status, COALESCE(r.status_by, ''),
    COALESCE(r.is_fork, false),
    (SELECT count(DISTINCT ` + ghrepo.VulnOfSQL + `) FROM github_repo_cve c WHERE c.repo_id = r.id AND c.basis IN ('name', 'description', 'topic')) > $2
FROM github_repo r
WHERE r.state = 'ok' AND r.full_name IS NOT NULL AND r.status <> 'rejected' AND r.id <> ALL($3)
  AND EXISTS (SELECT 1 FROM github_repo_name n WHERE n.repo_id = r.id AND n.name_key = lower(r.full_name))
  AND `

const (
	searchCountedWhere = `r.github_id = ANY (ARRAY(SELECT e.dedupe_key::bigint FROM event e
        WHERE e.cve_id = $1 AND e.source = 'github' AND e.type = 'poc_published' AND e.dedupe_key ~ '^[1-9][0-9]{0,17}$'))
  AND $4::timestamptz IS NOT NULL AND $5::int IS NOT NULL
ORDER BY r.stars DESC NULLS LAST, r.repo_created_at ASC NULLS LAST, r.id
LIMIT $6`
	searchOtherWhere = `EXISTS (SELECT 1 FROM github_repo_cve c WHERE c.repo_id = r.id AND ` + vulnMatch1 + ` AND c.basis IN ('name', 'description', 'topic'))
  AND NOT ` + countedSQL1 + `
  AND (r.status = 'trusted' AND r.status_by = 'admin'
       OR NOT COALESCE(r.is_fork, false) AND r.seen_at >= $4
          AND (SELECT count(DISTINCT ` + ghrepo.VulnOfSQL + `) FROM github_repo_cve c WHERE c.repo_id = r.id AND c.basis IN ('name', 'description', 'topic')) <= $2)
ORDER BY least(COALESCE(r.stars, 0), $5) DESC, r.repo_created_at ASC NULLS LAST, r.id
LIMIT $6`
)

// repoResources decorates the root code links of rs that are stamped with
// an 'ok' repository still under that name (postRepoSQL, ApplyRepos), then
// lists the other fetched repositories associated with cve by name,
// description or topic (AddSearchRepos); a 'gone', 'pending' or 'failed'
// repository is never read, so its links stay plain. Without migration 0025 (no review status) the links are
// decorated as before review existed and nothing else is listed; without
// 0023 (no github tables) rs is returned unchanged.
func (s *Store) repoResources(ctx context.Context, cve string, rs []Resource) ([]Resource, error) {
	var keys []string
	for _, r := range rs {
		if r.Kind != xlinks.KindCode {
			continue
		}
		if k, ok := ghrepo.RootKeyOf(r.URL); ok {
			keys = append(keys, k)
		}
	}
	sqlState := func(err error) string {
		var se interface{ SQLState() string }
		if errors.As(err, &se) {
			return se.SQLState()
		}
		return ""
	}
	byKey := map[string]RepoMatch{}
	var found []SearchRepo
	reviewed := true
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		if len(keys) > 0 {
			rows, err := conn.Query(ctx, postRepoSQL, keys, cve)
			if err == nil {
				err = scanMatches(rows, byKey)
			}
			if sqlState(err) == "42703" { // before migration 0025
				reviewed = false
				rows, err = conn.Query(ctx, postRepoSQL0023, keys, cve)
				if err == nil {
					err = scanMatches(rows, byKey)
				}
			}
			if err != nil {
				return err
			}
		}
		if !reviewed {
			return nil
		}
		shown := []int64{}
		for _, m := range byKey {
			shown = append(shown, m.ID)
		}
		scan := func(where string, limit int, counted bool) error {
			rows, err := conn.Query(ctx, searchRepoSQL+where, cve, ghrepo.CollectionMin, shown,
				s.clock().Add(-SearchStaleAfter), unverifiedStarCap, limit)
			if err != nil {
				return err
			}
			more, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SearchRepo, error) {
				var f SearchRepo
				f.Counted = counted
				return f, row.Scan(&f.ID, &f.Repo.FullName, &f.Repo.Stars, &f.Repo.Created, &f.Status, &f.StatusBy, &f.Fork, &f.Collection)
			})
			found = append(found, more...)
			return err
		}
		if err := scan(searchCountedWhere, searchRepoScan, true); err != nil {
			return err
		}
		return scan(searchOtherWhere, MaxUnverifiedRepos+searchRepoSlack, false)
	})
	if err != nil {
		switch sqlState(err) {
		case "42P01": // before migration 0023
			return rs, nil
		case "42703": // before migration 0025 (search listing only)
			return ApplyRepos(rs, byKey), nil
		}
		return nil, err
	}
	out := ApplyRepos(rs, byKey)
	if !reviewed {
		return out, nil
	}
	shown := map[int64]bool{}
	for _, r := range out {
		if r.Repo == nil {
			continue
		}
		if k, ok := ghrepo.RootKeyOf(r.URL); ok {
			if m, ok := byKey[k]; ok {
				shown[m.ID] = true
			}
		}
	}
	return AddSearchRepos(out, shown, found), nil
}

// scanMatches reads postRepoSQL rows into byKey.
func scanMatches(rows pgx.Rows, byKey map[string]RepoMatch) error {
	defer rows.Close()
	for rows.Next() {
		var k string
		var m RepoMatch
		if err := rows.Scan(&k, &m.ID, &m.Repo.FullName, &m.Repo.Stars, &m.Repo.Created, &m.PoC, &m.Status, &m.StatusBy, &m.Counted); err != nil {
			return err
		}
		if ghrepo.ValidFullName(m.Repo.FullName) {
			byKey[k] = m
		}
	}
	return rows.Err()
}
