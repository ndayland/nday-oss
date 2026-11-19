package ghrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ------------------------------------------------------------------ review
//
// Review of repositories (github_repo.status, migrations/0025). A status
// belongs to a repository identity: a row with a GitHub id (identity.go).
// A repository found by search is 'unverified' until an administrator
// decides; one that a root link of an allowlisted researcher's post is
// stamped with is 'trusted' by rule (stampLinks, the only place); one
// whose owner is a trusted account is 'trusted' by 'owner' (owner.go). An
// administrator can set any identity to trusted, rejected or back to
// unverified (SetStatus: status_by 'admin'); no automatic path changes
// that, and no automatic path moves it to another repository: a name that
// comes to answer with another GitHub id belongs to another row. A
// rejection also records the identity's name key (github_rejected_name):
// an identity nobody decided about that turns up under such a key is
// rejected by rule (observe). These functions only read the list and switch
// the status; the admin page is built on them.

// Review statuses (github_repo.status) and who set them (status_by).
const (
	StatusUnverified = "unverified"
	StatusTrusted    = "trusted"
	StatusRejected   = "rejected"
	StatusByRule     = "rule"
	StatusByAdmin    = "admin"
)

// CollectionMin: a repository associated with more than this many CVEs by
// name, description or topic is a collection (ReviewItem.Collection), not a
// PoC of one of them; the public panel does not list one found only by
// search.
const CollectionMin = 3

// ReviewMaxCVEs caps ReviewItem.CVEs (a collection may name thousands).
const ReviewMaxCVEs = 50

// ErrRepoNotFound: no repository with that id.
var ErrRepoNotFound = errors.New("ghrepo: repository not found")

// vulnOfSQL is the SQL expression for the vulnerability an association row
// c names: the CVE (or other main id) a GHSA id is a 'ghsa' alias of, else
// the id itself (a CVE id, the id of a GHSA-keyed vulnerability, or a GHSA
// id we do not know). Ids are stored as found; this is the read-time
// resolution, so a GHSA-keyed vulnerability that gets its CVE (pipeline
// mergeVuln leaves the alias) takes its repositories along with no row
// changed here. vuln_alias is unique on (alias_type, alias).
const vulnOfSQL = `COALESCE((SELECT a.cve_id FROM vuln_alias a WHERE a.alias_type = 'ghsa' AND a.alias = c.cve_id), c.cve_id)`

// VulnOfSQL is vulnOfSQL for internal/site (the association row must be
// aliased c).
const VulnOfSQL = vulnOfSQL

// ReviewCVE is one vulnerability a repository is associated with — its main
// id: the CVE when the association's GHSA id is an alias of one — and on
// what bases (BasisName, BasisDescription, BasisTopic, BasisPost; sorted).
type ReviewCVE struct {
	CVE   string
	Bases []string
}

// ReviewItem is one repository of ListReview. Description and OwnerLogin
// are cleaned third-party text: escape on display.
type ReviewItem struct {
	ID          int64
	FullName    string // "Owner/Name" as GitHub returns it
	OwnerLogin  string // "" = unknown
	Description string // "" = none
	Stars       int
	Forks       int
	Created     *time.Time // the repository's creation (GitHub), nil = unknown
	Pushed      *time.Time // its last push, nil = unknown
	IsFork      bool
	IsArchived  bool
	Status      string     // StatusUnverified, StatusTrusted, StatusRejected
	StatusBy    string     // StatusByRule, StatusByAdmin, StatusByOwner, "" = nobody decided
	StatusAt    *time.Time // when StatusBy was set
	FirstSource string     // "xposts" (a post link) or "search"
	// CVEs: the associated vulnerabilities by main id (CVE ids newest
	// first, then GHSA ids), at most ReviewMaxCVEs; CVECount is the number
	// of distinct associated vulnerabilities (a CVE and its own GHSA alias
	// are one; a GHSA id we cannot resolve counts on its own).
	CVEs     []ReviewCVE
	CVECount int
	// Collection: associated with more than CollectionMin CVEs by name,
	// description or topic.
	Collection bool
	// Predates: the repository was created before the earliest
	// publication date (vuln.published_at) of the CVEs it is associated
	// with by name, description or topic; false when either is unknown.
	Predates bool
	// Posted: an X post links it (a BasisPost association: written only by
	// Enqueue for a post's link, so only a post that names a vulnerability
	// counts). Nothing records that a search found a repository first
	// found otherwise.
	Posted bool
	// Owner: its owner is a trusted account ("on"), only a disabled one
	// ("off"), or none ("").
	Owner string
}

func checkStatus(status string) (string, error) {
	if status == "" {
		return StatusUnverified, nil
	}
	switch status {
	case StatusUnverified, StatusTrusted, StatusRejected:
		return status, nil
	}
	return "", fmt.Errorf("ghrepo: unknown review status %q", status)
}

// collectionSQL, predatesSQL and postedSQL are ReviewItem.Collection ($5
// is CollectionMin), ReviewItem.Predates and ReviewItem.Posted of
// github_repo r.
const (
	collectionSQL = `((SELECT count(DISTINCT ` + vulnOfSQL + `) FROM github_repo_cve c WHERE c.repo_id = r.id AND c.basis <> 'post') > $5)`
	postedSQL     = `EXISTS (SELECT 1 FROM github_repo_cve c WHERE c.repo_id = r.id AND c.basis = '` + BasisPost + `')`
	predatesSQL   = `COALESCE(r.repo_created_at < (SELECT min(v.published_at) FROM github_repo_cve c JOIN vuln v ON v.cve_id = ` + vulnOfSQL + `
                                          WHERE c.repo_id = r.id AND c.basis <> 'post'), false)`
)

// Sort keys of ListReviewSorted (ReviewSort.By).
const (
	SortStars = "stars" // stars
	SortFlags = "flags" // the flags' text (ReviewLabels)
	SortFound = "found" // the text of how it was found (ReviewLabels, ReviewOrigins)
)

// ReviewSort is an order of ListReviewSorted: By "" is the default order
// (most recently queued first); otherwise By, ascending or Desc, with the
// rows that have no value (unknown stars, no flag, another source) last in
// both directions, then the default order.
type ReviewSort struct {
	By   string
	Desc bool
}

// ParseReviewSort reads a sort parameter: "stars", "flags", "found", or one
// of them after '-' (descending). Anything else is the default order.
func ParseReviewSort(s string) ReviewSort {
	o := ReviewSort{By: s}
	if b, ok := strings.CutPrefix(s, "-"); ok {
		o = ReviewSort{By: b, Desc: true}
	}
	switch o.By {
	case SortStars, SortFlags, SortFound:
		return o
	}
	return ReviewSort{}
}

// String is the sort parameter of o ("" for the default order).
func (o ReviewSort) String() string {
	if o.By == "" {
		return ""
	}
	if o.Desc {
		return "-" + o.By
	}
	return o.By
}

// ReviewLabels are the words a page shows for the flags (in this order,
// joined by Sep; Owner is the flag of status_by 'owner') and for how a repository was found (ReviewOrigins, joined
// by Sep); SortFlags and
// SortFound order by that text (ASCII letters lowercased, then byte order:
// "search" before "X post"), so they match what the page shows. They are
// query parameters, never SQL.
type ReviewLabels struct {
	Fork, Archived, Collection, Predates, Sep string
	Owner                                     string
	Search, Post                              string // SearchSource, Source
}

// reviewOrder is the ORDER BY of a sort (only these fixed fragments; a
// text key's labels are the parameters from $6 on, args those values).
func reviewOrder(o ReviewSort, l ReviewLabels) (order string, args []any) {
	const tie = `r.created_at DESC, r.id DESC`
	dir := "ASC"
	if o.Desc {
		dir = "DESC"
	}
	switch o.By {
	case SortStars:
		return `r.stars ` + dir + ` NULLS LAST, ` + tie, nil
	case SortFlags:
		return `lower(NULLIF(concat_ws($10::text, CASE WHEN COALESCE(r.is_fork, false) THEN $6::text END,
            CASE WHEN COALESCE(r.is_archived, false) THEN $7::text END, CASE WHEN ` + collectionSQL + ` THEN $8::text END,
            CASE WHEN ` + predatesSQL + ` THEN $9::text END, CASE WHEN r.status_by = '` + StatusByOwner + `' THEN $11::text END), '')) COLLATE "C" ` +
				dir + ` NULLS LAST, ` + tie,
			[]any{l.Fork, l.Archived, l.Collection, l.Predates, l.Sep, l.Owner}
	case SortFound: // the labels of ReviewOrigins, joined by Sep
		return `lower(NULLIF(concat_ws($8::text, CASE r.first_source WHEN '` + SearchSource + `' THEN $6::text WHEN '` + Source + `' THEN $7::text END,
            CASE WHEN r.first_source <> '` + Source + `' AND ` + postedSQL + ` THEN $7::text END), '')) COLLATE "C" ` +
			dir + ` NULLS LAST, ` + tie, []any{l.Search, l.Post, l.Sep}
	}
	return tie, nil
}

// ReviewOrigins are how a repository was found, as the review page shows
// them: its first source (SearchSource or Source; nothing for another
// one), then Source when an X post links it and it was first found
// otherwise.
func ReviewOrigins(it ReviewItem) []string {
	var out []string
	if it.FirstSource == SearchSource || it.FirstSource == Source {
		out = append(out, it.FirstSource)
	}
	if it.Posted && it.FirstSource != Source {
		out = append(out, Source)
	}
	return out
}

// ListReview returns at most limit fetched repositories (state 'ok') with
// the given status ("" = unverified), skipping offset, most recently
// queued first (created_at desc, id desc). Skipped forks nobody decided
// about (skippedForkSQL) aren't in the queue.
func ListReview(ctx context.Context, db DB, status string, limit, offset int) ([]ReviewItem, error) {
	return ListReviewSorted(ctx, db, status, ReviewSort{}, ReviewLabels{}, limit, offset)
}

// ListReviewSorted is ListReview in the order o (labels: the text SortFlags
// and SortFound order by).
func ListReviewSorted(ctx context.Context, db DB, status string, o ReviewSort, labels ReviewLabels, limit, offset int) ([]ReviewItem, error) {
	status, err := checkStatus(status)
	if err != nil {
		return nil, err
	}
	if limit < 0 || offset < 0 {
		return nil, fmt.Errorf("ghrepo: negative limit %d or offset %d", limit, offset)
	}
	order, extra := reviewOrder(ParseReviewSort(o.String()), labels)
	args := append([]any{status, limit, offset, ReviewMaxCVEs, CollectionMin}, extra...)
	rows, err := db.Query(ctx, `SELECT r.id, r.full_name, COALESCE(r.owner_login, ''), COALESCE(r.description, ''),
            COALESCE(r.stars, 0), COALESCE(r.forks, 0), r.repo_created_at, r.pushed_at, COALESCE(r.is_fork, false),
            COALESCE(r.is_archived, false), r.status, COALESCE(r.status_by, ''), r.status_at, r.first_source,
            (SELECT COALESCE(json_agg(json_build_object('cve', x.vid, 'bases', x.bases) ORDER BY x.ghsa, x.y DESC, x.n DESC, x.vid), '[]')
               FROM (SELECT g.vid, array_agg(DISTINCT g.basis ORDER BY g.basis) AS bases, g.vid LIKE 'GHSA-%' AS ghsa,
                            CASE WHEN g.vid LIKE 'CVE-%' THEN split_part(g.vid, '-', 2)::int END AS y,
                            CASE WHEN g.vid LIKE 'CVE-%' THEN split_part(g.vid, '-', 3)::numeric END AS n
                       FROM (SELECT `+vulnOfSQL+` AS vid, c.basis FROM github_repo_cve c WHERE c.repo_id = r.id) g
                       GROUP BY g.vid
                       ORDER BY ghsa, y DESC, n DESC, g.vid LIMIT $4) x),
            (SELECT count(DISTINCT `+vulnOfSQL+`) FROM github_repo_cve c WHERE c.repo_id = r.id),
            `+collectionSQL+`,
            `+predatesSQL+`,
            `+postedSQL+`,
            COALESCE(`+ownerStateSQL+`, '')
        FROM github_repo r
        WHERE r.state = 'ok' AND r.status = $1 AND NOT `+skippedForkSQL+`
        ORDER BY `+order+`
        LIMIT $2 OFFSET $3`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ReviewItem, error) {
		var it ReviewItem
		var cves []byte
		err := row.Scan(&it.ID, &it.FullName, &it.OwnerLogin, &it.Description, &it.Stars, &it.Forks, &it.Created, &it.Pushed,
			&it.IsFork, &it.IsArchived, &it.Status, &it.StatusBy, &it.StatusAt, &it.FirstSource, &cves, &it.CVECount,
			&it.Collection, &it.Predates, &it.Posted, &it.Owner)
		if err != nil {
			return it, err
		}
		var list []struct {
			CVE   string   `json:"cve"`
			Bases []string `json:"bases"`
		}
		if err := json.Unmarshal(cves, &list); err != nil {
			return it, err
		}
		it.CVEs = make([]ReviewCVE, 0, len(list))
		for _, c := range list {
			it.CVEs = append(it.CVEs, ReviewCVE{CVE: c.CVE, Bases: c.Bases})
		}
		for _, p := range []**time.Time{&it.Created, &it.Pushed, &it.StatusAt} {
			if *p != nil {
				t := (*p).UTC()
				*p = &t
			}
		}
		return it, nil
	})
}

// CountReview counts what ListReview would list for status ("" =
// unverified) without a limit.
func CountReview(ctx context.Context, db DB, status string) (int, error) {
	status, err := checkStatus(status)
	if err != nil {
		return 0, err
	}
	var n int
	err = db.QueryRow(ctx, `SELECT count(*) FROM github_repo r WHERE r.state = 'ok' AND r.status = $1 AND NOT `+skippedForkSQL, status).Scan(&n)
	return n, err
}

// GetForUpdate reads one row's full name ("" for a placeholder),
// status and status_by ("" = nobody decided), locking its row until the end
// of the caller's transaction (db must be a pgx.Tx). It first takes the
// store lock (lockStore), in the order the passes take them — store lock,
// then row — so the decision that follows (SetStatus) reads the row's names
// while no pass is moving them. ErrRepoNotFound if absent.
func GetForUpdate(ctx context.Context, db DB, id int64) (fullName, status, statusBy string, err error) {
	if err := lockStore(ctx, db); err != nil {
		return "", "", "", err
	}
	err = db.QueryRow(ctx, `SELECT COALESCE(full_name, ''), status, COALESCE(status_by, '') FROM github_repo
        WHERE id = $1 FOR NO KEY UPDATE`, id).Scan(&fullName, &status, &statusBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", ErrRepoNotFound
	}
	return fullName, status, statusBy, err
}

// SetStatus records an administrator's decision about the identity in row
// id: status (StatusTrusted, StatusRejected or StatusUnverified; "" is not
// accepted), status_by 'admin', status_at now. changed is false when the
// row already had that status by an admin (status_at is then left alone).
// The decision stays with that GitHub id whatever its name becomes, and no
// sweep, fetch or search changes it. ErrRepoNotFound if the row is absent
// or a placeholder (no GitHub id: there is no repository to decide about).
//
// A rejection records the name key the identity holds now and the key of
// its stored full name (github_rejected_name, with the row that recorded
// it): an identity that holds no key at that moment — another repository
// answered for its name and its own refresh has not run yet — is still
// rejected under the name the administrator saw. observe adds the keys it
// holds later while it stays rejected. Any other decision removes
// the keys recorded for this identity, and only those.
func SetStatus(ctx context.Context, db DB, id int64, status string) (changed bool, err error) {
	if status == "" {
		return false, fmt.Errorf("ghrepo: empty review status")
	}
	if _, err := checkStatus(status); err != nil {
		return false, err
	}
	var exists bool
	err = db.QueryRow(ctx, `WITH u AS (
            UPDATE github_repo SET status = $2, status_by = 'admin', status_at = now()
            WHERE id = $1 AND github_id IS NOT NULL AND (status <> $2 OR status_by IS DISTINCT FROM 'admin') RETURNING 1)
        SELECT EXISTS (SELECT 1 FROM u), EXISTS (SELECT 1 FROM github_repo WHERE id = $1 AND github_id IS NOT NULL)`, id, status).Scan(&changed, &exists)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, ErrRepoNotFound
	}
	q := `DELETE FROM github_rejected_name WHERE repo_id = $1`
	if status == StatusRejected {
		q = `INSERT INTO github_rejected_name (name_key, repo_id)
            SELECT name_key, repo_id FROM github_repo_name WHERE repo_id = $1
            UNION SELECT lower(full_name), id FROM github_repo WHERE id = $1 AND full_name IS NOT NULL
            ON CONFLICT DO NOTHING`
	}
	if _, err := db.Exec(ctx, q, id); err != nil {
		return false, err
	}
	return changed, nil
}
