package ghrepo

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// PoCSource is the event source of the PoC events trusted repositories
// give (migrations/0032_github_poc.sql): one poc_published event per
// (vulnerability, repository), dedupe_key the GitHub id, occurred_at the
// repository's creation time (day precision). The triggers of 0032 keep
// these events in step with every change of a repository, its
// associations and the GHSA aliases, in the same transaction; SyncPoC is
// the backfill and repair (also for what no trigger sees: a changed
// vuln.published_at or disclosed event, the predates test).
const PoCSource = "github"

// PoCSyncBatch is how many vulnerabilities SyncPoC handles per transaction.
const PoCSyncBatch = 500

// PoCSyncResult is what SyncPoC did (or, in a dry run, would do).
type PoCSyncResult struct {
	Vulns   int  `json:"vulns"`   // vulnerabilities looked at: every one a repository is associated with or that has a github event
	Added   int  `json:"added"`   // events inserted
	Removed int  `json:"removed"` // events deleted (the repository stopped counting)
	Updated int  `json:"updated"` // events whose time, URL or name changed
	DryRun  bool `json:"dry_run"`
}

// Changed reports whether the run changed (or would change) an event.
func (r PoCSyncResult) Changed() bool { return r.Added+r.Removed+r.Updated > 0 }

// pocIDsSQL: every vulnerability a repository is associated with
// (resolved like the pages) and every one with a github event, so stray
// events whose association is gone are visited too.
const pocIDsSQL = `SELECT vid FROM (
    SELECT ` + vulnOfSQL + ` AS vid FROM github_repo_cve c
    UNION SELECT cve_id FROM event WHERE source = 'github') x ORDER BY vid`

// SyncPoC runs github_poc_sync over the vulnerabilities of pocIDsSQL,
// PoCSyncBatch per transaction (one statement each), in id order. What it
// adds is history (is_backfill): never an X draft. With nothing out of
// step it changes nothing, so it can be run (or rerun after a failure) at
// any time. A dry run only compares
// (github_poc_diff): no locks, no writes, no event ids used.
func SyncPoC(ctx context.Context, conn *pgx.Conn, dryRun bool) (PoCSyncResult, error) {
	res := PoCSyncResult{DryRun: dryRun}
	rows, err := conn.Query(ctx, pocIDsSQL)
	if err != nil {
		return res, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	fn := "github_poc_sync($1, true)"
	if dryRun {
		fn = "github_poc_diff($1)"
	}
	for len(ids) > 0 {
		n := min(PoCSyncBatch, len(ids))
		batch := ids[:n]
		ids = ids[n:]
		var a, r, u int
		if err := conn.QueryRow(ctx, `SELECT added, removed, updated FROM `+fn, batch).Scan(&a, &r, &u); err != nil {
			return res, err
		}
		res.Vulns += n
		res.Added += a
		res.Removed += r
		res.Updated += u
	}
	return res, nil
}

// PoCFingerprint sums up the github events (ids, vulnerabilities, times,
// URLs) through the partial index of 0032; two equal values mean nothing
// changed in between. Callers compare it around a pass to decide whether
// vuln_state_mat needs a refresh.
func PoCFingerprint(ctx context.Context, db DB) (string, error) {
	var fp string
	err := db.QueryRow(ctx, `SELECT count(*)::text || ':' || COALESCE(sum(hashtextextended(
            concat_ws('|', id, cve_id, dedupe_key, occurred_at, url), 0)), 0)::text
        FROM event WHERE source = 'github'`).Scan(&fp)
	return fp, err
}
