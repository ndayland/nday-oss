package ghrepo

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The review refresh: after its search part, every discovery run brings
// the repositories waiting for review ('unverified', 'ok', with a GitHub
// id) up to date, so the stars an admin sorts the review queue by are at
// most about an hour old. It's a plain refresh by id through the fetch
// pass's own code (task, handle): If-None-Match with the stored ETag, a
// 304 only stamps fetched_at, a 200 goes through observe (a rename is the
// same identity under a new name), a 404/410/451 or a repository that
// isn't public is 'gone' (noAnswer → markGone). Nothing here decides
// trust; whatever observe and the triggers do on a fetch happens here too.
const (
	// RefreshUnverifiedAfter: a row fetched (or returned by search) less
	// than this long ago is left alone. A bit under the hourly timer, so
	// each run picks up what the last one refreshed.
	RefreshUnverifiedAfter = 50 * time.Minute
	// RefreshUnverifiedLimit caps the refreshes of one run with a token
	// (5,000 core requests an hour); RefreshUnverifiedAnonLimit without one
	// (60 an hour per address, shared with the fetch pass after each
	// collection and admin lookups).
	RefreshUnverifiedLimit     = 500
	RefreshUnverifiedAnonLimit = 20
	// RefreshSpacingAuth and RefreshSpacingAnon are the waits between two
	// refresh requests (the core API has no per-minute limit, but GitHub
	// asks for requests one at a time and not in a tight loop).
	RefreshSpacingAuth = 300 * time.Millisecond
	RefreshSpacingAnon = time.Second
	// RefreshReserveAuth and RefreshReserveAnon: the refresh stops once the
	// core limit reports fewer requests left than this, so the fetch pass
	// and admin lookups keep some headroom.
	RefreshReserveAuth = 500
	RefreshReserveAnon = 20
	// RefreshMinTime is the part of MaxRunTime kept for the refresh: the
	// search part stops at MaxRunTime - RefreshMinTime (10 minutes), and the
	// refresh may run until MaxRunTime from the start of the run.
	RefreshMinTime = 5 * time.Minute
)

// refreshShare is the part of a run time of d kept for the refresh:
// RefreshMinTime, or a third of a shorter run time.
func refreshShare(d time.Duration) time.Duration {
	return min(RefreshMinTime, d/3)
}

// RefreshResult counts the review refresh of one Discover run.
type RefreshResult struct {
	Candidates  int  `json:"candidates"`   // rows due (all of them, also past the cap)
	Requests    int  `json:"requests"`     // core requests made (followed redirects included)
	OK          int  `json:"ok"`           // 200: metadata updated
	NotModified int  `json:"not_modified"` // 304: only fetched_at stamped
	Gone        int  `json:"gone"`         // 404 / 410 / 451 / not public: now 'gone'
	Failed      int  `json:"failed"`       // transient failures (attempts + 1, the row stays 'ok')
	RateLimited bool `json:"rate_limited"` // stopped on a 403 / 429 or the reserve
	Capped      bool `json:"capped"`       // more rows were due than the cap allows
	TimedOut    bool `json:"timed_out"`    // stopped at the run's time
	Remaining   int  `json:"remaining"`    // the last core x-ratelimit-remaining (-1 = none)
}

// refreshDueSQL: rows waiting for review whose last fetch is older than $1.
const refreshDueSQL = `g.state = 'ok' AND g.status = 'unverified' AND g.github_id IS NOT NULL
    AND (g.fetched_at IS NULL OR g.fetched_at < $1)`

// refreshSQL selects the due rows, oldest fetch first, at most $2, in the
// columns of scanTask. The last column asks unconditionally, as in the
// fetch pass: an identity that holds no name key, and a row whose owner id
// is missing while its login names a trusted account (ownerRefetchSQL,
// its $6 is $3 here). Without it a 304 every hour would keep stamping
// fetched_at and the owner refetch would never come.
var refreshSQL = `SELECT g.id, g.github_id, g.queued_name, g.etag, g.state, g.attempts,
        NOT EXISTS (SELECT 1 FROM github_repo_name n WHERE n.repo_id = g.id) OR ` + strings.ReplaceAll(ownerRefetchSQL, "$6", "$3") + `
    FROM github_repo g WHERE ` + refreshDueSQL + `
    ORDER BY g.fetched_at NULLS FIRST, g.id LIMIT $2`

// refreshUnverified is the review refresh: the rows of refreshDueSQL,
// oldest fetch first, at most the limit (Capped when more are due),
// RefreshSpacing apart, until run ends (TimedOut; a request cut short
// writes nothing). It stops cleanly on a rate-limit answer (nothing
// written), on any other 403 (written as a transient failure, so that row
// goes to the back of the line), and once the core limit reports fewer
// than RefreshReserve left. Errors are database errors and ctx's.
func (d *discoverer) refreshUnverified(ctx, run context.Context) error {
	o, rr := d.o, &d.res.Refresh
	if o.RefreshLimit < 0 {
		return nil
	}
	auth := o.Client.Authenticated()
	limit, spacing, reserve := RefreshUnverifiedAnonLimit, RefreshSpacingAnon, RefreshReserveAnon
	if auth {
		limit, spacing, reserve = RefreshUnverifiedLimit, RefreshSpacingAuth, RefreshReserveAuth
	}
	if o.RefreshLimit > 0 {
		limit = o.RefreshLimit
	}
	if o.RefreshSpacing > 0 {
		spacing = o.RefreshSpacing
	}
	if o.RefreshReserve > 0 {
		reserve = o.RefreshReserve
	}
	now := o.Now().UTC()
	cutoff := now.Add(-RefreshUnverifiedAfter)
	if err := d.db.QueryRow(ctx, `SELECT count(*) FROM github_repo g WHERE `+refreshDueSQL, cutoff).Scan(&rr.Candidates); err != nil {
		return err
	}
	if rr.Candidates == 0 {
		return nil
	}
	rr.Capped = rr.Candidates > limit
	rows, err := d.db.Query(ctx, refreshSQL, cutoff, limit, now.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	todo, err := pgx.CollectRows(rows, scanTask)
	if err != nil {
		return err
	}
	timedOut := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rr.TimedOut = true
		o.Logger.Info("github review refresh stopped at the run time", "requests", rr.Requests)
		return nil
	}
	for _, t := range todo {
		if err := ctx.Err(); err != nil {
			return err
		}
		// an answer earlier in this run (or an admin) may have changed it
		var due bool
		if err := d.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM github_repo g WHERE g.id = $1 AND g.github_id = $2
            AND g.state = 'ok' AND g.status = 'unverified')`, t.id, t.githubID).Scan(&due); err != nil {
			return err
		}
		if !due {
			continue
		}
		if rr.Requests > 0 {
			if err := o.Sleep(run, spacing); err != nil {
				return timedOut()
			}
		}
		if run.Err() != nil {
			return timedOut()
		}
		rr.Requests++
		resp, gerr := o.Client.Get(run, t.path(), t.etag)
		if run.Err() != nil {
			return timedOut()
		}
		if resp != nil {
			rr.Requests += resp.Redirects
			if resp.Remaining >= 0 {
				rr.Remaining = resp.Remaining
			}
			if resp.RateLimited() {
				rr.RateLimited = true
				o.Logger.Warn("github rate limit reached; review refresh stopped", "status", resp.Status, "reset", resp.Reset,
					"retry_after", resp.RetryAfter, "authenticated", auth)
				return nil
			}
		}
		oc := handle(ctx, d.db, t, resp, gerr, DecodeRepo, o.Logger, o.Now().UTC())
		if oc.err != nil {
			return oc.err
		}
		switch oc.kind {
		case outOK:
			rr.OK++
		case outNotModified:
			rr.NotModified++
		case outGone:
			rr.Gone++
		case outRetry, outFailed:
			rr.Failed++
		}
		if resp != nil && resp.Status == http.StatusForbidden {
			// a secondary limit may come without headers
			rr.RateLimited = true
			o.Logger.Warn("github answered 403; review refresh stopped", "repo_id", t.id, "authenticated", auth)
			return nil
		}
		if resp != nil && resp.Remaining >= 0 && resp.Remaining < reserve {
			rr.RateLimited = true
			o.Logger.Info("github core limit down to the reserve; review refresh stopped", "remaining", resp.Remaining,
				"reserve", reserve, "reset", resp.Reset, "authenticated", auth)
			return nil
		}
	}
	return nil
}
