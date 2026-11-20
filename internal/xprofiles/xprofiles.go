// Package xprofiles fills x_user (the display name and avatar URL the
// researcher section shows) for the allow-listed accounts straight from the
// X API user lookup by id, so authors fill in without waiting for their
// next collected post (`nday x-profiles`, docs/xposts.md "Author profiles
// and avatars"). It reuses everything of the collector path: the lookup
// client (internal/xlookup: fixed https://api.x.com, the
// NDAY_X_BEARER_TOKEN token never logged, one attempt, 429 never retried),
// the cleaning and validation (xavatar.Profile) and the upsert
// (pipeline.UpsertXUser, newest fetch wins). It never fetches images: the
// avatar pass of `nday site-icons` does that.
package xprofiles

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/xavatar"
	"nday.land/nday/internal/xlookup"
)

// Limits of one run.
const (
	// MaxRequests caps the lookup requests of a run (100 ids each, so 1000
	// accounts at most; a re-run with OnlyMissing picks up the rest).
	MaxRequests = 10
	// Pause between two requests.
	Pause = time.Second
	// Budget bounds a whole run.
	Budget = 2 * time.Minute
	// StaleAfter: with OnlyMissing, a profile fetched longer ago than this
	// is fetched again.
	StaleAfter = 30 * 24 * time.Hour
	// maxRejectedLogged is how many rejected avatar URLs are logged (host
	// and first path segment only).
	maxRejectedLogged = 3
)

// Lookup is the X client (xlookup.Client).
type Lookup interface {
	ProfilesByID(ctx context.Context, ids []string) (map[string]xlookup.Profile, []string, error)
}

// DB is the database handle (*pgx.Conn, pgx.Tx).
type DB interface {
	pipeline.Execer
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Options configures Run.
type Options struct {
	DryRun      bool // fetch and validate, write nothing
	OnlyMissing bool // only accounts without a profile or with one older than StaleAfter
	Now         func() time.Time
	Sleep       func(ctx context.Context, d time.Duration) error
	Logger      *slog.Logger
}

// Result counts one run (also the command's JSON output).
type Result struct {
	Considered     int      `json:"considered"`      // enabled accounts picked
	Requested      int      `json:"requested"`       // ids sent to X
	Returned       int      `json:"returned"`        // profiles X sent back
	WithName       int      `json:"with_name"`       // of those, a name left after cleaning
	AvatarAccepted int      `json:"avatar_accepted"` // an avatar URL xavatar.AvatarURL accepts
	AvatarRejected int      `json:"avatar_rejected"` // an avatar URL it refuses
	RejectedSample []string `json:"rejected_sample,omitempty"`
	NotReturned    int      `json:"not_returned"` // suspended, deleted or otherwise absent
	Written        int      `json:"written"`      // rows written (0 on a dry run)
	Requests       int      `json:"requests"`
	RateLimited    bool     `json:"rate_limited"` // HTTP 429 stopped the run
	TimedOut       bool     `json:"timed_out"`    // the budget stopped the run
	Capped         bool     `json:"capped"`       // MaxRequests stopped the run
	DryRun         bool     `json:"dry_run"`
}

// accounts returns the enabled allow-listed ids to fetch, in id order.
func accounts(ctx context.Context, db DB, onlyMissing bool, staleBefore time.Time) ([]string, error) {
	q := `SELECT xa.user_id FROM x_accounts xa LEFT JOIN x_user u ON u.user_id = xa.user_id
WHERE xa.enabled`
	args := []any{}
	if onlyMissing {
		q += ` AND (u.user_id IS NULL OR u.seen_at < $1)`
		args = append(args, staleBefore)
	}
	q += ` ORDER BY length(xa.user_id), xa.user_id`
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Run is one pass: the accounts to fetch, MaxPerRequest ids a request,
// Pause apart, at most MaxRequests requests and Budget in all; each
// returned profile is cleaned and validated (xavatar.Profile) and, unless
// DryRun, upserted with seen_at = the time of its request. HTTP 429 stops
// the run cleanly (RateLimited; what was written stays); any other request
// error is returned, also after the rows written before it.
func Run(ctx context.Context, db DB, lk Lookup, o Options) (Result, error) {
	res := Result{DryRun: o.DryRun}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	ids, err := accounts(ctx, db, o.OnlyMissing, o.Now().Add(-StaleAfter))
	if err != nil {
		return res, err
	}
	res.Considered = len(ids)
	bctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	for i := 0; i < len(ids); i += xlookup.MaxPerRequest {
		if res.Requests == MaxRequests {
			res.Capped = true
			break
		}
		if res.Requests > 0 {
			if err := o.Sleep(bctx, Pause); err != nil {
				break
			}
		}
		if bctx.Err() != nil {
			break
		}
		batch := ids[i:min(i+xlookup.MaxPerRequest, len(ids))]
		at := o.Now().UTC()
		res.Requests++
		got, missing, err := lk.ProfilesByID(bctx, batch)
		if errors.Is(err, xlookup.ErrRateLimited) {
			res.RateLimited = true
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			if bctx.Err() != nil {
				break
			}
			return res, err
		}
		res.Requested += len(batch)
		res.NotReturned += len(missing)
		for _, id := range batch {
			p, ok := got[id]
			if !ok {
				continue
			}
			res.Returned++
			u, rejected, ok := xavatar.Profile(id, p.Name, p.ProfileImageURL, at)
			if !ok {
				continue
			}
			if u.Name != nil {
				res.WithName++
			}
			if u.AvatarURL != nil {
				res.AvatarAccepted++
			}
			if rejected {
				res.AvatarRejected++
				if len(res.RejectedSample) < maxRejectedLogged {
					res.RejectedSample = append(res.RejectedSample, urlShape(p.ProfileImageURL))
				}
			}
			if o.DryRun {
				continue
			}
			if err := pipeline.UpsertXUser(ctx, db, u); err != nil {
				return res, err
			}
			res.Written++
		}
	}
	if bctx.Err() != nil && ctx.Err() == nil {
		res.TimedOut = true
	}
	return res, ctx.Err()
}

// urlShape is what may be logged of a refused avatar URL: its scheme, host
// and first path segment (enough to see if X moved the images), nothing
// that names the user.
func urlShape(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparsable)"
	}
	seg := strings.SplitN(strings.TrimPrefix(u.EscapedPath(), "/"), "/", 2)[0]
	if len(seg) > 40 {
		seg = seg[:40]
	}
	return u.Scheme + "://" + u.Host + "/" + seg
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
