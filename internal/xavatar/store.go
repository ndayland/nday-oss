package xavatar

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/pagefetch"
	"nday.land/nday/internal/researchsql"
	"nday.land/nday/internal/siteicon"
)

// Job constants.
const (
	// DefaultLimit is the number of avatars a run fetches at most.
	DefaultLimit = 100
	// RunBudget bounds a whole run; users not reached stay due. With the
	// site icons' 15 minutes it stays under the unit's TimeoutStartSec=20min.
	RunBudget = 3 * time.Minute
	// Delay between two requests (one CDN host, so be gentle).
	Delay = 500 * time.Millisecond
	// RefreshOK is when a stored avatar is fetched again even though its
	// URL did not change (X changes the URL when the picture changes, so
	// this is only a safety net).
	RefreshOK = 30 * 24 * time.Hour
	// RetryNone is when an unusable URL is tried again.
	RetryNone = 30 * 24 * time.Hour
	// errMax is the stored length of avatar_error.
	errMax = 200
)

// DB is the database handle (*pgx.Conn, pgx.Tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Candidate is a user whose avatar is due.
type Candidate struct {
	UserID   string
	URL      string // x_user.avatar_url
	Tried    string // x_user.avatar_tried ("" = never)
	Failures int
}

// dueSQL: authors the public outline shows (researchsql.ListedAuthor at
// $1: an enabled allow-listed account with a post in some vulnerability
// page's outline; anyone else's picture would reveal allowlist membership
// the outline does not) with an avatar URL that was never tried, changed
// since the last attempt, or whose next try ($1) passed; changed URLs
// first, at most $2.
var dueSQL = `SELECT u.user_id, u.avatar_url, COALESCE(u.avatar_tried, ''), u.avatar_failures
FROM x_user u
WHERE u.avatar_url IS NOT NULL
  AND (u.avatar_tried IS DISTINCT FROM u.avatar_url OR u.avatar_next_try_at IS NULL OR u.avatar_next_try_at <= $1)
  AND ` + researchsql.ListedAuthor("u.user_id", "$1") + `
ORDER BY (u.avatar_tried IS DISTINCT FROM u.avatar_url) DESC, u.avatar_next_try_at NULLS FIRST, u.user_id
LIMIT $2`

// Due returns at most limit users whose avatar is due at now.
func Due(ctx context.Context, db DB, now time.Time, limit int) ([]Candidate, error) {
	rows, err := db.Query(ctx, dueSQL, now, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Candidate, error) {
		var c Candidate
		return c, r.Scan(&c.UserID, &c.URL, &c.Tried, &c.Failures)
	})
}

// Options configures Run.
type Options struct {
	Limit  int           // avatars per run; <= 0 means DefaultLimit
	Budget time.Duration // <= 0 means RunBudget
	// Fetcher; nil means NewFetcher with the production (guarded)
	// settings. Tests inject one from code.
	Fetcher *Fetcher
	Now     func() time.Time
	Sleep   func(ctx context.Context, d time.Duration) error
	Logger  *slog.Logger
}

// Result counts one run.
type Result struct {
	Candidates int  `json:"candidates"`
	OK         int  `json:"ok"`
	None       int  `json:"none"`
	Error      int  `json:"error"`
	Refused    int  `json:"refused"`
	TimedOut   bool `json:"timed_out"`
}

// Run is one pass: the Due users, one at a time, Delay apart, each avatar
// fetched (Fetcher.Fetch) and its row written on its own. ok: the image
// replaces the stored one, refreshed after RefreshOK; none: any stored
// image is dropped, tried again after RetryNone (or when the URL changes);
// error: failures + 1 (counting from 1 again for a new URL), tried again
// after siteicon.ErrorDelay, a stored image kept. A cancelled ctx stops
// the run with ctx.Err(); the budget stops it cleanly (TimedOut).
func Run(ctx context.Context, db DB, o Options) (Result, error) {
	var res Result
	if o.Limit <= 0 {
		o.Limit = DefaultLimit
	}
	if o.Budget <= 0 {
		o.Budget = RunBudget
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	if o.Fetcher == nil {
		o.Fetcher = NewFetcher(pagefetch.Options{})
	}
	bctx, cancel := context.WithTimeout(ctx, o.Budget)
	defer cancel()
	todo, err := Due(ctx, db, o.Now().UTC(), o.Limit)
	if err != nil {
		return res, err
	}
	res.Candidates = len(todo)
	for i, c := range todo {
		if i > 0 {
			if err := o.Sleep(bctx, Delay); err != nil {
				return res, stopped(ctx, &res)
			}
		}
		if bctx.Err() != nil {
			return res, stopped(ctx, &res)
		}
		f := o.Fetcher.Fetch(bctx, c.URL)
		if bctx.Err() != nil { // the run ended during this one: not its fault
			return res, stopped(ctx, &res)
		}
		if f.Refused {
			res.Refused++
		}
		if err := store(ctx, db, c, f, o.Now().UTC()); err != nil {
			return res, err
		}
		switch f.Status {
		case StatusOK:
			res.OK++
		case StatusNone:
			res.None++
		default:
			res.Error++
		}
		if f.Status != StatusOK {
			o.Logger.Info("x avatar not stored", "user_id", c.UserID, "status", f.Status, "why", f.Why)
		}
	}
	return res, nil
}

func stopped(ctx context.Context, res *Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	res.TimedOut = true
	return nil
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

// store writes outcome f for candidate c at now. Every write is guarded by
// avatar_url = c.URL, so a URL the collector changed meanwhile is left for
// the next run.
func store(ctx context.Context, db DB, c Candidate, f Fetched, now time.Time) error {
	why := f.Why
	if len(why) > errMax {
		why = why[:errMax]
	}
	switch f.Status {
	case StatusOK:
		_, err := db.Exec(ctx, `UPDATE x_user SET avatar_status = 'ok', avatar_type = $3, avatar_image = $4, avatar_hash = $5,
    avatar_src = $2, avatar_tried = $2, avatar_fetched_at = $6, avatar_next_try_at = $7, avatar_failures = 0, avatar_error = NULL
WHERE user_id = $1 AND avatar_url = $2`, c.UserID, c.URL, f.ContentType, f.Image, siteicon.Hash(f.Image), now, now.Add(RefreshOK))
		return err
	case StatusNone:
		_, err := db.Exec(ctx, `UPDATE x_user SET avatar_status = 'none', avatar_type = NULL, avatar_image = NULL, avatar_hash = NULL,
    avatar_src = NULL, avatar_tried = $2, avatar_fetched_at = $3, avatar_next_try_at = $4, avatar_failures = 0, avatar_error = $5
WHERE user_id = $1 AND avatar_url = $2`, c.UserID, c.URL, now, now.Add(RetryNone), why)
		return err
	default:
		n := c.Failures + 1
		if c.Tried != c.URL {
			n = 1
		}
		_, err := db.Exec(ctx, `UPDATE x_user SET avatar_tried = $2, avatar_fetched_at = $3, avatar_next_try_at = $4,
    avatar_failures = $5, avatar_error = $6,
    avatar_status = CASE WHEN avatar_status = 'ok' THEN 'ok' ELSE 'error' END
WHERE user_id = $1 AND avatar_url = $2`, c.UserID, c.URL, now, now.Add(siteicon.ErrorDelay(n)), n, why)
		return err
	}
}

// Avatar is a stored avatar.
type Avatar struct {
	ContentType string
	Image       []byte
	Hash        string
}

// HashRe is the form of an avatar key (x_user.avatar_hash).
var HashRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Path is the same-origin URL path of an avatar with hash h ("" for "").
func Path(h string) string {
	if !HashRe.MatchString(h) {
		return ""
	}
	return "/avatar/" + h
}

// Load returns the stored avatar whose hash is h, only of an author the
// public outline shows at now (researchsql.ListedAuthor: a disabled
// account, or one without a listed post, is not served), nil when there is
// none, h is not a hash, or the table does not exist yet.
func Load(ctx context.Context, db DB, h string, now time.Time) (*Avatar, error) {
	if !HashRe.MatchString(h) {
		return nil, nil
	}
	rows, err := db.Query(ctx, `SELECT u.avatar_type, u.avatar_image, u.avatar_hash
FROM x_user u
WHERE u.avatar_hash = $1 AND u.avatar_image IS NOT NULL AND `+researchsql.ListedAuthor("u.user_id", "$2")+`
LIMIT 1`, h, now)
	if err != nil {
		if missingTable(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil && !missingTable(err) {
			return nil, err
		}
		return nil, nil
	}
	var a Avatar
	if err := rows.Scan(&a.ContentType, &a.Image, &a.Hash); err != nil {
		return nil, err
	}
	return &a, rows.Err()
}

func missingTable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42P01"
}
