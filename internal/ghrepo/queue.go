package ghrepo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Pass constants.
const (
	// MaxAttempts per repository; 'failed' after that many transient
	// failures in a row.
	MaxAttempts = 3
	// MaxTotalAttempts caps the slow retries of 'failed' rows (once per
	// SlowRetryAfter).
	MaxTotalAttempts = 6
	// SlowRetryAfter is the wait after the last attempt of a 'failed' row.
	SlowRetryAfter = 24 * time.Hour
	// RefreshAfter: an 'ok' repository is fetched again at most this often.
	RefreshAfter = 7 * 24 * time.Hour
	// DefaultLimit is the number of repositories per pass.
	DefaultLimit = 50
	// DefaultRefreshLimit is the most 'ok' repositories refreshed per pass
	// (within Limit; new ones go first).
	DefaultRefreshLimit = 10
	// Delay between two requests.
	Delay = time.Second
	// GoneRetryAfter and GoneRetryWindow: a 'gone' repository is fetched
	// again at most once per GoneRetryAfter while it was queued (our
	// created_at) less than GoneRetryWindow ago; after that 'gone' is final.
	// These retries share RefreshLimit with the 'ok' refreshes.
	GoneRetryAfter  = 24 * time.Hour
	GoneRetryWindow = 7 * 24 * time.Hour
	// MinRemaining: the pass stops when GitHub reports this many requests
	// or fewer left in the rate-limit window (so a pass without a token
	// never takes the last requests of the shared hourly 60).
	MinRemaining = 5
	// Source is the producer name of the X post links (first_source).
	Source = "xposts"
	// MaxCheckAttempts: a root link whose check (a request for its key by
	// name) failed transiently this many times is no longer picked for its
	// own sake; it is still checked when its key is asked again (a
	// placeholder's retry, or another link to the same key).
	MaxCheckAttempts = MaxAttempts
	// storeLockID is the first key of the transaction advisory lock every
	// writer of github_repo_name takes (Enqueue per link, the stores of a
	// fetch pass and of Discover): they run one after another, so a sweep
	// never queues a name while a pass moves or deletes its placeholder
	// ("ndGI"; second key hashtext(current_schema()), as DiscoverLockID).
	storeLockID int32 = 0x6E644749
)

// States (github_repo.state).
const (
	StatePending = "pending"
	StateOK      = "ok"
	StateGone    = "gone"
	StateFailed  = "failed"
)

// DB is the database handle (*pgx.Conn, pgx.Tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// EnqueueResult counts one Enqueue sweep.
type EnqueueResult struct {
	Candidates int `json:"candidates"` // link rows swept (new or with a changed final URL)
	Added      int `json:"added"`      // new names queued (placeholder rows)
	NotRepo    int `json:"not_repo"`   // links that are not a repository URL (ParseURL)
	PostCVEs   int `json:"post_cves"`  // new 'post' associations
	Revived    int `json:"revived"`    // 'gone' rows made 'pending' again by a new link
}

// enqueueBatch is the number of link rows read per round.
const enqueueBatch = 1000

// enqueueKinds are the x_post_link kinds swept: repository links
// (xlinks.KindCode). Commits, pull requests and compares (patch) are
// patches, not repositories, and are left to the web page module.
var enqueueKinds = []string{"code"}

// Enqueue sweeps the GitHub links of stored X posts: every x_post_link row
// with status 'ok', host github.com, a kind of enqueueKinds, whose
// final_url differs from its repo_swept_url (never swept by this code, or
// changed since), oldest first. repo_swept_url is this release's marker;
// the phase-1 marker repo_queued_url is neither read for that nor written
// (a phase-1 binary still running during a deploy may set it: it knows no
// root keys, so its mark must not hide a link from this sweep). For a final URL that ParseURL accepts, one
// transaction per link:
//   - its name key is queued unless a row holds it (github_repo_name; a new
//     placeholder row, 'pending', github_id NULL);
//   - the 'post' association of that row with each vulnerability id of the
//     post (its social_post events: CVE ids, and GHSA ids of advisories
//     without a CVE) is added;
//   - a link never swept before (by either marker) whose row is 'gone' and
//     was last asked before the link was stored makes it 'pending' again
//     with attempts 0 (a later post revives a repository made public since).
//
// Then the link's root key is written (RootKeyOf; NULL for deep links and
// other URLs) and repo_swept_url = final_url marks the row done, whatever
// the outcome. A root key that differs from the stored one clears the
// link's check and stamp (repo_checked_at, repo_github_id), and the
// repository that was stamped loses its rule trust if no other link is
// stamped with it (untrust); the same root key (another spelling of the
// URL) keeps them.
//
// The sweep never decides trust and never reads repository metadata: a
// root link is vouched for only by the fetch pass (FetchPending), from a
// fresh API answer for its key. Idempotent (also the backfill); cheap when
// nothing is new (one indexed query). Safe next to a running pass: a name
// created concurrently is used, not inserted twice.
func Enqueue(ctx context.Context, db DB, log *slog.Logger) (EnqueueResult, error) {
	var res EnqueueResult
	if log == nil {
		log = slog.Default()
	}
	type link struct {
		postID, url string
		pos         int
		fresh       bool // never swept before, by this code or by phase 1
		created     time.Time
	}
	for {
		rows, err := db.Query(ctx, `SELECT l.post_id, l.pos, l.final_url, l.repo_swept_url IS NULL AND l.repo_queued_url IS NULL, l.created_at
            FROM x_post_link l
            WHERE l.status = 'ok' AND l.host = 'github.com' AND l.kind = ANY($1)
              AND l.final_url IS NOT NULL AND l.final_url <> ''
              AND l.repo_swept_url IS DISTINCT FROM l.final_url
            ORDER BY l.created_at, char_length(l.post_id), l.post_id, l.pos
            LIMIT $2`, enqueueKinds, enqueueBatch)
		if err != nil {
			return res, err
		}
		links, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (link, error) {
			var l link
			return l, r.Scan(&l.postID, &l.pos, &l.url, &l.fresh, &l.created)
		})
		if err != nil {
			return res, err
		}
		for _, l := range links {
			if err := ctx.Err(); err != nil {
				return res, err
			}
			key, isRepo := KeyOf(l.url)
			var root any
			if k, ok := RootKeyOf(l.url); ok {
				root = k
			}
			var one EnqueueResult
			err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
				one = EnqueueResult{}
				if err := lockStore(ctx, tx); err != nil {
					return err
				}
				if isRepo {
					id, added, err := queue(ctx, tx, key, Source)
					if err != nil {
						return err
					}
					if added {
						one.Added++
					}
					if l.fresh && !added {
						tag, err := tx.Exec(ctx, `UPDATE github_repo SET state = 'pending', attempts = 0
                            WHERE id = $1 AND state = 'gone' AND (fetched_at IS NULL OR fetched_at < $2)`, id, l.created)
						if err != nil {
							return err
						}
						one.Revived += int(tag.RowsAffected())
					}
					tag, err := tx.Exec(ctx, `INSERT INTO github_repo_cve (repo_id, cve_id, basis)
                        SELECT DISTINCT $1::bigint, e.cve_id, 'post' FROM event e
                        WHERE e.source = 'xposts' AND e.type = 'social_post' AND e.dedupe_key = $2
                          AND (e.cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$' OR e.cve_id ~ '^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$')
                        ON CONFLICT DO NOTHING`, id, l.postID)
					if err != nil {
						return err
					}
					one.PostCVEs += int(tag.RowsAffected())
				} else {
					one.NotRepo++
				}
				// the sweep marker and the root key; the check and the stamp
				// survive only while the root key stays the same
				var cleared *int64
				err := tx.QueryRow(ctx, `SELECT repo_github_id FROM x_post_link WHERE post_id = $1 AND pos = $2 AND final_url = $3
                    AND repo_github_id IS NOT NULL AND repo_root_key IS DISTINCT FROM $4 FOR UPDATE`, l.postID, l.pos, l.url, root).Scan(&cleared)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				_, err = tx.Exec(ctx, `UPDATE x_post_link SET repo_swept_url = final_url,
                    repo_github_id = CASE WHEN repo_root_key IS NOT DISTINCT FROM $4 THEN repo_github_id END,
                    repo_checked_at = CASE WHEN repo_root_key IS NOT DISTINCT FROM $4 THEN repo_checked_at END,
                    repo_check_attempts = CASE WHEN repo_root_key IS NOT DISTINCT FROM $4 THEN repo_check_attempts ELSE 0 END,
                    repo_root_key = $4
                    WHERE post_id = $1 AND pos = $2 AND final_url = $3`, l.postID, l.pos, l.url, root)
				if err != nil || cleared == nil {
					return err
				}
				return untrust(ctx, tx, *cleared)
			})
			if err != nil {
				return res, err
			}
			res.Candidates++
			res.Added += one.Added
			res.NotRepo += one.NotRepo
			res.PostCVEs += one.PostCVEs
			res.Revived += one.Revived
			if !isRepo {
				log.Debug("github link is not a repository", "post_id", l.postID, "pos", l.pos)
			}
		}
		if len(links) < enqueueBatch {
			return res, nil
		}
	}
}

// queue returns the row that holds name key, creating a placeholder
// ('pending', github_id NULL) and its name when no row holds it. A key
// that another transaction creates at the same moment is not an error:
// the name is inserted with ON CONFLICT DO NOTHING (which waits for that
// transaction) and the row that won is returned.
func queue(ctx context.Context, db DB, key, source string) (id int64, added bool, err error) {
	err = pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		for try := 0; try < 5; try++ {
			added = false
			err := tx.QueryRow(ctx, `SELECT repo_id FROM github_repo_name WHERE name_key = $1`, key).Scan(&id)
			if err == nil {
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err := tx.QueryRow(ctx, `INSERT INTO github_repo (queued_name, first_source) VALUES ($1, $2) RETURNING id`,
				key, source).Scan(&id); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO github_repo_name (name_key, repo_id) VALUES ($1, $2)
                ON CONFLICT (name_key) DO NOTHING`, key, id)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				added = true
				return nil
			}
			// someone else holds the key now: drop our placeholder, use theirs
			if _, err := tx.Exec(ctx, `DELETE FROM github_repo WHERE id = $1 AND github_id IS NULL`, id); err != nil {
				return err
			}
		}
		return fmt.Errorf("ghrepo: name key %q kept changing hands", key)
	})
	return id, added, err
}

// Options configures FetchPending.
type Options struct {
	Limit        int // requests per pass; <= 0 means DefaultLimit
	RefreshLimit int // refreshes and 'gone' retries per pass; 0 means DefaultRefreshLimit, < 0 none
	// Client makes the requests; nil means NewClient with Token.
	Client *Client
	Token  string // used only when Client is nil; "" = unauthenticated
	Delay  time.Duration
	Now    func() time.Time
	Sleep  func(ctx context.Context, d time.Duration) error
	Logger *slog.Logger

	decode func([]byte) (*Repo, error) // tests only; nil = DecodeRepo
}

// Result counts one pass.
type Result struct {
	Candidates  int  `json:"candidates"`   // requests planned (rows, link checks, refreshes)
	OK          int  `json:"ok"`           // a public repository answered (200) and was stored
	NotModified int  `json:"not_modified"` // 304 on a refresh
	Gone        int  `json:"gone"`         // 404 / 410 / 451 / not public
	Merged      int  `json:"merged"`       // placeholders folded into the identity that answered for their name
	Retry       int  `json:"retry"`        // transient failure, attempts left
	Failed      int  `json:"failed"`       // transient failure, now 'failed'
	Panics      int  `json:"panics"`       // handling a row panicked (counted in Retry/Failed)
	LinkChecks  int  `json:"link_checks"`  // name keys asked only because root links to them were unchecked
	Stamped     int  `json:"stamped"`      // root links stamped with the identity that answered for their key
	RateLimited bool `json:"rate_limited"` // the pass stopped on the rate limit
	Requests    int  `json:"requests"`
	// OwnersPinned: trusted accounts whose id this pass looked up
	// (GET /users/{login}, counted in Requests)
	OwnersPinned int `json:"owners_pinned"`
	// Remaining is the last x-ratelimit-remaining seen (-1 = none).
	Remaining int `json:"remaining"`
	// Locked: another GitHub pass (FetchPending or Discover) held the
	// lock; nothing was done.
	Locked bool `json:"locked"`
}

// task is one request of a pass.
type task struct {
	id       int64  // the github_repo row the request is made for; 0 = none (a link check)
	githubID int64  // > 0: that row is an identity and is asked by id
	key      string // the name key asked by name; "" when asked by id
	etag     string
	state    string
	attempts int
	keyless  bool // an identity that holds no name key
}

// path is the request path: an identity is asked by id (a rename is then
// the same repository under a new full_name), a name by name.
func (t task) path() string {
	if t.githubID > 0 {
		return "/repositories/" + strconv.FormatInt(t.githubID, 10)
	}
	return "/repos/" + t.key
}

// FetchPending makes one pass of at most Limit requests, Delay apart:
//
//  1. rows to fetch, oldest first: 'pending' with attempts < MaxAttempts
//     and 'failed' with attempts < MaxTotalAttempts whose last attempt is
//     older than SlowRetryAfter;
//  2. link checks: the root keys of x_post_link rows not checked yet
//     (repo_checked_at NULL, fewer than MaxCheckAttempts failures), oldest
//     link first, one request per distinct key not already asked in 1;
//  3. at most RefreshLimit refreshes, oldest fetch first: 'ok' rows last
//     fetched more than RefreshAfter ago (except rows found by search that
//     nobody decided about: Discover's review refresh, refreshUnverified,
//     brings those up to date every run), 'ok' identities that
//     hold no name (another repository answered for theirs: they learn
//     their current name, or that they are gone; at most MaxTotalAttempts
//     failures in a row), and 'gone' rows queued less than GoneRetryWindow
//     ago whose last attempt is older than GoneRetryAfter.
//
// A placeholder (github_id NULL) and a link check ask GET /repos/{key}; an
// identity asks GET /repositories/{github_id}, with If-None-Match when it
// is 'ok' and has an ETag. Outcomes:
//
//   - 200 with a public repository: stored (observe). By id, a changed
//     full_name is a rename of the same identity. By name, the identity
//     that answered gets the key, and the unchecked root links to that key
//     are checked and, when the repository was created no later than the
//     link was stored, stamped with it (stampLinks: the only source of
//     rule trust);
//   - 304: unchanged, fetched_at updated (holdName: the row holds its
//     name unless another identity does). An identity that holds no name
//     key is asked without If-None-Match, so it gets a 200;
//   - 404, 410, 451 or a repository that is not public: by id the identity
//     is 'gone' (status untouched, its name released); by name the
//     placeholder is 'gone' and the root links to the key are checked
//     without a stamp;
//   - a rate-limit response (RateLimited): nothing is written and the pass
//     stops, without an error;
//   - 5xx, other 403, 408, malformed or oversized bodies, refused
//     redirects, transport errors, an answer by id with another id:
//     attempts+1 ('failed' at MaxAttempts; an 'ok' or 'gone' row keeps its
//     state); a request by name counts the failure on the unchecked
//     links to its key, which stay unchecked.
//
// The pass also stops after a response that reports MinRemaining or fewer
// requests left, and before a request by name when fewer than
// MinRemaining+2 are left (GitHub may redirect a renamed repository's name:
// two requests). Requests counts followed redirects too. A panic while handling one request is recovered and
// counted as a transient failure. Each request is written on its own, so
// a cancelled or expired context stops the pass between requests (the
// error is ctx.Err()).
func FetchPending(ctx context.Context, db DB, o Options) (Result, error) {
	res := Result{Remaining: -1}
	if o.Limit <= 0 {
		o.Limit = DefaultLimit
	}
	if o.RefreshLimit == 0 {
		o.RefreshLimit = DefaultRefreshLimit
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Delay == 0 {
		o.Delay = Delay
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.Client == nil {
		o.Client = NewClient(ClientOptions{Token: o.Token})
	}
	if o.decode == nil {
		o.decode = DecodeRepo
	}
	// one GitHub pass at a time (Discover takes the same lock)
	locked, err := tryLock(ctx, db)
	if err != nil {
		return res, err
	}
	if !locked {
		res.Locked = true
		o.Logger.Info("github fetch pass skipped: another github pass holds the lock")
		return res, nil
	}
	defer unlock(ctx, db)
	// trusted accounts whose id is still pending (owner.go)
	pinned, lookups, err := resolveOwners(ctx, db, o.Client, o.Logger)
	res.OwnersPinned, res.Requests = pinned, lookups
	if err != nil {
		return res, err
	}
	now := o.Now().UTC()
	asked := map[string]bool{} // name keys already in the plan
	scan := scanTask
	var todo []task
	add := func(ts []task) {
		for _, t := range ts {
			if t.key != "" {
				if asked[t.key] {
					continue
				}
				asked[t.key] = true
			}
			if len(todo) < o.Limit {
				todo = append(todo, t)
			}
		}
	}
	rows, err := db.Query(ctx, `SELECT g.id, g.github_id, g.queued_name, g.etag, g.state, g.attempts,
            g.github_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM github_repo_name n WHERE n.repo_id = g.id)
        FROM github_repo g
        WHERE (g.state = 'pending' AND g.attempts < $1)
           OR (g.state = 'failed' AND g.attempts < $2 AND g.fetched_at < $3)
        ORDER BY g.created_at, g.id LIMIT $4`, MaxAttempts, MaxTotalAttempts, now.Add(-SlowRetryAfter), o.Limit)
	if err != nil {
		return res, err
	}
	due, err := pgx.CollectRows(rows, scan)
	if err != nil {
		return res, err
	}
	add(due)
	if len(todo) < o.Limit {
		rows, err := db.Query(ctx, `SELECT repo_root_key FROM x_post_link
            WHERE repo_root_key IS NOT NULL AND repo_checked_at IS NULL AND repo_check_attempts < $1
            GROUP BY repo_root_key ORDER BY min(created_at), repo_root_key LIMIT $2`, MaxCheckAttempts, o.Limit)
		if err != nil {
			return res, err
		}
		keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return res, err
		}
		checks := make([]task, 0, len(keys))
		for _, k := range keys {
			checks = append(checks, task{key: k})
		}
		before := len(todo)
		add(checks)
		res.LinkChecks = len(todo) - before
	}
	if n := min(o.RefreshLimit, o.Limit-len(todo)); n > 0 {
		// search-found rows nobody decided about are left out here: they're
		// waiting for review, and every discovery run refreshes those
		// (refreshUnverified in refresh.go), so they'd only take slots here.
		// The last column asks unconditionally: a keyless identity, and a
		// row whose owner id is missing while its login names a trusted
		// account (ownerRefetchSQL: only a 200 carries owner.id)
		rows, err := db.Query(ctx, `SELECT g.id, g.github_id, g.queued_name, g.etag, g.state, g.attempts,
                g.github_id IS NOT NULL AND (NOT EXISTS (SELECT 1 FROM github_repo_name n WHERE n.repo_id = g.id) OR `+ownerRefetchSQL+`)
            FROM github_repo g
            WHERE (g.state = 'ok' AND g.fetched_at < $1 AND (g.first_source <> 'search' OR g.status_by IS NOT NULL))
               OR (g.state = 'ok' AND g.attempts < $5 AND NOT EXISTS (SELECT 1 FROM github_repo_name n WHERE n.repo_id = g.id))
               OR (g.state = 'gone' AND g.created_at > $3 AND g.fetched_at < $4)
               OR `+ownerRefetchSQL+`
            ORDER BY g.fetched_at, g.id LIMIT $2`, now.Add(-RefreshAfter), n, now.Add(-GoneRetryWindow), now.Add(-GoneRetryAfter),
			MaxTotalAttempts, now.Add(-24*time.Hour))
		if err != nil {
			return res, err
		}
		more, err := pgx.CollectRows(rows, scan)
		if err != nil {
			return res, err
		}
		add(more)
	}
	res.Candidates = len(todo)
	for _, t := range todo {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if t.id != 0 {
			// a placeholder folded into an identity earlier in this pass
			// is gone; one that became an identity is asked by id
			var gh *int64
			err := db.QueryRow(ctx, `SELECT github_id FROM github_repo WHERE id = $1`, t.id).Scan(&gh)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return res, err
			}
			if gh != nil && t.githubID == 0 {
				t.githubID, t.key = *gh, ""
			}
		}
		if t.githubID == 0 && !ValidFullName(t.key) {
			// not a name GitHub can have: no request
			oc := noAnswer(ctx, db, t, nil, o.Now().UTC())
			if oc.err != nil {
				return res, oc.err
			}
			res.Gone++
			continue
		}
		if t.githubID == 0 && res.Remaining >= 0 && res.Remaining < MinRemaining+2 {
			// a request by name may be redirected (a renamed repository): two
			// requests against the limit, which would go below MinRemaining
			res.RateLimited = true
			o.Logger.Info("github rate limit nearly used; pass stopped before a request by name", "remaining", res.Remaining,
				"authenticated", o.Client.Authenticated())
			return res, nil
		}
		if res.Requests > 0 {
			if err := o.Sleep(ctx, o.Delay); err != nil {
				return res, err
			}
		}
		res.Requests++
		resp, gerr := o.Client.Get(ctx, t.path(), t.etag)
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if resp != nil {
			res.Requests += resp.Redirects // each followed redirect is a request against the limit
		}
		if resp != nil && resp.Remaining >= 0 {
			res.Remaining = resp.Remaining
		}
		if resp != nil && resp.RateLimited() {
			res.RateLimited = true
			o.Logger.Warn("github rate limit reached; pass stopped", "status", resp.Status, "reset", resp.Reset, "retry_after", resp.RetryAfter,
				"authenticated", o.Client.Authenticated())
			return res, nil
		}
		oc := handle(ctx, db, t, resp, gerr, o.decode, o.Logger, o.Now().UTC())
		if oc.err != nil {
			return res, oc.err
		}
		switch oc.kind {
		case outOK:
			res.OK++
			res.Merged += oc.merged
			res.Stamped += oc.stamped
		case outNotModified:
			res.NotModified++
		case outGone:
			res.Gone++
		case outRetry:
			res.Retry++
		case outFailed:
			res.Failed++
		}
		if oc.panicked {
			res.Panics++
		}
		if resp != nil && resp.Remaining >= 0 && resp.Remaining <= MinRemaining {
			res.RateLimited = true
			o.Logger.Info("github rate limit nearly used; pass stopped", "remaining", resp.Remaining, "reset", resp.Reset,
				"authenticated", o.Client.Authenticated())
			return res, nil
		}
	}
	return res, nil
}

// scanTask reads one task from a row of (id, github_id, queued_name, etag,
// state, attempts, unconditional).
func scanTask(r pgx.CollectableRow) (task, error) {
	var t task
	var gh *int64
	var etag *string
	var queued string
	if err := r.Scan(&t.id, &gh, &queued, &etag, &t.state, &t.attempts, &t.keyless); err != nil {
		return t, err
	}
	if gh != nil {
		t.githubID = *gh
		// a keyless identity is asked unconditionally: only a 200
		// tells its current name and gives it the key back (and the
		// owner id of a trusted account's candidate row)
		if etag != nil && t.state == StateOK && !t.keyless {
			t.etag = *etag
		}
	} else {
		t.key = queued
	}
	return t, nil
}

type outKind int

const (
	outOK outKind = iota
	outNotModified
	outGone
	outRetry
	outFailed
)

type outcome struct {
	kind     outKind
	merged   int
	stamped  int
	panicked bool
	err      error // a database error: the pass stops
}

// handle decides and writes the outcome of task t. A panic anywhere in it
// is recovered: the task gets a transient failure (written outside the
// panicking code).
func handle(ctx context.Context, db DB, t task, resp *Response, gerr error, decode func([]byte) (*Repo, error),
	log *slog.Logger, now time.Time) (out outcome) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("github repository handling panicked", "repo_id", t.id, "panic", fmt.Sprint(r))
			out = transient(ctx, db, t, now)
			out.panicked = true
		}
	}()
	switch {
	case gerr != nil:
		log.Info("github request failed", "repo_id", t.id, "refused", errors.Is(gerr, ErrRefused), "attempt", t.attempts+1)
		return transient(ctx, db, t, now)
	case resp.Status == http.StatusNotModified && t.githubID > 0 && t.state == StateOK:
		err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			if err := lockStore(ctx, tx); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE github_repo SET fetched_at = $2, seen_at = $2, attempts = 0 WHERE id = $1`, t.id, now); err != nil {
				return err
			}
			return holdName(ctx, tx, t.id)
		})
		return outcome{kind: outNotModified, err: err}
	case resp.Status == http.StatusNotFound || resp.Status == http.StatusGone || resp.Status == http.StatusUnavailableForLegalReasons:
		return noAnswer(ctx, db, t, nil, now)
	case resp.Status == http.StatusOK:
		if resp.TooBig {
			log.Info("github response too large", "repo_id", t.id, "attempt", t.attempts+1)
			return transient(ctx, db, t, now)
		}
		r, err := decode(resp.Body)
		if err != nil {
			log.Info("github response unusable", "repo_id", t.id, "attempt", t.attempts+1)
			return transient(ctx, db, t, now)
		}
		if t.githubID > 0 && r.ID != t.githubID {
			// asked by id, answered with another id: never an identity change
			log.Warn("github answered a request by id with another id", "repo_id", t.id)
			return transient(ctx, db, t, now)
		}
		if !r.Public {
			return noAnswer(ctx, db, t, r, now)
		}
		return store(ctx, db, t, r, cleanETag(resp.ETag), now)
	default:
		log.Info("github request not successful", "repo_id", t.id, "status", resp.Status, "attempt", t.attempts+1)
		return transient(ctx, db, t, now)
	}
}

// store writes a public repository's answer to task t in one transaction:
// observe, and for a request by name the check of the root links to that
// key (stampLinks). Links already checked without a stamp are looked at
// again only when the key's placeholder was 'gone' until this answer AND
// is still inside GoneRetryWindow (whatever made the pass ask the key),
// under the same creation-time condition. After the window a link checked
// with a 404 is never stamped.
func store(ctx context.Context, db DB, t task, r *Repo, etag string, now time.Time) outcome {
	out := outcome{kind: outOK}
	out.err = pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		out.merged, out.stamped = 0, 0
		if err := lockStore(ctx, tx); err != nil {
			return err
		}
		late := false
		if t.key != "" {
			err := tx.QueryRow(ctx, `SELECT p.github_id IS NULL AND p.state = 'gone' AND p.created_at > $2 FROM github_repo_name n
                JOIN github_repo p ON p.id = n.repo_id WHERE n.name_key = $1`, t.key, now.Add(-GoneRetryWindow)).Scan(&late)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		ob, err := observe(ctx, tx, r, answer{key: t.key, row: t.id, etag: etag, source: Source}, now)
		if err != nil {
			return err
		}
		out.merged = ob.absorbed
		if t.key != "" {
			out.stamped, err = stampLinks(ctx, tx, t.key, r, late, now)
		}
		return err
	})
	return out
}

// noAnswer writes a definite "no public repository" for task t (404, 410,
// 451, or the non-public repository r): by name, the key's placeholder is
// 'gone', the unchecked root links to the key are checked without a stamp,
// and an identity that held the key loses it — nothing else of it changes;
// its own refresh by id decides whether it is renamed or gone. The
// identity asked by id, or named by r, is 'gone' (markGone).
func noAnswer(ctx context.Context, db DB, t task, r *Repo, now time.Time) outcome {
	out := outcome{kind: outGone}
	out.err = pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if err := lockStore(ctx, tx); err != nil {
			return err
		}
		if t.githubID == 0 {
			if _, err := tx.Exec(ctx, `UPDATE github_repo p SET state = 'gone', attempts = attempts + 1, fetched_at = $3
                WHERE p.github_id IS NULL AND (p.id = $1 OR p.id = (SELECT repo_id FROM github_repo_name WHERE name_key = $2))`,
				t.id, t.key, now); err != nil {
				return err
			}
			// nobody answers for the key: an identity that still held it
			// loses it (the next pass asks it by id for its current name)
			if _, err := tx.Exec(ctx, `DELETE FROM github_repo_name n USING github_repo p
                WHERE n.name_key = $1 AND p.id = n.repo_id AND p.github_id IS NOT NULL`, t.key); err != nil {
				return err
			}
			if _, err := stampLinks(ctx, tx, t.key, nil, false, now); err != nil {
				return err
			}
		}
		gid := t.githubID
		if r != nil {
			gid = r.ID
		}
		if gid > 0 {
			if _, err := markGone(ctx, tx, gid, false, now); err != nil {
				return err
			}
		}
		return nil
	})
	return out
}

// transient records a transient failure of task t: its row gets attempts+1
// (a row that is 'pending' or 'failed' becomes 'failed' at MaxAttempts; an
// 'ok' row stays 'ok', its next refresh RefreshAfter later; a 'gone' row
// stays 'gone', next retry GoneRetryAfter later within GoneRetryWindow); a
// request by name counts the failure on the unchecked links to its key.
func transient(ctx context.Context, db DB, t task, now time.Time) outcome {
	out := outcome{kind: outRetry}
	if t.id != 0 {
		state := StatePending
		switch {
		case t.state == StateOK, t.state == StateGone: // a refresh or a 'gone' retry keeps its state
			state = t.state
		case t.state == StateFailed || t.attempts+1 >= MaxAttempts:
			state, out.kind = StateFailed, outFailed
		}
		if _, out.err = db.Exec(ctx, `UPDATE github_repo SET state = $2, attempts = attempts + 1, fetched_at = $3 WHERE id = $1`,
			t.id, state, now); out.err != nil {
			return out
		}
	}
	if t.key != "" {
		_, out.err = db.Exec(ctx, `UPDATE x_post_link SET repo_check_attempts = repo_check_attempts + 1
            WHERE repo_root_key = $1 AND repo_checked_at IS NULL`, t.key)
	}
	return out
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
