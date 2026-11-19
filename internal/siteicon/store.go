package siteicon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/pagefetch"
)

// Job constants.
const (
	// DefaultLimit is the number of hosts a run handles at most.
	DefaultLimit = 200
	// MaxLimit caps --limit.
	MaxLimit = 2000
	// RunBudget bounds a whole run; hosts not reached stay due.
	RunBudget = 15 * time.Minute
	// Delay between two hosts.
	Delay = time.Second
	// RefreshOK is when a stored icon is fetched again.
	RefreshOK = 30 * 24 * time.Hour
	// RetryNone is when a host without a usable icon is tried again.
	RetryNone = 30 * 24 * time.Hour
	// firstErrorDelay is the wait after a first transient failure; it is
	// multiplied by 4 for each further one, up to maxErrorDelay.
	firstErrorDelay = time.Hour
	maxErrorDelay   = 30 * 24 * time.Hour
	// lastErrorMax is the stored length of last_error.
	lastErrorMax = 200
	// PerBucket is the number of hosts a run takes at most from one bucket
	// (the last two labels of the name, a rough registrable domain), so
	// many subdomains of one site cannot fill a run.
	PerBucket = 5
	// StaleAfter: a row whose host no page links any more is deleted once
	// its last attempt is this old.
	StaleAfter = 90 * 24 * time.Hour
	// deleteBatch bounds the rows deleted at the end of one run.
	deleteBatch = 1000
)

// LinkedHosts are the hosts the vulnerability page links to from Go code
// rather than from stored URLs: GitHub advisories and repositories
// (webui.AliasLink, resources), MITRE CWE definitions (webui.CWELink) and
// researchers' X profiles (site.ResearcherEntry.AuthorURL). Run always
// considers them, first. A test in internal/webui renders the seeded
// pages and checks that every outbound host is one Run would choose.
var LinkedHosts = []string{"github.com", "cwe.mitre.org", "x.com"}

// DB is the database handle (*pgx.Conn, pgx.Tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Hash is the cache-busting key of icon bytes: the first 16 hex digits of
// their SHA-256 (site_icon.hash, the ?v= of the icon URL).
func Hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

// ErrorDelay is the wait before host is tried again after its n-th
// consecutive transient failure (n >= 1): 1 h, 4 h, 16 h, 64 h, ...,
// at most 30 days.
func ErrorDelay(n int) time.Duration {
	d := firstErrorDelay
	for i := 1; i < n && d < maxErrorDelay; i++ {
		d *= 4
	}
	return min(d, maxErrorDelay)
}

// linkedHostsSQL is the CTE of the hosts the vulnerability page can link
// to from stored data: event source URLs (also the advisory, CVSS and
// summary-source links), PoC item URLs in event.detail, fix-commit URLs of
// patch events and the resolved targets of researcher post links (the
// resources panel), plus LinkedHosts ($1). n is the number of DISTINCT
// vulnerabilities linking the host (a post without a CVE counts as its
// own), so repeating one link many times does not raise a host;
// LinkedHosts rank first. Only names of the site_icon.host form ($2,
// hostRe) are kept; the few of them ValidHost still refuses (IP
// addresses) are stored as 'none' by Run without a request.
const linkedHostsSQL = `
WITH urls(u, v) AS (
    SELECT url, cve_id FROM event WHERE url IS NOT NULL
    UNION ALL SELECT detail->>'url', cve_id FROM event WHERE type = 'poc_published' AND detail ? 'url'
    UNION ALL SELECT jsonb_array_elements_text(detail->'fix_commit_urls'), cve_id FROM event
        WHERE type = 'patch_released' AND jsonb_typeof(detail->'fix_commit_urls') = 'array'
    UNION ALL SELECT l.final_url, COALESCE(p.cve_id, 'post:' || l.post_id)
        FROM x_post_link l LEFT JOIN event p ON p.dedupe_key = l.post_id AND p.type = 'social_post'
        WHERE l.status = 'ok' AND l.final_url IS NOT NULL
), linked(host, n) AS (
    SELECT rtrim(lower(substring(u FROM '^[Hh][Tt][Tt][Pp][Ss]?://(?:[^/?#@]*@)?([^/?#:]+)')), '.'), count(DISTINCT v)
    FROM urls GROUP BY 1
    UNION ALL SELECT unnest($1::text[]), 9223372036854775807
), hosts AS (
    SELECT host, max(n) AS n FROM linked
    WHERE host IS NOT NULL AND char_length(host) <= 253 AND host ~ $2 GROUP BY host
)`

// candidatesSQL picks due hosts of linkedHostsSQL: no site_icon row yet,
// or next_try_at ($3) passed; new hosts first, then the most linked; at
// most $5 (PerBucket) a bucket (the last two labels), at most $4 in all.
const candidatesSQL = linkedHostsSQL + `, due AS (
    SELECT h.host, h.n, i.host IS NULL AS fresh, COALESCE(i.status, '') AS status, COALESCE(i.failures, 0) AS failures,
           row_number() OVER (PARTITION BY substring(h.host FROM '[^.]+[.][^.]+$')
                              ORDER BY (i.host IS NULL) DESC, h.n DESC, h.host) AS k
    FROM hosts h LEFT JOIN site_icon i ON i.host = h.host
    WHERE i.host IS NULL OR i.next_try_at <= $3
)
SELECT host, status, failures FROM due WHERE k <= $5
ORDER BY fresh DESC, n DESC, host
LIMIT $4`

// staleSQL deletes at most $4 rows whose host linkedHostsSQL no longer
// yields and whose last attempt is older than $3.
const staleSQL = linkedHostsSQL + `
DELETE FROM site_icon WHERE host IN (
    SELECT s.host FROM site_icon s
    WHERE s.fetched_at < $3 AND NOT EXISTS (SELECT 1 FROM hosts h WHERE h.host = s.host)
    LIMIT $4)`

// Candidate is a due host.
type Candidate struct {
	Host     string
	Status   string // current site_icon.status, "" = no row yet
	Failures int
}

// Due returns at most limit due hosts at now (candidatesSQL).
func Due(ctx context.Context, db DB, now time.Time, limit int) ([]Candidate, error) {
	rows, err := db.Query(ctx, candidatesSQL, LinkedHosts, hostRe.String(), now, limit, PerBucket)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Candidate, error) {
		var c Candidate
		return c, r.Scan(&c.Host, &c.Status, &c.Failures)
	})
}

// Prune deletes at most deleteBatch rows whose host no vulnerability page
// links any more (staleSQL) and whose last attempt is older than
// StaleAfter at now; it returns how many.
func Prune(ctx context.Context, db DB, now time.Time) (int, error) {
	tag, err := db.Exec(ctx, staleSQL, LinkedHosts, hostRe.String(), now.Add(-StaleAfter), deleteBatch)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// Options configures Run.
type Options struct {
	Limit int // hosts per run; <= 0 means DefaultLimit
	// Budget bounds the run; <= 0 means RunBudget.
	Budget time.Duration
	// Fetcher fetches the icons; nil means NewFetcher with the production
	// (guarded) settings. Tests inject one from code.
	Fetcher *Fetcher
	Now     func() time.Time
	Sleep   func(ctx context.Context, d time.Duration) error
	Logger  *slog.Logger
}

// Result counts one run.
type Result struct {
	Candidates int  `json:"candidates"` // due hosts picked
	OK         int  `json:"ok"`         // icon stored (new or refreshed)
	None       int  `json:"none"`       // no usable icon: tried again in 30 days
	Error      int  `json:"error"`      // transient failure: tried again with back-off
	Kept       int  `json:"kept"`       // transient failure of a host with an icon: the icon is kept (counted in Error too)
	Requests   int  `json:"requests"`
	Refused    int  `json:"refused"`   // requests refused by the URL rules or the address guard
	TimedOut   bool `json:"timed_out"` // the run budget ended the run; the remaining hosts stay due
	Deleted    int  `json:"deleted"`   // stale rows deleted at the end (Prune)
}

// Run is one pass of the job: Due hosts, one at a time, Delay apart, each
// fetched (Fetcher.Fetch, at most HostTimeout) and its row written on its
// own. ok: the icon replaces the stored one, refreshed after RefreshOK;
// none: any stored icon is dropped, tried again after RetryNone; error:
// failures + 1, tried again after ErrorDelay(failures), and a stored icon
// is kept (status stays 'ok'). When the budget ends during a fetch, that
// host is not written. At the end (also after the budget) stale rows are
// deleted (Prune). A cancelled ctx stops the run with ctx.Err().
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
	if err := fetchAll(ctx, bctx, db, todo, o, &res); err != nil {
		return res, err
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	n, err := Prune(ctx, db, o.Now().UTC())
	res.Deleted = n
	return res, err
}

// fetchAll fetches and stores the candidates until done or the budget
// (bctx) ends (res.TimedOut); a cancelled ctx is returned as its error.
func fetchAll(ctx, bctx context.Context, db DB, todo []Candidate, o Options, res *Result) error {
	for _, c := range todo {
		if res.Requests > 0 {
			if err := o.Sleep(bctx, Delay); err != nil {
				return stopped(ctx, res)
			}
		}
		if bctx.Err() != nil {
			return stopped(ctx, res)
		}
		hctx, hcancel := context.WithTimeout(bctx, HostTimeout)
		f := o.Fetcher.Fetch(hctx, c.Host)
		hcancel()
		res.Requests += f.Requests
		res.Refused += f.Refused
		if bctx.Err() != nil { // the run ended during this host: not its fault
			return stopped(ctx, res)
		}
		if err := store(ctx, db, c, f, o.Now().UTC()); err != nil {
			return err
		}
		switch f.Status {
		case StatusOK:
			res.OK++
		case StatusNone:
			res.None++
		default:
			res.Error++
			if c.Status == StatusOK {
				res.Kept++
			}
		}
		if f.Status != StatusOK {
			o.Logger.Info("site icon not found", "host", c.Host, "status", f.Status, "why", f.Why)
		}
	}
	return nil
}

// stopped ends the fetching whose budget or context is done: ctx.Err()
// when the caller cancelled, else a clean stop with TimedOut.
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

// store writes the outcome f for candidate c at now.
func store(ctx context.Context, db DB, c Candidate, f Fetched, now time.Time) error {
	why := f.Why
	if len(why) > lastErrorMax {
		why = why[:lastErrorMax]
	}
	switch f.Status {
	case StatusOK, StatusNone:
		var ct, hash, src *string
		var img []byte
		next := now.Add(RetryNone)
		var lastErr *string
		if f.Status == StatusOK {
			h := Hash(f.Image)
			ct, hash, img, next = &f.ContentType, &h, f.Image, now.Add(RefreshOK)
			if len(f.SourceURL) <= pagefetch.MaxURL {
				src = &f.SourceURL
			}
		} else {
			lastErr = &why
		}
		_, err := db.Exec(ctx, `INSERT INTO site_icon (host, status, content_type, image, hash, source_url, fetched_at, next_try_at, failures, last_error)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9)
ON CONFLICT (host) DO UPDATE SET status = EXCLUDED.status, content_type = EXCLUDED.content_type, image = EXCLUDED.image,
    hash = EXCLUDED.hash, source_url = EXCLUDED.source_url, fetched_at = EXCLUDED.fetched_at,
    next_try_at = EXCLUDED.next_try_at, failures = 0, last_error = EXCLUDED.last_error`,
			c.Host, f.Status, ct, img, hash, src, now, next, lastErr)
		return err
	default:
		n := c.Failures + 1
		_, err := db.Exec(ctx, `INSERT INTO site_icon (host, status, fetched_at, next_try_at, failures, last_error)
VALUES ($1, 'error', $2, $3, $4, $5)
ON CONFLICT (host) DO UPDATE SET fetched_at = EXCLUDED.fetched_at, next_try_at = EXCLUDED.next_try_at,
    failures = EXCLUDED.failures, last_error = EXCLUDED.last_error,
    status = CASE WHEN site_icon.status = 'ok' THEN 'ok' ELSE 'error' END`,
			c.Host, now, now.Add(ErrorDelay(n)), n, why)
		return err
	}
}

// Icon is a stored icon.
type Icon struct {
	ContentType string
	Image       []byte
	Hash        string
}

// missingTable reports an undefined_table error: the migration is not
// applied yet, so there are no icons.
func missingTable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42P01"
}

// Lookup returns host -> hash for the hosts that have a stored icon, in
// one query. Hosts ValidHost refuses are not looked up. Without the
// site_icon table (migration not applied) the map is empty.
func Lookup(ctx context.Context, db DB, hosts []string) (map[string]string, error) {
	out := map[string]string{}
	var q []string
	for _, h := range hosts {
		if ValidHost(h) {
			q = append(q, h)
		}
	}
	if len(q) == 0 {
		return out, nil
	}
	rows, err := db.Query(ctx, `SELECT host, hash FROM site_icon WHERE host = ANY($1) AND status = 'ok' AND image IS NOT NULL`, q)
	if err != nil {
		if missingTable(err) {
			return out, nil
		}
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h, v string
		if err := rows.Scan(&h, &v); err != nil {
			return nil, err
		}
		out[h] = v
	}
	if err := rows.Err(); err != nil {
		if missingTable(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	return out, nil
}

// Load returns the stored icon of host, nil when there is none (or no
// site_icon table). host must pass ValidHost (else nil).
func Load(ctx context.Context, db DB, host string) (*Icon, error) {
	if !ValidHost(host) {
		return nil, nil
	}
	rows, err := db.Query(ctx, `SELECT content_type, image, hash FROM site_icon WHERE host = $1 AND status = 'ok' AND image IS NOT NULL`, host)
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
	var ic Icon
	if err := rows.Scan(&ic.ContentType, &ic.Image, &ic.Hash); err != nil {
		return nil, err
	}
	return &ic, rows.Err()
}
