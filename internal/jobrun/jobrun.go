// Package jobrun keeps the last run of the background jobs that are not
// collectors (table job_run, migrations/0035_job_run.sql) so /admin/system
// can show them next to the collectors. Writing the record never fails a
// job: a write error (an old database without the table, a busy row) is
// logged and the job goes on.
package jobrun

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgconn"
)

// Job names (job_run.name). The admin page lists them in this order.
const (
	GitHubDiscover = "github-discover"
	GitHubPoC      = "github-poc"
	GitHubFetch    = "github-fetch"
	PagesFetch     = "pages-fetch"
	SiteIcons      = "site-icons"
)

// Names is every job, in page order.
var Names = []string{GitHubDiscover, GitHubPoC, GitHubFetch, PagesFetch, SiteIcons}

// MaxError caps job_run.error (runes; the column's CHECK).
const MaxError = 500

// writeTimeout bounds each write, so a stuck row never holds a job up.
const writeTimeout = 5 * time.Second

// DB is what the helper needs (*pgx.Conn, a pool, a tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Run is one started run. A nil *Run is fine to Finish (does nothing).
type Run struct {
	db   DB
	name string
	now  func() time.Time
}

// Start records that the job started (finished_at, ok and error cleared;
// last_success_at kept). now may be nil (time.Now).
func Start(ctx context.Context, db DB, name string, now func() time.Time) *Run {
	if now == nil {
		now = time.Now
	}
	r := &Run{db: db, name: name, now: now}
	r.exec(ctx, "start", `INSERT INTO job_run (name, started_at) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET started_at = EXCLUDED.started_at,
			finished_at = NULL, ok = NULL, error = NULL, detail = NULL`, name, now().UTC())
	return r
}

// Finish records the outcome: ok when err is nil. detail is the run's
// counters (a result struct of numbers and booleans), nil for none.
func (r *Run) Finish(ctx context.Context, err error, detail any) {
	if r == nil || r.db == nil {
		return
	}
	var msg *string
	if err != nil {
		s := CleanError(err.Error())
		if s == "" {
			s = "error"
		}
		msg = &s
	}
	var det *string
	if detail != nil {
		if b, jerr := json.Marshal(detail); jerr == nil && len(b) <= 4096 {
			s := string(b)
			det = &s
		}
	}
	at := r.now().UTC()
	r.exec(ctx, "finish", `INSERT INTO job_run (name, started_at, finished_at, ok, error, last_success_at, detail)
		VALUES ($1, $2, $2, $3, $4, CASE WHEN $3 THEN $2::timestamptz END, $5::jsonb)
		ON CONFLICT (name) DO UPDATE SET finished_at = EXCLUDED.finished_at, ok = EXCLUDED.ok,
			error = EXCLUDED.error, detail = EXCLUDED.detail,
			last_success_at = CASE WHEN EXCLUDED.ok THEN EXCLUDED.finished_at ELSE job_run.last_success_at END`,
		r.name, at, err == nil, msg, det)
}

func (r *Run) exec(ctx context.Context, step, sql string, args ...any) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if _, err := r.db.Exec(wctx, sql, args...); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "42P01" {
			slog.Warn("job run not recorded: migration 0035 not applied (run `nday migrate`)", "job", r.name)
			return
		}
		slog.Warn("job run not recorded (job unaffected)", "job", r.name, "step", step, "err", err)
	}
}

// urlRe matches URLs in an error text; CleanError keeps scheme, host and
// path only.
var urlRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)

// CleanError is an error text fit for job_run.error: URLs cut to scheme,
// host and path (no user info, query or fragment), control characters
// turned into spaces, at most MaxError runes.
func CleanError(s string) string {
	s = urlRe.ReplaceAllStringFunc(s, func(u string) string {
		scheme, rest, _ := strings.Cut(u, "://")
		if i := strings.IndexAny(rest, "?#"); i >= 0 {
			rest = rest[:i]
		}
		host, path, _ := strings.Cut(rest, "/")
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
		if path != "" {
			return scheme + "://" + host + "/" + path
		}
		if strings.Contains(rest, "/") {
			return scheme + "://" + host + "/"
		}
		return scheme + "://" + host
	})
	s = strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return ' '
		}
		return c
	}, s)
	s = strings.TrimSpace(s)
	if rs := []rune(s); len(rs) > MaxError {
		s = string(rs[:MaxError-1]) + "…"
	}
	return s
}
