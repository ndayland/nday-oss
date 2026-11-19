// Package webpages is the queue of third-party web pages whose metadata the
// site shows (table web_page, migrations/0020_web_page.sql; see
// docs/webpages.md) and the pass that fetches them. Producers call Enqueue
// (today internal/xlinks for the links of X posts); FetchPending fetches
// pending pages through internal/pagefetch (SSRF-guarded) and stores the
// title, the site name and the publication time the page states
// (pagefetch.ExtractPublished; with Options.Backfill it also re-fetches,
// once each, 'ok' pages fetched before that time was read). This package
// knows nothing about where URLs come from.
package webpages

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/pagefetch"
)

// Pass constants.
const (
	// MaxAttempts per page; a page is 'failed' after that many transient
	// failures.
	MaxAttempts = 3
	// MaxTotalAttempts caps the slow retries: a 'failed' page is tried
	// again once per SlowRetryAfter until it has this many attempts.
	MaxTotalAttempts = 6
	// SlowRetryAfter is the wait after the last attempt of a 'failed' page.
	SlowRetryAfter = 24 * time.Hour
	// DefaultLimit is the number of pages per pass.
	DefaultLimit = 100
	// Delay between two requests.
	Delay = time.Second
	// DefaultBackfill is the number of 'ok' pages a pass re-fetches for
	// their publication time when the caller asks for the backfill
	// (Options.Backfill; `nday pages-fetch` and the pass after
	// `nday collect xposts` do).
	DefaultBackfill = 20
	// backfillReserve: the backfill stops when the context's deadline is
	// nearer than this (one request may take pagefetch's 25 s), so a pass
	// with a deadline ends on its own instead of with an error.
	backfillReserve = 30 * time.Second
	// UserAgent of every request (also the t.co resolver's, internal/xlinks).
	UserAgent = "nday-linkresolver/1"
)

// Page statuses (web_page.status).
const (
	StatusPending = "pending"
	StatusOK      = "ok"
	StatusNone    = "none"
	StatusFailed  = "failed"
)

// DB is the database handle (*pgx.Conn, pgx.Tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

var sourceRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// ErrSource is returned by Enqueue for a source name that is not
// [a-z][a-z0-9_]{0,31}.
var ErrSource = errors.New("webpages: invalid source name")

// Enqueue adds u to the queue as 'pending' unless a page with the same key
// (pagefetch.URLKey) is already there; added is true when a row was
// inserted. u must pass pagefetch.CheckURL (else an error wrapping
// pagefetch.ErrRefused, nothing stored). source names the producer (stored
// as first_source on insert).
func Enqueue(ctx context.Context, db DB, u, source string) (added bool, err error) {
	if !sourceRe.MatchString(source) {
		return false, ErrSource
	}
	if _, err := pagefetch.CheckURL(u); err != nil {
		return false, err
	}
	key, ok := pagefetch.URLKey(u)
	if !ok {
		return false, errors.Join(pagefetch.ErrRefused, errors.New("no URL key"))
	}
	tag, err := db.Exec(ctx, `INSERT INTO web_page (url_key, url, first_source) VALUES ($1, $2, $3)
        ON CONFLICT (url_key) DO NOTHING`, key, u, source)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Options configures FetchPending.
type Options struct {
	Limit int // pages per pass; <= 0 means DefaultLimit
	// Client fetches the pages; nil means pagefetch.New with UserAgent (the
	// production, guarded client). Tests inject one from code.
	Client *pagefetch.Client
	Now    func() time.Time
	Sleep  func(ctx context.Context, d time.Duration) error
	Logger *slog.Logger
	// Backfill is the number of 'ok' pages not yet looked at for their
	// publication time (web_page.published_checked_at NULL) to re-fetch
	// after the pending ones, oldest first; 0 = none. Each such page is
	// requested once: whatever the outcome, it is marked looked at, and only
	// its publication time is written (its status, attempts and title stay).
	Backfill int

	extract func(*pagefetch.Page) pagefetch.Meta // tests only; nil = pagefetch.ExtractMeta
}

// Result counts one pass.
type Result struct {
	Candidates int `json:"candidates"` // pages picked
	OK         int `json:"ok"`         // title stored
	None       int `json:"none"`       // final: no usable title / not HTML / not 200 / refused
	Retry      int `json:"retry"`      // transient failure, attempts left
	Failed     int `json:"failed"`     // transient failure, now 'failed'
	Refused    int `json:"refused"`    // refused by the URL rules or the address guard (counted in None too)
	OtherHost  int `json:"other_host"` // redirected to another host: no title (counted in None too)
	Panics     int `json:"panics"`     // handling the page panicked: 'none' (counted in None too)
	Requests   int `json:"requests"`
	Published  int `json:"published"` // pages stored with a publication time (fetched or re-fetched)
	// Backfilled: 'ok' pages re-fetched for their publication time.
	Backfilled int `json:"backfilled"`
}

type pending struct {
	key, url string
	attempts int
}

// FetchPending fetches queued pages: rows with status 'pending' and
// attempts < MaxAttempts, or 'failed' with attempts < MaxTotalAttempts whose
// last attempt (fetched_at) is older than SlowRetryAfter by o.Now; oldest
// first, at most Limit, ONE Get each (pagefetch: URL rules, connect-time
// address guard, at most 3 redirects, 25 s, 512 KiB), Delay between
// requests. A 200 HTML page with a
// title (pagefetch.ExtractMeta) becomes 'ok' with title and site_name
// and the publication time it states (pagefetch.ExtractPublished, judged
// against o.Now; every written row is marked looked at); a
// transport error, 5xx, 408 or 429 adds one attempt ('failed' at
// MaxAttempts); anything else — another status, not HTML, no usable title,
// a refused URL, redirect or address — is 'none' (final). A URL that fails
// pagefetch.CheckURL is 'none' without a request. A title is accepted only
// when the final URL (after redirects) is on the same host as the queued
// URL (sameHost); otherwise the page is 'none', so a redirector never puts
// another site's title next to its own host. A panic while handling one
// page is recovered, logged (url_key and panic value) and the page made
// 'none'; the pass goes on. Each page is written on its own, so a
// cancelled or expired context stops the pass between pages or during a
// request (the error is ctx.Err()); rows not yet written keep their status
// and attempts.
// Then, with o.Backfill > 0, the backfill (backfill).
func FetchPending(ctx context.Context, db DB, o Options) (Result, error) {
	var res Result
	if o.Limit <= 0 {
		o.Limit = DefaultLimit
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if o.Client == nil {
		o.Client = pagefetch.New(pagefetch.Options{UserAgent: UserAgent})
	}
	rows, err := db.Query(ctx, `SELECT url_key, url, attempts FROM web_page
        WHERE (status = 'pending' AND attempts < $1)
           OR (status = 'failed' AND attempts < $3 AND fetched_at < $4)
        ORDER BY created_at, url_key LIMIT $2`, MaxAttempts, o.Limit, MaxTotalAttempts, o.Now().Add(-SlowRetryAfter))
	if err != nil {
		return res, err
	}
	todo, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pending, error) {
		var p pending
		return p, r.Scan(&p.key, &p.url, &p.attempts)
	})
	if err != nil {
		return res, err
	}
	res.Candidates = len(todo)
	for _, p := range todo {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if _, err := pagefetch.CheckURL(p.url); err != nil {
			if _, err := db.Exec(ctx, `UPDATE web_page SET status = 'none'
                WHERE url_key = $1 AND status IN ('pending', 'failed')`, p.key); err != nil {
				return res, err
			}
			o.Logger.Warn("web page refused, not requested", "url_key", p.key, "why", err.Error())
			res.Refused++
			res.None++
			continue
		}
		if res.Requests > 0 {
			if err := o.Sleep(ctx, Delay); err != nil {
				return res, err
			}
		}
		res.Requests++
		page, gerr := o.Client.Get(ctx, p.url)
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		oc := outcomeOf(p, page, gerr, o.extract, o.Logger)
		if oc.status == StatusOK {
			oc.pub = publishedOf(p, page, gerr, o.Now().UTC(), o.Logger)
		}
		status, why, title, site := oc.status, oc.why, oc.title, oc.site
		switch oc.flag {
		case flagRefused:
			res.Refused++
		case flagOtherHost:
			res.OtherHost++
		case flagPanic:
			res.Panics++
		}
		switch status {
		case StatusOK:
			res.OK++
		case StatusNone:
			res.None++
		case StatusFailed:
			res.Failed++
		default:
			res.Retry++
		}
		if why != "" {
			o.Logger.Info("web page without title", "url_key", p.key, "status", status, "why", why, "attempt", p.attempts+1)
		}
		var pubAt *time.Time
		var pubPrec, pubSrc *string
		if oc.pub != nil && status == StatusOK {
			pubAt, pubPrec, pubSrc = &oc.pub.At, &oc.pub.Precision, &oc.pub.Source
			res.Published++
		}
		now := o.Now().UTC()
		if _, err := db.Exec(ctx, `UPDATE web_page SET status = $2, attempts = attempts + 1, title = $3, site_name = $4, fetched_at = $5,
                published_at = $6, published_precision = $7, published_source = $8, published_checked_at = $5
            WHERE url_key = $1 AND status IN ('pending', 'failed')`, p.key, status, title, site, now, pubAt, pubPrec, pubSrc); err != nil {
			return res, err
		}
	}
	if o.Backfill > 0 {
		return res, backfill(ctx, db, o, &res)
	}
	return res, nil
}

// backfill re-fetches up to o.Backfill 'ok' pages whose publication time
// was never looked for (published_checked_at NULL), oldest first, and
// stores only that: the time when the page (200 HTML, same host) states a
// plausible one, and the mark. A failure of any kind only sets the mark,
// so each page is requested once; status, attempts and title never change
// here. It stops early, without an error, when ctx's deadline is near
// (backfillReserve).
func backfill(ctx context.Context, db DB, o Options, res *Result) error {
	rows, err := db.Query(ctx, `SELECT url_key, url FROM web_page
        WHERE status = 'ok' AND published_checked_at IS NULL
        ORDER BY created_at, url_key LIMIT $1`, o.Backfill)
	if err != nil {
		return err
	}
	todo, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pending, error) {
		var p pending
		return p, r.Scan(&p.key, &p.url)
	})
	if err != nil {
		return err
	}
	for _, p := range todo {
		if err := ctx.Err(); err != nil {
			return err
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < backfillReserve {
			return nil
		}
		var pub *pagefetch.Published
		if _, err := pagefetch.CheckURL(p.url); err == nil {
			if res.Requests > 0 {
				if err := o.Sleep(ctx, Delay); err != nil {
					return err
				}
			}
			res.Requests++
			page, gerr := o.Client.Get(ctx, p.url)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			pub = publishedOf(p, page, gerr, o.Now().UTC(), o.Logger)
		}
		res.Backfilled++
		var pubAt *time.Time
		var pubPrec, pubSrc *string
		if pub != nil {
			pubAt, pubPrec, pubSrc = &pub.At, &pub.Precision, &pub.Source
			res.Published++
		}
		if _, err := db.Exec(ctx, `UPDATE web_page SET published_at = $2, published_precision = $3, published_source = $4, published_checked_at = $5
            WHERE url_key = $1 AND status = 'ok' AND published_checked_at IS NULL`, p.key, pubAt, pubPrec, pubSrc, o.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

// publishedOf is the publication time of a re-fetched page: only from a
// 200 HTML page on the queued URL's host; nil otherwise or on a panic.
func publishedOf(p pending, page *pagefetch.Page, gerr error, now time.Time, log *slog.Logger) (out *pagefetch.Published) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("web page handling panicked", "url_key", p.key, "panic", fmt.Sprint(r))
			out = nil
		}
	}()
	if gerr != nil || page == nil || !page.IsHTML() || !sameHost(p.url, page.URL) {
		return nil
	}
	if pub, ok := pagefetch.ExtractPublished(page, now); ok {
		return &pub
	}
	return nil
}

type flag int

const (
	flagNone flag = iota
	flagRefused
	flagOtherHost
	flagPanic
)

type outcome struct {
	status, why string
	title, site *string
	flag        flag
	pub         *pagefetch.Published // set by FetchPending for an 'ok' page
}

// outcomeOf decides the new status of page p from the Get result. A panic
// (in extraction or anywhere here) gives 'none' with flagPanic.
func outcomeOf(p pending, page *pagefetch.Page, gerr error, extract func(*pagefetch.Page) pagefetch.Meta, log *slog.Logger) (out outcome) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("web page handling panicked", "url_key", p.key, "panic", fmt.Sprint(r))
			out = outcome{status: StatusNone, why: "panic", flag: flagPanic}
		}
	}()
	if extract == nil {
		extract = pagefetch.ExtractMeta
	}
	out.status = StatusNone
	switch {
	case gerr != nil && errors.Is(gerr, pagefetch.ErrRefused):
		out.why, out.flag = gerr.Error(), flagRefused
	case gerr != nil:
		out.status, out.why = retryStatus(p.attempts), "transport error"
	case page.IsHTML() && !sameHost(p.url, page.URL):
		out.why, out.flag = "redirected to another host", flagOtherHost
	case page.IsHTML():
		m := extract(page)
		if m.SiteName != "" {
			out.site = &m.SiteName
		}
		if m.Title != "" {
			out.status, out.title = StatusOK, &m.Title
		} else {
			out.why = "no usable title"
		}
	case page.Status >= 500 || page.Status == http.StatusTooManyRequests || page.Status == http.StatusRequestTimeout:
		out.status, out.why = retryStatus(p.attempts), "HTTP "+http.StatusText(page.Status)
	default:
		out.why = "not a 200 HTML page"
	}
	return out
}

// sameHost reports whether URLs a and b have the same host name after
// lower-casing and dropping a trailing dot and one leading "www." (scheme
// and port may differ: http to https on the same host is fine).
func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	norm := func(h string) string {
		return strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(h), "."), "www.")
	}
	ha, hb := norm(ua.Hostname()), norm(ub.Hostname())
	return ha != "" && ha == hb
}

// retryStatus is the status after a transient failure of a page with
// attempts made so far.
func retryStatus(attempts int) string {
	if attempts+1 >= MaxAttempts {
		return StatusFailed
	}
	return StatusPending
}
