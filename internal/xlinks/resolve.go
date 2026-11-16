package xlinks

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/webpages"
)

// Resolver constants.
const (
	// ShortBase is the only host the resolver ever requests.
	ShortBase = "https://t.co"
	// MaxAttempts per row; the row is 'failed' after that many.
	MaxAttempts = 3
	// DefaultLimit is the number of rows per pass.
	DefaultLimit = 200
	// RequestTimeout bounds each request.
	RequestTimeout = 8 * time.Second
	// Delay between two requests.
	Delay     = 250 * time.Millisecond
	userAgent = webpages.UserAgent // one User-Agent for every request of ours to third parties
)

// shortRe is the only short link form the resolver accepts.
var shortRe = regexp.MustCompile(`^https://t\.co/([A-Za-z0-9]+)$`)

// IsShortURL reports whether s is exactly https://t.co/<letters and digits>.
func IsShortURL(s string) bool { return shortRe.MatchString(s) }

// DB is the database handle (*pgx.Conn, pgx.Tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Options configures Resolve.
type Options struct {
	Limit     int               // rows per pass; <= 0 means DefaultLimit
	Transport http.RoundTripper // nil: http.DefaultTransport
	// BaseURL replaces ShortBase in the request (tests only; set from code,
	// never from the environment). The stored short URL must still be an
	// https://t.co/ link.
	BaseURL string
	Now     func() time.Time
	Sleep   func(ctx context.Context, d time.Duration) error
	Logger  *slog.Logger
}

// Result counts one pass.
type Result struct {
	Candidates int `json:"candidates"` // pending rows picked
	Resolved   int `json:"resolved"`   // now 'ok'
	Retry      int `json:"retry"`      // still 'pending' (attempts left)
	Failed     int `json:"failed"`     // now 'failed'
	Refused    int `json:"refused"`    // not a t.co link: 'failed' without a request
	Requests   int `json:"requests"`
}

type pendingRow struct {
	postID, shortURL string
	pos, attempts    int
}

// Resolve expands pending t.co links of x_post_link: for each row with status
// 'pending' and attempts < MaxAttempts (oldest first, at most Limit), ONE GET
// of the short link, without following redirects; the Location header gives
// expanded_url = final_url, host and kind (origin 'resolver', status 'ok').
// No Location, another status or a transport error adds one attempt ('failed'
// at MaxAttempts). A short URL that is not exactly https://t.co/<alnum> is
// marked 'failed' without any request. Each row is written on its own, so a
// cancelled context stops the pass between rows (the error is ctx.Err()).
func Resolve(ctx context.Context, db DB, o Options) (Result, error) {
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
	base := ShortBase
	if o.BaseURL != "" {
		base = strings.TrimSuffix(o.BaseURL, "/")
	}
	tr := o.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	client := &http.Client{Transport: tr, Timeout: RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	rows, err := db.Query(ctx, `SELECT post_id, pos, short_url, attempts FROM x_post_link
        WHERE status = 'pending' AND attempts < $1
        ORDER BY created_at, char_length(post_id), post_id, pos LIMIT $2`, MaxAttempts, o.Limit)
	if err != nil {
		return res, err
	}
	todo, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pendingRow, error) {
		var p pendingRow
		return p, r.Scan(&p.postID, &p.pos, &p.shortURL, &p.attempts)
	})
	if err != nil {
		return res, err
	}
	res.Candidates = len(todo)
	for i, p := range todo {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		m := shortRe.FindStringSubmatch(p.shortURL)
		if m == nil {
			if _, err := db.Exec(ctx, `UPDATE x_post_link SET status = 'failed'
                WHERE post_id = $1 AND pos = $2 AND status = 'pending'`, p.postID, p.pos); err != nil {
				return res, err
			}
			o.Logger.Warn("x link not a t.co link, not requested", "post_id", p.postID, "pos", p.pos)
			res.Refused++
			continue
		}
		if i > 0 && res.Requests > 0 {
			if err := o.Sleep(ctx, Delay); err != nil {
				return res, err
			}
		}
		res.Requests++
		target, why := fetchLocation(ctx, client, base+"/"+m[1])
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if target != "" {
			host, kind := Classify(target, p.postID)
			var h *string
			if host != "" {
				h = &host
			}
			if _, err := db.Exec(ctx, `UPDATE x_post_link SET expanded_url = $3, final_url = $3, host = $4, kind = $5,
                    origin = 'resolver', status = 'ok', attempts = attempts + 1, resolved_at = $6
                WHERE post_id = $1 AND pos = $2 AND status = 'pending'`,
				p.postID, p.pos, target, h, kind, o.Now().UTC()); err != nil {
				return res, err
			}
			res.Resolved++
			continue
		}
		next := p.attempts + 1
		status := "pending"
		if next >= MaxAttempts {
			status = "failed"
			res.Failed++
		} else {
			res.Retry++
		}
		o.Logger.Info("x link not resolved", "post_id", p.postID, "pos", p.pos, "why", why, "attempt", next)
		if _, err := db.Exec(ctx, `UPDATE x_post_link SET attempts = attempts + 1, status = $3
            WHERE post_id = $1 AND pos = $2 AND status = 'pending'`, p.postID, p.pos, status); err != nil {
			return res, err
		}
	}
	return res, nil
}

// fetchLocation makes one GET of u (no redirect followed) and returns the
// absolute http(s) Location of a 3xx response, or "" and why not.
func fetchLocation(ctx context.Context, client *http.Client, u string) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err.Error()
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", "transport error"
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return "", fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	loc := strings.TrimSpace(resp.Header.Get("Location"))
	if loc == "" {
		return "", "no Location"
	}
	lu, err := url.Parse(loc)
	if err != nil || !lu.IsAbs() || (lu.Scheme != "http" && lu.Scheme != "https") || len(loc) > 4096 {
		return "", "Location is not an absolute http(s) URL"
	}
	return loc, ""
}
