// Package httpc is the shared HTTP layer for collectors (Go port of the
// download() plumbing in src/nday/collectors/_feed.py and the retry loops in
// cvelist.py / ghsa.py).
//
// What Client.Get does:
//   - sends the generic User-Agent "nday-collector/0.1.0" (Python:
//     nday.USER_AGENT) plus caller headers; never anything identifying;
//   - connect / per-read idle / optional overall timeouts;
//   - up to MaxAttempts tries with exponential backoff (BackoffBase * 2^(n-1):
//     1s, 2s, 4s) on 429, 5xx and transport errors; a Retry-After header
//     consisting of ASCII digits (seconds) replaces the backoff, capped at
//     MaxRetryAfter (HTTP-date values are ignored, like Python);
//   - statuses accepted by GetOptions.Accept (default: 2xx) are returned,
//     anything else is a *StatusError (after the retries for 429/5xx);
//   - a hard cap on the DECODED body size (Content-Length checked first, then
//     while reading): *TooLargeError, so a runaway response aborts the run.
//
// Tests inject Options.Transport (an http.RoundTripper, e.g. RoundTripFunc)
// and Options.Sleep, so no test touches the network or really sleeps.
package httpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// UserAgent is Python's nday.USER_AGENT (f"nday-collector/{__version__}").
const UserAgent = "nday-collector/0.1.0"

// Defaults mirror _feed.py.
const (
	DefaultMaxAttempts   = 4                // 1 try + 3 retries
	DefaultBackoffBase   = time.Second      // 1, 2, 4 s
	DefaultMaxRetryAfter = 60 * time.Second // Retry-After cap
	DefaultMaxBytes      = 64 << 20         // decoded body cap
	DefaultConnTimeout   = 15 * time.Second
	DefaultReadTimeout   = 120 * time.Second // per-read idle timeout (httpx read timeout)
)

// RoundTripFunc adapts a function to http.RoundTripper (fake transports in tests).
type RoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Options configures a Client. Zero values select the defaults above, except
// MaxAttempts where 0 means DefaultMaxAttempts and 1 means "no retry".
type Options struct {
	Transport     http.RoundTripper // nil: a dedicated *http.Transport with ConnTimeout
	MaxAttempts   int
	BackoffBase   time.Duration
	MaxRetryAfter time.Duration
	MaxBytes      int64
	ConnTimeout   time.Duration // TCP connect + TLS handshake
	ReadTimeout   time.Duration // max idle time waiting for headers / between body reads
	TotalTimeout  time.Duration // optional overall per-attempt deadline (0 = none)
	// Sleep waits between retries; tests replace it. Default: context-aware sleep.
	Sleep  func(ctx context.Context, d time.Duration) error
	Logger *slog.Logger
}

// Client performs GETs with the policy above.
type Client struct {
	opt  Options
	http *http.Client
}

// New builds a Client.
func New(opt Options) *Client {
	if opt.MaxAttempts <= 0 {
		opt.MaxAttempts = DefaultMaxAttempts
	}
	if opt.BackoffBase <= 0 {
		opt.BackoffBase = DefaultBackoffBase
	}
	if opt.MaxRetryAfter <= 0 {
		opt.MaxRetryAfter = DefaultMaxRetryAfter
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = DefaultMaxBytes
	}
	if opt.ConnTimeout <= 0 {
		opt.ConnTimeout = DefaultConnTimeout
	}
	if opt.ReadTimeout <= 0 {
		opt.ReadTimeout = DefaultReadTimeout
	}
	if opt.Sleep == nil {
		opt.Sleep = sleepCtx
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	rt := opt.Transport
	if rt == nil {
		dialer := &net.Dialer{Timeout: opt.ConnTimeout, KeepAlive: 30 * time.Second}
		rt = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   opt.ConnTimeout,
			ResponseHeaderTimeout: opt.ReadTimeout,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
		}
	}
	// Redirects are followed (httpx follow_redirects=True); Go stops after 10.
	return &Client{opt: opt, http: &http.Client{Transport: rt}}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// GetOptions are per-request options.
type GetOptions struct {
	Header http.Header
	// Accept reports whether a final status is returned to the caller instead
	// of a *StatusError (e.g. 304 for conditional requests, 404 for "missing").
	// nil accepts 2xx only. 429 and 5xx are retried before Accept is consulted.
	Accept func(status int) bool
}

// Response is a fully read response.
type Response struct {
	Status   int
	Header   http.Header
	Body     []byte // decoded (Go's transport transparently gunzips)
	Attempts int
	URL      string // final URL after redirects
}

// StatusError is a non-accepted HTTP status (Python: httpx.HTTPStatusError).
type StatusError struct {
	Status int
	URL    string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("HTTP status %d %s for url %s", e.Status, http.StatusText(e.Status), e.URL)
}

// TooLargeError is a body over the size cap (Python: FeedTooLarge).
type TooLargeError struct {
	URL   string
	Limit int64
	Msg   string
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("%s: %s (cap %d bytes)", e.URL, e.Msg, e.Limit)
}

func retryable(status int) bool { return status == http.StatusTooManyRequests || status >= 500 }

// Get fetches url following the package policy.
func (c *Client) Get(ctx context.Context, url string, o GetOptions) (*Response, error) {
	accept := o.Accept
	if accept == nil {
		accept = func(s int) bool { return s >= 200 && s < 300 }
	}
	for attempt := 1; ; attempt++ {
		delay := c.opt.BackoffBase << (attempt - 1)
		resp, err := c.once(ctx, url, o.Header, attempt)
		last := attempt >= c.opt.MaxAttempts
		switch {
		case err != nil:
			var tl *TooLargeError
			if errors.As(err, &tl) || ctx.Err() != nil || last {
				return nil, err
			}
			c.opt.Logger.Warn("GET failed, retrying", "url", url, "err", err, "attempt", attempt, "delay", delay)
		case retryable(resp.Status) && !last:
			if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); isASCIIDigits(ra) {
				delay = c.opt.MaxRetryAfter
				if secs, err := strconv.ParseInt(ra, 10, 64); err == nil && secs < int64(c.opt.MaxRetryAfter/time.Second) {
					delay = time.Duration(secs) * time.Second
				}
			}
			c.opt.Logger.Warn("GET retryable status, retrying", "url", url, "status", resp.Status, "attempt", attempt, "delay", delay)
		case accept(resp.Status):
			return resp, nil
		default:
			return nil, &StatusError{Status: resp.Status, URL: url}
		}
		if err := c.opt.Sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// once performs a single attempt and reads the body when the status may be
// returned (bodies of retryable statuses are discarded).
func (c *Client) once(ctx context.Context, url string, hdr http.Header, attempt int) (*Response, error) {
	if c.opt.TotalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opt.TotalTimeout)
		defer cancel()
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := &Response{Status: resp.StatusCode, Header: resp.Header, Attempts: attempt, URL: resp.Request.URL.String()}
	if retryable(resp.StatusCode) {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return out, nil
	}
	if resp.ContentLength > c.opt.MaxBytes {
		return nil, &TooLargeError{URL: url, Limit: c.opt.MaxBytes, Msg: fmt.Sprintf("Content-Length %d", resp.ContentLength)}
	}
	// Per-read idle timeout: cancel the request if no data arrives in time.
	idle := time.AfterFunc(c.opt.ReadTimeout, func() {
		cancel(fmt.Errorf("read timeout: no data for %s", c.opt.ReadTimeout))
	})
	defer idle.Stop()
	body, err := readCapped(resp.Body, c.opt.MaxBytes, func() { idle.Reset(c.opt.ReadTimeout) })
	if err != nil {
		if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
			return nil, cause
		}
		if errors.Is(err, errTooLarge) {
			return nil, &TooLargeError{URL: url, Limit: c.opt.MaxBytes, Msg: "body exceeds cap"}
		}
		return nil, err
	}
	out.Body = body
	return out, nil
}

var errTooLarge = errors.New("body too large")

func readCapped(r io.Reader, limit int64, progress func()) ([]byte, error) {
	var buf []byte
	chunk := make([]byte, 32<<10)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			progress()
			if int64(len(buf)+n) > limit {
				return nil, errTooLarge
			}
			buf = append(buf, chunk[:n]...)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
