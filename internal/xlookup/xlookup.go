// Package xlookup resolves X handles to numeric user ids through the
// official X API v2 user lookup (GET /2/users/by?usernames=…, app-only
// Bearer token), for the allowlist of the xposts collector: the back office
// (/admin/x) and `nday x-accounts-import` bind a handle to its id at the
// moment an administrator enters it (docs/xposts.md, docs/admin.md).
//
// Rules:
//   - the token (NDAY_X_BEARER_TOKEN) is sent only as the Authorization
//     header to the base URL; it is never logged and never part of an error
//     string or a result;
//   - the base URL is https://api.x.com; only code can change it (tests and
//     tools/authdev use Options.BaseURL or Options.Transport), never an
//     environment variable, so a production environment cannot send the
//     token elsewhere;
//   - handles are checked with xconfig.ValidHandle before any request;
//   - one attempt per request, a short overall timeout, no retry (429 is
//     reported as ErrRateLimited at once); the caller's context is honoured;
//   - at most MaxPerRequest usernames per request (the documented maximum).
package xlookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nday.land/nday/internal/httpc"
	"nday.land/nday/internal/xconfig"
)

// Constants (docs/xposts.md quotes the X documentation for each).
const (
	// TokenEnv is the app-only Bearer token, shared with the collector.
	TokenEnv = "NDAY_X_BEARER_TOKEN"
	// DefaultBaseURL is the X API host.
	DefaultBaseURL = "https://api.x.com"
	// Path is the user lookup by usernames endpoint.
	Path = "/2/users/by"
	// MaxPerRequest is the documented maximum of usernames per request.
	MaxPerRequest = 100
	// DefaultTimeout bounds one request (connect, headers and body).
	DefaultTimeout = 10 * time.Second
	maxBody        = 1 << 20
)

// Errors of a whole request. The messages never contain the token.
var (
	// ErrNotConfigured: no token, so no request is made.
	ErrNotConfigured = errors.New("X user lookup is not configured (no " + TokenEnv + ")")
	// ErrBadHandle: a handle failed xconfig.ValidHandle (no request made).
	ErrBadHandle = errors.New("invalid X handle")
	// ErrRateLimited: HTTP 429 from the X API (not retried).
	ErrRateLimited = errors.New("X API rate limit reached (HTTP 429); try again later")
	// ErrAuth: HTTP 401 or 403 (the token was refused).
	ErrAuth = errors.New("X API refused the credentials (HTTP 401/403)")
	// ErrUpstream: timeout, transport error, 5xx, another status or a
	// response that does not parse.
	ErrUpstream = errors.New("X API request failed")
)

// Outcome of one handle.
type Outcome string

const (
	Found       Outcome = "found"
	NotFound    Outcome = "not_found"
	Unavailable Outcome = "unavailable" // suspended or otherwise withheld
)

// Result is one handle's answer: on Found, ID and Handle (the canonical
// spelling X returned) are set.
type Result struct {
	Outcome Outcome
	ID      string
	Handle  string
}

// Options configures New.
type Options struct {
	Token string
	// BaseURL replaces DefaultBaseURL (tests and tools/authdev only;
	// cmd/nday never sets it).
	BaseURL   string
	Transport http.RoundTripper
	Timeout   time.Duration
	Logger    *slog.Logger
}

// Client looks up users. A nil *Client is valid and not configured.
type Client struct {
	token   string // never logged, never in errors
	base    string
	timeout time.Duration
	http    *httpc.Client
}

// ErrBadToken: the token holds characters that cannot go in a header.
var ErrBadToken = errors.New(TokenEnv + " contains characters not allowed in an HTTP header")

// New builds a client. An empty token gives a client that is not
// configured (every lookup returns ErrNotConfigured without a request).
func New(o Options) (*Client, error) {
	tok := strings.TrimSpace(o.Token)
	for i := 0; i < len(tok); i++ {
		if tok[i] < 0x21 || tok[i] > 0x7e {
			return nil, ErrBadToken
		}
	}
	base := DefaultBaseURL
	if o.BaseURL != "" {
		base = strings.TrimRight(o.BaseURL, "/")
	}
	t := o.Timeout
	if t <= 0 {
		t = DefaultTimeout
	}
	lg := o.Logger
	if lg == nil {
		lg = slog.Default()
	}
	return &Client{token: tok, base: base, timeout: t,
		http: httpc.New(httpc.Options{Transport: o.Transport, MaxAttempts: 1, MaxBytes: maxBody,
			ConnTimeout: t, ReadTimeout: t, TotalTimeout: t, Logger: lg})}, nil
}

// Configured reports whether lookups can be made (a token is set).
func (c *Client) Configured() bool { return c != nil && c.token != "" }

// Key is the case-insensitive key of a handle in Lookup's result.
func Key(handle string) string { return strings.ToLower(handle) }

// Lookup resolves handles (without '@'), MaxPerRequest per request, in
// order. The result maps Key(handle) to its Result. A request-level error
// (ErrRateLimited, ErrAuth, ErrUpstream wrapped with a short reason, or the
// context's error) stops the lookup and nothing is returned.
func (c *Client) Lookup(ctx context.Context, handles []string) (map[string]Result, error) {
	var keys []string
	seen := map[string]bool{}
	for _, h := range handles {
		if !xconfig.ValidHandle(h) {
			return nil, fmt.Errorf("%w %q", ErrBadHandle, h)
		}
		if k := Key(h); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	out := make(map[string]Result, len(keys))
	for i := 0; i < len(keys); i += MaxPerRequest {
		batch := keys[i:min(i+MaxPerRequest, len(keys))]
		if err := c.lookup(ctx, batch, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// LookupOne is Lookup of one handle.
func (c *Client) LookupOne(ctx context.Context, handle string) (Result, error) {
	m, err := c.Lookup(ctx, []string{handle})
	if err != nil {
		return Result{}, err
	}
	return m[Key(handle)], nil
}

type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Value  any    `json:"value"`
	Detail string `json:"detail"`
}

type response struct {
	Data []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"data"`
	Errors []problem `json:"errors"`
}

func (c *Client) lookup(parent context.Context, batch []string, out map[string]Result) error {
	if err := parent.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	v := url.Values{}
	v.Set("usernames", strings.Join(batch, ","))
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+c.token)
	hdr.Set("Accept", "application/json")
	resp, err := c.http.Get(ctx, c.base+Path+"?"+v.Encode(), httpc.GetOptions{Header: hdr, Accept: func(int) bool { return true }})
	if err != nil {
		if perr := parent.Err(); perr != nil {
			return perr // the caller cancelled (or its own deadline passed)
		}
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return fmt.Errorf("%w: no answer within %s", ErrUpstream, c.timeout)
		}
		return fmt.Errorf("%w: %s", ErrUpstream, transportReason(err))
	}
	switch {
	case resp.Status == http.StatusTooManyRequests:
		return ErrRateLimited
	case resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden:
		return ErrAuth
	case resp.Status != http.StatusOK:
		return fmt.Errorf("%w: HTTP %d", ErrUpstream, resp.Status)
	}
	var r response
	if err := json.Unmarshal(resp.Body, &r); err != nil {
		return fmt.Errorf("%w: response is not the expected JSON", ErrUpstream)
	}
	want := map[string]bool{}
	for _, k := range batch {
		want[k] = true
	}
	for _, u := range r.Data {
		k := Key(u.Username)
		if !want[k] {
			continue // not asked for
		}
		if !xconfig.ValidUserID(u.ID) || !xconfig.ValidHandle(u.Username) {
			return fmt.Errorf("%w: response holds an invalid user id or username", ErrUpstream)
		}
		out[k] = Result{Outcome: Found, ID: u.ID, Handle: u.Username}
	}
	for _, p := range r.Errors {
		s, _ := p.Value.(string)
		k := Key(strings.TrimPrefix(s, "@"))
		if !want[k] {
			continue
		}
		if _, done := out[k]; done {
			continue
		}
		out[k] = Result{Outcome: classify(p)}
	}
	// a handle neither in data nor in errors is treated as not found
	for _, k := range batch {
		if _, ok := out[k]; !ok {
			out[k] = Result{Outcome: NotFound}
		}
	}
	return nil
}

// classify maps a partial error of the response to an outcome: the
// documented problem types resource-not-found and resource-unavailable
// (host-independent: older answers say api.twitter.com). Anything else that
// names the handle counts as unavailable, so it is never bound blindly.
func classify(p problem) Outcome {
	switch {
	case strings.HasSuffix(p.Type, "/2/problems/resource-not-found"):
		return NotFound
	default:
		return Unavailable
	}
}

// transportReason is a short, token-free description of a transport error
// (the URL holds only the handles; the header is never part of it).
func transportReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "..."
	}
	return s
}
