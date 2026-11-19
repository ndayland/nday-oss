package ghrepo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nday.land/nday/internal/pagefetch"
)

// API and client limits.
const (
	// APIHost is the only host the client connects to.
	APIHost = "api.github.com"
	// APIBase is the base URL of every request.
	APIBase = "https://" + APIHost
	// Accept and APIVersion are the headers GitHub recommends (the same
	// values as the ghsa collector).
	Accept     = "application/vnd.github+json"
	APIVersion = "2022-11-28"
	// UserAgent of every request (GitHub rejects requests without one).
	UserAgent = "nday-ghrepo/1"
	// MaxRedirects followed per request, each to https://api.github.com only.
	MaxRedirects = 2
	// MaxBody is the most response bytes read (a repository is ~6 KiB).
	MaxBody = 256 << 10
	// MaxSearchBody is the most bytes read of one search page (Search): 100
	// items of ~6 KiB each (582 KB measured for a page of 100 on
	// 2026-11-16), up to ~10 KiB with a 500-character escaped description
	// and 20 topics, so 1 MiB at worst; twice that as headroom.
	MaxSearchBody = 2 << 20
	// Timeout bounds one HTTP request (http.Client.Timeout); each redirect
	// hop Get follows is a request of its own with its own Timeout.
	Timeout = 20 * time.Second
	// DialTimeout and HeaderTimeout bound the connection and the wait for
	// response headers.
	DialTimeout   = 5 * time.Second
	HeaderTimeout = 15 * time.Second
)

// ErrRefused wraps refusals: a redirect away from https://api.github.com or
// past MaxRedirects, a dial to any other address. No request is sent for
// the refused hop.
var ErrRefused = errors.New("ghrepo: refused")

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRefused}, args...)...)
}

// ClientOptions configures a Client. The zero value is the production
// setting (unauthenticated).
type ClientOptions struct {
	// Token is sent as "Authorization: Bearer <token>" to
	// https://api.github.com only; "" = unauthenticated. Never logged.
	Token string

	// Tests only (set from code, never from the environment):
	// DialControl replaces pagefetch.GuardControl as the dialer's Control
	// hook; RewriteAddr maps the dialled "api.github.com:443" to a test
	// listener; RootCAs replaces the system roots.
	DialControl func(network, address string, c syscall.RawConn) error
	RewriteAddr func(addr string) string
	RootCAs     *x509.CertPool
}

// Client makes GET requests to https://api.github.com. Safe for concurrent
// use; no global state.
type Client struct {
	hc    *http.Client
	token string
}

// NewClient returns a Client with its own transport: no proxy (never from
// the environment), TLS verified, connections only to api.github.com:443
// through pagefetch.GuardControl (public addresses only), timeouts, no
// automatic redirects (Get follows them itself).
func NewClient(o ClientOptions) *Client {
	ctrl := o.DialControl
	if ctrl == nil {
		ctrl = pagefetch.GuardControl
	}
	d := &net.Dialer{Timeout: DialTimeout, Control: ctrl}
	rewrite := o.RewriteAddr
	tr := &http.Transport{
		Proxy: nil, // never ProxyFromEnvironment
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != APIHost+":443" {
				return nil, refused("dial %s", addr)
			}
			if rewrite != nil {
				addr = rewrite(addr)
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig:        &tls.Config{RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    DialTimeout,
		ResponseHeaderTimeout:  HeaderTimeout,
		MaxIdleConns:           2,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &Client{token: strings.TrimSpace(o.Token),
		hc: &http.Client{Transport: tr, Timeout: Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Authenticated reports whether requests carry a token.
func (c *Client) Authenticated() bool { return c.token != "" }

// Response is the outcome of a Get that reached GitHub.
type Response struct {
	Status int
	Body   []byte // read for 200 only, at most MaxBody bytes
	TooBig bool   // the 200 body was longer than MaxBody (Body is nil)
	ETag   string
	// FinalPath is the path of the last request (after redirects);
	// Redirects is how many redirects were followed to get there (each one
	// is a request of its own against the rate limit).
	FinalPath string
	Redirects int
	// Rate limit headers; Remaining is -1 when absent. Resource is
	// x-ratelimit-resource ("core", "search", ...; "" when absent).
	Remaining int
	Resource  string
	Reset     time.Time // zero when absent
	// RetryAfter is the Retry-After header in seconds (0 when absent).
	RetryAfter int
}

// RateLimited reports whether the response is a rate-limit refusal: a 429,
// or a 403 with x-ratelimit-remaining 0 or a Retry-After header (GitHub
// answers an exhausted primary limit with 403 or 429, a secondary limit
// with 403 or 429 and Retry-After).
func (r *Response) RateLimited() bool {
	return r.Status == http.StatusTooManyRequests ||
		(r.Status == http.StatusForbidden && (r.Remaining == 0 || r.RetryAfter > 0))
}

// apiURL checks that u is https://api.github.com/... (default port, no user
// info): the only URLs a request (and so the token) may go to.
func apiURL(u *url.URL) error {
	if u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Hostname() != APIHost || (u.Port() != "" && u.Port() != "443") {
		return refused("not %s: %s://%s", APIBase, u.Scheme, u.Host)
	}
	return nil
}

// Get makes a GET of APIBase+path, with If-None-Match: etag when etag is
// not "". A 301, 302, 307 or 308 whose Location stays on
// https://api.github.com is followed (at most MaxRedirects); one to any
// other place is refused (ErrRefused, no request). The token goes only on
// requests to https://api.github.com.
func (c *Client) Get(ctx context.Context, path, etag string) (*Response, error) {
	return c.get(ctx, path, etag, MaxBody, MaxRedirects)
}

// Search is Get without an ETag, with a body cap of MaxSearchBody and
// without redirects: any 3xx answer is refused (ErrRefused, the Location
// is not requested). For GET /search/repositories?... (path includes the
// query string).
func (c *Client) Search(ctx context.Context, path string) (*Response, error) {
	return c.get(ctx, path, "", MaxSearchBody, 0)
}

func (c *Client) get(ctx context.Context, path, etag string, maxBody, maxRedirects int) (*Response, error) {
	u, err := url.Parse(APIBase + path)
	if err != nil {
		return nil, refused("path %q", path)
	}
	for hop := 0; ; hop++ {
		if err := apiURL(u); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, refused("request: %v", err)
		}
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("Accept", Accept)
		req.Header.Set("X-GitHub-Api-Version", APIVersion)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		if c.token != "" && req.URL.Hostname() == APIHost && req.URL.Scheme == "https" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if maxRedirects == 0 && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			resp.Body.Close()
			return nil, refused("redirect (%d) not followed", resp.StatusCode)
		}
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			if hop >= maxRedirects {
				return nil, refused("more than %d redirects", maxRedirects)
			}
			next, err := u.Parse(loc)
			if err != nil || loc == "" {
				return nil, refused("bad redirect location")
			}
			u = next
			continue
		}
		defer resp.Body.Close()
		r := &Response{Status: resp.StatusCode, ETag: resp.Header.Get("ETag"), FinalPath: u.EscapedPath(), Redirects: hop, Remaining: -1}
		if res := strings.TrimSpace(resp.Header.Get("X-RateLimit-Resource")); len(res) <= 40 {
			r.Resource = res
		}
		if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining"))); err == nil && n >= 0 {
			r.Remaining = n
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(resp.Header.Get("X-RateLimit-Reset")), 10, 64); err == nil && n > 0 {
			r.Reset = time.Unix(n, 0).UTC()
		}
		if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n > 0 {
			r.RetryAfter = n
		}
		if resp.StatusCode != http.StatusOK {
			return r, nil
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)+1))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if len(b) > maxBody {
			r.TooBig = true
		} else {
			r.Body = b
		}
		return r, nil
	}
}
