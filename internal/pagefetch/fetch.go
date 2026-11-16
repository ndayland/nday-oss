// Package pagefetch fetches third-party web pages safely and reads their
// metadata (see docs/webpages.md). It knows nothing about where URLs come
// from: no database, no collectors, no site code.
//
// Every request goes to an arbitrary host, so the package is built around
// SSRF limits: URL rules (CheckURL: absolute http/https, no user info,
// default ports only, no non-public IP literal, at most MaxURL bytes), a
// connect-time address guard (GuardControl / IsPublicAddr, applied by the
// dialer to every connection, so DNS rebinding cannot bypass it), at most
// MaxRedirects redirects each re-checked by the URL rules, no proxy, TLS
// verification on, GET only, an overall timeout, a response header timeout
// and a body cap. Nothing is configurable from the environment; tests inject
// a dial control or address rewrite from code.
package pagefetch

import (
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Limits.
const (
	// MaxRedirects is the number of redirects followed per Get.
	MaxRedirects = 3
	// MaxBody is the number of body bytes read (the rest is not read).
	MaxBody = 512 << 10
	// Timeout bounds one Get, redirects included (some blogs take ~15 s to
	// the first byte).
	Timeout = 25 * time.Second
	// HeaderTimeout bounds the wait for response headers per request.
	HeaderTimeout = 20 * time.Second
	// DialTimeout bounds each connection attempt.
	DialTimeout = 5 * time.Second
)

// Options configures a Client. The zero value is the production setting
// except for UserAgent.
type Options struct {
	UserAgent string // sent with every request
	Accept    string // "" = "text/html"

	// Tests only (set from code, never from the environment):
	// DialControl replaces GuardControl as the dialer's Control hook.
	DialControl func(network, address string, c syscall.RawConn) error
	// RewriteAddr maps the dialled "host:port" before name resolution
	// (to reach an httptest listener behind a name on a default port).
	// The Control hook still sees the resolved address.
	RewriteAddr func(addr string) string
}

// Client fetches pages. Safe for concurrent use. No global state: each
// Client has its own transport.
type Client struct {
	hc        *http.Client
	userAgent string
	accept    string
}

// Page is the result of a Get that reached a server.
type Page struct {
	URL         string // final URL (after redirects)
	Status      int
	ContentType string // media type, lower case ("" when absent or invalid)
	Charset     string // charset parameter of Content-Type, lower case
	// Body is read only for status 200 with an HTML content type (IsHTML),
	// at most MaxBody bytes; nil otherwise.
	Body      []byte
	Truncated bool // the body was longer than MaxBody
}

// IsHTML reports whether the page is a 200 response with an HTML content
// type (text/html or application/xhtml+xml): the only pages whose body is
// read.
func (p *Page) IsHTML() bool {
	return p.Status == http.StatusOK && (p.ContentType == "text/html" || p.ContentType == "application/xhtml+xml")
}

// New returns a Client with its own guarded transport.
func New(o Options) *Client {
	ctrl := o.DialControl
	if ctrl == nil {
		ctrl = GuardControl
	}
	d := &net.Dialer{Timeout: DialTimeout, Control: ctrl}
	rewrite := o.RewriteAddr
	tr := &http.Transport{
		Proxy: nil, // never ProxyFromEnvironment
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if rewrite != nil {
				addr = rewrite(addr)
			}
			return d.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    DialTimeout,
		ResponseHeaderTimeout:  HeaderTimeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	accept := o.Accept
	if accept == "" {
		accept = "text/html"
	}
	c := &Client{userAgent: o.UserAgent, accept: accept}
	c.hc = &http.Client{Transport: tr, Timeout: Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return refused("more than %d redirects", MaxRedirects)
			}
			if _, err := CheckURL(req.URL.String()); err != nil {
				return err
			}
			if req.Method != http.MethodGet {
				return refused("redirect to method %s", req.Method)
			}
			// net/http adds the previous URL as Referer on redirects: never
			// tell one third party about another (no cookie jar, so no
			// Cookie either)
			req.Header.Del("Referer")
			req.Header.Del("Cookie")
			req.Header.Set("User-Agent", c.userAgent)
			req.Header.Set("Accept", c.accept)
			return nil
		}}
	return c
}

// CheckURL applies the URL rules to raw: an absolute http or https URL of
// at most MaxURL bytes, with a host, without user info, on the default port
// only (an explicit port is accepted only when it is 80 for http or 443 for
// https), and whose host, if an IP literal, is a public address. The error
// wraps ErrRefused.
func CheckURL(raw string) (*url.URL, error) {
	if len(raw) > MaxURL {
		return nil, refused("URL longer than %d bytes", MaxURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, refused("unparsable URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, refused("scheme %q", u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return nil, refused("no host")
	}
	if u.User != nil {
		return nil, refused("user info in URL")
	}
	if p := u.Port(); p != "" {
		if !(u.Scheme == "http" && p == "80") && !(u.Scheme == "https" && p == "443") {
			return nil, refused("port %s", p)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, refused("empty port")
	}
	h := u.Hostname()
	if strings.ContainsAny(h, "%") {
		return nil, refused("zone or escape in host")
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if !IsPublicAddr(a) {
			return nil, refused("non-public IP literal %s", a)
		}
	}
	return u, nil
}

// Get makes a GET of raw (CheckURL first; nothing is sent when it fails),
// following at most MaxRedirects redirects that each pass CheckURL. It
// returns the final page; the body is read only when IsHTML, capped at
// MaxBody. Errors: ErrRefused-wrapping errors for refusals (no connection
// made for the refused hop), the context's error when it is done, else a
// transport error.
func (c *Client) Get(ctx context.Context, raw string) (*Page, error) {
	u, err := CheckURL(raw)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, refused("request: %v", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", c.accept)
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	defer resp.Body.Close()
	p := &Page{URL: resp.Request.URL.String(), Status: resp.StatusCode}
	if mt, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil {
		p.ContentType = strings.ToLower(mt)
		p.Charset = strings.ToLower(strings.TrimSpace(params["charset"]))
	}
	if !p.IsHTML() {
		return p, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil && !errors.Is(err, io.EOF) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if len(b) > MaxBody {
		b, p.Truncated = b[:MaxBody], true
	}
	p.Body = b
	return p, nil
}
