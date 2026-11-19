// Package web is the nday HTTP server: the read-only JSON API over
// internal/site plus reusable middleware for the HTML pages.
//
// Routes (all GET/HEAD; anything else is a JSON 405):
//
//	/healthz                     DB reachability + data freshness (no-store)
//	/api/hot                     ?since=7d&min_stage=patch&include_rejected=0&limit=50&offset=0|cursor=
//	/api/vulns                   ?stage=&year=&tag=&include_rejected=0&limit=50&cursor= (catalogue: every CVE)
//	/api/discussed               ?limit=50&offset=0 (CVEs by researcher count, last 7 days)
//	/api/vuln/{cve}              case-insensitive CVE id, or GHSA id (site.ParseVulnID)
//	/api/sources                 collector health and totals
//	/api/stats                   stage and feature counts
//	/api/search                  ?q=...&limit=20
//	/api/affected/suggest        ?q=...&limit=8 (vendor/product names; also on the
//	                             site host in two-host mode: the welcome page calls it)
//	/raw/{source}/{key}.json     latest stored upstream record (key may contain "/")
//
// Every route above except /healthz needs a personal access token
// (Authorization: Bearer, see Gate and SetAPIAuth); /api/affected/suggest
// and /raw/... on the site host also accept a signed-in session cookie.
// See docs/api.md for the response shapes.
//
// # Two-host mode (Config.APIURL, NDAY_API_URL)
//
// With an API origin configured, requests whose Host is the API host are
// served only by the API mux (apihost.go): the same endpoints under /v1/
// (/v1/hot, /v1/vulns, /v1/discussed, /v1/vuln/{cve}, /v1/sources, /v1/stats, /v1/search, /v1/affected/suggest,
// /v1/raw/{source}/{key}.json, with /raw/... as an alias), /healthz, a JSON
// index at / and /v1,
// robots.txt and JSON 404s, with CORS for any origin (APIHeaders). Routes
// registered with Handle (pages, sign-in) are never reachable there. On every
// other host the data routes above answer 308 to the API host, except
// /api/affected/suggest, which page scripts call (CSP connect-src 'self'),
// and /raw/..., which signed-in readers open from vulnerability pages;
// /healthz and everything registered with Handle stay as they are.
//
// # Adding HTML routes
//
//	srv := web.New(web.Config{Store: store, Logger: log})
//	srv.Handle("GET /{$}", homeHandler)            // any net/http pattern
//	srv.Handle("GET /vuln/{cve}", vulnPage)
//	http.ListenAndServe(addr, srv.Handler())       // or web.Serve(ctx, addr, srv.Handler(), log)
//
// HTTPS: web.ServeTLS with a config from TLSOptions.Config (TLS 1.2+,
// optionally mandatory, verified client certificates).
//
// Handler() wraps every route (yours and the API) in the same middleware:
// Recover (panic -> logged 500), AccessLog (slog: method, path, status,
// bytes, duration, cf_ip), SecurityHeaders and a per-request Timeout
// (context deadline). Inside handlers use srv.Store for data, srv.Cache
// (TTL + singleflight) for expensive shared results, and WriteBody /
// WriteError / CacheList for responses. Patterns you register win over the
// JSON 404 fallback; if you register "/" (or "GET /"), it replaces it.
package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"nday.land/nday/internal/site"
)

// Config for New.
type Config struct {
	Store  *site.Store
	Logger *slog.Logger
	// RequestTimeout is each request's context deadline (default 10s).
	RequestTimeout time.Duration
	// CacheTTL for list responses in the in-process cache (default 30s;
	// negative disables caching but keeps request coalescing).
	CacheTTL time.Duration
	// CacheEntries bounds the in-process cache (default 2000).
	CacheEntries int
	// PublicURL is the public site origin (ParseOrigin form; "" = not
	// configured). Used for the documentation link of the API host index.
	PublicURL string
	// APIURL is the API host origin (ParseOrigin form). "" = single-host mode.
	APIURL string
	// Logs, if set, receive the access lines (AccessLogFile) instead of
	// Logger; nil = one slog INFO line per request on Logger, as before.
	Logs *LogFiles
}

// Server holds the routes. Create with New; register extra routes with
// Handle before calling Handler.
type Server struct {
	Store *site.Store
	Log   *slog.Logger
	Cache *Cache

	cfg     Config
	mux     *http.ServeMux
	hasRoot bool
	// patterns is every pattern registered on either host, in order
	// (Patterns).
	patterns []string

	// two-host mode (APIURL set)
	apiOrigin string       // configured origin, e.g. https://api.nday.land
	apiScheme string       // its scheme
	apiHost   string       // its canonical host (lower case, no default port)
	apiMux    http.Handler // everything the API host serves

	publicScheme string // scheme of cfg.PublicURL

	// apiAuth authenticates the gated routes (SetAPIAuth); nil = every
	// gated route answers 401.
	apiAuth APIAuth
}

// New builds a server with the API routes registered.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 10 * time.Second
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	if cfg.CacheEntries <= 0 {
		cfg.CacheEntries = 2000
	}
	s := &Server{Store: cfg.Store, Log: cfg.Logger, cfg: cfg, mux: http.NewServeMux(),
		Cache: NewCache(cfg.CacheEntries, cfg.RequestTimeout)}
	if cfg.APIURL != "" {
		if sch, host, ok := splitOrigin(cfg.APIURL); ok {
			s.apiOrigin, s.apiScheme, s.apiHost = cfg.APIURL, sch, host
		}
	}
	s.handle("/healthz", GetOnly(http.HandlerFunc(s.healthz)))
	for _, rt := range s.apiRoutes() {
		if s.apiOrigin == "" || rt.page {
			mode := AuthBearer
			if rt.page {
				mode = AuthSession
			}
			s.handle(rt.site, GetOnly(s.Gate(mode, rt.h)))
		} else {
			s.handle(rt.site, GetOnly(http.HandlerFunc(s.redirectToAPI)))
		}
	}
	if s.apiOrigin != "" {
		s.apiMux = s.buildAPIMux()
	}
	if sch, _, ok := splitOrigin(cfg.PublicURL); ok {
		s.publicScheme = sch
	}
	s.handle("/api/", GetOnly(http.HandlerFunc(notFound)))
	s.handle("/raw/", GetOnly(http.HandlerFunc(notFound)))
	return s
}

// handle registers pattern on the site mux and remembers it.
func (s *Server) handle(pattern string, h http.Handler) {
	s.patterns = append(s.patterns, pattern)
	s.mux.Handle(pattern, h)
}

// Patterns returns every pattern registered so far on the site host and,
// in two-host mode, on the API host (net/http pattern syntax, method
// included when one was given). Tests use it to check that each top-level
// path segment is reserved as a handle (internal/auth ReservedNames).
func (s *Server) Patterns() []string { return append([]string(nil), s.patterns...) }

// Handle registers an extra route (net/http ServeMux pattern syntax).
func (s *Server) Handle(pattern string, h http.Handler) {
	p := pattern
	if i := strings.IndexByte(p, ' '); i >= 0 {
		p = strings.TrimSpace(p[i+1:])
	}
	if p == "/" {
		s.hasRoot = true
	}
	s.handle(pattern, h)
}

// HandleFunc is Handle for a function.
func (s *Server) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	s.Handle(pattern, http.HandlerFunc(h))
}

// Handler returns the complete handler with middleware. Call it after all
// Handle calls. In two-host mode it dispatches on the Host header first:
// the API host gets only the API mux, every other host the site mux. When
// the public origin's host is www.<X>, GET/HEAD requests for the bare <X>
// answer 308 to the same path and query on the public origin (apex.go).
// With a public origin configured, any other host that is not a loopback
// name is not served either (foreign.go).
func (s *Server) Handler() http.Handler {
	if !s.hasRoot {
		s.hasRoot = true
		s.mux.Handle("/", http.HandlerFunc(notFound))
	}
	site, api := s.mux, s.apiMux
	apex := s.apexHost()
	_, public, gated := splitOrigin(s.cfg.PublicURL)
	var h http.Handler = s.mux
	if api != nil || apex != "" || gated {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := canonicalHost(s.publicScheme, strings.ToLower(r.Host))
			read := r.Method == http.MethodGet || r.Method == http.MethodHead
			switch {
			case api != nil && s.IsAPIHost(r.Host):
				api.ServeHTTP(w, r)
			case apex != "" && read && host == apex:
				s.redirectApex(w, r)
			case gated && host != public && (apex == "" || host != apex) && !loopbackHost(host):
				// a host this site is not configured for (foreign.go)
				if read {
					s.redirectPublic(w, r, CacheNever)
				} else {
					WriteError(w, http.StatusMisdirectedRequest, "wrong_host", "this host does not serve the site", "")
				}
			default:
				site.ServeHTTP(w, r)
			}
		})
	}
	return Chain(h, s.Middleware()...)
}

// Middleware is the stack Handler applies, outermost first.
func (s *Server) Middleware() []Middleware {
	access := AccessLog(s.Log)
	if s.cfg.Logs != nil {
		access = AccessLogFile(s.cfg.Logs, s.Log, s.cfg.PublicURL, s.apiOrigin)
	}
	return []Middleware{access, Recover(s.Log), SecurityHeaders, Timeout(s.cfg.RequestTimeout)}
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	WriteError(w, http.StatusNotFound, "not_found", "no such endpoint", "")
}

// Server timeouts (Serve).
const (
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	WriteTimeout      = 30 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 32 << 10
	ShutdownTimeout   = 20 * time.Second
)

// NewHTTPServer returns an http.Server with production timeouts.
func NewHTTPServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// TLSOptions enable HTTPS in Serve. CertFile and KeyFile are PEM files
// (e.g. a Cloudflare origin certificate). ClientCAFile, if set, makes the
// server REQUIRE a client certificate signed by that CA (Cloudflare
// Authenticated Origin Pulls): connections without one fail the handshake.
type TLSOptions struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
}

// Enabled reports whether any TLS option is set.
func (o TLSOptions) Enabled() bool {
	return o.CertFile != "" || o.KeyFile != "" || o.ClientCAFile != ""
}

// Validate checks that the options are consistent (files are read by Config).
func (o TLSOptions) Validate() error {
	switch {
	case !o.Enabled():
		return nil
	case o.CertFile == "" || o.KeyFile == "":
		return errors.New("TLS needs both a certificate and a key (--tls-cert and --tls-key)")
	}
	return nil
}

// Config builds the server TLS configuration: TLS 1.2 minimum, the given
// certificate, and mandatory verified client certificates when ClientCAFile
// is set. nil, nil when TLS is not enabled.
func (o TLSOptions) Config() (*tls.Config, error) {
	if !o.Enabled() {
		return nil, nil
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: loading certificate/key: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if o.ClientCAFile != "" {
		pem, err := os.ReadFile(o.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls: reading client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls: no PEM certificate in client CA file %s", o.ClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// Serve listens on addr and serves h until ctx is cancelled (SIGTERM /
// SIGINT in the CLI), then shuts down gracefully: stops accepting, waits up
// to ShutdownTimeout for in-flight requests. ready, if non-nil, receives the
// bound address once listening.
func Serve(ctx context.Context, addr string, h http.Handler, log *slog.Logger, ready func(net.Addr)) error {
	return ServeTLS(ctx, addr, h, log, ready, nil)
}

// ServeTLS is Serve over TLS when tlsCfg is non-nil (see TLSOptions.Config),
// plain HTTP otherwise.
func ServeTLS(ctx context.Context, addr string, h http.Handler, log *slog.Logger, ready func(net.Addr), tlsCfg *tls.Config) error {
	srv := NewHTTPServer(addr, h, log)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if ready != nil {
		ready(ln.Addr())
	}
	errc := make(chan error, 1)
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
		log.Info("listening", "addr", ln.Addr().String(), "tls", true,
			"client_cert", tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert)
		go func() { errc <- srv.ServeTLS(ln, "", "") }()
	} else {
		log.Info("listening", "addr", ln.Addr().String())
		go func() { errc <- srv.Serve(ln) }()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down", "timeout", ShutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
