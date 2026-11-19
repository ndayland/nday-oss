package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Environment variables naming the public origins (read by `nday serve`).
const (
	// EnvPublicURL is the public site origin, e.g. https://www.nday.land.
	EnvPublicURL = "NDAY_PUBLIC_URL"
	// EnvAPIURL is the optional origin of the public data API host, e.g.
	// https://api.nday.land. Unset: single-host mode (the API lives under
	// /api/ and /raw/ of the site host).
	EnvAPIURL = "NDAY_API_URL"
)

// DefaultPublicURL is the site origin used in links when none is configured.
const DefaultPublicURL = "https://nday.land"

// APICSP is the Content-Security-Policy of every response on the API host
// (JSON only: nothing may load, nothing may frame it).
const APICSP = "default-src 'none'; frame-ancestors 'none'"

// apiAllowHeaders are the request headers a cross-origin preflight may ask
// for. Accept is CORS-safelisted anyway; Authorization carries the API
// token; If-None-Match is what makes the ETags useful from a browser.
const apiAllowHeaders = "Accept, Authorization, If-None-Match"

// ParseOrigin returns v as an origin ("scheme://host[:port]") when it is an
// absolute http(s) URL without credentials, path, query or fragment and its
// host[:port] is made of plain hostname characters only. Surrounding space
// and trailing slashes are ignored; "" stays "" without an error.
func ParseOrigin(v string) (string, error) {
	v = strings.TrimRight(strings.TrimSpace(v), "/")
	if v == "" {
		return "", nil
	}
	bad := errors.New("must be an origin like https://api.nday.land (http or https, no user info, path, query or fragment)")
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", bad
	}
	for _, r := range u.Host { // host[:port] made of plain hostname characters only
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':') {
			return "", bad
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

// SameOrigin reports whether two origins from ParseOrigin name the same
// scheme and host (case-insensitive, default port ignored).
func SameOrigin(a, b string) bool {
	sa, ha, okA := splitOrigin(a)
	sb, hb, okB := splitOrigin(b)
	return okA && okB && sa == sb && ha == hb
}

// splitOrigin returns the scheme and canonical host of an origin.
func splitOrigin(o string) (scheme, host string, ok bool) {
	scheme, rest, ok := strings.Cut(o, "://")
	if !ok || rest == "" {
		return "", "", false
	}
	scheme = strings.ToLower(scheme)
	return scheme, canonicalHost(scheme, strings.ToLower(rest)), true
}

// canonicalHost drops an explicit default port (":443" for https, ":80" for
// http) and an empty port. Same rule as internal/auth's canonicalHost (which
// imports this package, so it cannot be shared).
func canonicalHost(scheme, host string) string {
	def := map[string]string{"https": "443", "http": "80"}[scheme]
	if h, ok := strings.CutSuffix(host, ":"); ok {
		return h
	}
	if def != "" {
		if h, ok := strings.CutSuffix(host, ":"+def); ok && (!strings.Contains(h, ":") || strings.HasSuffix(h, "]")) {
			return h
		}
	}
	return host
}

// APIOrigin is the configured API host origin ("" in single-host mode).
func (s *Server) APIOrigin() string { return s.apiOrigin }

// PublicURL is the configured public site origin ("" when not configured).
func (s *Server) PublicURL() string { return s.cfg.PublicURL }

// IsAPIHost reports whether a request Host header names the API host
// (case-insensitive, default port ignored). Always false in single-host mode.
func (s *Server) IsAPIHost(host string) bool {
	return s.apiHost != "" && canonicalHost(s.apiScheme, strings.ToLower(host)) == s.apiHost
}

// apiRoute is one data endpoint: its path on the site host in single-host
// mode and on the API host. Every one needs an API token (Gate). page: the
// site's own pages use it (page scripts, whose CSP connect-src 'self'
// forbids following a redirect to the API host, or links a signed-in reader
// opens), so the site host keeps answering it in two-host mode too and
// there also accepts the session cookie.
type apiRoute struct {
	site, api string
	h         http.HandlerFunc
	page      bool
}

func (s *Server) apiRoutes() []apiRoute {
	return []apiRoute{
		{"/api/hot", "/v1/hot", s.hot, false},
		{"/api/vulns", "/v1/vulns", s.vulns, false},
		{"/api/discussed", "/v1/discussed", s.discussed, false},
		{"/api/vuln/{cve}", "/v1/vuln/{cve}", s.vuln, false},
		{"/api/sources", "/v1/sources", s.sources, false},
		{"/api/stats", "/v1/stats", s.stats, false},
		{"/api/search", "/v1/search", s.search, false},
		{"/api/tags", "/v1/tags", s.tags, false},
		{"/api/affected/suggest", "/v1/affected/suggest", s.suggest, true},
		{"/raw/{source}/{key...}", "/v1/raw/{source}/{key...}", s.raw, true},
	}
}

// apiEndpoints are listed by the API host's index (GET / and GET /v1).
var apiEndpoints = []string{"/v1/hot", "/v1/vulns", "/v1/discussed", "/v1/vuln/{cve}", "/v1/search", "/v1/tags", "/v1/affected/suggest", "/v1/sources", "/v1/stats",
	"/v1/raw/{source}/{key}.json", "/healthz"}

// buildAPIMux returns the only handler the API host ever reaches: the data
// endpoints under /v1 and /raw/... (alias of /v1/raw/...), which need an API
// token, and the public /healthz, index, robots.txt and JSON 404s.
// Nothing registered with Handle (pages, sign-in, static files) is on it.
func (s *Server) buildAPIMux() http.Handler {
	mux := http.NewServeMux()
	m := &recordingMux{ServeMux: mux, patterns: &s.patterns}
	for _, rt := range s.apiRoutes() {
		m.Handle(rt.api, GetOnly(s.Gate(AuthBearer, rt.h)))
	}
	m.Handle("/healthz", GetOnly(http.HandlerFunc(s.healthz)))
	// Alias: raw_records[].path in /v1/vuln is "/raw/...", so it resolves
	// against the API origin too.
	m.Handle("/raw/{source}/{key...}", GetOnly(s.Gate(AuthBearer, http.HandlerFunc(s.raw))))
	docs := s.cfg.PublicURL
	if docs == "" {
		docs = DefaultPublicURL
	}
	type authHint struct {
		Scheme   string `json:"scheme"`
		Header   string `json:"header"`
		TokenURL string `json:"token_url"`
	}
	index, err := NewBody(struct {
		Name      string   `json:"name"`
		Docs      string   `json:"docs"`
		Auth      authHint `json:"auth"`
		Endpoints []string `json:"endpoints"`
	}{"nday", docs + "/account#api", authHint{"Bearer", "Authorization", docs + "/account#api"}, apiEndpoints})
	if err != nil {
		panic(err) // static data
	}
	serveIndex := func(w http.ResponseWriter, r *http.Request) { WriteBody(w, r, http.StatusOK, index, CacheList) }
	m.Handle("/{$}", GetOnly(http.HandlerFunc(serveIndex)))
	m.Handle("/v1", GetOnly(http.HandlerFunc(serveIndex)))
	m.Handle("/robots.txt", GetOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})))
	m.Handle("/", http.HandlerFunc(notFound))
	return APIHeaders(mux)
}

// recordingMux is a ServeMux that also appends each pattern to patterns
// (Server.Patterns).
type recordingMux struct {
	*http.ServeMux
	patterns *[]string
}

func (m *recordingMux) Handle(pattern string, h http.Handler) {
	*m.patterns = append(*m.patterns, pattern)
	m.ServeMux.Handle(pattern, h)
}

func (m *recordingMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(h))
}

// APIHeaders is the API host's middleware: CORS for any origin (never with
// credentials), a JSON-only CSP, cross-origin resource policy, answers
// OPTIONS preflights with 204, refuses methods other than GET/HEAD/OPTIONS
// with a JSON 405, and strips any Set-Cookie before it is sent.
func APIHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", "ETag, Retry-After, WWW-Authenticate")
		h.Set("Cross-Origin-Resource-Policy", "cross-origin")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", APICSP)
		w = &noCookieWriter{ResponseWriter: w}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		case http.MethodOptions:
			h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
			h.Set("Access-Control-Allow-Headers", apiAllowHeaders)
			h.Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			h.Set("Allow", "GET, HEAD, OPTIONS")
			WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET, HEAD and OPTIONS are supported", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// noCookieWriter deletes Set-Cookie from the header before it is written.
type noCookieWriter struct{ http.ResponseWriter }

func (w *noCookieWriter) WriteHeader(code int) {
	w.ResponseWriter.Header().Del("Set-Cookie")
	w.ResponseWriter.WriteHeader(code)
}

func (w *noCookieWriter) Write(b []byte) (int, error) {
	w.ResponseWriter.Header().Del("Set-Cookie")
	return w.ResponseWriter.Write(b)
}

func (w *noCookieWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// redirectToAPI answers a data route on the site host (two-host mode) with
// 308 to the same endpoint under NDAY_API_URL/v1, keeping the query string.
func (s *Server) redirectToAPI(w http.ResponseWriter, r *http.Request) {
	target, ok := s.apiRedirectTarget(r.URL.EscapedPath(), r.URL.RawQuery)
	if !ok {
		WriteError(w, http.StatusBadRequest, "bad_request", "this URL cannot be redirected to the API host", "")
		return
	}
	h := w.Header()
	h.Set("Location", target)
	h.Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusPermanentRedirect)
}

// apiRedirectTarget maps an escaped site path ("/api/hot", "/raw/k/x.json")
// and raw query to its URL on the API host. The URL is built only from the
// configured origin; the result is re-parsed and must keep that origin and a
// /v1/ path, and may not contain control characters or backslashes outside
// the query. ok is false otherwise.
func (s *Server) apiRedirectTarget(escapedPath, rawQuery string) (string, bool) {
	var rest string
	switch {
	case strings.HasPrefix(escapedPath, "/api/"):
		rest = strings.TrimPrefix(escapedPath, "/api")
	case strings.HasPrefix(escapedPath, "/raw/"):
		rest = escapedPath
	default:
		return "", false
	}
	if s.apiOrigin == "" || strings.HasPrefix(rest, "//") || strings.ContainsRune(rest, '\\') {
		return "", false
	}
	target := s.apiOrigin + "/v1" + rest
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme+"://"+u.Host != s.apiOrigin || u.User != nil || u.Fragment != "" ||
		!strings.HasPrefix(u.EscapedPath(), "/v1/") {
		return "", false
	}
	return target, true
}
