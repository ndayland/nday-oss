package web

import (
	"net/http"
	"net/url"
	"strings"
)

// Apex redirect. Session cookies are __Host- cookies of the public host, so
// a visitor on the bare domain would never see their sign-in state there
// (and WebAuthn/Origin checks would refuse it). When NDAY_PUBLIC_URL is
// https://www.<X>, a GET or HEAD for host <X> (case-insensitive, default
// port ignored) answers 308 to the same path and query on the public
// origin. Other methods, the API host and every other host are untouched.

// apexHost is the bare host of a www. public origin ("" otherwise).
func (s *Server) apexHost() string {
	_, host, ok := splitOrigin(s.cfg.PublicURL)
	if !ok {
		return ""
	}
	apex, ok := strings.CutPrefix(host, "www.")
	if !ok || apex == "" || strings.HasPrefix(apex, ".") || strings.HasPrefix(apex, ":") {
		return ""
	}
	if s.apiHost != "" && apex == s.apiHost {
		return ""
	}
	return apex
}

func (s *Server) redirectApex(w http.ResponseWriter, r *http.Request) {
	s.redirectPublic(w, r, "public, max-age=3600")
}

// redirectPublic answers 308 to the same path and query on the public
// origin, with the given Cache-Control.
func (s *Server) redirectPublic(w http.ResponseWriter, r *http.Request, cache string) {
	target, ok := s.apexRedirectTarget(r.URL.EscapedPath(), r.URL.RawQuery)
	if !ok {
		WriteError(w, http.StatusBadRequest, "bad_request", "this URL cannot be redirected to the public host", "")
		return
	}
	h := w.Header()
	h.Set("Location", target)
	h.Set("Cache-Control", cache)
	w.WriteHeader(http.StatusPermanentRedirect)
}

// apexRedirectTarget maps an escaped path and raw query to the public
// origin. Same safety approach as apiRedirectTarget: the URL is built only
// from the configured origin, the path must be absolute and may not start
// with "//" or contain a backslash, no control characters anywhere, and the
// re-parsed result must keep exactly the configured origin.
func (s *Server) apexRedirectTarget(escapedPath, rawQuery string) (string, bool) {
	origin := strings.TrimRight(s.cfg.PublicURL, "/")
	if origin == "" || !strings.HasPrefix(escapedPath, "/") || strings.HasPrefix(escapedPath, "//") ||
		strings.ContainsRune(escapedPath, '\\') {
		return "", false
	}
	target := origin + escapedPath
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme+"://"+u.Host != origin || u.User != nil || u.Fragment != "" ||
		!strings.HasPrefix(u.EscapedPath(), "/") {
		return "", false
	}
	return target, true
}
