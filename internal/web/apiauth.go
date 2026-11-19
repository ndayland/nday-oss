package web

import (
	"net/http"
	"strings"
)

// AuthMode lists the credentials a gated route accepts. A personal access
// token in "Authorization: Bearer <token>" is always accepted.
type AuthMode uint8

const (
	// AuthBearer: the API token only.
	AuthBearer AuthMode = 0
	// AuthSession: also the session cookie of a signed-in user (site host
	// only: page scripts and links in signed-in pages).
	AuthSession AuthMode = 1 << 0
	// AuthFeedKey: also the private feed key in ?key= (the Atom feed only).
	AuthFeedKey AuthMode = 1 << 1
)

// APIAuth authenticates requests to gated routes (internal/auth.Service
// implements it). On failure AuthenticateData writes the error response and
// returns ok false; on success it returns the writer and request the
// handler must use (it may wrap the writer, e.g. no-store for a response
// authenticated by the session cookie).
type APIAuth interface {
	AuthenticateData(w http.ResponseWriter, r *http.Request, mode AuthMode) (http.ResponseWriter, *http.Request, bool)
}

// SetAPIAuth installs the authenticator of the gated routes. Call it before
// serving. Without one every gated route answers 401 token_required: the data
// API needs accounts.
func (s *Server) SetAPIAuth(a APIAuth) { s.apiAuth = a }

// AuthRealm is the realm of the WWW-Authenticate challenge.
const AuthRealm = `Bearer realm="nday"`

// WriteUnauthorized writes a 401 JSON error with the Bearer challenge.
func WriteUnauthorized(w http.ResponseWriter, code, msg string) {
	w.Header().Set("WWW-Authenticate", AuthRealm)
	WriteError(w, http.StatusUnauthorized, code, msg, "")
}

// MsgTokenRequired is the message of the 401 token_required error.
const MsgTokenRequired = "this endpoint needs an API token: send Authorization: Bearer <token> (create one on your account page)"

// Gate runs next only for a request authenticated by the credentials mode
// allows. The authentication runs before next, so nothing next computes or
// caches (the in-process response cache) is served to an unauthenticated
// request. Every response carries Vary: Authorization, and a response next
// marks "public" is sent "private" instead (no shared cache may keep it).
// The feed key mode also sets Referrer-Policy: no-referrer.
func (s *Server) Gate(mode AuthMode, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Vary", "Authorization")
		if mode&AuthFeedKey != 0 {
			h.Set("Referrer-Policy", "no-referrer")
		}
		if s.apiAuth == nil {
			WriteUnauthorized(w, "token_required", MsgTokenRequired)
			return
		}
		w2, r2, ok := s.apiAuth.AuthenticateData(w, r, mode)
		if !ok {
			return
		}
		next.ServeHTTP(&privateWriter{ResponseWriter: w2}, r2)
	})
}

// privateWriter rewrites a "public" Cache-Control to "private" when the
// header is written, and drops the CDN-specific cache headers.
type privateWriter struct {
	http.ResponseWriter
	done bool
}

func (w *privateWriter) apply() {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	h.Set("Cache-Control", PrivateCache(h.Get("Cache-Control")))
	h.Del("CDN-Cache-Control")
	h.Del("Cloudflare-CDN-Cache-Control")
	h.Del("Surrogate-Control")
}

func (w *privateWriter) WriteHeader(code int) {
	if code >= 200 {
		w.apply()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *privateWriter) Write(b []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(b)
}

func (w *privateWriter) Flush() {
	w.apply()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *privateWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// PrivateCache turns a Cache-Control value into one no shared cache may
// store: "public" and s-maxage are dropped, a qualified private="…" is
// replaced by a bare "private", and "private" is added when neither a bare
// private nor no-store is present ("" becomes "private, no-cache").
func PrivateCache(cc string) string {
	if strings.TrimSpace(cc) == "" {
		return "private, no-cache"
	}
	parts := strings.Split(cc, ",")
	out := make([]string, 0, len(parts)+1)
	private := false
	for _, p := range parts {
		p = strings.TrimSpace(p)
		name, _, _ := strings.Cut(p, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "public", "s-maxage":
			continue
		case "private":
			if !strings.EqualFold(p, "private") {
				continue // private="field": shared caches may keep the rest; replaced by a bare private
			}
			private = true
		case "no-store":
			private = true
		}
		if p != "" {
			out = append(out, p)
		}
	}
	if !private {
		out = append([]string{"private"}, out...)
	}
	return strings.Join(out, ", ")
}
