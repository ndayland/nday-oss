package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"nday.land/nday/internal/web"
)

type ctxKey struct{}

type principal struct {
	user    *User
	session *Session
}

// CurrentUser returns the signed-in user of a request that went through
// Load, RequireUser, RequireActive or RequireRole; nil when signed out (or
// when the request did not pass through one of them).
func CurrentUser(r *http.Request) *User {
	if p, ok := r.Context().Value(ctxKey{}).(*principal); ok && p != nil {
		return p.user
	}
	return nil
}

func withPrincipal(r *http.Request, p *principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, p))
}

// noStoreWriter makes a personal response uncacheable whatever the wrapped
// handler sets: when the header is written
// (WriteHeader with a final status, first Write or Flush) it forces
// Cache-Control: no-store, removes ETag, Last-Modified, Expires and the CDN
// cache headers (CDN-Cache-Control, Cloudflare-CDN-Cache-Control,
// Surrogate-Control), and adds
// Vary: Cookie.
type noStoreWriter struct {
	http.ResponseWriter
	done bool
}

func (w *noStoreWriter) apply() {
	h := w.Header()
	h.Set("Cache-Control", web.CacheNever)
	h.Del("ETag")
	h.Del("Last-Modified")
	h.Del("Expires")
	// CDN-specific directives would override Cache-Control at the edge
	h.Del("CDN-Cache-Control")
	h.Del("Cloudflare-CDN-Cache-Control")
	h.Del("Surrogate-Control")
	for _, v := range h.Values("Vary") {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); strings.EqualFold(t, "Cookie") || t == "*" {
				return
			}
		}
	}
	h.Add("Vary", "Cookie")
}

func (w *noStoreWriter) WriteHeader(code int) {
	if !w.done {
		w.apply()
		w.done = code >= 200 // 1xx: the final header comes later
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *noStoreWriter) Write(b []byte) (int, error) {
	if !w.done {
		w.apply()
		w.done = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *noStoreWriter) Flush() {
	if !w.done {
		w.apply()
		w.done = true
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *noStoreWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// personal wraps w in a noStoreWriter and drops the conditional request
// headers, so the handler never answers 304 to a personal request; the
// deferred call fixes the headers when the handler panics before writing
// (web.Recover then writes its 500 through the same header map).
func personal(w http.ResponseWriter, r *http.Request) (*noStoreWriter, *http.Request) {
	nw := &noStoreWriter{ResponseWriter: w}
	if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
		r = r.Clone(r.Context())
		r.Header.Del("If-None-Match")
		r.Header.Del("If-Modified-Since")
	}
	return nw, r
}

func (w *noStoreWriter) onPanic() {
	if p := recover(); p != nil {
		if !w.done {
			w.apply()
		}
		panic(p)
	}
}

// PublicHost reports whether host (a request's Host header) is the host of
// the configured public origin (case-insensitive, explicit default port
// ignored): the same test the built-in routes use to answer 421 wrong_host.
// Features outside this package that read the
// session use it so another Cloudflare zone pointed at the origin cannot
// proxy them. A nil *Service answers false.
func (s *Service) PublicHost(host string) bool {
	return s != nil && canonicalHost(s.scheme(), strings.ToLower(host)) == s.host
}

// Load makes CurrentUser available to next without requiring a session.
// When the request carries a session cookie (valid or not) the final
// response is always Cache-Control: no-store with Vary: Cookie and no
// validators, whatever next sets; requests without one get no-store as a
// default that next may override. Still, do NOT wrap public, cacheable
// pages with it: they would lose their caching for signed-in visitors.
func (s *Service) Load(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", web.CacheNever)
		if s == nil {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie(SessionCookie); err == nil {
			nw, r2 := personal(w, r)
			defer nw.onPanic()
			w, r = nw, r2
		}
		ss, u, _, err := s.session(r)
		if err != nil {
			s.sessionError(w, err)
			return
		}
		if ss != nil {
			r = withPrincipal(r, &principal{user: u, session: ss})
		}
		next.ServeHTTP(w, r)
	})
}

// RequireUser answers 401 unless the request has a valid session. For
// methods other than GET/HEAD/OPTIONS it also enforces the same-origin and
// CSRF checks of the built-in endpoints (header X-CSRF-Token), so a future
// write feature is protected by default. The final response is always
// no-store (see Load).
func (s *Service) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nw, r := personal(w, r)
		defer nw.onPanic()
		w = nw
		w.Header().Set("Cache-Control", web.CacheNever)
		if s == nil {
			web.WriteError(w, http.StatusNotFound, "not_found", "accounts are not enabled", "")
			return
		}
		var ss *Session
		var u *User
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			var present bool
			var err error
			ss, u, present, err = s.session(r)
			if err != nil {
				s.sessionError(w, err)
				return
			}
			if ss == nil {
				if present {
					s.clearCookie(w, SessionCookie)
				}
				web.WriteError(w, http.StatusUnauthorized, "not_signed_in", "sign in first", "")
				return
			}
		default:
			var ok bool
			if ss, u, ok = s.guard(w, r); !ok {
				return
			}
		}
		next.ServeHTTP(w, withPrincipal(r, &principal{user: u, session: ss}))
	})
}

// RequireActive is RequireUser that also refuses (403 "suspended") users
// whose suspension has not elapsed. Use it for every write feature.
func (s *Service) RequireActive(next http.Handler) http.Handler {
	return s.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if CurrentUser(r).EffectiveStatus(s.now()) != StatusActive {
			web.WriteError(w, http.StatusForbidden, "suspended", "your account is suspended", "")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RecentSignIn reports whether the session of a request that went through
// Load/RequireUser/RequireActive/RequireRole was created within the
// sensitive-action window (the same needRecent rule as the built-in
// endpoints; false when signed out). Features with sensitive actions answer
// 403 "reauth_required" when it is false.
func (s *Service) RecentSignIn(r *http.Request) bool {
	p, ok := r.Context().Value(ctxKey{}).(*principal)
	if s == nil || !ok || p == nil || p.session == nil {
		return false
	}
	_, code, _ := s.refusal(s.cur(r.Context()).cfg, p.session, p.user, needRecent)
	return code == ""
}

// Now is the service clock (tests set Options.Now).
func (s *Service) Now() time.Time { return s.now() }

// RequireRole is RequireActive plus a minimum role (user < moderator < admin).
func (s *Service) RequireRole(min string) func(http.Handler) http.Handler {
	if !ValidRole(min) {
		panic("auth: RequireRole: unknown role " + min)
	}
	return func(next http.Handler) http.Handler {
		return s.RequireActive(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !CurrentUser(r).HasRole(min) {
				web.WriteError(w, http.StatusForbidden, "forbidden", "insufficient role", "")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}
