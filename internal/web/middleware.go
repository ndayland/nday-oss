package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares so that the first one is the outermost.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// statusWriter records the status and size of a response.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// AccessLog logs one line per request: method, path, query (truncated),
// status, bytes, duration, and the client IP from CF-Connecting-IP (a log
// field only; never used for any decision). No other headers are logged.
func AccessLog(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			defer func() {
				status := sw.status
				if status == 0 {
					status = http.StatusOK
				}
				attrs := []any{"method", r.Method, "path", trunc(r.URL.Path, 300), "status", status,
					"bytes", sw.bytes, "dur_ms", float64(time.Since(start).Microseconds()) / 1000}
				if q := r.URL.RawQuery; q != "" {
					attrs = append(attrs, "query", trunc(RedactQuery(r.URL.Path, q), 300))
				}
				if ip := clientIP(r); ip != "" {
					attrs = append(attrs, "cf_ip", ip)
				}
				if c := sw.Header().Get("X-Nday-Cache"); c != "" {
					attrs = append(attrs, "cache", c)
				}
				log.Info("http", attrs...)
			}()
			next.ServeHTTP(sw, r)
		})
	}
}

// RedactQuery hides query values that must never reach a log: under
// /auth/ (sign-in: authorization codes, state, CSRF tokens) every value
// except return, intent and error is replaced by "REDACTED".
func RedactQuery(path, rawQuery string) string {
	if !strings.HasPrefix(path, "/auth/") {
		return rawQuery
	}
	parts := strings.Split(rawQuery, "&")
	for i, kv := range parts {
		k, _, hasVal := strings.Cut(kv, "=")
		if hasVal && k != "return" && k != "intent" && k != "error" {
			parts[i] = k + "=REDACTED"
		}
	}
	return strings.Join(parts, "&")
}

// clientIP returns CF-Connecting-IP if it looks like an IP address.
func clientIP(r *http.Request) string {
	v := r.Header.Get("CF-Connecting-IP")
	if len(v) > 45 {
		return ""
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':') {
			return ""
		}
	}
	return v
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Recover turns a panic into a logged error and (if nothing was written
// yet) a JSON 500. http.ErrAbortHandler is re-raised.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw, ok := w.(*statusWriter)
			if !ok {
				sw = &statusWriter{ResponseWriter: w}
			}
			defer func() {
				p := recover()
				if p == nil {
					return
				}
				if p == http.ErrAbortHandler {
					panic(p)
				}
				log.Error("panic", "method", r.Method, "path", trunc(r.URL.Path, 300), "panic", fmt.Sprint(p),
					"stack", string(debug.Stack()))
				if sw.status == 0 {
					WriteError(sw, http.StatusInternalServerError, "internal", "internal error", "")
				}
			}()
			next.ServeHTTP(sw, r)
		})
	}
}

// Timeout gives every request a context deadline (database queries are
// cancelled when it expires).
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PermissionsPolicy is sent on every response (SecurityHeaders).
const PermissionsPolicy = "publickey-credentials-create=(self), publickey-credentials-get=(self)"

// SecurityHeaders sets headers every response gets.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Passkeys (WebAuthn): only the site itself, never a frame of another origin.
		h.Set("Permissions-Policy", PermissionsPolicy)
		next.ServeHTTP(w, r)
	})
}

// GetOnly answers anything but GET/HEAD with a JSON 405.
func GetOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET and HEAD are supported", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Cache-Control values.
const (
	CacheList  = "public, max-age=60"
	CacheRaw   = "public, max-age=3600"
	CacheNever = "no-store"
)

// APIError is the JSON error body: {"error": {...}}.
type APIError struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Param   string `json:"param,omitempty"`
}

// WriteError writes a JSON error (Cache-Control: no-store unless already set).
func WriteError(w http.ResponseWriter, status int, code, msg, param string) {
	h := w.Header()
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", CacheNever)
	}
	h.Del("ETag")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	b, _ := json.Marshal(struct {
		Error APIError `json:"error"`
	}{APIError{Status: status, Code: code, Message: msg, Param: param}})
	_, _ = w.Write(append(b, '\n'))
}

// EncodeJSON renders v as compact JSON with a trailing newline (HTML
// characters are not escaped: this is an API, served as application/json).
func EncodeJSON(v any) ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// Body is an encoded response with its validator.
type Body struct {
	JSON []byte
	ETag string
}

// NewBody encodes v and computes a weak ETag from the bytes.
func NewBody(v any) (Body, error) {
	b, err := EncodeJSON(v)
	if err != nil {
		return Body{}, err
	}
	sum := sha256.Sum256(b)
	return Body{JSON: b, ETag: `W/"` + hex.EncodeToString(sum[:12]) + `"`}, nil
}

// WriteBody writes a JSON body with ETag and Cache-Control, answering
// If-None-Match with 304.
func WriteBody(w http.ResponseWriter, r *http.Request, status int, b Body, cacheControl string) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", cacheControl)
	if b.ETag != "" {
		h.Set("ETag", b.ETag)
		if status == http.StatusOK && etagMatch(r.Header.Get("If-None-Match"), b.ETag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	h.Set("Content-Length", fmt.Sprint(len(b.JSON)))
	w.WriteHeader(status)
	_, _ = w.Write(b.JSON)
}

// etagMatch implements weak comparison for If-None-Match.
func etagMatch(header, etag string) bool {
	if header == "" {
		return false
	}
	norm := func(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), "W/") }
	for _, t := range strings.Split(header, ",") {
		if strings.TrimSpace(t) == "*" || norm(t) == norm(etag) {
			return true
		}
	}
	return false
}

// errorStatus maps an error from the query layer to an HTTP status.
func isTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}
