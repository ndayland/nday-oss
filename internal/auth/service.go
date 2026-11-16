package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/web"
)

// Cookie names. The __Host- prefix makes browsers accept the cookie only
// with Secure, Path=/ and no Domain, so a sibling subdomain can neither set
// nor overwrite it.
const (
	SessionCookie = "__Host-nday_session"
	FlowCookie    = "__Host-nday_flow"
)

// FlowTTL is how long a started sign-in may take.
const FlowTTL = 10 * time.Minute

// CSRFHeader carries the CSRF token on state-changing requests.
const CSRFHeader = "X-CSRF-Token"

// Outcome codes appended to the return path as ?auth=<code>.
const (
	OutcomeOK       = "ok"
	OutcomeLinked   = "linked"
	OutcomeDenied   = "denied"
	OutcomeConflict = "conflict"
	OutcomeError    = "error"
	// OutcomeSignedInAsOther: a signed-in browser started a plain sign-in
	// that would have ended on another (or a new) account; nothing changed
	// Switching accounts needs a "switch" ticket.
	OutcomeSignedInAsOther = "signed_in_as_other"
	// OutcomeReauthRequired: a link was finished on a session older than
	// the sensitive-action window.
	OutcomeReauthRequired = "reauth_required"
	// OutcomeSuspended: a suspended user tried to link an identity.
	OutcomeSuspended = "suspended"
)

// Options for New.
type Options struct {
	Store  *Store
	Logger *slog.Logger
	// Client for provider calls (default NewProviderClient()).
	Client *http.Client
	// Endpoints overrides ProductionEndpoints per provider (tests).
	Endpoints map[string]Endpoints
	// Now is the clock (tests); the Store has its own.
	Now func() time.Time
	// StartLimit and CallbackLimit rate-limit the two public flow endpoints
	// per client address (defaults: burst 10, then 1 per 6 s each).
	StartLimit, CallbackLimit *RateLimiter
	// PasskeyLimit rate-limits the anonymous passkey endpoints (default
	// burst 20, then 1 per 3 s).
	PasskeyLimit *RateLimiter
	// AccountLimit rate-limits /api/me and every signed-in endpoint per
	// client address (default burst 300, then 5 per second).
	AccountLimit *RateLimiter
	// SignupLimit rate-limits passkey-only sign-up per client address
	// (default burst SignupBurst, then 1 per Config.SignupInterval).
	SignupLimit *RateLimiter
	// TokenLimit rate-limits each session token, whatever the client
	// address (default burst 120, then 4 per second): one cookie replayed
	// from many addresses is throttled by itself.
	TokenLimit *RateLimiter
	// SessionLookups caps concurrent session lookups (and the database work
	// of /api/me), so a flood of session cookies cannot take every
	// connection of the small auth pool (default 2).
	SessionLookups int
}

// Service is the sign-in and account HTTP surface. A nil *Service is a
// valid "feature disabled" value for the helper middlewares.
type Service struct {
	// state is the part derived from the replaceable configuration
	// (Reconfigure); a request reads it once (cur).
	state atomic.Pointer[authState]
	// origin is Config.PublicOrigin, fixed for the life of the service.
	origin    string
	endpoints map[string]Endpoints // Options.Endpoints
	// signupFixed: Options.SignupLimit was given; Reconfigure keeps it.
	signupFixed bool
	reconfMu    sync.Mutex

	store   *Store
	log     *slog.Logger
	hc      *http.Client
	keys    *keyset
	now     func() time.Time
	startRL *RateLimiter
	cbRL    *RateLimiter
	pkRL    *RateLimiter
	acctRL  *RateLimiter
	tokenRL *RateLimiter
	dead    *deadTokens   // token hashes known not to load
	host    string        // host[:port] of PublicOrigin
	lookups chan struct{} // session lookup slots
	rlWarn  warnAggregate // aggregated rate-limit warnings
	signups dailyCounter  // passkey-only sign-ups per day
}

// New builds the service for a validated, enabled configuration.
func New(cfg *Config, opt Options) (*Service, error) {
	if !cfg.Enabled() {
		return nil, errors.New("auth: no provider and no passkeys configured")
	}
	if opt.Store == nil {
		return nil, errors.New("auth: no store")
	}
	keys, err := newKeyset(cfg.Secrets)
	if err != nil {
		return nil, err
	}
	s := &Service{store: opt.Store, log: opt.Logger, hc: opt.Client, keys: keys, endpoints: opt.Endpoints,
		now: opt.Now, startRL: opt.StartLimit, cbRL: opt.CallbackLimit, pkRL: opt.PasskeyLimit,
		acctRL: opt.AccountLimit, signupFixed: opt.SignupLimit != nil, tokenRL: opt.TokenLimit,
		dead: newDeadTokens(deadTokensMax, deadTokensTTL)}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.hc == nil {
		s.hc = NewProviderClient()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.startRL == nil {
		s.startRL = NewRateLimiter(10, 6*time.Second)
	}
	if s.cbRL == nil {
		s.cbRL = NewRateLimiter(10, 6*time.Second)
	}
	if s.pkRL == nil {
		s.pkRL = NewRateLimiter(20, 3*time.Second)
	}
	if s.tokenRL == nil {
		// a real user's tabs call /api/me about once per page view; 120 at
		// once and 4 per second sustained is far above that
		s.tokenRL = NewRateLimiter(120, 250*time.Millisecond)
	}
	if s.acctRL == nil {
		s.acctRL = NewRateLimiter(300, 200*time.Millisecond)
	}
	applyDefaults(cfg)
	n := opt.SessionLookups
	if n <= 0 {
		n = 2
	}
	s.lookups = make(chan struct{}, n)
	u, err := url.Parse(cfg.PublicOrigin)
	if err != nil || u.Host == "" {
		return nil, errors.New("auth: invalid public origin")
	}
	s.host = canonicalHost(u.Scheme, strings.ToLower(u.Host))
	s.origin = cfg.PublicOrigin
	s.state.Store(s.newState(cfg, nil, opt.SignupLimit))
	return s, nil
}

// Enabled lists the enabled providers (of the current configuration).
func (s *Service) Enabled() []string { return append([]string(nil), s.state.Load().enabled...) }

// Config returns the current configuration (see Reconfigure). Treat it as
// read-only.
func (s *Service) Config() *Config { return s.state.Load().cfg }

// Register mounts the auth routes on the web server. Only these three
// subtrees are touched; public pages never see the session cookie.
func (s *Service) Register(srv *web.Server) {
	srv.Handle("/auth/", s)
	srv.Handle("/account/", s)
	srv.Handle("/api/me", s)
}

// ServeHTTP routes /auth/*, /account/* and /api/me. Every response is
// Cache-Control: no-store (enforced on the final header, see noStoreWriter).
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nw := &noStoreWriter{ResponseWriter: w}
	w = nw
	w.Header().Set("Cache-Control", web.CacheNever)
	// These routes answer only for the configured public host, so
	// another Cloudflare zone pointed at this origin cannot proxy them.
	if canonicalHost(s.scheme(), strings.ToLower(r.Host)) != s.host {
		web.WriteError(w, http.StatusMisdirectedRequest, "wrong_host", "this host does not serve sign-in", "")
		return
	}
	// one configuration for the whole request (Reconfigure may swap it)
	st := s.state.Load()
	r = r.WithContext(context.WithValue(r.Context(), stateKey{}, st))
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	type route struct {
		method string
		h      func(http.ResponseWriter, *http.Request)
		// account: a signed-in endpoint (or /api/me), rate limited per
		// client by AccountLimit
		account bool
	}
	var rt *route
	switch {
	case r.URL.Path == "/api/me":
		rt = &route{http.MethodGet, s.me, true}
	case r.URL.Path == "/auth/signout":
		rt = &route{http.MethodPost, s.signOut, true}
	case r.URL.Path == "/auth/signout-all":
		rt = &route{http.MethodPost, s.signOutAll, true}
	case len(segs) == 4 && segs[0] == "auth" && segs[1] == "passkey":
		if h := s.passkeyRoute(st.cfg, segs[2], segs[3]); h != nil {
			rt = &route{http.MethodPost, h, segs[2] == "register"}
		}
	case len(segs) == 4 && segs[0] == "account" && segs[1] == "passkeys":
		if h := s.passkeyAccount(st, segs[2], segs[3]); h != nil {
			rt = &route{http.MethodPost, h, true}
		}
	case len(segs) == 3 && segs[0] == "auth":
		p := st.providers[segs[1]]
		if p == nil {
			break // disabled or unknown provider: 404
		}
		switch segs[2] {
		case "start":
			rt = &route{http.MethodGet, func(w http.ResponseWriter, r *http.Request) { s.start(w, r, p) }, false}
		case "callback":
			rt = &route{http.MethodGet, func(w http.ResponseWriter, r *http.Request) { s.callback(w, r, p) }, false}
		case "unlink":
			rt = &route{http.MethodPost, func(w http.ResponseWriter, r *http.Request) { s.unlink(w, r, p) }, true}
		case "ticket":
			rt = &route{http.MethodPost, func(w http.ResponseWriter, r *http.Request) { s.ticket(w, r, p) }, true}
		}
	case len(segs) == 2 && segs[0] == "account":
		switch segs[1] {
		case "delete":
			rt = &route{http.MethodPost, s.deleteAccount, true}
		case "locale":
			rt = &route{http.MethodPost, s.setLocale, true}
		case "handle":
			rt = &route{http.MethodPost, s.setHandle, true}
		case "accept-terms":
			rt = &route{http.MethodPost, s.acceptTerms, true}
		case "follows":
			rt = &route{http.MethodPost, s.setFollows, true}
		}
	case r.URL.Path == "/account/follows/match":
		rt = &route{http.MethodPost, s.matchFollows, true}
	}
	if rt == nil {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such endpoint", "")
		return
	}
	// Exact methods only (no HEAD alias for the GET routes: a HEAD of
	// the callback would otherwise run the whole code exchange).
	if r.Method != rt.method {
		w.Header().Set("Allow", rt.method)
		web.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use "+rt.method, "")
		return
	}
	if rt.account && s.rateLimited(w, r, s.acctRL, "account") {
		return
	}
	rt.h(w, r)
}

func (s *Service) scheme() string {
	if strings.HasPrefix(s.origin, "http://") {
		return "http"
	}
	return "https"
}

// ---- cookies ----

func (s *Service) secureCookies() bool { return true }

func (s *Service) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(maxAge / time.Second),
		Secure: s.secureCookies(), HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: s.secureCookies(), HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// Session cookie value: base64url(token(32) || tag(16)), where tag is an
// HMAC of the token under a key derived from the server secret. Only the
// SHA-256 of the token is stored. The tag lets a forged or random cookie be
// refused without a database query.
const sessionTokenLen, sessionTagLen = 32, 16

// sessionHash returns the SHA-256 of the session token in the request's
// cookie, or nil when there is no well-formed, correctly tagged one.
func (s *Service) sessionHash(r *http.Request) []byte {
	c, err := r.Cookie(SessionCookie)
	if err != nil || len(c.Value) != b64.EncodedLen(sessionTokenLen+sessionTagLen) {
		return nil
	}
	raw, err := b64.DecodeString(c.Value)
	if err != nil || len(raw) != sessionTokenLen+sessionTagLen || !s.keys.checkSessionTag(raw[:sessionTokenLen], raw[sessionTokenLen:]) {
		return nil
	}
	return sha256Raw(raw[:sessionTokenLen])
}

// errBusy: every session lookup slot is taken; answered with 503.
var errBusy = errors.New("auth: session lookups saturated")

// errTokenLimited: one session token is used too often; answered with 429.
var errTokenLimited = errors.New("auth: session token rate limited")

// beforeLookup is the cheap part of a session lookup: a token known to
// be dead answers "no session" at once; a live-looking one is rate limited
// per token before it may take a lookup slot.
func (s *Service) beforeLookup(h []byte) (dead bool, err error) {
	if s.dead.has(h) {
		return true, nil
	}
	if ok, _ := s.tokenRL.Allow(b64.EncodeToString(h)); !ok {
		s.rlWarn.note(s.log, "session_token")
		return false, errTokenLimited
	}
	return false, nil
}

// lookupWait is how long a request waits for a session lookup slot.
var lookupWait = 2 * time.Second

// withLookupSlot runs fn while holding one of the SessionLookups slots.
func (s *Service) withLookupSlot(ctx context.Context, fn func() error) error {
	t := time.NewTimer(lookupWait)
	defer t.Stop()
	select {
	case s.lookups <- struct{}{}:
	case <-t.C:
		return errBusy
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.lookups }()
	return fn()
}

// session loads the request's valid session, or nil. present reports
// whether a session cookie was sent at all (so a stale one can be cleared).
func (s *Service) session(r *http.Request) (ss *Session, u *User, present bool, err error) {
	h := s.sessionHash(r)
	if h == nil {
		_, cerr := r.Cookie(SessionCookie)
		return nil, nil, cerr == nil, nil
	}
	if dead, err := s.beforeLookup(h); dead || err != nil {
		return nil, nil, true, err
	}
	err = s.withLookupSlot(r.Context(), func() error {
		var err error
		ss, u, present, err = s.sessionInSlot(r, h)
		return err
	})
	return ss, u, true, err
}

// sessionInSlot is session for a caller that already holds a lookup slot.
func (s *Service) sessionInSlot(r *http.Request, h []byte) (*Session, *User, bool, error) {
	if h == nil {
		_, cerr := r.Cookie(SessionCookie)
		return nil, nil, cerr == nil, nil
	}
	ss, u, err := s.store.LoadSession(r.Context(), h, s.cur(r.Context()).cfg.SessionIdle)
	if errors.Is(err, ErrNotFound) {
		s.dead.add(h)
		return nil, nil, true, nil
	}
	return ss, u, true, err
}

// sessionError answers a failed session lookup: 503 when the lookup slots
// are saturated, 500 otherwise.
func (s *Service) sessionError(w http.ResponseWriter, err error) {
	if errors.Is(err, errTokenLimited) {
		w.Header().Set("Retry-After", "1")
		web.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again later", "")
		return
	}
	if errors.Is(err, errBusy) {
		w.Header().Set("Retry-After", "1")
		web.WriteError(w, http.StatusServiceUnavailable, "busy", "try again in a moment", "")
		return
	}
	s.internal(w, "session", err)
}

// newSession creates a session for user and sets the cookie.
func (s *Service) newSession(ctx context.Context, w http.ResponseWriter, user UserID) error {
	raw := make([]byte, sessionTokenLen)
	if _, err := randRead(raw); err != nil {
		return err
	}
	maxAge := s.cur(ctx).cfg.SessionMax
	if _, err := s.store.CreateSession(ctx, user, sha256Raw(raw), maxAge); err != nil {
		return err
	}
	s.setCookie(w, SessionCookie, b64.EncodeToString(append(raw, s.keys.sessionTag(raw)...)), maxAge)
	return nil
}

// ---- CSRF / same-origin ----

// sameOrigin requires browser evidence that the request comes from our own
// pages: Sec-Fetch-Site, when sent, must be "same-origin"; Origin, when
// sent, must equal the public origin; at least one of them must be sent.
func (s *Service) sameOrigin(r *http.Request) bool {
	sfs := r.Header.Get("Sec-Fetch-Site")
	origin := r.Header.Get("Origin")
	if sfs != "" && sfs != "same-origin" {
		return false
	}
	if origin != "" && origin != s.origin {
		return false
	}
	return sfs != "" || origin != ""
}

// need lists what a signed-in endpoint requires beyond a valid session,
// same-origin and the CSRF token. guardFor/refusal are the ONE place these
// rules are enforced.
//
// While suspended a user may still: sign in,
// sign out, sign out everywhere, delete the account, read /api/me, accept
// the terms, set the locale, rename and delete own passkeys and get a
// "switch" ticket. A suspended user may NOT change the handle, link or
// unlink an identity, or register a passkey (needActive).
//
// Recent sign-in: registering a passkey, linking an identity and
// deleting the account need a session created within
// Config.SensitiveWindow (needRecent); signing in again (any method) makes
// a fresh session. Removing access (unlink, passkey delete, sign-out) does
// not.
type need uint8

const (
	needActive need = 1 << iota // refused while suspended
	needRecent                  // session created within SensitiveWindow
)

// recentUntil is the end of the session's sensitive-action window.
func recentUntil(cfg *Config, ss *Session) time.Time { return ss.CreatedAt.Add(cfg.SensitiveWindow) }

// refusal returns the error code (and message) for a session/user that
// does not meet n, or "" when it does.
func (s *Service) refusal(cfg *Config, ss *Session, u *User, n need) (int, string, string) {
	if n&needActive != 0 && u.EffectiveStatus(s.now()) != StatusActive {
		return http.StatusForbidden, "suspended", "your account is suspended"
	}
	if n&needRecent != 0 && !s.now().Before(recentUntil(cfg, ss)) {
		return http.StatusForbidden, "reauth_required", "sign in again to do this (your sign-in is too old)"
	}
	return 0, "", ""
}

// guard enforces same-origin + CSRF on a state-changing request and returns
// the signed-in session and user. It writes the error response itself.
func (s *Service) guard(w http.ResponseWriter, r *http.Request) (*Session, *User, bool) {
	return s.guardFor(w, r, 0)
}

// guardFor is guard plus the requirements n (see need).
func (s *Service) guardFor(w http.ResponseWriter, r *http.Request, n need) (*Session, *User, bool) {
	if !s.sameOrigin(r) {
		web.WriteError(w, http.StatusForbidden, "cross_site", "cross-site request refused", "")
		return nil, nil, false
	}
	ss, u, present, err := s.session(r)
	if err != nil {
		s.sessionError(w, err)
		return nil, nil, false
	}
	if ss == nil {
		if present {
			s.clearCookie(w, SessionCookie)
		}
		web.WriteError(w, http.StatusUnauthorized, "not_signed_in", "sign in first", "")
		return nil, nil, false
	}
	if !s.keys.checkCSRF(ss.TokenHash, r.Header.Get(CSRFHeader)) {
		web.WriteError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token", CSRFHeader)
		return nil, nil, false
	}
	if status, code, msg := s.refusal(s.cur(r.Context()).cfg, ss, u, n); code != "" {
		web.WriteError(w, status, code, msg, "")
		return nil, nil, false
	}
	return ss, u, true
}

// readJSON decodes a small JSON body (Content-Type application/json, at
// most 4 KiB, no unknown fields).
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return readJSONLimit(w, r, v, 4096)
}

// readJSONLimit is readJSON with another body limit (bytes); a larger body
// is a 400 bad_request like any other unreadable body.
func readJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		web.WriteError(w, http.StatusUnsupportedMediaType, "bad_request", "Content-Type must be application/json", "")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		web.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		web.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		return false
	}
	return true
}

func (s *Service) internal(w http.ResponseWriter, what string, err error) {
	s.log.Error("auth: internal error", "op", what, "err", err)
	web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := web.EncodeJSON(v)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (s *Service) rateLimited(w http.ResponseWriter, r *http.Request, l *RateLimiter, what string) bool {
	ok, wait := l.Allow(ClientAddr(r))
	if ok {
		return false
	}
	secs := int(wait/time.Second) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	s.rlWarn.note(s.log, what)
	web.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again later", "")
	return true
}

// warnAggregate logs rate limiting at most once per warnEvery: the
// first refusal of an interval is logged at once, together with how many
// refusals per endpoint were not logged since the previous line.
type warnAggregate struct {
	mu   sync.Mutex
	last time.Time
	n    map[string]int
}

const warnEvery = time.Minute

func (a *warnAggregate) note(log *slog.Logger, what string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if !a.last.IsZero() && now.Sub(a.last) < warnEvery {
		if a.n == nil {
			a.n = map[string]int{}
		}
		a.n[what]++
		return
	}
	attrs := []any{"endpoint", what}
	if len(a.n) > 0 {
		keys := make([]string, 0, len(a.n))
		total := 0
		for k, v := range a.n {
			keys = append(keys, k)
			total += v
		}
		slices.Sort(keys)
		var b strings.Builder
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%s=%d", k, a.n[k])
		}
		attrs = append(attrs, "suppressed", total, "suppressed_by_endpoint", b.String(), "since", a.last.UTC().Format(time.RFC3339))
	}
	log.Warn("auth: rate limited", attrs...)
	a.last, a.n = now, nil
}

// ---- sign-in flow ----

// flowData is sealed into FlowCookie between start and callback.
type flowData struct {
	Provider    string `json:"p"`
	State       string `json:"s"`
	Nonce       string `json:"n"`
	Verifier    string `json:"v"`
	Return      string `json:"r"`
	LinkUser    string `json:"lu,omitempty"`
	LinkSession string `json:"ls,omitempty"` // b64 session hash the link or reauth was started from
	Switch      bool   `json:"sw,omitempty"` // a switch ticket allowed ending on another account
	Reauth      bool   `json:"ra,omitempty"` // a reauth ticket: a same-account sign-in refreshes the session
	Exp         int64  `json:"e"`
}

const flowPurpose = "nday auth flow v1"

// Start tickets: linking an identity, or
// deliberately switching to another account from a signed-in browser,
// starts with POST /auth/{provider}/ticket (session + CSRF), which returns a
// start URL with a sealed, single-use ticket valid for TicketTTL and bound
// to the session and the provider. The CSRF token itself never appears in a
// URL.
const (
	TicketTTL     = 2 * time.Minute
	ticketPurpose = "nday auth ticket v1"
)

type ticketData struct {
	Intent   string `json:"i"` // link | switch | reauth
	Provider string `json:"p"`
	Session  string `json:"s"` // b64 session hash
	Nonce    string `json:"n"` // single-use marker
	Exp      int64  `json:"e"`
}

// ticket: POST /auth/{provider}/ticket with {"intent":"link"|"switch"|"reauth","return":"/path"}
//
// "reauth": a re-sign-in started from our own page; it is the
// only way a signed-in browser gets a fresh session (and so passes
// needRecent) through a provider. Suspended users may reauth.
func (s *Service) ticket(w http.ResponseWriter, r *http.Request, p *provider) {
	var body struct {
		Intent string `json:"intent"`
		Return string `json:"return"`
	}
	ss, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	if !readJSON(w, r, &body) {
		return
	}
	switch body.Intent {
	case "link":
		if status, code, msg := s.refusal(s.cur(r.Context()).cfg, ss, u, needActive|needRecent); code != "" {
			web.WriteError(w, status, code, msg, "")
			return
		}
	case "switch", "reauth":
	default:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "intent must be link, switch or reauth", "intent")
		return
	}
	exp := s.now().Add(TicketTTL)
	td := ticketData{Intent: body.Intent, Provider: p.name, Session: b64.EncodeToString(ss.TokenHash),
		Nonce: randomToken(16), Exp: exp.Unix()}
	b, _ := json.Marshal(td)
	tk := s.keys.sealB64(ticketPurpose, b)
	start := "/auth/" + p.name + "/start?" + url.Values{"ticket": {tk}, "return": {SafeReturnPath(body.Return)}}.Encode()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "signed_in": true, "intent": body.Intent,
		"start_url": start, "expires_at": exp.UTC().Format(time.RFC3339)})
}

// start: GET /auth/{provider}/start?return=/path[&ticket=<from POST .../ticket>]
func (s *Service) start(w http.ResponseWriter, r *http.Request, p *provider) {
	if s.rateLimited(w, r, s.startRL, "start") {
		return
	}
	q := r.URL.Query()
	ret := SafeReturnPath(q.Get("return"))
	fd := flowData{Provider: p.name, State: randomToken(32), Nonce: randomToken(32), Verifier: randomToken(32),
		Return: ret, Exp: s.now().Add(FlowTTL).Unix()}
	intent := q.Get("intent")
	switch intent {
	case "", "login", "link", "switch", "reauth":
	default:
		web.WriteError(w, http.StatusBadRequest, "bad_request", "intent must be login, link, switch or reauth", "intent")
		return
	}
	tk := q.Get("ticket")
	if tk == "" && (intent == "link" || intent == "switch" || intent == "reauth") {
		web.WriteError(w, http.StatusForbidden, "ticket_required", "get a ticket with POST /auth/"+p.name+"/ticket first", "ticket")
		return
	}
	if tk != "" {
		// A ticket changes what the sign-in may do to the signed-in
		// account, so it also needs a same-site navigation.
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			web.WriteError(w, http.StatusForbidden, "cross_site", "cross-site request refused", "")
			return
		}
		invalid := func() {
			web.WriteError(w, http.StatusForbidden, "ticket_invalid", "the ticket is invalid, used or expired; request a new one", "ticket")
		}
		ss, u, _, err := s.session(r)
		if err != nil {
			s.sessionError(w, err)
			return
		}
		var td ticketData
		pt, err := s.keys.openB64(ticketPurpose, tk)
		if ss == nil || err != nil || json.Unmarshal(pt, &td) != nil || td.Provider != p.name ||
			td.Session != b64.EncodeToString(ss.TokenHash) || s.now().Unix() > td.Exp || (intent != "" && intent != td.Intent) {
			invalid()
			return
		}
		if td.Intent == "link" {
			if status, code, msg := s.refusal(s.cur(r.Context()).cfg, ss, u, needActive|needRecent); code != "" {
				web.WriteError(w, status, code, msg, "")
				return
			}
		}
		fresh, err := s.store.UseState(r.Context(), sha256Bytes("ticket:"+td.Nonce), time.Unix(td.Exp, 0).Add(time.Minute))
		if err != nil {
			s.internal(w, "use_ticket", err)
			return
		}
		if !fresh {
			invalid()
			return
		}
		switch td.Intent {
		case "link":
			fd.LinkUser, fd.LinkSession = u.ID, b64.EncodeToString(ss.TokenHash)
		case "switch":
			fd.Switch = true
		case "reauth":
			// Bound to the session that got the ticket: the callback only
			// refreshes that very session (a flow cookie carried to another
			// signed-in browser is an ordinary ticketless sign-in there).
			fd.Reauth, fd.LinkSession = true, b64.EncodeToString(ss.TokenHash)
		default:
			invalid()
			return
		}
	}
	b, _ := json.Marshal(fd)
	s.setCookie(w, FlowCookie, s.keys.sealB64(flowPurpose, b), FlowTTL)
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, p.authURL(s.cur(r.Context()).cfg.RedirectURI(p.name), fd.State, fd.Nonce, fd.Verifier), http.StatusFound)
}

// callback: GET /auth/{provider}/callback?code=...&state=... (or error=...)
func (s *Service) callback(w http.ResponseWriter, r *http.Request, p *provider) {
	if s.rateLimited(w, r, s.cbRL, "callback") {
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	ret := "/"
	finish := func(outcome, reason string, attrs ...any) {
		a := append([]any{"provider", p.name, "outcome", outcome, "reason", reason}, attrs...)
		if outcome == OutcomeOK || outcome == OutcomeLinked {
			s.log.Info("auth: sign-in", a...)
		} else {
			s.log.Warn("auth: sign-in failed", a...)
		}
		http.Redirect(w, r, withOutcome(ret, outcome), http.StatusSeeOther)
	}
	// The flow cookie is single-use whatever happens next.
	c, err := r.Cookie(FlowCookie)
	if err == nil {
		s.clearCookie(w, FlowCookie)
	}
	if err != nil {
		finish(OutcomeError, "no_flow")
		return
	}
	pt, err := s.keys.openB64(flowPurpose, c.Value)
	var fd flowData
	if err != nil || json.Unmarshal(pt, &fd) != nil {
		finish(OutcomeError, "bad_flow")
		return
	}
	ret = SafeReturnPath(fd.Return)
	q := r.URL.Query()
	switch {
	case fd.Provider != p.name:
		finish(OutcomeError, "provider_mismatch")
		return
	case s.now().Unix() > fd.Exp:
		finish(OutcomeError, "flow_expired")
		return
	case q.Get("state") == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(fd.State)) != 1:
		finish(OutcomeError, "state_mismatch")
		return
	}
	fresh, err := s.store.UseState(r.Context(), sha256Bytes(fd.State), time.Unix(fd.Exp, 0).Add(time.Minute))
	if err != nil {
		finish(OutcomeError, "db")
		s.log.Error("auth: internal error", "op", "use_state", "err", err)
		return
	}
	if !fresh {
		finish(OutcomeError, "state_replayed")
		return
	}
	if e := q.Get("error"); e != "" {
		code := safeCode(e)
		if code == "access_denied" || code == "user_cancelled_authorize" {
			finish(OutcomeDenied, "provider_"+code)
		} else {
			finish(OutcomeError, "provider_"+code)
		}
		return
	}
	// RFC 9207 mix-up defence: an iss parameter, when present, must be
	// ours; when the provider declares authorization_response_iss_parameter_supported
	// it must be present.
	iss := q.Get("iss")
	if iss == "" && p.ep.IssParameterSupported {
		finish(OutcomeError, "iss_missing")
		return
	}
	if iss != "" && len(p.ep.Issuers) > 0 && !contains(p.ep.Issuers, iss) {
		finish(OutcomeError, "iss_mismatch")
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 2048 {
		finish(OutcomeError, "no_code")
		return
	}
	id, err := p.exchange(r.Context(), s.hc, code, s.cur(r.Context()).cfg.RedirectURI(p.name), fd.Verifier, fd.Nonce, s.now())
	if err != nil {
		var pe *providerError
		if errors.As(err, &pe) {
			finish(OutcomeError, pe.Step+"_"+pe.Code)
		} else {
			finish(OutcomeError, "exchange")
		}
		return
	}
	ctx := r.Context()
	if fd.LinkUser != "" {
		ss, u, _, err := s.session(r)
		if err != nil || ss == nil || u.ID != fd.LinkUser || b64.EncodeToString(ss.TokenHash) != fd.LinkSession {
			finish(OutcomeError, "link_session_gone")
			return
		}
		switch _, code, _ := s.refusal(s.cur(r.Context()).cfg, ss, u, needActive|needRecent); code {
		case "suspended":
			finish(OutcomeSuspended, "suspended", "user", u.ID)
			return
		case "reauth_required":
			finish(OutcomeReauthRequired, "reauth_required", "user", u.ID)
			return
		}
		switch err := s.store.Link(ctx, u.ID, p.name, id.Subject, id.Handle, s.keys.suspendedIdentity); {
		case err == nil:
			finish(OutcomeLinked, "linked", "user", u.ID)
		case errors.Is(err, ErrIdentityOwned):
			finish(OutcomeConflict, "identity_owned_by_other_user", "user", u.ID)
		case errors.Is(err, ErrIdentitySuspended):
			// Shown as a plain conflict: the banner for "suspended" talks
			// about this account, which isn't the one that was suspended.
			finish(OutcomeConflict, "identity_suspended", "user", u.ID)
		case errors.Is(err, ErrProviderLinked):
			finish(OutcomeConflict, "provider_already_linked", "user", u.ID)
		default:
			s.log.Error("auth: internal error", "op", "link", "err", err)
			finish(OutcomeError, "db")
		}
		return
	}
	// A signed-in browser may only sign in again to the same account
	// unless it got a switch ticket; otherwise a cross-site navigation to
	// /start could silently replace the session or create an account.
	// Also, only a flow started with a "reauth" ticket (from our
	// own page) refreshes the session; a ticketless same-account sign-in
	// leaves the existing session (token, created_at) untouched, so it can
	// never satisfy needRecent.
	if !fd.Switch {
		ss, u, _, err := s.session(r)
		if err != nil {
			s.log.Error("auth: internal error", "op", "session", "err", err)
			finish(OutcomeError, "db")
			return
		}
		if ss != nil {
			owner, err := s.store.IdentityOwner(ctx, p.name, id.Subject)
			if err != nil && !errors.Is(err, ErrNotFound) {
				s.log.Error("auth: internal error", "op", "identity_owner", "err", err)
				finish(OutcomeError, "db")
				return
			}
			if owner != u.ID {
				finish(OutcomeSignedInAsOther, "signed_in_as_other", "user", u.ID)
				return
			}
			if !fd.Reauth || b64.EncodeToString(ss.TokenHash) != fd.LinkSession {
				// Nothing is written: the session stays as it is, and no
				// store call could act on an identity unlinked meanwhile.
				finish(OutcomeOK, "already_signed_in", "user", u.ID)
				return
			}
		}
	}
	// Sign-in: rotate — whatever session this browser had is revoked and a
	// fresh token is issued (no session fixation).
	if h := s.sessionHash(r); h != nil {
		if err := s.store.DeleteSession(ctx, h); err != nil {
			s.log.Error("auth: internal error", "op", "revoke_old_session", "err", err)
			finish(OutcomeError, "db")
			return
		}
	}
	uid, created, err := s.store.SignIn(ctx, p.name, id.Subject, id.Handle, SafeDisplayName(id.DisplayName), s.keys.suspendedIdentity)
	if err != nil {
		s.log.Error("auth: internal error", "op", "sign_in", "err", err)
		finish(OutcomeError, "db")
		return
	}
	if err := s.newSession(ctx, w, uid); err != nil {
		s.log.Error("auth: internal error", "op", "new_session", "err", err)
		finish(OutcomeError, "db")
		return
	}
	if created {
		// A new account goes to the first-sign-in page first; it continues
		// to the original return path (?next=).
		ret = WelcomeReturn(ret)
	}
	finish(OutcomeOK, "signed_in", "user", uid, "new_user", created)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---- JSON endpoints ----

type meIdentity struct {
	Provider string    `json:"provider"`
	Handle   *string   `json:"handle"`
	LinkedAt time.Time `json:"linked_at"`
}

type meTerms struct {
	AcceptedVersion *string    `json:"accepted_version"`
	AcceptedAt      *time.Time `json:"accepted_at"`
	CurrentVersion  *string    `json:"current_version"`
	UpToDate        bool       `json:"up_to_date"`
}

type meUser struct {
	ID                 UserID       `json:"id"`
	DisplayName        *string      `json:"display_name"`
	Handle             *string      `json:"handle"`
	HandleChangeableAt *time.Time   `json:"handle_changeable_at"`
	Locale             *string      `json:"locale"`
	Role               string       `json:"role"`
	Status             string       `json:"status"`
	SuspendedUntil     *time.Time   `json:"suspended_until"`
	StatusReason       *string      `json:"status_reason"`
	Terms              meTerms      `json:"terms"`
	Identities         []meIdentity `json:"identities"`
	Passkeys           []Passkey    `json:"passkeys"`
	Follows            []Follow     `json:"follows"`
	CreatedAt          time.Time    `json:"created_at"`
}

type mePasskeys struct {
	Enabled    bool `json:"enabled"`
	Signup     bool `json:"signup"`
	MaxPerUser int  `json:"max_per_user"`
}

// meSession describes the current session: sensitive actions need
// recent_sign_in; after recent_sign_in_until the UI must have the user sign
// in again (any method, same account) first.
type meSession struct {
	CreatedAt         time.Time `json:"created_at"`
	RecentSignIn      bool      `json:"recent_sign_in"`
	RecentSignInUntil time.Time `json:"recent_sign_in_until"`
}

type meResponse struct {
	SignedIn  bool       `json:"signed_in"`
	User      *meUser    `json:"user,omitempty"`
	Session   *meSession `json:"session,omitempty"`
	CSRFToken string     `json:"csrf_token,omitempty"`
	Providers []string   `json:"providers"`
	Passkeys  mePasskeys `json:"passkeys"`
}

// me: GET /api/me
func (s *Service) me(w http.ResponseWriter, r *http.Request) {
	st := s.cur(r.Context())
	cfg := st.cfg
	resp := meResponse{Providers: append([]string(nil), st.enabled...), Passkeys: mePasskeys{Enabled: cfg.Passkeys,
		Signup: cfg.Passkeys && cfg.PasskeySignup, MaxPerUser: cfg.MaxPasskeys}}
	h := s.sessionHash(r)
	if h == nil {
		if _, err := r.Cookie(SessionCookie); err == nil {
			s.clearCookie(w, SessionCookie)
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	dead, err := s.beforeLookup(h)
	if err != nil {
		s.sessionError(w, err)
		return
	}
	if dead {
		s.clearCookie(w, SessionCookie)
		writeJSON(w, http.StatusOK, resp)
		return
	}
	// All database work of /api/me runs in one lookup slot.
	var ss *Session
	var u *User
	var ids []Identity
	pks := []Passkey{}
	fols := []Follow{}
	op := "session"
	err = s.withLookupSlot(r.Context(), func() error {
		var err error
		if ss, u, _, err = s.sessionInSlot(r, h); err != nil || ss == nil {
			return err
		}
		op = "identities"
		if ids, err = s.store.Identities(r.Context(), u.ID); err != nil {
			return err
		}
		op = "follows"
		if fols, err = s.store.Follows(r.Context(), u.ID); err != nil {
			return err
		}
		if cfg.Passkeys {
			op = "passkeys"
			pks, err = s.store.Passkeys(r.Context(), u.ID)
		}
		return err
	})
	if err != nil {
		if errors.Is(err, errBusy) || errors.Is(err, errTokenLimited) {
			s.sessionError(w, err)
		} else {
			s.internal(w, op, err)
		}
		return
	}
	if ss == nil {
		s.clearCookie(w, SessionCookie)
		writeJSON(w, http.StatusOK, resp)
		return
	}
	now := s.now()
	mu := &meUser{Passkeys: pks, Follows: fols, ID: u.ID, DisplayName: u.DisplayName, Handle: u.Handle, Locale: u.Locale, Role: u.Role,
		Status: u.EffectiveStatus(now), CreatedAt: u.CreatedAt.UTC(), Identities: []meIdentity{}}
	if mu.Status == StatusSuspended {
		mu.SuspendedUntil, mu.StatusReason = u.SuspendedUntil, u.StatusReason
	}
	if u.Handle != nil && u.HandleChangedAt != nil {
		t := u.HandleChangedAt.Add(HandleChangeInterval).UTC()
		mu.HandleChangeableAt = &t
	}
	mu.Terms = meTerms{AcceptedVersion: u.TermsVersion, AcceptedAt: u.TermsAcceptedAt}
	if cfg.TermsVersion != "" {
		v := cfg.TermsVersion
		mu.Terms.CurrentVersion = &v
		mu.Terms.UpToDate = u.TermsVersion != nil && *u.TermsVersion == v
	}
	for _, i := range ids {
		mu.Identities = append(mu.Identities, meIdentity{Provider: i.Provider, Handle: i.Handle, LinkedAt: i.LinkedAt.UTC()})
	}
	until := recentUntil(cfg, ss)
	resp.Session = &meSession{CreatedAt: ss.CreatedAt.UTC(), RecentSignIn: now.Before(until), RecentSignInUntil: until.UTC()}
	resp.SignedIn, resp.User, resp.CSRFToken = true, mu, s.keys.csrfToken(ss.TokenHash)
	writeJSON(w, http.StatusOK, resp)
}

type okResponse struct {
	OK       bool `json:"ok"`
	SignedIn bool `json:"signed_in"`
}

// signOut: POST /auth/signout — revokes this session server-side.
func (s *Service) signOut(w http.ResponseWriter, r *http.Request) {
	if s.sessionHash(r) == nil {
		// Nothing to revoke; just make sure no cookie is left.
		if !s.sameOrigin(r) {
			web.WriteError(w, http.StatusForbidden, "cross_site", "cross-site request refused", "")
			return
		}
		s.clearCookie(w, SessionCookie)
		writeJSON(w, http.StatusOK, okResponse{OK: true})
		return
	}
	ss, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteSession(r.Context(), ss.TokenHash); err != nil {
		s.internal(w, "signout", err)
		return
	}
	s.dead.add(ss.TokenHash)
	s.clearCookie(w, SessionCookie)
	s.log.Info("auth: signed out", "user", u.ID)
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// signOutAll: POST /auth/signout-all — revokes every session of the user.
func (s *Service) signOutAll(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	n, err := s.store.DeleteUserSessions(r.Context(), u.ID)
	if err != nil {
		s.internal(w, "signout_all", err)
		return
	}
	s.clearCookie(w, SessionCookie)
	s.log.Info("auth: signed out everywhere", "user", u.ID, "sessions", n)
	writeJSON(w, http.StatusOK, struct {
		okResponse
		Revoked int64 `json:"revoked_sessions"`
	}{okResponse{OK: true}, n})
}

// unlink: POST /auth/{provider}/unlink
func (s *Service) unlink(w http.ResponseWriter, r *http.Request, p *provider) {
	// Not while suspended: an unlinked identity is free to sign up again as
	// a new, active account.
	_, u, ok := s.guardFor(w, r, needActive)
	if !ok {
		return
	}
	st := s.cur(r.Context())
	switch err := s.store.Unlink(r.Context(), u.ID, p.name, st.enabled, st.cfg.Passkeys); {
	case err == nil:
		s.log.Info("auth: unlinked", "user", u.ID, "provider", p.name)
		writeJSON(w, http.StatusOK, okResponse{OK: true, SignedIn: true})
	case errors.Is(err, ErrNotLinked):
		web.WriteError(w, http.StatusNotFound, "not_linked", "this provider is not linked to your account", "")
	case errors.Is(err, ErrLastIdentity):
		web.WriteError(w, http.StatusConflict, "last_identity", "you cannot remove your only sign-in method; delete the account instead", "")
	case errors.Is(err, ErrNoUsableMethod):
		web.WriteError(w, http.StatusConflict, "last_usable_method", ErrNoUsableMethod.Error(), "")
	default:
		s.internal(w, "unlink", err)
	}
}

// deleteAccount: POST /account/delete with {"confirm": true}
func (s *Service) deleteAccount(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guardFor(w, r, needRecent)
	if !ok {
		return
	}
	var body struct {
		Confirm bool `json:"confirm"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !body.Confirm {
		web.WriteError(w, http.StatusBadRequest, "bad_request", `send {"confirm": true} to delete the account`, "confirm")
		return
	}
	if err := s.store.DeleteUser(r.Context(), u.ID, s.cur(r.Context()).cfg.HandleHold, s.keys.suspendedIdentity); err != nil {
		s.internal(w, "delete_account", err)
		return
	}
	s.clearCookie(w, SessionCookie)
	s.log.Info("auth: account deleted", "user", u.ID)
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// setLocale: POST /account/locale with {"locale": "zh-Hans" | null}
func (s *Service) setLocale(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	var body struct {
		Locale *string `json:"locale"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	loc := ""
	if body.Locale != nil {
		loc = *body.Locale
		if !ValidLocale(loc) {
			web.WriteError(w, http.StatusBadRequest, "bad_request", "locale must be a BCP 47 tag like zh-Hans, or null", "locale")
			return
		}
	}
	if err := s.store.SetLocale(r.Context(), u.ID, loc); err != nil {
		s.internal(w, "set_locale", err)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, SignedIn: true})
}

// setHandle: POST /account/handle with {"handle": "Alice_1"}
func (s *Service) setHandle(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guardFor(w, r, needActive)
	if !ok {
		return
	}
	var body struct {
		Handle string `json:"handle"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	key, err := CanonicalHandle(body.Handle)
	switch {
	case errors.Is(err, ErrHandleReserved):
		web.WriteError(w, http.StatusConflict, "handle_reserved", err.Error(), "handle")
		return
	case err != nil:
		web.WriteError(w, http.StatusBadRequest, "invalid_handle", err.Error(), "handle")
		return
	}
	retry, err := s.store.SetHandle(r.Context(), u.ID, body.Handle, key, s.cur(r.Context()).cfg.HandleHold)
	switch {
	case err == nil:
		s.log.Info("auth: handle set", "user", u.ID)
		writeJSON(w, http.StatusOK, struct {
			okResponse
			Handle string `json:"handle"`
		}{okResponse{OK: true, SignedIn: true}, body.Handle})
	case errors.Is(err, ErrHandleTaken):
		web.WriteError(w, http.StatusConflict, "handle_taken", err.Error(), "handle")
	case errors.Is(err, ErrHandleTooSoon):
		web.WriteError(w, http.StatusConflict, "handle_change_too_soon",
			fmt.Sprintf("the handle can be changed again after %s", retry.UTC().Format(time.RFC3339)), "handle")
	default:
		s.internal(w, "set_handle", err)
	}
}

// acceptTerms: POST /account/accept-terms with {"version": "<current>"}
func (s *Service) acceptTerms(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	var body struct {
		Version string `json:"version"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	switch terms := s.cur(r.Context()).cfg.TermsVersion; {
	case terms == "":
		web.WriteError(w, http.StatusConflict, "no_terms", "no terms are published", "")
		return
	case body.Version != terms:
		web.WriteError(w, http.StatusConflict, "terms_version_mismatch", "that is not the current terms version", "version")
		return
	}
	if err := s.store.AcceptTerms(r.Context(), u.ID, body.Version); err != nil {
		s.internal(w, "accept_terms", err)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, SignedIn: true})
}

// setFollows: POST /account/follows with {"terms":[{"label":"Fortinet"}, ...]}
// replaces the user's whole list (docs/follows.md).
func (s *Service) setFollows(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guardFor(w, r, needActive)
	if !ok {
		return
	}
	var body struct {
		Terms []struct {
			Label string `json:"label"`
		} `json:"terms"`
	}
	if !readJSONLimit(w, r, &body, followBodyLimit) {
		return
	}
	if body.Terms == nil {
		web.WriteError(w, http.StatusBadRequest, "bad_request", `send {"terms": [...]} ([] removes every follow)`, "terms")
		return
	}
	labels := make([]string, len(body.Terms))
	for i, t := range body.Terms {
		labels[i] = t.Label
	}
	saved, err := s.store.SetFollows(r.Context(), u.ID, labels)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, struct {
			okResponse
			Follows []Follow `json:"follows"`
		}{okResponse{OK: true, SignedIn: true}, saved})
	case errors.Is(err, ErrFollowInvalid):
		web.WriteError(w, http.StatusBadRequest, "invalid_follow", err.Error(), "terms")
	case errors.Is(err, ErrTooManyFollows):
		web.WriteError(w, http.StatusBadRequest, "too_many_follows", err.Error(), "terms")
	default:
		s.internal(w, "set_follows", err)
	}
}

// matchFollows: POST /account/follows/match with {"cve_ids":["CVE-…", ...]}
// answers {"matches":[...]}: the ids (at most MaxMatchCVEs, canonical form)
// of vulnerabilities affecting a followed vendor or product. A read, but a
// POST (the list does not fit a URL), so it is guarded like the others.
func (s *Service) matchFollows(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	var body struct {
		CVEIDs []string `json:"cve_ids"`
	}
	if !readJSONLimit(w, r, &body, matchBodyLimit) {
		return
	}
	if len(body.CVEIDs) > MaxMatchCVEs {
		web.WriteError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("at most %d cve_ids", MaxMatchCVEs), "cve_ids")
		return
	}
	ids := make([]string, 0, len(body.CVEIDs))
	for _, raw := range body.CVEIDs {
		id, valid := site.ParseCVEID(raw)
		if !valid {
			web.WriteError(w, http.StatusBadRequest, "bad_request", "not a CVE id (expected CVE-YYYY-NNNN...)", "cve_ids")
			return
		}
		ids = append(ids, id)
	}
	m, err := s.store.MatchFollows(r.Context(), u.ID, ids)
	if err != nil {
		s.internal(w, "match_follows", err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Matches []string `json:"matches"`
	}{m})
}

// RunHousekeeping runs GC now and then every interval until ctx ends.
func (s *Service) RunHousekeeping(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r, err := s.store.GC(ctx, s.state.Load().cfg.SessionIdle)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("auth: housekeeping failed", "err", err)
		} else if err == nil && (r.Sessions+r.Flows+r.Names+r.Unsuspended+r.SuspendedIdentities) > 0 {
			s.log.Info("auth: housekeeping", "sessions", r.Sessions, "flows", r.Flows, "names", r.Names, "unsuspended", r.Unsuspended,
				"suspended_identities", r.SuspendedIdentities)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// LoginURL is the start URL for a provider (for the UI and docs).
func LoginURL(provider, returnPath string) string {
	return "/auth/" + provider + "/start?return=" + url.QueryEscape(SafeReturnPath(returnPath))
}
