// Package corrections lets signed-in readers report that something on a
// vulnerability page is wrong or missing, and staff accept or reject the
// report (docs/corrections.md, migrations/0017_corrections.sql).
//
// An accepted correction becomes a public revision note on the
// vulnerability page (internal/site.Store.Corrections): the editor's note,
// the category, when it was accepted and the submitter's handle. Accepting
// does NOT change the vulnerability data, which comes from the collectors.
//
// HTTP (only on the public host; like /api/discuss every response is
// Cache-Control: no-store with Vary: Cookie):
//
//	POST /api/corrections/{cve}             submit (signed in, active, handle, current rules)
//	GET  /api/corrections/mine?cve=         the caller's own corrections and their status
//	POST /api/corrections/item/{id}/accept  staff: {"note": public note} (required)
//	POST /api/corrections/item/{id}/reject  staff: {"note": internal note} (optional)
//
// Writes need the same origin and X-CSRF-Token (internal/auth), a JSON body
// and pass the per-user limits (Limits, SetLimits). Decisions write their
// audit row (internal/audit) in their own transaction. Nothing here logs a
// submission's text, link or note.
package corrections

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/discuss/md"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/web"
)

// Options for New.
type Options struct {
	Store *Store
	// Auth is the sign-in service (required): sessions, CSRF, roles, terms.
	Auth   *auth.Service
	Logger *slog.Logger
	Limits *Limits // nil: DefaultLimits
	// NewAccount returns the discussion's limits in force (discuss.Service
	// Limits): their definition of a new account (NewAccountAge,
	// NewAccountComments) and NewPostDaily apply to submissions too (Store.Submit).
	// nil: discuss.DefaultLimits.
	NewAccount func() discuss.Limits
	// Now is the clock of the rate limiters (tests); the Store has its own.
	Now func() time.Time
}

type limState struct {
	lim      Limits
	submitRL *auth.RateLimiter
}

// Service is the HTTP surface.
type Service struct {
	store  *Store
	auth   *auth.Service
	newAcc func() discuss.Limits
	log    *slog.Logger
	now    func() time.Time
	lims   atomic.Pointer[limState]
	limMu  sync.Mutex
	readRL *auth.RateLimiter
	modRL  *auth.RateLimiter

	hSubmit, hMine, hAccept, hReject http.Handler
}

// New builds the service.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Auth == nil {
		return nil, errors.New("corrections: store and auth service are required")
	}
	s := &Service{store: o.Store, auth: o.Auth, log: o.Logger, now: o.Now, newAcc: o.NewAccount}
	if s.newAcc == nil {
		s.newAcc = discuss.DefaultLimits
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	lim := DefaultLimits()
	if o.Limits != nil {
		lim = *o.Limits
	}
	mk := func(burst int, every time.Duration) *auth.RateLimiter {
		l := auth.NewRateLimiter(burst, every)
		l.Now = s.now
		return l
	}
	s.readRL, s.modRL = mk(readBurst, readEvery), mk(modBurst, modEvery)
	s.lims.Store(&limState{lim: lim, submitRL: mk(lim.Burst, lim.Every)})
	a := s.auth
	s.hSubmit = a.RequireActive(http.HandlerFunc(s.submit))
	s.hMine = a.RequireUser(http.HandlerFunc(s.mine)) // a suspended user may still see their own
	mod := a.RequireRole(auth.RoleModerator)
	s.hAccept = mod(http.HandlerFunc(s.accept))
	s.hReject = mod(http.HandlerFunc(s.reject))
	return s, nil
}

// Register mounts /api/corrections/ on the site host (never on the API host).
func (s *Service) Register(srv *web.Server) { srv.Handle("/api/corrections/", s) }

// Limits returns the limits in force.
func (s *Service) Limits() Limits { return s.lims.Load().lim }

// SetLimits replaces the limits of the running service (validated values,
// e.g. LimitsFromEnv). The submit token bucket is kept while its burst and
// interval are unchanged. Safe for concurrent use.
func (s *Service) SetLimits(l Limits) {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	prev := s.lims.Load()
	rl := prev.submitRL
	if rl.Burst != float64(l.Burst) || rl.Every != l.Every {
		rl = auth.NewRateLimiter(l.Burst, l.Every)
		rl.Now = s.now
	}
	s.lims.Store(&limState{lim: l, submitRL: rl})
}

// ---- HTTP plumbing (the same rules as internal/discuss)

// noStore forces Cache-Control: no-store (and drops validators and CDN
// cache headers) with Vary: Cookie on every response.
type noStore struct {
	http.ResponseWriter
	done bool
}

func (w *noStore) apply() {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	h.Set("Cache-Control", web.CacheNever)
	for _, k := range []string{"ETag", "Last-Modified", "Expires", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control"} {
		h.Del(k)
	}
	if !slices.ContainsFunc(h.Values("Vary"), func(v string) bool { return strings.Contains(strings.ToLower(v), "cookie") }) {
		h.Add("Vary", "Cookie")
	}
}

func (w *noStore) WriteHeader(code int) {
	if code >= 200 {
		w.apply()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *noStore) Write(b []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(b)
}

func (w *noStore) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ServeHTTP routes /api/corrections/*.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nw := &noStore{ResponseWriter: w}
	w = nw
	w.Header().Set("Cache-Control", web.CacheNever)
	defer func() {
		if p := recover(); p != nil {
			nw.apply()
			panic(p)
		}
	}()
	if !s.auth.PublicHost(r.Host) {
		web.WriteError(w, http.StatusMisdirectedRequest, "wrong_host", "this host does not serve corrections", "")
		return
	}
	// decisions record the client in their audit row (docs/admin.md)
	r = r.WithContext(audit.WithClient(r.Context(), auth.ClientAddr(r), r.Header.Get("Cf-Ray")))
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	var h http.Handler
	method := http.MethodPost
	switch {
	case len(segs) == 3 && segs[2] == "mine":
		method, h = http.MethodGet, s.hMine
	case len(segs) == 3 && segs[2] != "item":
		h = s.hSubmit
	case len(segs) == 5 && segs[2] == "item":
		h = map[string]http.Handler{"accept": s.hAccept, "reject": s.hReject}[segs[4]]
	}
	if h == nil {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such endpoint", "")
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		web.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use "+method, "")
		return
	}
	h.ServeHTTP(w, r)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		web.WriteError(w, http.StatusUnsupportedMediaType, "bad_request", "Content-Type must be application/json", "")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, e := dec.Token(); e != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			web.WriteError(w, http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("request body over %d bytes", MaxRequestBytes), "")
		} else {
			web.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		}
		return false
	}
	return true
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

func retryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(d/time.Second)+1))
}

func (s *Service) limited(w http.ResponseWriter, l *auth.RateLimiter, key, what string) bool {
	ok, wait := l.Allow(key)
	if ok {
		return false
	}
	retryAfter(w, wait)
	s.log.Warn("corrections: rate limited", "limit", what)
	web.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again later", "")
	return true
}

func (s *Service) fail(w http.ResponseWriter, op string, err error) {
	var le *LimitError
	switch {
	case errors.As(err, &le):
		retryAfter(w, le.RetryAfter)
		s.log.Warn("corrections: rate limited", "limit", op+"_"+le.Code)
		web.WriteError(w, http.StatusTooManyRequests, le.Code, "daily limit reached; try again later", "")
	case errors.Is(err, ErrNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", err.Error(), "")
	case errors.Is(err, ErrNoVuln):
		web.WriteError(w, http.StatusNotFound, "not_found", err.Error(), "cve")
	case errors.Is(err, ErrWrongStatus):
		web.WriteError(w, http.StatusConflict, "wrong_status", err.Error(), "")
	case errors.Is(err, ErrUserOpen):
		web.WriteError(w, http.StatusConflict, "too_many_open", err.Error(), "")
	case errors.Is(err, ErrVulnOpen):
		web.WriteError(w, http.StatusConflict, "queue_full", err.Error(), "")
	default:
		s.log.Error("corrections: internal error", "op", op, "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

// writeRefused answers 403 handle_required / terms_required when the user
// may not write content (the same rule as posting a comment).
func (s *Service) writeRefused(w http.ResponseWriter, u *auth.User) bool {
	if u.Handle == nil {
		web.WriteError(w, http.StatusForbidden, "handle_required", "choose a public handle first (POST /account/handle)", "")
		return true
	}
	if v := s.auth.Config().TermsVersion; v != "" && (u.TermsVersion == nil || *u.TermsVersion != v) {
		web.WriteError(w, http.StatusForbidden, "terms_required", "accept the current community rules first (POST /account/accept-terms)", v)
		return true
	}
	return false
}

// ValidID reports whether s is a UUID in canonical text form (any case).
func ValidID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// NormalizeBody cleans a submission: md.Clean (control, bidi and invisible
// characters, CR LF), trimmed; ok when it has 1..MaxBodyChars characters,
// at least one of them visible.
func NormalizeBody(s string) (string, bool) {
	s = strings.TrimSpace(md.Clean(s))
	n := utf8.RuneCountInString(s)
	return s, n >= 1 && n <= MaxBodyChars && visible(s)
}

// NormalizeNote cleans a one-line note (md.Clean, line breaks and tabs
// become spaces, trimmed).
func NormalizeNote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, md.Clean(s))
	return strings.TrimSpace(s)
}

func visible(s string) bool {
	for _, r := range s {
		if !unicode.IsSpace(r) && !unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf) {
			return true
		}
	}
	return false
}

// NormalizeURL validates an optional evidence link: "" (after trimming) is
// none; otherwise it must be an absolute http(s) URL that md.SafeURL accepts
// (printable ASCII, a host, no user info, at most MaxURLBytes bytes).
func NormalizeURL(s string) (*string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, true
	}
	if len(s) > MaxURLBytes {
		return nil, false
	}
	u, ok := md.SafeURL(s)
	if !ok {
		return nil, false
	}
	return &u, true
}

// ---- handlers

type itemResponse struct {
	OK         bool        `json:"ok"`
	Correction *Correction `json:"correction"`
}

// submit: POST /api/corrections/{cve} with {"category","body","evidence_url"?}
func (s *Service) submit(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	seg := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[2]
	cve, ok := site.ParseVulnID(seg)
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "bad_cve", "not a vulnerability id", "cve")
		return
	}
	if s.writeRefused(w, u) {
		return
	}
	cur := s.lims.Load() // one set of limits for the whole request
	if s.limited(w, cur.submitRL, u.ID, "submit") {
		return
	}
	var body struct {
		Category    string  `json:"category"`
		Body        string  `json:"body"`
		EvidenceURL *string `json:"evidence_url"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !slices.Contains(Categories, body.Category) {
		web.WriteError(w, http.StatusBadRequest, "bad_category", "category must be one of "+strings.Join(Categories, ", "), "category")
		return
	}
	text, ok := NormalizeBody(body.Body)
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "invalid_body", fmt.Sprintf("the text must have 1 to %d characters", MaxBodyChars), "body")
		return
	}
	var link *string
	if body.EvidenceURL != nil {
		if link, ok = NormalizeURL(*body.EvidenceURL); !ok {
			web.WriteError(w, http.StatusBadRequest, "bad_url", "evidence_url must be an absolute http or https URL", "evidence_url")
			return
		}
	}
	c, err := s.store.Submit(r.Context(), Submission{CVE: cve, Submitter: u.ID, Category: body.Category, Body: text, EvidenceURL: link}, cur.lim, s.newAcc())
	if err != nil {
		s.fail(w, "submit", err)
		return
	}
	s.log.Info("corrections: submitted", "user", u.ID, "correction", c.ID, "cve", cve, "category", c.Category)
	writeJSON(w, http.StatusCreated, itemResponse{OK: true, Correction: c})
}

// mine: GET /api/corrections/mine?cve=
func (s *Service) mine(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	if s.limited(w, s.readRL, u.ID, "mine") {
		return
	}
	cve := ""
	if v := r.URL.Query().Get("cve"); v != "" {
		id, ok := site.ParseVulnID(v)
		if !ok {
			web.WriteError(w, http.StatusBadRequest, "bad_cve", "not a vulnerability id", "cve")
			return
		}
		cve = id
	}
	list, err := s.store.Mine(r.Context(), u.ID, cve)
	if err != nil {
		s.fail(w, "mine", err)
		return
	}
	if list == nil {
		list = []*Correction{}
	}
	writeJSON(w, http.StatusOK, struct {
		Corrections []*Correction `json:"corrections"`
		Limits      struct {
			MaxBodyChars int `json:"max_body_chars"`
			MaxURLBytes  int `json:"max_url_bytes"`
		} `json:"limits"`
	}{Corrections: list, Limits: struct {
		MaxBodyChars int `json:"max_body_chars"`
		MaxURLBytes  int `json:"max_url_bytes"`
	}{MaxBodyChars, MaxURLBytes}})
}

func itemID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[3]
	if !ValidID(id) {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such correction", "")
		return "", false
	}
	return strings.ToLower(id), true
}

// accept: POST /api/corrections/item/{id}/accept with {"note"} (staff)
func (s *Service) accept(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := itemID(w, r)
	if !ok || s.limited(w, s.modRL, u.ID, "mod") {
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	note := NormalizeNote(body.Note)
	switch n := utf8.RuneCountInString(note); {
	case n == 0 || !visible(note):
		web.WriteError(w, http.StatusBadRequest, "note_required", "accepting needs a public note saying what was changed or confirmed", "note")
		return
	case n > MaxPublicNote:
		web.WriteError(w, http.StatusBadRequest, "bad_note", fmt.Sprintf("note: at most %d characters", MaxPublicNote), "note")
		return
	}
	c, err := s.store.Accept(r.Context(), id, u.ID, note)
	if err != nil {
		s.fail(w, "accept", err)
		return
	}
	s.log.Info("corrections: accepted", "user", u.ID, "correction", c.ID, "cve", c.CVE)
	writeJSON(w, http.StatusOK, itemResponse{OK: true, Correction: c})
}

// reject: POST /api/corrections/item/{id}/reject with {"note"?} (staff)
func (s *Service) reject(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := itemID(w, r)
	if !ok || s.limited(w, s.modRL, u.ID, "mod") {
		return
	}
	var body struct {
		Note *string `json:"note"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	var note *string
	if body.Note != nil {
		n := NormalizeNote(*body.Note)
		if utf8.RuneCountInString(n) > MaxInternalNote {
			web.WriteError(w, http.StatusBadRequest, "bad_note", fmt.Sprintf("note: at most %d characters", MaxInternalNote), "note")
			return
		}
		if n != "" {
			note = &n
		}
	}
	c, err := s.store.Reject(r.Context(), id, u.ID, note)
	if err != nil {
		s.fail(w, "reject", err)
		return
	}
	s.log.Info("corrections: rejected", "user", u.ID, "correction", c.ID, "cve", c.CVE)
	writeJSON(w, http.StatusOK, itemResponse{OK: true, Correction: c})
}
