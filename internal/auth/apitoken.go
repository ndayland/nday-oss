package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"nday.land/nday/internal/web"
)

// Personal access tokens for the JSON data API and private feed keys.
//
// A token is "nday_" + base64url(32 random bytes || 16-byte tag) (69
// characters), the tag an HMAC of the random bytes under a key derived from
// the server secret (keyset.apiTokenTag), so a forged token is refused in
// memory, before any rate limiter, cache or lookup. Only the SHA-256 of the
// whole string is stored (api_tokens.token_hash); the secret is returned
// once, by the create endpoint, and is never logged. It is accepted only in
// "Authorization: Bearer <token>". A token tagged with a secret that is no
// longer configured stops working.
//
// A private feed key is "<user id>.<mac>.<tag>": mac is base64url of
// HMAC-SHA256(k, "feed-key|" + user id + "|" + salt)[:16] under a key k
// derived from each configured server secret (keyset.feed), salt the user's
// random feed_keys.salt; tag (keyset.ftag) authenticates "<user id>.<mac>"
// so a forged key is refused before any lookup. It works on the Atom feed
// only (?key=).

// APITokenPrefix starts every API token.
const APITokenPrefix = "nday_"

const apiTokenBytes = 32

// APITokenLen is the length of a token.
var APITokenLen = len(APITokenPrefix) + b64.EncodedLen(apiTokenBytes+tagLen)

// newAPIToken returns a fresh secret and its SHA-256.
func (s *Service) newAPIToken() (string, []byte, error) {
	raw := make([]byte, apiTokenBytes)
	if _, err := randRead(raw); err != nil {
		return "", nil, err
	}
	secret := APITokenPrefix + b64.EncodeToString(append(raw, s.keys.apiTokenTag(raw)...))
	return secret, sha256Bytes(secret), nil
}

// decodeCanonical decodes base64url (no padding) of exactly n bytes and
// accepts only the one canonical spelling (no other trailing bits, no
// ignored characters).
func decodeCanonical(v string, n int) ([]byte, bool) {
	if len(v) != b64.EncodedLen(n) {
		return nil, false
	}
	b, err := b64.Strict().DecodeString(v)
	if err != nil || len(b) != n || b64.EncodeToString(b) != v {
		return nil, false
	}
	return b, true
}

// validAPIToken reports whether v is a token this server issued (shape and
// tag, any configured secret); no lookup.
func (s *Service) validAPIToken(v string) bool {
	if len(v) != APITokenLen || !strings.HasPrefix(v, APITokenPrefix) {
		return false
	}
	b, ok := decodeCanonical(v[len(APITokenPrefix):], apiTokenBytes+tagLen)
	return ok && s.keys.checkAPITokenTag(b[:apiTokenBytes], b[apiTokenBytes:])
}

// apiLookupWait is how long a token or feed key lookup waits for a slot.
var apiLookupWait = 200 * time.Millisecond

// withAPISlot runs fn while holding one of the APILookups slots (never a
// session lookup slot); errBusy when none frees up within apiLookupWait.
func (s *Service) withAPISlot(ctx context.Context, fn func() error) error {
	t := time.NewTimer(apiLookupWait)
	defer t.Stop()
	select {
	case s.apiSlots <- struct{}{}:
	case <-t.C:
		return errBusy
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.apiSlots }()
	return fn()
}

// IssueAPIToken creates a token for user without the account page (no
// re-verification, no limit check beyond MaxAPITokens): for operators and
// tests. The secret is returned once.
func (s *Service) IssueAPIToken(ctx context.Context, user UserID, name string) (string, error) {
	secret, hash, err := s.newAPIToken()
	if err != nil {
		return "", err
	}
	if _, err := s.store.CreateAPIToken(ctx, user, name, hash, MaxAPITokens); err != nil {
		return "", err
	}
	return secret, nil
}

// bearer returns the token of the Authorization header. present: the
// header was sent; ok: it is exactly one "Bearer <token>" value.
func bearer(r *http.Request) (token string, present, ok bool) {
	vs := r.Header.Values("Authorization")
	if len(vs) == 0 {
		return "", false, false
	}
	if len(vs) > 1 {
		return "", true, false
	}
	scheme, tok, found := strings.Cut(strings.TrimSpace(vs[0]), " ")
	tok = strings.TrimSpace(tok)
	if !found || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return "", true, false
	}
	return tok, true, true
}

const msgInvalidToken = "the API token is invalid or has been revoked"

// AuthenticateData authenticates a request to a gated route (web.Gate):
//
//   - "Authorization: Bearer <token>": a live API token whose user exists
//     and is not suspended. When the header is sent, nothing else counts.
//   - mode web.AuthFeedKey: else, ?key= with a valid private feed key.
//   - mode web.AuthSession, on the public host: else, the session cookie of
//     a signed-in user; the response is then no-store with Vary: Cookie.
//
// Errors: 401 token_required (no credential, a malformed header, or an
// invalid feed key), 401 invalid_token (an unknown or revoked token: which
// of the two is not told), 403 suspended, 429 rate_limited, 503 busy.
func (s *Service) AuthenticateData(w http.ResponseWriter, r *http.Request, mode web.AuthMode) (http.ResponseWriter, *http.Request, bool) {
	tok, present, ok := bearer(r)
	switch {
	case present && !ok:
		web.WriteUnauthorized(w, "token_required", "send the API token as Authorization: Bearer <token>")
		return nil, nil, false
	case present:
		return w, r, s.checkAPIToken(w, r, tok)
	case mode&web.AuthFeedKey != 0 && r.URL.Query().Has("key"):
		w.Header().Set("Cache-Control", "private, no-store")
		return w, r, s.checkFeedKey(w, r)
	case mode&web.AuthSession != 0 && s.PublicHost(r.Host):
		if _, err := r.Cookie(SessionCookie); err == nil {
			nw, r2 := personal(w, r)
			if !s.checkSession(nw, r2) {
				return nil, nil, false
			}
			return nw, r2, true
		}
	}
	web.WriteUnauthorized(w, "token_required", web.MsgTokenRequired)
	return nil, nil, false
}

// lookupAllowed applies the per-client and per-credential rate limits
// before a token or feed key lookup; it writes the 429 itself.
func (s *Service) lookupAllowed(w http.ResponseWriter, r *http.Request, credKey string) bool {
	if s.rateLimited(w, r, s.apiAddrRL, "api_client") {
		return false
	}
	if ok, wait := s.apiRL.Allow(credKey); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		s.rlWarn.note(s.log, "api_token")
		web.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again later", "")
		return false
	}
	return true
}

// activeOrRefuse writes 403 suspended unless u is active.
func (s *Service) activeOrRefuse(w http.ResponseWriter, u *User) bool {
	if u.EffectiveStatus(s.now()) != StatusActive {
		web.WriteError(w, http.StatusForbidden, "suspended", "your account is suspended", "")
		return false
	}
	return true
}

func (s *Service) checkAPIToken(w http.ResponseWriter, r *http.Request, tok string) bool {
	// not issued by this server (shape or tag): refused in memory, before
	// the rate limiters, the cache and any lookup
	if !s.validAPIToken(tok) {
		web.WriteUnauthorized(w, "invalid_token", msgInvalidToken)
		return false
	}
	h := sha256Bytes(tok)
	// an unknown or revoked token never becomes valid: answered from memory
	if s.apiDead.has(h) {
		web.WriteUnauthorized(w, "invalid_token", msgInvalidToken)
		return false
	}
	if !s.lookupAllowed(w, r, "t:"+b64.EncodeToString(h)) {
		return false
	}
	var u *User
	err := s.withAPISlot(r.Context(), func() error {
		var err error
		u, err = s.store.LoadAPIToken(r.Context(), h)
		return err
	})
	switch {
	case errors.Is(err, ErrNotFound):
		s.apiDead.add(h)
		web.WriteUnauthorized(w, "invalid_token", msgInvalidToken)
		return false
	case err != nil:
		s.sessionError(w, err)
		return false
	}
	return s.activeOrRefuse(w, u)
}

// parseFeedKey splits a feed key "<user id>.<mac>.<tag>" into a canonical
// (lower-case) user id, its MAC and its tag; ok is false for anything else,
// including any other spelling of the same bytes.
func parseFeedKey(v string) (user string, mac, tag []byte, ok bool) {
	user, rest, found := strings.Cut(v, ".")
	m, tg, found2 := strings.Cut(rest, ".")
	if !found || !found2 || len(user) != 36 {
		return "", nil, nil, false
	}
	for i := 0; i < len(user); i++ {
		c := user[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", nil, nil, false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return "", nil, nil, false
			}
		}
	}
	mac, ok1 := decodeCanonical(m, feedKeyMACLen)
	tag, ok2 := decodeCanonical(tg, tagLen)
	if !ok1 || !ok2 {
		return "", nil, nil, false
	}
	return user, mac, tag, true
}

// checkFeedKey: a wrong key, whether or not its user id exists, is the
// same 401 token_required as no credential.
func (s *Service) checkFeedKey(w http.ResponseWriter, r *http.Request) bool {
	refuse := func() bool {
		web.WriteUnauthorized(w, "token_required", web.MsgTokenRequired)
		return false
	}
	vs := r.URL.Query()["key"]
	if len(vs) != 1 {
		return refuse()
	}
	user, mac, tag, ok := parseFeedKey(vs[0])
	// not issued by this server: refused before any limiter or lookup
	if !ok || !s.keys.checkFeedKeyTag(vs[0][:strings.LastIndexByte(vs[0], '.')], tag) {
		return refuse()
	}
	h := sha256Bytes("feed-key:" + vs[0])
	if s.apiDead.has(h) {
		return refuse()
	}
	if !s.lookupAllowed(w, r, "f:"+b64.EncodeToString(h)) {
		return false
	}
	var u *User
	var salt []byte
	err := s.withAPISlot(r.Context(), func() error {
		var err error
		u, salt, err = s.store.FeedKeyOwner(r.Context(), user)
		return err
	})
	switch {
	case errors.Is(err, ErrNotFound):
		// no such user or no salt: do the same MAC work as for a real one
		s.keys.checkFeedMAC(user, make([]byte, feedSaltLen), mac)
		s.apiDead.add(h)
		return refuse()
	case err != nil:
		s.sessionError(w, err)
		return false
	}
	if !s.keys.checkFeedMAC(user, salt, mac) {
		// a rotated or forged key: a new salt is random, so it never
		// becomes valid again
		s.apiDead.add(h)
		return refuse()
	}
	return s.activeOrRefuse(w, u)
}

// checkSession authenticates by the session cookie (w is a noStoreWriter).
func (s *Service) checkSession(w http.ResponseWriter, r *http.Request) bool {
	ss, u, _, err := s.session(r)
	if err != nil {
		s.sessionError(w, err)
		return false
	}
	if ss == nil {
		web.WriteUnauthorized(w, "token_required", web.MsgTokenRequired)
		return false
	}
	return s.activeOrRefuse(w, u)
}

// ---- account endpoints (session + same-origin + CSRF, like the others) ----

// apiTokensResponse is the body of GET /account/tokens.
type apiTokensResponse struct {
	OK       bool       `json:"ok"`
	SignedIn bool       `json:"signed_in"`
	Tokens   []APIToken `json:"tokens"`
	Max      int        `json:"max"`
}

// listAPITokens: GET /account/tokens
func (s *Service) listAPITokens(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	ts, err := s.store.APITokens(r.Context(), u.ID)
	if err != nil {
		s.internal(w, "api_tokens", err)
		return
	}
	writeJSON(w, http.StatusOK, apiTokensResponse{OK: true, SignedIn: true, Tokens: ts, Max: MaxAPITokens})
}

// createAPIToken: POST /account/tokens with {"name": "..."}. Needs an active
// user and a recent sign-in (like adding a passkey). The secret is in this
// response only.
func (s *Service) createAPIToken(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guardFor(w, r, needActive|needRecent)
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if utf8.RuneCountInString(strings.TrimSpace(body.Name)) > MaxAPITokenName {
		web.WriteError(w, http.StatusBadRequest, "bad_request", "name must be at most 64 characters", "name")
		return
	}
	name := SanitizeDisplayName(body.Name)
	if name == "" {
		web.WriteError(w, http.StatusBadRequest, "bad_request", "name must not be empty", "name")
		return
	}
	secret, hash, err := s.newAPIToken()
	if err != nil {
		s.internal(w, "api_token_rand", err)
		return
	}
	t, err := s.store.CreateAPIToken(r.Context(), u.ID, name, hash, MaxAPITokens)
	switch {
	case errors.Is(err, ErrTokenLimit):
		web.WriteError(w, http.StatusConflict, "token_limit", err.Error(), "")
		return
	case err != nil:
		s.internal(w, "create_api_token", err)
		return
	}
	s.log.Info("auth: api token created", "user", u.ID, "token", t.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "signed_in": true, "token": t, "secret": secret})
}

// revokeAPIToken: POST /account/tokens/{id}/revoke (idempotent).
func (s *Service) revokeAPIToken(w http.ResponseWriter, r *http.Request, id string) {
	_, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	switch err := s.store.RevokeAPIToken(r.Context(), u.ID, id); {
	case errors.Is(err, ErrNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such token", "")
	case err != nil:
		s.internal(w, "revoke_api_token", err)
	default:
		s.log.Info("auth: api token revoked", "user", u.ID, "token", id)
		writeJSON(w, http.StatusOK, okResponse{OK: true, SignedIn: true})
	}
}

// feedResponse is the body of GET /account/feed and POST /account/feed/rotate.
type feedResponse struct {
	OK       bool   `json:"ok"`
	SignedIn bool   `json:"signed_in"`
	Key      string `json:"key"`
	URL      string `json:"url"`
}

func (s *Service) feedBody(user string, salt []byte) feedResponse {
	k := s.keys.feedKey(user, salt)
	return feedResponse{OK: true, SignedIn: true, Key: k, URL: s.origin + "/feed.xml?key=" + k}
}

// feedAddress: GET /account/feed — the private feed address (the salt is
// created on first use).
func (s *Service) feedAddress(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guard(w, r)
	if !ok {
		return
	}
	salt, err := s.store.FeedSalt(r.Context(), u.ID, true)
	if err != nil {
		s.internal(w, "feed_salt", err)
		return
	}
	writeJSON(w, http.StatusOK, s.feedBody(u.ID, salt))
}

// rotateFeedKey: POST /account/feed/rotate — a new address; the old one
// stops working at once. Needs an active user.
func (s *Service) rotateFeedKey(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.guardFor(w, r, needActive)
	if !ok {
		return
	}
	salt, err := s.store.RotateFeedSalt(r.Context(), u.ID)
	if err != nil {
		s.internal(w, "rotate_feed_salt", err)
		return
	}
	s.log.Info("auth: feed key rotated", "user", u.ID)
	writeJSON(w, http.StatusOK, s.feedBody(u.ID, salt))
}
