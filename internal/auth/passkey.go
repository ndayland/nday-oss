package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"nday.land/nday/internal/auth/webauthn"
	"nday.land/nday/internal/web"
)

// Passkey ceremony parameters.
const (
	CeremonyCookie   = "__Host-nday_webauthn"
	CeremonyTTL      = 5 * time.Minute
	ceremonyTimeout  = 300000 // ms, the "timeout" option
	ceremonyPurpose  = "nday auth webauthn v1"
	maxFinishBody    = 64 << 10
	defaultKeyName   = "Passkey"
	defaultSignupNym = "nday account"
)

// ceremony is sealed into CeremonyCookie between begin and finish: it binds
// the challenge to the browser that began the ceremony.
type ceremony struct {
	Kind      string `json:"k"` // register | login | signup
	Challenge string `json:"c"` // base64url
	Exp       int64  `json:"e"`
	User      string `json:"u,omitempty"` // register: the signed-in user
	Session   string `json:"s,omitempty"` // register: b64 session hash
	Handle    string `json:"h,omitempty"` // signup: new WebAuthn user handle (b64)
	Name      string `json:"n,omitempty"` // signup: display name
}

var knownTransports = []string{"usb", "nfc", "ble", "smart-card", "hybrid", "internal"}

type credentialJSON struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string   `json:"clientDataJSON"`
		AttestationObject string   `json:"attestationObject"`
		AuthenticatorData string   `json:"authenticatorData"`
		Signature         string   `json:"signature"`
		UserHandle        *string  `json:"userHandle"`
		Transports        []string `json:"transports"`
	} `json:"response"`
	Name string `json:"name"` // nday extension: name for a new passkey
	// Switch (nday extension, login/finish): a browser signed in to another
	// account may end on the passkey's account. Without it that is refused
	// (409 signed_in_as_other).
	Switch bool `json:"switch"`
}

func unb64(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return b, err == nil
}

// readFinish decodes a finish body (PublicKeyCredential.toJSON() plus
// "name"); unknown members are ignored because browsers add new ones.
func readFinish(w http.ResponseWriter, r *http.Request) (*credentialJSON, bool) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		web.WriteError(w, http.StatusUnsupportedMediaType, "bad_request", "Content-Type must be application/json", "")
		return nil, false
	}
	var c credentialJSON
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFinishBody))
	if err := dec.Decode(&c); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			web.WriteError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large", "")
			return nil, false
		}
		web.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		web.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		return nil, false
	}
	if c.Type != "public-key" || c.ID == "" || (c.RawID != "" && c.RawID != c.ID) {
		web.WriteError(w, http.StatusBadRequest, "bad_request", "not a public-key credential", "")
		return nil, false
	}
	return &c, true
}

func (s *Service) passkeyRejected(w http.ResponseWriter, what string, code string, attrs ...any) {
	s.log.Warn("auth: passkey rejected", append([]any{"ceremony", what, "reason", code}, attrs...)...)
	web.WriteError(w, http.StatusBadRequest, "passkey_rejected", code, "")
}

// beginCeremony issues a challenge bound to this browser.
func (s *Service) beginCeremony(w http.ResponseWriter, c ceremony) string {
	ch := randomToken(32)
	c.Challenge, c.Exp = ch, s.now().Add(CeremonyTTL).Unix()
	b, _ := json.Marshal(c)
	s.setCookie(w, CeremonyCookie, s.keys.sealB64(ceremonyPurpose, b), CeremonyTTL)
	return ch
}

// finishCeremony consumes the browser's ceremony: the cookie is cleared,
// the kind and expiry checked, and the challenge marked used (single use).
func (s *Service) finishCeremony(w http.ResponseWriter, r *http.Request, kind string) (*ceremony, []byte, bool) {
	ck, err := r.Cookie(CeremonyCookie)
	if err == nil {
		s.clearCookie(w, CeremonyCookie)
	}
	var c ceremony
	reason := ""
	switch {
	case err != nil:
		reason = "no_ceremony"
	default:
		pt, err := s.keys.openB64(ceremonyPurpose, ck.Value)
		if err != nil || json.Unmarshal(pt, &c) != nil {
			reason = "bad_ceremony"
		} else if c.Kind != kind {
			reason = "ceremony_kind"
		} else if s.now().Unix() > c.Exp {
			reason = "ceremony_expired"
		}
	}
	if reason == "" {
		fresh, err := s.store.UseState(r.Context(), sha256Bytes("webauthn:"+c.Challenge), time.Unix(c.Exp, 0).Add(time.Minute))
		if err != nil {
			s.internal(w, "use_challenge", err)
			return nil, nil, false
		}
		if !fresh {
			reason = "challenge_replayed"
		}
	}
	if reason != "" {
		s.log.Warn("auth: passkey rejected", "ceremony", kind, "reason", reason)
		web.WriteError(w, http.StatusBadRequest, "ceremony_invalid", "start the passkey ceremony again", "")
		return nil, nil, false
	}
	ch, _ := unb64(c.Challenge)
	return &c, ch, true
}

func rp(cfg *Config) *webauthn.RP {
	return &webauthn.RP{ID: cfg.RPID, Origins: cfg.Origins, RequireUV: true}
}

func pubKeyCredParams() []map[string]any {
	out := []map[string]any{}
	for _, a := range webauthn.SupportedAlgs {
		out = append(out, map[string]any{"type": "public-key", "alg": a})
	}
	return out
}

func creationOptions(cfg *Config, challenge string, userHandle []byte, name, displayName string, exclude [][]byte) map[string]any {
	ex := []map[string]any{}
	for _, id := range exclude {
		ex = append(ex, map[string]any{"type": "public-key", "id": b64.EncodeToString(id)})
	}
	return map[string]any{"publicKey": map[string]any{
		"rp":                 map[string]any{"id": cfg.RPID, "name": "nday"},
		"user":               map[string]any{"id": b64.EncodeToString(userHandle), "name": name, "displayName": displayName},
		"challenge":          challenge,
		"pubKeyCredParams":   pubKeyCredParams(),
		"timeout":            ceremonyTimeout,
		"excludeCredentials": ex,
		"authenticatorSelection": map[string]any{"residentKey": "required", "requireResidentKey": true,
			"userVerification": "required"},
		"attestation": "none",
		"hints":       []string{},
	}}
}

func cleanTransports(in []string) []string {
	out := []string{}
	for _, t := range in {
		if slices.Contains(knownTransports, t) && !slices.Contains(out, t) && len(out) < 8 {
			out = append(out, t)
		}
	}
	return out
}

func keyName(n string) string {
	if n = SanitizeDisplayName(n); n == "" {
		return defaultKeyName
	}
	return n
}

// passkeyRoute dispatches POST /auth/passkey/{register|login|signup}/{begin|finish}.
func (s *Service) passkeyRoute(cfg *Config, ceremonyName, step string) func(http.ResponseWriter, *http.Request) {
	if !cfg.Passkeys {
		return nil
	}
	switch ceremonyName + "/" + step {
	case "register/begin":
		return s.registerBegin
	case "register/finish":
		return s.registerFinish
	case "login/begin":
		return s.loginBegin
	case "login/finish":
		return s.loginFinish
	case "signup/begin":
		if cfg.PasskeySignup {
			return s.signupBegin
		}
	case "signup/finish":
		if cfg.PasskeySignup {
			return s.signupFinish
		}
	}
	return nil
}

// anonGuard: rate limit + same-origin for the anonymous ceremonies.
func (s *Service) anonGuard(w http.ResponseWriter, r *http.Request, what string) bool {
	if s.rateLimited(w, r, s.pkRL, what) {
		return false
	}
	if !s.sameOrigin(r) {
		web.WriteError(w, http.StatusForbidden, "cross_site", "cross-site request refused", "")
		return false
	}
	return true
}

func (s *Service) registerBegin(w http.ResponseWriter, r *http.Request) {
	ss, u, ok := s.guardFor(w, r, needActive|needRecent)
	if !ok {
		return
	}
	ctx := r.Context()
	handle, err := s.store.WebAuthnID(ctx, u.ID)
	if err != nil {
		s.internal(w, "webauthn_id", err)
		return
	}
	exclude, err := s.store.CredentialIDs(ctx, u.ID)
	if err != nil {
		s.internal(w, "credential_ids", err)
		return
	}
	cfg := s.cur(ctx).cfg
	if len(exclude) >= cfg.MaxPasskeys {
		web.WriteError(w, http.StatusConflict, "passkey_limit", ErrPasskeyLimit.Error(), "")
		return
	}
	dn := ""
	if u.DisplayName != nil {
		dn = *u.DisplayName
	}
	name := dn
	if u.Handle != nil {
		name = *u.Handle
	}
	if name == "" {
		name = defaultSignupNym
	}
	ch := s.beginCeremony(w, ceremony{Kind: "register", User: u.ID, Session: b64.EncodeToString(ss.TokenHash)})
	writeJSON(w, http.StatusOK, creationOptions(cfg, ch, handle, name, dn, exclude))
}

func (s *Service) registerFinish(w http.ResponseWriter, r *http.Request) {
	ss, u, ok := s.guardFor(w, r, needActive|needRecent)
	if !ok {
		return
	}
	c, ch, ok := s.finishCeremony(w, r, "register")
	if !ok {
		return
	}
	if c.User != u.ID || c.Session != b64.EncodeToString(ss.TokenHash) {
		s.passkeyRejected(w, "register", "session_changed")
		return
	}
	cj, ok := readFinish(w, r)
	if !ok {
		return
	}
	cd, ok1 := unb64(cj.Response.ClientDataJSON)
	ao, ok2 := unb64(cj.Response.AttestationObject)
	rawID, ok3 := unb64(cj.ID)
	if !ok1 || !ok2 || !ok3 {
		s.passkeyRejected(w, "register", "encoding")
		return
	}
	cr, err := rp(s.cur(r.Context()).cfg).VerifyRegistration(ch, cd, ao, webauthn.SupportedAlgs)
	if err != nil {
		s.passkeyRejected(w, "register", webauthn.Code(err), "user", u.ID)
		return
	}
	if string(cr.ID) != string(rawID) {
		s.passkeyRejected(w, "register", "credential_id_mismatch", "user", u.ID)
		return
	}
	id, err := s.store.AddPasskey(r.Context(), u.ID, cr, cleanTransports(cj.Response.Transports), keyName(cj.Name), s.cur(r.Context()).cfg.MaxPasskeys)
	switch {
	case errors.Is(err, ErrCredentialExists):
		s.log.Warn("auth: passkey rejected", "ceremony", "register", "reason", "credential_exists", "user", u.ID)
		web.WriteError(w, http.StatusConflict, "passkey_exists", err.Error(), "")
		return
	case errors.Is(err, ErrPasskeyLimit):
		web.WriteError(w, http.StatusConflict, "passkey_limit", err.Error(), "")
		return
	case err != nil:
		s.internal(w, "add_passkey", err)
		return
	}
	s.log.Info("auth: passkey added", "user", u.ID, "passkey", id, "alg", cr.Alg)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "signed_in": true, "passkey": map[string]any{
		"id": id, "name": keyName(cj.Name), "backed_up": cr.BS}})
}

func (s *Service) loginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.anonGuard(w, r, "passkey_login_begin") {
		return
	}
	ch := s.beginCeremony(w, ceremony{Kind: "login"})
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": map[string]any{
		"challenge": ch, "rpId": s.cur(r.Context()).cfg.RPID, "timeout": ceremonyTimeout,
		"userVerification": "required", "allowCredentials": []any{}, "hints": []string{},
	}})
}

func (s *Service) loginFinish(w http.ResponseWriter, r *http.Request) {
	if !s.anonGuard(w, r, "passkey_login_finish") {
		return
	}
	_, ch, ok := s.finishCeremony(w, r, "login")
	if !ok {
		return
	}
	cj, ok := readFinish(w, r)
	if !ok {
		return
	}
	cd, ok1 := unb64(cj.Response.ClientDataJSON)
	ad, ok2 := unb64(cj.Response.AuthenticatorData)
	sig, ok3 := unb64(cj.Response.Signature)
	rawID, ok4 := unb64(cj.ID)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(rawID) == 0 || len(rawID) > webauthn.MaxCredentialIDLen {
		s.passkeyRejected(w, "login", "encoding")
		return
	}
	ctx := r.Context()
	pk, err := s.store.PasskeyByCredentialID(ctx, rawID)
	if errors.Is(err, ErrNotFound) {
		s.passkeyRejected(w, "login", "unknown_credential")
		return
	}
	if err != nil {
		s.internal(w, "find_passkey", err)
		return
	}
	// L3 §7.2 step 6: the user was not identified beforehand, so
	// userHandle must be present and must be the credential owner's.
	var uh []byte
	if cj.Response.UserHandle != nil {
		uh, _ = unb64(*cj.Response.UserHandle)
	}
	if len(uh) == 0 || len(pk.UserHandle) == 0 || string(uh) != string(pk.UserHandle) {
		s.passkeyRejected(w, "login", "user_handle", "user", pk.UserID)
		return
	}
	as, err := rp(s.cur(r.Context()).cfg).VerifyAssertion(ch, cd, ad, sig, pk.Algorithm, pk.PublicKey)
	if err != nil {
		s.passkeyRejected(w, "login", webauthn.Code(err), "user", pk.UserID)
		return
	}
	// §7.2 step 19: backup eligibility is fixed at creation.
	if as.BE != pk.BackupEligible {
		s.passkeyRejected(w, "login", "backup_eligibility_changed", "user", pk.UserID)
		return
	}
	// A browser signed in to a DIFFERENT account is not switched silently
	// (as with providers, where a plain sign-in is signed_in_as_other):
	// refuse unless the finish body says "switch": true. The check runs
	// after the assertion is verified (a refusal reveals nothing about a
	// credential the caller cannot use) and BEFORE PasskeyUsed and the
	// counter checks, so a refused sign-in writes nothing for the passkey's
	// owner (no sign count, last_used_at or regression record); the
	// single-use challenge is spent either way. The current session and
	// its cookie are left as they are. Same account: a fresh session below
	// (the re-verification path). No valid session: unchanged.
	if !cj.Switch {
		cur, _, _, err := s.session(r)
		if err != nil {
			s.sessionError(w, err)
			return
		}
		if cur != nil && cur.UserID != pk.UserID {
			s.log.Info("auth: sign-in", "provider", "passkey", "outcome", OutcomeSignedInAsOther, "user", cur.UserID)
			web.WriteError(w, http.StatusConflict, "signed_in_as_other",
				"this browser is signed in to another account; sign out first", "")
			return
		}
	}
	// §7.2 step 22: a counter that does not increase is a cloning signal;
	// nday records it and refuses (0/0 = synced passkey without counter).
	// The check is repeated atomically by PasskeyUsed: of two
	// concurrent assertions with the same counter only one can win.
	advanced := (as.SignCount == 0 && pk.SignCount == 0) || as.SignCount > pk.SignCount
	if advanced {
		var err error
		if advanced, err = s.store.PasskeyUsed(ctx, pk.ID, as.SignCount, as.BS); err != nil {
			s.internal(w, "passkey_used", err)
			return
		}
	}
	if !advanced {
		if err := s.store.PasskeyCounterRegression(ctx, pk.ID); err != nil {
			s.internal(w, "counter_regression", err)
			return
		}
		s.passkeyRejected(w, "login", "counter_regression", "user", pk.UserID, "passkey", pk.ID)
		return
	}
	if !s.startSession(w, r, pk.UserID) {
		return
	}
	s.log.Info("auth: sign-in", "provider", "passkey", "outcome", OutcomeOK, "user", pk.UserID, "passkey", pk.ID)
	writeJSON(w, http.StatusOK, okResponse{OK: true, SignedIn: true})
}

// startSession revokes the browser's current session (rotation) and issues
// a new one for user.
func (s *Service) startSession(w http.ResponseWriter, r *http.Request, user UserID) bool {
	ctx := r.Context()
	if h := s.sessionHash(r); h != nil {
		if err := s.store.DeleteSession(ctx, h); err != nil {
			s.internal(w, "revoke_old_session", err)
			return false
		}
	}
	if err := s.newSession(ctx, w, user); err != nil {
		s.internal(w, "new_session", err)
		return false
	}
	return true
}

func (s *Service) signupBegin(w http.ResponseWriter, r *http.Request) {
	if !s.anonGuard(w, r, "passkey_signup_begin") {
		return
	}
	var body struct {
		DisplayName string `json:"display_name"`
	}
	if r.ContentLength != 0 && !readJSON(w, r, &body) {
		return
	}
	dn := SanitizeDisplayName(body.DisplayName)
	if DisplayNameImpersonates(dn) {
		web.WriteError(w, http.StatusBadRequest, "display_name_reserved", "this display name is reserved for the site and its staff", "display_name")
		return
	}
	handle := make([]byte, 32)
	_, _ = randRead(handle)
	name := dn
	if name == "" {
		name = defaultSignupNym
	}
	ch := s.beginCeremony(w, ceremony{Kind: "signup", Handle: b64.EncodeToString(handle), Name: dn})
	writeJSON(w, http.StatusOK, creationOptions(s.cur(r.Context()).cfg, ch, handle, name, dn, nil))
}

func (s *Service) signupFinish(w http.ResponseWriter, r *http.Request) {
	if !s.anonGuard(w, r, "passkey_signup_finish") {
		return
	}
	// Passkey-only sign-up has its own, stricter per-client limit and a
	// global daily cap.
	if s.rateLimited(w, r, s.cur(r.Context()).signupRL, "passkey_signup") {
		return
	}
	c, ch, ok := s.finishCeremony(w, r, "signup")
	if !ok {
		return
	}
	cj, ok := readFinish(w, r)
	if !ok {
		return
	}
	cd, ok1 := unb64(cj.Response.ClientDataJSON)
	ao, ok2 := unb64(cj.Response.AttestationObject)
	rawID, ok3 := unb64(cj.ID)
	handle, ok4 := unb64(c.Handle)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(handle) != 32 {
		s.passkeyRejected(w, "signup", "encoding")
		return
	}
	cr, err := rp(s.cur(r.Context()).cfg).VerifyRegistration(ch, cd, ao, webauthn.SupportedAlgs)
	if err != nil {
		s.passkeyRejected(w, "signup", webauthn.Code(err))
		return
	}
	if string(cr.ID) != string(rawID) {
		s.passkeyRejected(w, "signup", "credential_id_mismatch")
		return
	}
	// counted only for a verified credential, so failed ceremonies cannot
	// use up the day's quota
	if !s.signups.take(s.now(), s.cur(r.Context()).cfg.SignupDaily) {
		s.rlWarn.note(s.log, "passkey_signup_daily_cap")
		w.Header().Set("Retry-After", strconv.Itoa(int(s.signups.untilReset(s.now())/time.Second)+1))
		web.WriteError(w, http.StatusTooManyRequests, "signup_limit", "new passkey-only accounts are paused until tomorrow (UTC); sign in with a provider instead", "")
		return
	}
	uid, err := s.store.SignUpWithPasskey(r.Context(), handle, SafeDisplayName(c.Name), cr, cleanTransports(cj.Response.Transports), keyName(cj.Name))
	if err != nil {
		s.signups.giveBack(s.now())
	}
	switch {
	case errors.Is(err, ErrCredentialExists):
		s.log.Warn("auth: passkey rejected", "ceremony", "signup", "reason", "credential_exists")
		web.WriteError(w, http.StatusConflict, "passkey_exists", err.Error(), "")
		return
	case err != nil:
		s.internal(w, "signup", err)
		return
	}
	if !s.startSession(w, r, uid) {
		return
	}
	s.log.Info("auth: sign-in", "provider", "passkey", "outcome", OutcomeOK, "user", uid, "new_user", true)
	writeJSON(w, http.StatusOK, okResponse{OK: true, SignedIn: true})
}

// passkeyAccount handles POST /account/passkeys/{id}/{rename|delete}.
func (s *Service) passkeyAccount(st *authState, id, action string) func(http.ResponseWriter, *http.Request) {
	if !st.cfg.Passkeys {
		return nil
	}
	switch action {
	case "rename":
		return func(w http.ResponseWriter, r *http.Request) {
			_, u, ok := s.guard(w, r)
			if !ok {
				return
			}
			var body struct {
				Name string `json:"name"`
			}
			if !readJSON(w, r, &body) {
				return
			}
			n := SanitizeDisplayName(body.Name)
			if n == "" {
				web.WriteError(w, http.StatusBadRequest, "bad_request", "name must not be empty", "name")
				return
			}
			switch err := s.store.RenamePasskey(r.Context(), u.ID, id, n); {
			case errors.Is(err, ErrNotFound):
				web.WriteError(w, http.StatusNotFound, "not_found", "no such passkey", "")
			case err != nil:
				s.internal(w, "rename_passkey", err)
			default:
				writeJSON(w, http.StatusOK, map[string]any{"ok": true, "signed_in": true, "name": n})
			}
		}
	case "delete":
		return func(w http.ResponseWriter, r *http.Request) {
			_, u, ok := s.guard(w, r)
			if !ok {
				return
			}
			switch err := s.store.DeletePasskey(r.Context(), u.ID, id, st.enabled); {
			case errors.Is(err, ErrNotFound):
				web.WriteError(w, http.StatusNotFound, "not_found", "no such passkey", "")
			case errors.Is(err, ErrLastMethod):
				web.WriteError(w, http.StatusConflict, "last_identity", "you cannot remove your only sign-in method; delete the account instead", "")
			case errors.Is(err, ErrNoUsableMethod):
				web.WriteError(w, http.StatusConflict, "last_usable_method", err.Error(), "")
			case err != nil:
				s.internal(w, "delete_passkey", err)
			default:
				s.log.Info("auth: passkey deleted", "user", u.ID, "passkey", id)
				writeJSON(w, http.StatusOK, okResponse{OK: true, SignedIn: true})
			}
		}
	}
	return nil
}

// dailyCounter counts passkey-only sign-ups per UTC day. It is held in
// memory: per process, reset on restart (like the rate limiters).
type dailyCounter struct {
	mu  sync.Mutex
	day string
	n   int
}

func (d *dailyCounter) roll(now time.Time) {
	if day := now.UTC().Format(time.DateOnly); day != d.day {
		d.day, d.n = day, 0
	}
}

// take counts one sign-up unless max is reached for today.
func (d *dailyCounter) take(now time.Time, max int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.roll(now)
	if d.n >= max {
		return false
	}
	d.n++
	return true
}

// giveBack undoes take for a sign-up that did not happen.
func (d *dailyCounter) giveBack(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.roll(now)
	if d.n > 0 {
		d.n--
	}
}

func (d *dailyCounter) untilReset(now time.Time) time.Duration {
	n := now.UTC()
	return time.Date(n.Year(), n.Month(), n.Day()+1, 0, 0, 0, 0, time.UTC).Sub(n)
}
