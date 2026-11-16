package admin

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/xconfig"
)

// The action endpoints (docs/admin.md section 4):
//
//	POST /api/admin/users/{id}/suspend      {"reason":"…","duration":"1d"|"7d"|"30d"|"lifted"}
//	POST /api/admin/users/{id}/unsuspend    (no body)
//	POST /api/admin/users/{id}/role         {"role":"moderator"|"user"}
//	POST /api/admin/users/{id}/signout-all  (no body)
//
// and the X endpoints (api_x.go, api_xdrafts.go) and the settings
// endpoints (api_settings.go).
//
// Order of the checks: host (421), route (404), method (405), session and,
// for POST, same origin + CSRF (auth.RequireUser: 401, 403 cross_site/csrf),
// staff (404 not_found: the area is not revealed), admin (403 forbidden),
// per-user rate limit (429), recent sign-in (403 reauth_required), target
// id (404), body (415/413/400), then the conditional statement of the
// store (404, 403 self/protected, 409 no_change).

// Register mounts /api/admin/ on the site host.
func (s *Service) Register(srv *web.Server) { srv.Handle("/api/admin/", s) }

// Durations a suspension may have ("lifted" = until an admin lifts it).
var Durations = map[string]time.Duration{"1d": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "lifted": 0}

// DurationOrder is the display order of Durations.
var DurationOrder = []string{"1d", "7d", "30d", "lifted"}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidID reports whether s is a UUID in text form.
func ValidID(s string) bool { return uuidRe.MatchString(s) }

const maxBody = 4096

// ServeHTTP routes /api/admin/*.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pw := &personal{ResponseWriter: w}
	defer pw.onPanic()
	w = pw
	r = dropConditional(r)
	if !s.auth.PublicHost(r.Host) {
		web.WriteError(w, http.StatusMisdirectedRequest, "wrong_host", "this host does not serve the back office", "")
		return
	}
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	type action func(http.ResponseWriter, *http.Request, *auth.User, string)
	var act action
	id, idOK := "", func(string) bool { return true }
	switch {
	case len(segs) == 5 && segs[1] == "admin" && segs[2] == "users":
		act = map[string]action{"suspend": s.suspend, "unsuspend": s.unsuspend, "role": s.role, "signout-all": s.signOutAll}[segs[4]]
		id, idOK = segs[3], ValidID
	case len(segs) == 4 && segs[1] == "admin" && segs[2] == "x":
		act = map[string]action{"settings": s.xSettings, "accounts": s.xAdd, "import": s.xImport}[segs[3]]
	case len(segs) == 6 && segs[1] == "admin" && segs[2] == "x" && segs[3] == "accounts":
		act = map[string]action{"update": s.xUpdate, "enable": s.xEnable, "disable": s.xDisable}[segs[5]]
		id, idOK = segs[4], xconfig.ValidUserID
	case len(segs) == 6 && segs[1] == "admin" && segs[2] == "x" && segs[3] == "candidates":
		act = map[string]action{"add": s.xCandidateAdd, "dismiss": s.xCandidateDismiss, "restore": s.xCandidateRestore}[segs[5]]
		id, idOK = segs[4], xconfig.ValidUserID
	case len(segs) == 3 && segs[1] == "admin" && segs[2] == "settings":
		act = s.settingsSave
	case len(segs) == 4 && segs[1] == "admin" && segs[2] == "settings" && segs[3] == "secret":
		act = s.settingsSecret
	case len(segs) == 5 && segs[1] == "admin" && segs[2] == "settings" && segs[3] == "secret" && segs[4] == "clear":
		act = s.settingsSecretClear
	case len(segs) == 6 && segs[1] == "admin" && segs[2] == "x" && segs[3] == "drafts":
		act = map[string]action{"save": s.xDraftSave, "posted": s.xDraftPosted, "discard": s.xDraftDiscard,
			"restore": s.xDraftRestore}[segs[5]]
		id, idOK = segs[4], ValidDraftID
	}
	if act == nil {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such endpoint", "")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		web.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST", "")
		return
	}
	r = r.WithContext(audit.WithClient(r.Context(), auth.ClientAddr(r), r.Header.Get("Cf-Ray")))
	s.auth.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := auth.CurrentUser(r)
		if !s.IsStaff(u) {
			web.WriteError(w, http.StatusNotFound, "not_found", "no such endpoint", "")
			return
		}
		if u.Role != auth.RoleAdmin {
			web.WriteError(w, http.StatusForbidden, "forbidden", "admins only", "")
			return
		}
		if ok, wait := s.o.ActionLimit.Allow(u.ID); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
			web.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again later", "")
			return
		}
		if !s.auth.RecentSignIn(r) {
			web.WriteError(w, http.StatusForbidden, "reauth_required", "sign in again to do this (your sign-in is too old)", "")
			return
		}
		if !idOK(id) {
			web.WriteError(w, http.StatusNotFound, "not_found", "no such user or account", "")
			return
		}
		act(w, r, u, strings.ToLower(id))
	})).ServeHTTP(w, r)
}

// readBody decodes a small JSON object into v. With v nil the body must be
// empty or "{}" (any Content-Type is then irrelevant).
func readBody(w http.ResponseWriter, r *http.Request, v any) bool { return readBodyN(w, r, v, maxBody) }

// readBodyN is readBody with a size limit.
func readBodyN(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if v == nil {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			web.WriteError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large", "")
			return false
		}
		if t := strings.TrimSpace(string(b)); t != "" && t != "{}" {
			web.WriteError(w, http.StatusBadRequest, "bad_request", "this endpoint takes no body", "")
			return false
		}
		return true
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		web.WriteError(w, http.StatusUnsupportedMediaType, "bad_request", "Content-Type must be application/json", "")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
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
			web.WriteError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large", "")
		} else {
			web.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		}
		return false
	}
	return true
}

// CleanReason is a suspension reason as stored: control, format and bidi
// characters removed, white space runs collapsed to one space, trimmed.
func CleanReason(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToValidUTF8(s, "�") {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

type userJSON struct {
	ID             string     `json:"id"`
	Handle         *string    `json:"handle"`
	Role           string     `json:"role"`
	Status         string     `json:"status"`
	SuspendedUntil *time.Time `json:"suspended_until"`
}

type actionResponse struct {
	OK      bool     `json:"ok"`
	User    userJSON `json:"user"`
	Revoked *int64   `json:"revoked_sessions,omitempty"`
}

func (s *Service) answer(w http.ResponseWriter, res *auth.StaffResult, err error, op string, revoked bool) {
	switch {
	case err == nil:
		u := res.User
		out := actionResponse{OK: true, User: userJSON{ID: u.ID, Handle: u.Handle, Role: u.Role, Status: u.EffectiveStatus(s.auth.Now())}}
		if out.User.Status == auth.StatusSuspended && u.SuspendedUntil != nil {
			t := u.SuspendedUntil.UTC()
			out.User.SuspendedUntil = &t
		}
		if revoked {
			n := res.Revoked
			out.Revoked = &n
		}
		b, _ := web.EncodeJSON(out)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	case errors.Is(err, auth.ErrNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such user", "")
	case errors.Is(err, auth.ErrSelf):
		web.WriteError(w, http.StatusForbidden, "self", auth.ErrSelf.Error(), "")
	case errors.Is(err, auth.ErrProtected):
		web.WriteError(w, http.StatusForbidden, "protected", auth.ErrProtected.Error(), "")
	case errors.Is(err, auth.ErrNotAdmin):
		web.WriteError(w, http.StatusForbidden, "forbidden", "admins only", "")
	case errors.Is(err, auth.ErrNoChange):
		web.WriteError(w, http.StatusConflict, "no_change", auth.ErrNoChange.Error(), "")
	default:
		s.log.Error("admin: internal error", "op", op, "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

func (s *Service) suspend(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	var in struct {
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
	}
	if !readBody(w, r, &in) {
		return
	}
	reason := CleanReason(in.Reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > auth.MaxSuspendReason {
		web.WriteError(w, http.StatusBadRequest, "bad_reason", "a reason of 1 to 500 characters is required", "reason")
		return
	}
	d, ok := Durations[in.Duration]
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "bad_duration", "duration must be 1d, 7d, 30d or lifted", "duration")
		return
	}
	var until *time.Time
	if d > 0 {
		t := s.auth.Now().Add(d).UTC().Truncate(time.Second)
		until = &t
	}
	res, err := s.write.StaffSuspend(r.Context(), u.ID, id, until, reason)
	if err == nil {
		s.log.Info("admin: user suspended", "actor", u.ID, "user", id, "duration", in.Duration)
	}
	s.answer(w, res, err, "suspend", false)
}

func (s *Service) unsuspend(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	if !readBody(w, r, nil) {
		return
	}
	res, err := s.write.StaffUnsuspend(r.Context(), u.ID, id)
	if err == nil {
		s.log.Info("admin: user unsuspended", "actor", u.ID, "user", id)
	}
	s.answer(w, res, err, "unsuspend", false)
}

func (s *Service) role(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	var in struct {
		Role string `json:"role"`
	}
	if !readBody(w, r, &in) {
		return
	}
	if in.Role != auth.RoleUser && in.Role != auth.RoleModerator {
		// the admin role is granted and revoked only on the server (CLI)
		web.WriteError(w, http.StatusBadRequest, "bad_role", "role must be user or moderator", "role")
		return
	}
	res, err := s.write.StaffSetRole(r.Context(), u.ID, id, in.Role)
	if err == nil {
		s.log.Info("admin: role changed", "actor", u.ID, "user", id, "role", in.Role)
	}
	s.answer(w, res, err, "role", false)
}

func (s *Service) signOutAll(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	if !readBody(w, r, nil) {
		return
	}
	res, err := s.write.StaffSignOutAll(r.Context(), u.ID, id)
	if err == nil {
		s.log.Info("admin: user signed out everywhere", "actor", u.ID, "user", id, "sessions", res.Revoked)
	}
	s.answer(w, res, err, "signout_all", true)
}
