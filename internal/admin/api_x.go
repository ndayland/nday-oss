package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlookup"
)

// The X collector endpoints (docs/admin.md section 4.1), behind the same
// checks as the user actions (admin, POST, same origin, CSRF, rate limit,
// recent sign-in: they change what is collected and what it costs):
//
//	POST /api/admin/x/settings                  {"enabled":true|false|null,"max_posts":N|null,"max_requests":N|null,
//	                                             "bootstrap_days":N|null,"max_query_length":N|null}  (every key; null = default)
//	POST /api/admin/x/accounts                  {"handle":"…","note":"…"}  add: the id is looked up on X
//	                                            {"user_id":"…","handle":"…","note":"…"}  add under that id (no lookup)
//	POST /api/admin/x/accounts/{user id}/update {"handle":"…","note":"…"}
//	POST /api/admin/x/accounts/{user id}/enable | /disable
//	POST /api/admin/x/import                    {"text":"…","dry_run":true|false}
//	POST /api/admin/x/candidates/{user id}/add | /dismiss | /restore  (xcandidates.go)

// MaxImportBytes bounds the import request body.
const MaxImportBytes = 256 << 10

func writeOK(w http.ResponseWriter, v any) {
	b, _ := web.EncodeJSON(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// writeErrorWith is web.WriteError with extra members in the error object.
func writeErrorWith(w http.ResponseWriter, status int, code, msg, param string, extra map[string]any) {
	e := map[string]any{"status": status, "code": code, "message": msg}
	if param != "" {
		e["param"] = param
	}
	for k, v := range extra {
		e[k] = v
	}
	b, _ := web.EncodeJSON(map[string]any{"error": e})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (s *Service) xFail(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, xconfig.ErrNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such account", "")
	case errors.Is(err, xconfig.ErrCandidateNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", "no such candidate", "")
	case errors.Is(err, ErrCandidateNoHandle):
		web.WriteError(w, http.StatusUnprocessableEntity, "no_handle", "the candidate has no valid handle", "handle")
	case errors.Is(err, xconfig.ErrOwnAccount):
		web.WriteError(w, http.StatusUnprocessableEntity, "own_account", "the site's own X account is never collected", "handle")
	case errors.Is(err, xconfig.ErrExists):
		web.WriteError(w, http.StatusConflict, "exists", "this user id is already listed", "user_id")
	case errors.Is(err, auth.ErrNotAdmin):
		web.WriteError(w, http.StatusForbidden, "forbidden", "admins only", "")
	case errors.Is(err, ErrNoXChange):
		web.WriteError(w, http.StatusConflict, "no_change", "nothing to change", "")
	// the X user lookup (internal/xlookup); its errors never hold the token
	case errors.Is(err, xlookup.ErrNotConfigured):
		web.WriteError(w, http.StatusServiceUnavailable, "x_lookup_off", "X user lookup is not configured on this server; enter the numeric user id", "user_id")
	case errors.Is(err, ErrXHandleNotFound):
		web.WriteError(w, http.StatusUnprocessableEntity, "x_not_found", "no X account has this handle", "handle")
	case errors.Is(err, ErrXUnavailable):
		web.WriteError(w, http.StatusUnprocessableEntity, "x_unavailable", "the X account is suspended or unavailable", "handle")
	case errors.Is(err, xlookup.ErrBadHandle):
		web.WriteError(w, http.StatusBadRequest, "bad_handle", "invalid handle", "handle")
	case errors.Is(err, xlookup.ErrRateLimited):
		s.log.Warn("admin: x lookup refused", "op", op, "err", err)
		web.WriteError(w, http.StatusServiceUnavailable, "x_rate_limited", "the X API rate limit is reached; try again later", "")
	case errors.Is(err, xlookup.ErrAuth):
		s.log.Warn("admin: x lookup refused", "op", op, "err", err)
		web.WriteError(w, http.StatusBadGateway, "x_auth", "the X API refused this server's credentials", "")
	case errors.Is(err, xlookup.ErrUpstream):
		s.log.Warn("admin: x lookup failed", "op", op, "err", err)
		web.WriteError(w, http.StatusBadGateway, "x_upstream", "the X API did not answer in time or failed", "")
	default:
		s.log.Error("admin: internal error", "op", op, "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

// SettingsJSON is the settings as the endpoint reads and answers them.
type SettingsJSON struct {
	Enabled        *bool `json:"enabled"`
	MaxPosts       *int  `json:"max_posts"`
	MaxRequests    *int  `json:"max_requests"`
	BootstrapDays  *int  `json:"bootstrap_days"`
	MaxQueryLength *int  `json:"max_query_length"`
}

var settingKeys = []string{"enabled", "max_posts", "max_requests", "bootstrap_days", "max_query_length"}

func (s *Service) xSettings(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	var raw map[string]json.RawMessage
	if !readBody(w, r, &raw) {
		return
	}
	fields := map[string]string{}
	for k := range raw {
		if !contains(settingKeys, k) {
			fields[k] = "unknown"
		}
	}
	var st xconfig.Stored
	for _, k := range settingKeys {
		v, ok := raw[k]
		if !ok {
			fields[k] = "missing"
			continue
		}
		if string(v) == "null" {
			continue
		}
		if k == "enabled" {
			var b bool
			if json.Unmarshal(v, &b) != nil {
				fields[k] = "type"
				continue
			}
			st.Enabled = &b
			continue
		}
		var n int
		if json.Unmarshal(v, &n) != nil {
			fields[k] = "type"
			continue
		}
		for _, b := range xconfig.Bounds {
			if b.Name == k && (n < b.Min || n > b.Max) {
				fields[k] = "range"
			}
		}
		switch k {
		case "max_posts":
			st.MaxPosts = &n
		case "max_requests":
			st.MaxRequests = &n
		case "bootstrap_days":
			st.BootstrapDays = &n
		case "max_query_length":
			st.MaxQueryLength = &n
		}
	}
	if len(fields) > 0 {
		names := make([]string, 0, len(fields))
		for k := range fields {
			names = append(names, k)
		}
		sort.Strings(names)
		writeErrorWith(w, http.StatusBadRequest, "bad_setting", "invalid settings (see fields)", names[0], map[string]any{"fields": fields})
		return
	}
	saved, err := s.XSaveSettings(r.Context(), u.ID, st)
	if err != nil {
		s.xFail(w, "x_settings", err)
		return
	}
	eff, _ := saved.Effective()
	s.log.Info("admin: x settings changed", "actor", u.ID)
	writeOK(w, map[string]any{"ok": true, "settings": SettingsJSON{saved.Enabled, saved.MaxPosts, saved.MaxRequests,
		saved.BootstrapDays, saved.MaxQueryLength},
		"worst_case_posts_per_run": XWorstPostsPerRun(eff)})
}

// accountFields checks the fields of an account request; "" = valid.
func accountFields(userID, handle, note string) (code, param string) {
	switch {
	case userID != "-" && !xconfig.ValidUserID(userID):
		return "bad_user_id", "user_id"
	case !xconfig.ValidHandle(handle):
		return "bad_handle", "handle"
	case !utf8.ValidString(note) || utf8.RuneCountInString(note) > xconfig.MaxNoteLen || strings.ContainsAny(note, "\x00\r\n"):
		return "bad_note", "note"
	}
	return "", ""
}

func (s *Service) xAdd(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	var in struct {
		UserID string `json:"user_id"`
		Handle string `json:"handle"`
		Note   string `json:"note"`
	}
	if !readBody(w, r, &in) {
		return
	}
	in.UserID, in.Handle, in.Note = strings.TrimSpace(in.UserID), strings.TrimPrefix(strings.TrimSpace(in.Handle), "@"), strings.TrimSpace(in.Note)
	id := in.UserID
	if id == "" {
		id = "-" // the handle alone: the id is looked up
	}
	// every field is checked before any request leaves for X
	if code, param := accountFields(id, in.Handle, in.Note); code != "" {
		web.WriteError(w, http.StatusBadRequest, code, "invalid "+param, param)
		return
	}
	if in.UserID != "" {
		if err := s.XAddAccount(r.Context(), u.ID, in.UserID, in.Handle, in.Note); err != nil {
			s.xFail(w, "x_account_add", err)
			return
		}
		s.log.Info("admin: x account added", "actor", u.ID, "x_user", in.UserID, "handle", in.Handle, "lookup", false)
		writeOK(w, map[string]any{"ok": true, "user_id": in.UserID, "handle": in.Handle, "result": "added", "looked_up": false})
		return
	}
	res, err := s.XAddByHandle(r.Context(), u.ID, in.Handle, in.Note)
	if err != nil {
		if errors.Is(err, xconfig.ErrExists) && res != nil {
			// the handle resolved to an id that is listed with this handle
			writeErrorWith(w, http.StatusConflict, "exists", "this account is already listed", "handle",
				map[string]any{"user_id": res.UserID, "handle": res.Handle})
			return
		}
		s.xFail(w, "x_account_add", err)
		return
	}
	if res.Renamed {
		s.log.Info("admin: x account handle updated from lookup", "actor", u.ID, "x_user", res.UserID, "handle", res.Handle, "previous", res.Previous)
		writeOK(w, map[string]any{"ok": true, "user_id": res.UserID, "handle": res.Handle, "result": "renamed",
			"previous_handle": res.Previous, "looked_up": true})
		return
	}
	s.log.Info("admin: x account added", "actor", u.ID, "x_user", res.UserID, "handle", res.Handle, "lookup", true)
	writeOK(w, map[string]any{"ok": true, "user_id": res.UserID, "handle": res.Handle, "result": "added", "looked_up": true})
}

func (s *Service) xUpdate(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	var in struct {
		Handle string `json:"handle"`
		Note   string `json:"note"`
	}
	if !readBody(w, r, &in) {
		return
	}
	in.Handle, in.Note = strings.TrimPrefix(strings.TrimSpace(in.Handle), "@"), strings.TrimSpace(in.Note)
	if code, param := accountFields("-", in.Handle, in.Note); code != "" {
		web.WriteError(w, http.StatusBadRequest, code, "invalid "+param, param)
		return
	}
	if err := s.XUpdateAccount(r.Context(), u.ID, id, in.Handle, in.Note); err != nil {
		s.xFail(w, "x_account_update", err)
		return
	}
	s.log.Info("admin: x account updated", "actor", u.ID, "x_user", id)
	writeOK(w, map[string]any{"ok": true, "user_id": id})
}

func (s *Service) xEnable(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.xSwitch(w, r, u, id, true)
}

func (s *Service) xDisable(w http.ResponseWriter, r *http.Request, u *auth.User, id string) {
	s.xSwitch(w, r, u, id, false)
}

func (s *Service) xSwitch(w http.ResponseWriter, r *http.Request, u *auth.User, id string, on bool) {
	if !readBody(w, r, nil) {
		return
	}
	if err := s.XSetAccountEnabled(r.Context(), u.ID, id, on); err != nil {
		s.xFail(w, "x_account_switch", err)
		return
	}
	s.log.Info("admin: x account switched", "actor", u.ID, "x_user", id, "enabled", on)
	writeOK(w, map[string]any{"ok": true, "user_id": id, "enabled": on})
}

func (s *Service) xImport(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	var in struct {
		Text   string `json:"text"`
		DryRun bool   `json:"dry_run"`
	}
	if !readBodyN(w, r, &in, MaxImportBytes) {
		return
	}
	res, lineErrs, err := s.XImport(r.Context(), u.ID, in.Text, in.DryRun)
	if err != nil {
		s.xFail(w, "x_import", err)
		return
	}
	if len(lineErrs) > 0 {
		var ls []map[string]any
		for _, e := range lineErrs {
			ls = append(ls, map[string]any{"line": e.Line, "message": e.Err.Error()})
		}
		writeErrorWith(w, http.StatusBadRequest, "bad_import", "invalid lines; nothing was imported", "text", map[string]any{"lines": ls})
		return
	}
	if !in.DryRun && res.Inserted+res.Updated > 0 {
		s.log.Info("admin: x accounts imported", "actor", u.ID, "inserted", res.Inserted, "updated", res.Updated)
	}
	lines := res.Lines
	if lines == nil {
		lines = []ImportLine{}
	}
	writeOK(w, map[string]any{"ok": true, "dry_run": in.DryRun, "inserted": res.Inserted, "updated": res.Updated,
		"unchanged": res.Unchanged, "lines": lines})
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
