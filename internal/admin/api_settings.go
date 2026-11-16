package admin

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/web"
)

// The settings endpoints (docs/settings.md, docs/admin.md), behind the same
// checks as every action (admin, POST, same origin, CSRF, rate limit,
// recent sign-in):
//
//	POST /api/admin/settings               {"set":{"NDAY_…":"value",…},"unset":["NDAY_…",…]}
//	                                       plain settings only in set; unset takes any registered key
//	                                       (a secret is cleared without a value)
//	POST /api/admin/settings/secret        {"key":"NDAY_…","value":"…"}  store or replace one secret
//	POST /api/admin/settings/secret/clear  {"key":"NDAY_…"}              remove one stored secret
//
// Success: 200 {"ok":true,"changed":[keys],"restart":[changed keys that
// apply after a restart],"settings":{KEY: state}} where state is
// {"source":"db"|"env"|"default","stored":bool,"restart":bool} plus
// "value" (the stored value of a plain setting) or "set" and "hint" (a
// secret: whether a usable value is stored, and its last characters). The
// value of a secret, and any value from the environment, is never in a
// response, an error or a log line.
//
// Refusals: 503 settings_off (no runtime in this process), 400 bad_request
// / 413 too_large / 415 (body), 400 unknown_setting (param = the key when it
// looks like one), 400 secret_setting (a secret in set), 400 not_secret (a
// plain key on the secret endpoints), 400 bad_setting {"fields":{KEY:
// "value"|"conflict"}}, 400 bad_secret (empty, too long or not text), 409
// no_master_key (NDAY_SETTINGS_KEY not configured), 422 invalid_config
// {"keys":[...]} and 422 sign_in_off (the runtime refused the resulting
// configuration; nothing was written), 500 not_applied {"changed":[...],
// "keys":[...],"settings":{...}} (stored, but the running site could not
// apply it; it applies at the next start, or when a later save, even one
// that changes nothing, applies it; "settings" is the stored state as in a
// success).

// Body limits: the plain batch (every plain key at the longest value fits)
// and one secret (the Apple .p8 key is about 250 bytes).
const (
	maxSettingsBody = 64 << 10
	maxSecretBody   = 16 << 10
)

// SettingState is one setting in an answer (and on the page).
type SettingState struct {
	Source  string  `json:"source"`
	Stored  bool    `json:"stored"`
	Restart bool    `json:"restart"`
	Value   *string `json:"value,omitempty"` // plain settings: the stored value
	Set     *bool   `json:"set,omitempty"`   // secrets: a usable value is stored
	Hint    *string `json:"hint,omitempty"`  // secrets: the stored hint ("" none)
}

// SettingStates describes every registered setting of snap: where its
// effective value comes from (env: the runtime's environment, only its
// presence is used) and what is stored. Never a secret, never an
// environment value.
func SettingStates(snap *settings.Snapshot, env func(string) (string, bool)) map[string]SettingState {
	out := map[string]SettingState{}
	for _, d := range settings.Defs() {
		st := SettingState{Source: snap.Source(d.Key, env), Stored: snap.Has(d.Key), Restart: d.Restart}
		if d.Secret {
			set := snap.Source(d.Key, nil) == settings.SourceDB
			hint := ""
			if set {
				hint = snap.Hint(d.Key)
			}
			st.Set, st.Hint = &set, &hint
		} else if v, ok := snap.Value(d.Key); ok {
			st.Value = &v
		}
		out[d.Key] = st
	}
	return out
}

// plausibleKey: k looks like a setting name (safe to echo in an error).
func plausibleKey(k string) bool {
	return len(k) <= 70 && keyNameRe.FindString(k) == k
}

func unknownSetting(w http.ResponseWriter, k string) {
	param := ""
	if plausibleKey(k) {
		param = k
	}
	web.WriteError(w, http.StatusBadRequest, "unknown_setting", "not a setting managed in the database", param)
}

func (s *Service) settingsSave(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	var in struct {
		Set   map[string]string `json:"set"`
		Unset []string          `json:"unset"`
	}
	if !readBodyN(w, r, &in, maxSettingsBody) {
		return
	}
	if s.o.Settings == nil {
		s.settingsFail(w, "settings", ErrSettingsOff)
		return
	}
	fields := map[string]string{}
	set := map[string]string{}
	for k, v := range in.Set {
		d, ok := settings.Lookup(k)
		switch {
		case !ok:
			unknownSetting(w, k)
			return
		case d.Secret:
			web.WriteError(w, http.StatusBadRequest, "secret_setting", "secrets are stored with /api/admin/settings/secret", k)
			return
		}
		cv, err := settings.CheckValue(k, v)
		if err != nil {
			fields[k] = "value"
			continue
		}
		set[k] = cv
	}
	seen := map[string]bool{}
	var unset []string
	for _, k := range in.Unset {
		if _, ok := settings.Lookup(k); !ok {
			unknownSetting(w, k)
			return
		}
		if _, both := in.Set[k]; both {
			fields[k] = "conflict"
			continue
		}
		if !seen[k] {
			seen[k] = true
			unset = append(unset, k)
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
	res, err := s.SaveSettings(r.Context(), u.ID, set, unset)
	s.settingsAnswer(w, u, "settings", res, err)
}

func (s *Service) settingsSecret(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	var in struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if !readBodyN(w, r, &in, maxSecretBody) {
		return
	}
	if s.o.Settings == nil {
		s.settingsFail(w, "secret", ErrSettingsOff)
		return
	}
	if !s.secretKey(w, in.Key) {
		return
	}
	v := strings.TrimSpace(in.Value)
	if v == "" || !utf8.ValidString(v) || len(v) > settings.MaxSecretLen || strings.ContainsRune(v, 0) {
		web.WriteError(w, http.StatusBadRequest, "bad_secret", "the value must be non-empty text of at most 16 KB", "value")
		return
	}
	res, err := s.SetSecret(r.Context(), u.ID, in.Key, v)
	s.settingsAnswer(w, u, "secret", res, err)
}

func (s *Service) settingsSecretClear(w http.ResponseWriter, r *http.Request, u *auth.User, _ string) {
	var in struct {
		Key string `json:"key"`
	}
	if !readBody(w, r, &in) {
		return
	}
	if s.o.Settings == nil {
		s.settingsFail(w, "secret_clear", ErrSettingsOff)
		return
	}
	if !s.secretKey(w, in.Key) {
		return
	}
	res, err := s.ClearSecret(r.Context(), u.ID, in.Key)
	s.settingsAnswer(w, u, "secret_clear", res, err)
}

// secretKey checks the key of a secret endpoint (false: answered).
func (s *Service) secretKey(w http.ResponseWriter, k string) bool {
	d, ok := settings.Lookup(k)
	switch {
	case !ok:
		unknownSetting(w, k)
		return false
	case !d.Secret:
		web.WriteError(w, http.StatusBadRequest, "not_secret", "this setting is not a secret; use /api/admin/settings", k)
		return false
	}
	return true
}

func (s *Service) settingsAnswer(w http.ResponseWriter, u *auth.User, op string, res SettingsChange, err error) {
	var ae *ApplyError
	if err != nil && !errors.As(err, &ae) {
		s.settingsFail(w, op, err)
		return
	}
	changed := res.Changed
	if changed == nil {
		changed = []string{}
	}
	restart := []string{}
	for _, k := range changed {
		if d, _ := settings.Lookup(k); d.Restart {
			restart = append(restart, k)
		}
	}
	if len(res.Changed) > 0 {
		s.log.Info("admin: settings changed", "actor", u.ID, "op", op, "keys", res.Changed)
	}
	if ae != nil {
		writeErrorWith(w, http.StatusInternalServerError, "not_applied",
			"stored, but the running site could not apply it; it applies at the next restart", "",
			map[string]any{"changed": changed, "keys": ae.Keys, "settings": SettingStates(res.Snapshot, s.o.Settings.Env())})
		return
	}
	writeOK(w, map[string]any{"ok": true, "changed": changed, "restart": restart,
		"settings": SettingStates(res.Snapshot, s.o.Settings.Env())})
}

func (s *Service) settingsFail(w http.ResponseWriter, op string, err error) {
	var ce *ConfigError
	switch {
	case errors.Is(err, ErrSettingsOff):
		web.WriteError(w, http.StatusServiceUnavailable, "settings_off", "database settings are not available on this server", "")
	case errors.Is(err, ErrNoMasterKey):
		web.WriteError(w, http.StatusConflict, "no_master_key", settings.EnvKey+" is not configured on this server; secrets cannot be stored", "")
	case errors.As(err, &ce) && ce.SignInOff:
		s.log.Warn("admin: settings refused", "op", op, "keys", ce.Keys, "sign_in_off", true)
		writeErrorWith(w, http.StatusUnprocessableEntity, "sign_in_off", "the change would turn sign-in off entirely", "",
			map[string]any{"keys": nonNil(ce.Keys)})
	case errors.As(err, &ce):
		s.log.Warn("admin: settings refused", "op", op, "keys", ce.Keys)
		param := ""
		if len(ce.Keys) > 0 {
			param = ce.Keys[0]
		}
		writeErrorWith(w, http.StatusUnprocessableEntity, "invalid_config", "the resulting configuration is invalid (see keys)", param,
			map[string]any{"keys": nonNil(ce.Keys)})
	case errors.Is(err, settings.ErrUnknownKey):
		web.WriteError(w, http.StatusBadRequest, "unknown_setting", "not a setting managed in the database", "")
	case errors.Is(err, settings.ErrSecretKey):
		web.WriteError(w, http.StatusBadRequest, "secret_setting", "secrets are stored with /api/admin/settings/secret", "")
	case errors.Is(err, settings.ErrPlainKey):
		web.WriteError(w, http.StatusBadRequest, "not_secret", "this setting is not a secret; use /api/admin/settings", "")
	case errors.Is(err, settings.ErrEmpty):
		web.WriteError(w, http.StatusBadRequest, "bad_secret", "the value must be non-empty text of at most 16 KB", "value")
	case errors.Is(err, auth.ErrNotAdmin):
		web.WriteError(w, http.StatusForbidden, "forbidden", "admins only", "")
	default:
		// (settings errors name keys; a database error carries no parameters)
		s.log.Error("admin: internal error", "op", op, "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
