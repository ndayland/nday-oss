package webui

import (
	"errors"
	"net/http"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/webui/i18n"
)

// /admin/settings: the database settings (internal/settings,
// docs/settings.md). Admin only. The page shows, per registered setting,
// where its effective value comes from (database / environment / default)
// and the value stored in the database for plain settings; it never
// renders a value of the environment, and never a secret (for a secret
// only whether one is stored and its hint). Saving is done by
// static/admin.js against /api/admin/settings*.

// AdminSetRow is one setting.
type AdminSetRow struct {
	Key     string
	Kind    string // text | onoff (plain); password | pem (secret)
	Source  string // db | env | default
	Restart bool
	// Effect is when a saved change takes effect: now | next_run |
	// next_run_now | restart (settingEffect)
	Effect string
	Stored bool   // a row exists (it may be unusable: see Warnings)
	Value  string // the stored value of a plain setting ("" = not stored)
	// secrets
	SecretState string // set | unset | unreadable
	Hint        string
}

// AdminSetGroup is one group (one form for its plain settings, one form
// per secret).
type AdminSetGroup struct {
	Name    string // collectors | discuss | auth | hot
	Plain   []AdminSetRow
	Secrets []AdminSetRow
}

// AdminSettingsView is the settings page.
type AdminSettingsView struct {
	Available bool // the process can store and apply settings
	HasKey    bool // NDAY_SETTINGS_KEY is configured: secrets can be stored
	Warnings  []string
	Groups    []AdminSetGroup
	// re-verification panel
	Providers []ProviderLink
	Passkeys2 bool
}

// setGroups is the display order of the page.
var setGroups = []string{settings.GroupCollectors, settings.GroupDiscuss, settings.GroupAuth, settings.GroupHot}

// onOffSettings are chosen from on / off.
var onOffSettings = map[string]bool{"NDAY_DISCUSS": true, discuss.EnvGuestRead: true, auth.EnvPasskeys: true,
	auth.EnvPasskeySignup: true}

// settingEffect is when a saved change of d takes effect, as
// docs/settings.md §4 states it: a Restart setting after a restart; the
// collectors' settings at the start of their next run (they read the
// database every run), except the X bearer token, which the running site
// also applies at once to the handle lookups of /admin/x
// (admin.Service.SetXLookup); every other setting at once (the save
// applies the stored state to the running site).
func settingEffect(d settings.Def) string {
	switch {
	case d.Restart:
		return "restart"
	case d.Key == "NDAY_X_BEARER_TOKEN":
		return "next_run_now"
	case d.Group == settings.GroupCollectors:
		return "next_run"
	}
	return "now"
}

func (u *UI) adminSettings(w http.ResponseWriter, r *http.Request, loc *i18n.Locale, me *auth.User) {
	a := u.opts.Admin
	v := AdminSettingsView{}
	if rt := a.Settings(); rt != nil {
		snap, err := a.SettingsSnapshot(r.Context())
		if err != nil && !errors.Is(err, admin.ErrSettingsOff) {
			u.adminFail(w, r, loc, err)
			return
		}
		v.Available, v.HasKey = true, rt.Key() != nil
		for _, wn := range snap.Warnings() {
			v.Warnings = append(v.Warnings, plain(wn))
		}
		states := admin.SettingStates(snap, rt.Env())
		for _, g := range setGroups {
			grp := AdminSetGroup{Name: g}
			for _, d := range settings.GroupDefs(g) {
				st := states[d.Key]
				row := AdminSetRow{Key: d.Key, Source: st.Source, Restart: d.Restart, Effect: settingEffect(d), Stored: st.Stored}
				if d.Secret {
					row.Kind, row.SecretState = "password", "unset"
					if d.Key == auth.EnvAppleKey {
						row.Kind = "pem"
					}
					switch {
					case st.Set != nil && *st.Set:
						row.SecretState = "set"
						if st.Hint != nil {
							row.Hint = plain(*st.Hint)
						}
					case st.Stored:
						row.SecretState = "unreadable"
					}
					grp.Secrets = append(grp.Secrets, row)
					continue
				}
				row.Kind = "text"
				if onOffSettings[d.Key] {
					row.Kind = "onoff"
				}
				if st.Value != nil {
					row.Value = plain(*st.Value)
				}
				grp.Plain = append(grp.Plain, row)
			}
			v.Groups = append(v.Groups, grp)
		}
	}
	if acc := u.opts.Accounts.Current(); acc != nil {
		for _, p := range acc.Providers {
			v.Providers = append(v.Providers, ProviderLink{ID: p, Name: providerNames[p]})
		}
		v.Passkeys2 = acc.Passkeys
	}
	u.adminRender(w, r, loc, me, "settings", "admin_settings", loc.Text("admin.nav", "tab", "settings"), v)
}
