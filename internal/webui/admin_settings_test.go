package webui

import (
	"strings"
	"testing"

	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/webui/i18n"
)

// TestSettingNames: every registered setting has a name and a description
// in keys.json and in the en and zh-Hans catalogs, so /admin/settings never
// labels a setting by its variable name alone. A key added to
// internal/settings/registry.go without them fails here.
func TestSettingNames(t *testing.T) {
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"admin.set.name", "admin.set.desc"} {
		def := set.Reference.Key(key)
		if def == nil || def.Select == nil || def.Select.Var != "key" {
			t.Fatalf("%s: not a select on key in keys.json", key)
		}
		have := map[string]bool{}
		for _, v := range def.Select.Values {
			have[v] = true
		}
		for _, d := range settings.Defs() {
			if !have[d.Key] {
				t.Errorf("%s has no variant for the registered setting %s", key, d.Key)
				continue
			}
			for _, tag := range []string{"en", "zh-Hans"} {
				l := set.ByTag(tag)
				txt := l.Text(key, "key", d.Key)
				if strings.TrimSpace(txt) == "" || l.FallsBack(key) || strings.Contains(txt, "NDAY_") && key == "admin.set.name" {
					t.Errorf("%s %s[%s] = %q", tag, key, d.Key, txt)
				}
			}
		}
	}
}

// TestSettingEffect: when a saved change applies, as docs/settings.md §4
// states it.
func TestSettingEffect(t *testing.T) {
	want := map[string]string{
		"NDAY_DISCUSS":              "restart",
		"NDAY_X_BEARER_TOKEN":       "next_run_now",
		"NDAY_GITHUB_TOKEN":         "next_run",
		"NDAY_CVELIST_MAX_FILES":    "next_run",
		"NDAY_DISCUSS_POST_BURST":   "now",
		"NDAY_AUTH_SESSION_IDLE":    "now",
		"NDAY_HOT_PIN_RECENT_HOURS": "now",
		"NDAY_CORRECTIONS_DAILY":    "now",
	}
	for k, w := range want {
		d, ok := settings.Lookup(k)
		if !ok {
			t.Fatalf("%s is not registered", k)
		}
		if got := settingEffect(d); got != w {
			t.Errorf("settingEffect(%s) = %s, want %s", k, got, w)
		}
	}
	// every value has a text (admin.set.restart for "restart")
	set, _ := i18n.Default()
	vals := set.Reference.Key("admin.set.effect").Select.Values
	for _, d := range settings.Defs() {
		e := settingEffect(d)
		if e == "restart" {
			continue
		}
		found := false
		for _, v := range vals {
			found = found || v == e
		}
		if !found {
			t.Errorf("%s: effect %q has no admin.set.effect variant", d.Key, e)
		}
	}
}
