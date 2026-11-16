package cli

import (
	"crypto/rand"
	"encoding/base64"
	"sort"
	"strings"
	"sync"
	"testing"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/site"
)

func mapLookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// recorder wraps a lookup and remembers every key asked for.
type recorder struct {
	mu   sync.Mutex
	seen map[string]bool
	next func(string) (string, bool)
}

func (r *recorder) lookup(k string) (string, bool) {
	r.mu.Lock()
	r.seen[k] = true
	r.mu.Unlock()
	return r.next(k)
}

func randSecret() string {
	b := make([]byte, 48)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// TestRegistryMatchesValidators: every registered key is actually read by
// the validator of its group, and the registered discussion keys are
// exactly the ones discuss and corrections read (minus the discussion pool
// size, environment-only).
func TestRegistryMatchesValidators(t *testing.T) {
	reg := map[string]settings.Def{}
	for _, d := range settings.Defs() {
		reg[d.Key] = d
	}
	// discuss
	var dk []string
	getenv := func(k string) string { dk = append(dk, k); return "" }
	_, _ = discuss.Enabled(getenv)
	_, _ = discuss.LimitsFromEnv(getenv)
	_, _ = corrections.LimitsFromEnv(getenv) // readers' corrections are shown with the discussion limits
	var want []string
	for _, d := range settings.GroupDefs(settings.GroupDiscuss) {
		want = append(want, d.Key)
	}
	sort.Strings(dk)
	sort.Strings(want)
	if strings.Join(dk, ",") != strings.Join(want, ",") {
		t.Errorf("discuss reads\n%v\nregistry has\n%v", dk, want)
	}
	// auth: a configuration that reads every variable
	r := &recorder{seen: map[string]bool{}, next: mapLookup(map[string]string{
		auth.EnvPublicURL: "https://www.nday.land", auth.EnvSecret: randSecret(),
		auth.EnvGitHubClientID: "Iv1.abc", auth.EnvGitHubClientSecret: "x",
	})}
	if _, err := auth.FromEnv(r.lookup); err != nil {
		t.Fatal(err)
	}
	for _, d := range settings.GroupDefs(settings.GroupAuth) {
		if !r.seen[d.Key] {
			t.Errorf("auth.FromEnv never reads %s", d.Key)
		}
	}
	// collectors
	r = &recorder{seen: map[string]bool{}, next: mapLookup(nil)}
	for _, c := range collectorChecks {
		cc, err := c.factory(collector.Deps{Env: r.lookup})
		if err != nil {
			t.Fatal(err)
		}
		closeCollector(cc)
	}
	for _, d := range settings.GroupDefs(settings.GroupCollectors) {
		if !r.seen[d.Key] {
			t.Errorf("no collector reads %s", d.Key)
		}
	}
	// hot list pinning: exactly the keys site reads
	var hk []string
	_, _ = site.PinConfigFromEnv(func(k string) string { hk = append(hk, k); return "" })
	want = nil
	for _, d := range settings.GroupDefs(settings.GroupHot) {
		want = append(want, d.Key)
	}
	sort.Strings(hk)
	sort.Strings(want)
	if strings.Join(hk, ",") != strings.Join(want, ",") {
		t.Errorf("site.PinConfigFromEnv reads\n%v\nregistry has\n%v", hk, want)
	}
}

func TestValidateSettings(t *testing.T) {
	if err := validateSettings(mapLookup(nil)); err != nil {
		t.Fatalf("empty configuration: %v", err)
	}
	const leak = "LEAKY-VALUE-42x"
	for _, c := range []struct {
		m    map[string]string
		want []string
	}{
		{map[string]string{"NDAY_DISCUSS": leak}, []string{"NDAY_DISCUSS must be on or off"}},
		{map[string]string{"NDAY_DISCUSS_POST_EVERY": leak}, []string{"NDAY_DISCUSS_POST_EVERY must be a duration"}},
		{map[string]string{"NDAY_CVELIST_MAX_FILES": leak, "NDAY_GHSA_OVERLAP_MINUTES": leak},
			[]string{"NDAY_CVELIST_MAX_FILES: invalid value (rejected by the cvelist collector)",
				"NDAY_GHSA_OVERLAP_MINUTES: invalid value (rejected by the ghsa collector)"}},
		{map[string]string{"NDAY_CVELIST_BOOTSTRAP_DAYS": "999999"}, []string{"NDAY_CVELIST_BOOTSTRAP_DAYS: invalid value"}},
		{map[string]string{"NDAY_X_BEARER_TOKEN": "a b" + leak}, []string{"NDAY_X_BEARER_TOKEN: invalid value (rejected by the xposts collector)"}},
		{map[string]string{"NDAY_AUTH_PASSKEYS": leak}, []string{"NDAY_AUTH_PASSKEYS must be on or off"}},
		{map[string]string{"NDAY_AUTH_GITHUB_CLIENT_ID": "Iv1", "NDAY_AUTH_GITHUB_CLIENT_SECRET": "sec ret" + leak,
			"NDAY_PUBLIC_URL": "https://www.nday.land", "NDAY_AUTH_SECRET": randSecret()},
			[]string{"NDAY_AUTH_GITHUB_CLIENT_SECRET must be"}},
		{map[string]string{"NDAY_HOT_PIN_MAX": leak}, []string{"NDAY_HOT_PIN_MAX must be an integer 0..20"}},
		{map[string]string{"NDAY_HOT_PIN_WAVE_DAYS": "999999"}, []string{"NDAY_HOT_PIN_WAVE_DAYS must be an integer 1..30"}},
		{map[string]string{"NDAY_HOT_PIN_RECENT_HOURS": "0"}, []string{"NDAY_HOT_PIN_RECENT_HOURS must be an integer 1..168"}},
	} {
		err := validateSettings(mapLookup(c.m))
		if err == nil {
			t.Errorf("%v accepted", c.m)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%v: %v lacks %q", c.m, err, w)
			}
		}
		if strings.Contains(err.Error(), leak) || strings.Contains(err.Error(), "999999") {
			t.Errorf("error echoes the value: %v", err)
		}
	}
}

func TestValidateCandidateSignInOff(t *testing.T) {
	base := map[string]string{"NDAY_AUTH_PASSKEYS": "on", "NDAY_PUBLIC_URL": "https://www.nday.land", "NDAY_AUTH_SECRET": randSecret()}
	env := mapLookup(base)
	if err := validateCandidate(env, env); err != nil {
		t.Fatal(err)
	}
	off := map[string]string{}
	for k, v := range base {
		off[k] = v
	}
	off["NDAY_AUTH_PASSKEYS"] = "off"
	if err := validateCandidate(mapLookup(off), env); err == nil || !strings.Contains(err.Error(), "turn sign-in off") {
		t.Errorf("sign-in off accepted: %v", err)
	}
	// sign-in off in the environment already: no objection
	if err := validateCandidate(mapLookup(off), mapLookup(off)); err != nil {
		t.Errorf("%v", err)
	}
}
