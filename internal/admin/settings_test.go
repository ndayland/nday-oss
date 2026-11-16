package admin_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/testutil"
)

// Secrets and environment values of these tests: none of them may appear in
// a response, an audit row, a log line or a page.
const (
	secretX     = "XSECRET-bearer-0123456789-wxyz"
	secretX2    = "XSECRET-second-9876543210-qrst"
	secretGH    = "GHSECRET-client-abcdefghij-klmn"
	envSecret   = "ENVSECRET-github-token-value-env1"
	envGHSAReqs = "987654321"
)

// fakeRuntime is a settings.Runtime: Validate runs the discussion limits
// validator and refuses passkeys off (sign-in off); Apply reads
// app_settings (like the real one) and records what it read.
type fakeRuntime struct {
	mu       sync.Mutex
	env      map[string]string
	key      *settings.Key
	load     func(context.Context) (*settings.Snapshot, error)
	applied  []*settings.Snapshot
	applyErr error
}

func (f *fakeRuntime) Env() func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := f.env[k]; return v, ok }
}
func (f *fakeRuntime) Key() *settings.Key { return f.key }
func (f *fakeRuntime) Validate(c *settings.Snapshot) error {
	look := c.Lookup(f.Env())
	get := func(k string) string { v, _ := look(k); return v }
	if _, err := discuss.LimitsFromEnv(get); err != nil {
		return err
	}
	if get(auth.EnvPasskeys) == "off" {
		return fmt.Errorf("%w (%s)", auth.ErrReconfigureDisabled, auth.EnvPasskeys)
	}
	return nil
}
func (f *fakeRuntime) Apply(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := f.load(ctx)
	if err != nil {
		return err
	}
	f.applied = append(f.applied, s)
	return f.applyErr
}
func (f *fakeRuntime) last() (*settings.Snapshot, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return nil, 0
	}
	return f.applied[len(f.applied)-1], len(f.applied)
}

func newKey(t *testing.T) *settings.Key {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	k, err := settings.ParseKey(base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func settingsHarness(t *testing.T, withKey bool) (*harness, *fakeRuntime) {
	rt := &fakeRuntime{env: map[string]string{"NDAY_GITHUB_TOKEN": envSecret, "NDAY_GHSA_MAX_REQUESTS": envGHSAReqs}}
	if withKey {
		rt.key = newKey(t)
	}
	h := newHarness(t, hopt{settings: rt})
	pc, err := pgx.ParseConfig(h.db.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(pc, dbpool.Options{Size: 2, Dial: testutil.Dial(pc)})
	t.Cleanup(pool.Close)
	rt.load = func(ctx context.Context) (*settings.Snapshot, error) {
		var snap *settings.Snapshot
		err := pool.WithConn(ctx, func(c *pgx.Conn) error {
			var err error
			snap, err = settings.LoadSnapshot(ctx, c, rt.key)
			return err
		})
		return snap, err
	}
	return h, rt
}

type auditRow struct {
	Action, TargetType, TargetID, Details string
}

func (h *harness) settingsAudit() []auditRow {
	h.t.Helper()
	rows, err := h.db.Conn.Query(context.Background(), `SELECT action, target_type, target_id, details::text FROM admin_audit
		WHERE action LIKE 'settings.%' ORDER BY id`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.Action, &r.TargetType, &r.TargetID, &r.Details); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (h *harness) settingRows() int { return h.count(`SELECT count(*) FROM app_settings`) }

// noSecrets fails when any secret of these tests is in s.
func noSecrets(t *testing.T, what, s string) {
	t.Helper()
	for _, x := range []string{secretX, secretX2, secretGH, envSecret, "XSECRET", "GHSECRET", "ENVSECRET"} {
		if strings.Contains(s, x) {
			t.Errorf("%s contains a secret (%d bytes)", what, len(x)) // (the secret itself is not printed)
		}
	}
}

// redact replaces the secrets of these tests in b (failure output never
// shows them).
func redact(b []byte) []byte {
	s := string(b)
	for _, x := range []string{secretX, secretX2, secretGH, envSecret} {
		s = strings.ReplaceAll(s, x, "[redacted]")
	}
	return []byte(s)
}

func sexpect(t *testing.T, what string, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	expect(t, what, resp, redact(body), status, code)
}

func scheck(t *testing.T, what string, status int, code string) func(*http.Response, []byte) {
	t.Helper()
	return func(resp *http.Response, body []byte) { t.Helper(); sexpect(t, what, resp, body, status, code) }
}

type setAnswer struct {
	OK       bool                    `json:"ok"`
	Changed  []string                `json:"changed"`
	Restart  []string                `json:"restart"`
	Settings map[string]settingState `json:"settings"`
}
type settingState struct {
	Source string  `json:"source"`
	Stored bool    `json:"stored"`
	Value  *string `json:"value"`
	Set    *bool   `json:"set"`
	Hint   *string `json:"hint"`
}

func decodeAnswer(t *testing.T, body []byte) setAnswer {
	t.Helper()
	var a setAnswer
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatalf("answer: %v", err)
	}
	return a
}

// TestSettingsAccess: /admin/settings and the three endpoints for every
// kind of visitor, CSRF, a stale sign-in, and no runtime at all.
func TestSettingsAccess(t *testing.T) {
	h, _ := settingsHarness(t, true)
	anon := h.browser()
	user := h.user("pat", "user")
	mod := h.user("mia", "moderator")
	adm := h.user("kim", "admin")
	for _, c := range []struct {
		b    *browser
		want int
	}{{anon, 302}, {user, 404}, {mod, 404}, {adm, 200}} {
		if resp, _ := c.b.do("GET", "/admin/settings", ""); resp.StatusCode != c.want {
			t.Errorf("page as %s: %d, want %d", c.b.name, resp.StatusCode, c.want)
		}
	}
	if _, body := mod.do("GET", "/admin/moderation", ""); strings.Contains(string(body), `href="/admin/settings"`) {
		t.Error("moderator sees the settings nav item")
	}
	if _, body := adm.do("GET", "/admin/moderation", ""); !strings.Contains(string(body), `href="/admin/settings"`) {
		t.Error("admin lacks the settings nav item")
	}
	eps := []struct{ path, body string }{
		{"/api/admin/settings", `{"set":{"NDAY_DISCUSS_POST_BURST":"9"},"unset":[]}`},
		{"/api/admin/settings/secret", `{"key":"NDAY_X_BEARER_TOKEN","value":"` + secretX + `"}`},
		{"/api/admin/settings/secret/clear", `{"key":"NDAY_X_BEARER_TOKEN"}`},
	}
	want := map[*browser]string{anon: "401 not_signed_in", user: "404 not_found", mod: "403 forbidden"}
	for _, e := range eps {
		for b, w := range want {
			resp, body := b.post(e.path, e.body)
			if got := fmt.Sprintf("%d %s", resp.StatusCode, errCode(body)); got != w {
				t.Errorf("%s as %s: %s, want %s", e.path, b.name, got, w)
			}
			noSecrets(t, e.path+" answer", string(body))
		}
		scheck(t, e.path+" no CSRF", 403, "csrf")(adm.post(e.path, e.body, "X-CSRF-Token", ""))
		scheck(t, e.path+" cross-site", 403, "cross_site")(adm.post(e.path, e.body, "Sec-Fetch-Site", "cross-site"))
		scheck(t, e.path+" GET", 405, "method_not_allowed")(adm.do("GET", e.path, ""))
	}
	scheck(t, "unknown settings endpoint", 404, "not_found")(adm.post("/api/admin/settings/token", `{}`))
	h.clock.Advance(16 * time.Minute)
	for _, e := range eps {
		resp, body := adm.post(e.path, e.body)
		sexpect(t, e.path+" stale", resp, body, 403, "reauth_required")
		noSecrets(t, "stale answer", string(body))
	}
	if n := h.settingRows(); n != 0 {
		t.Errorf("refused requests stored %d rows", n)
	}
	if a := h.settingsAudit(); len(a) != 0 {
		t.Errorf("refused requests wrote audit rows: %v", a)
	}
	noSecrets(t, "logs", h.logs.String())

	// a server without a settings runtime
	h2 := newHarness(t, hopt{})
	adm2 := h2.user("kim", "admin")
	for _, e := range eps {
		scheck(t, e.path+" without runtime", 503, "settings_off")(adm2.post(e.path, e.body))
	}
	resp, body := adm2.do("GET", "/admin/settings", "")
	if resp.StatusCode != 200 || !strings.Contains(string(body), "cannot store database settings") || strings.Contains(string(body), "adm-setform") {
		t.Errorf("page without runtime: %d", resp.StatusCode)
	}
}

// TestSettingsSave: the plain batch: refusals change nothing and name keys
// only; a change writes the rows and one exact audit row (key names only)
// and is applied; no change writes nothing.
func TestSettingsSave(t *testing.T) {
	h, rt := settingsHarness(t, true)
	adm := h.user("kim", "admin")
	save := func(body string) (*http.Response, []byte) { return adm.post("/api/admin/settings", body) }

	// refusals
	scheck(t, "unknown key", 400, "unknown_setting")(save(`{"set":{"NDAY_DATABASE_URL":"postgres://x"}}`))
	resp, body := save(`{"set":{"` + secretX + `":"1"}}`)
	sexpect(t, "value as key", resp, body, 400, "unknown_setting")
	noSecrets(t, "value-as-key answer", string(body))
	resp, body = save(`{"set":{"NDAY_X_BEARER_TOKEN":"` + secretX + `"}}`)
	sexpect(t, "secret in set", resp, body, 400, "secret_setting")
	noSecrets(t, "secret-in-set answer", string(body))
	scheck(t, "bad value", 400, "bad_setting")(save(`{"set":{"NDAY_DISCUSS_POST_BURST":"a\u0001b"}}`))
	scheck(t, "conflict", 400, "bad_setting")(save(`{"set":{"NDAY_DISCUSS_POST_BURST":"3"},"unset":["NDAY_DISCUSS_POST_BURST"]}`))
	scheck(t, "unknown field", 400, "bad_request")(save(`{"set":{},"token":"x"}`))
	scheck(t, "not JSON", 400, "bad_request")(save(`{"set":`))
	scheck(t, "too large", 413, "too_large")(save(`{"set":{"NDAY_DISCUSS_POST_BURST":"` + strings.Repeat("1", 70<<10) + `"}}`))
	// validation: the value is never echoed
	const badValue = "lots-of-posts-xyz"
	resp, body = save(`{"set":{"NDAY_DISCUSS_POST_BURST":"` + badValue + `","NDAY_DISCUSS_EDIT_BURST":"3"}}`)
	sexpect(t, "invalid", resp, body, 422, "invalid_config")
	var e struct {
		Error struct {
			Keys []string `json:"keys"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	if strings.Contains(string(body), badValue) || len(e.Error.Keys) != 1 || e.Error.Keys[0] != "NDAY_DISCUSS_POST_BURST" {
		t.Errorf("invalid: %s", redact(body))
	}
	scheck(t, "sign-in off", 422, "sign_in_off")(save(`{"set":{"NDAY_AUTH_PASSKEYS":"off"}}`))
	if n := h.settingRows(); n != 0 {
		t.Fatalf("refused saves stored %d rows", n)
	}
	if a := h.settingsAudit(); len(a) != 0 {
		t.Fatalf("refused saves wrote audit rows: %v", a)
	}
	if _, n := rt.last(); n != 0 {
		t.Fatalf("refused saves were applied %d times", n)
	}
	if strings.Contains(h.logs.String(), badValue) {
		t.Error("the logs hold a refused value")
	}

	// a change: two keys, one Restart key
	resp, body = save(`{"set":{"NDAY_DISCUSS_POST_BURST":" 9 ","NDAY_DISCUSS":"off"},"unset":["NDAY_DISCUSS_EDIT_BURST"]}`)
	sexpect(t, "save", resp, body, 200, "")
	a := decodeAnswer(t, body)
	if strings.Join(a.Changed, ",") != "NDAY_DISCUSS,NDAY_DISCUSS_POST_BURST" || strings.Join(a.Restart, ",") != "NDAY_DISCUSS" {
		t.Errorf("answer: %s", redact(body))
	}
	if s := a.Settings["NDAY_DISCUSS_POST_BURST"]; s.Source != "db" || s.Value == nil || *s.Value != "9" {
		t.Errorf("state: %+v", s)
	}
	if s := a.Settings["NDAY_GHSA_MAX_REQUESTS"]; s.Source != "env" || s.Value != nil {
		t.Errorf("env state: %+v", s)
	}
	if s := a.Settings["NDAY_GITHUB_TOKEN"]; s.Source != "env" || s.Set == nil || *s.Set {
		t.Errorf("env secret state: %+v", s)
	}
	if s := a.Settings["NDAY_DISCUSS_MOD_BURST"]; s.Source != "default" || s.Stored {
		t.Errorf("default state: %+v", s)
	}
	if len(a.Settings) != len(settings.Defs()) {
		t.Errorf("answer has %d settings", len(a.Settings))
	}
	noSecrets(t, "save answer", string(body))
	if strings.Contains(string(body), envGHSAReqs) {
		t.Error("the answer holds a value of the environment")
	}
	rows := h.settingsAudit()
	if len(rows) != 1 || rows[0] != (auditRow{audit.SettingsUpdate, audit.TargetSetting, "discuss",
		`{"set": ["NDAY_DISCUSS", "NDAY_DISCUSS_POST_BURST"]}`}) {
		t.Errorf("audit: %+v", rows)
	}
	snap, n := rt.last()
	if n != 1 {
		t.Fatalf("applied %d times", n)
	}
	if v, _ := snap.Lookup(nil)("NDAY_DISCUSS_POST_BURST"); v != "9" {
		t.Errorf("applied snapshot serves %q", v)
	}
	if l, err := discuss.LimitsFromEnv(func(k string) string { v, _ := snap.Lookup(nil)(k); return v }); err != nil || l.PostBurst != 9 {
		t.Errorf("applied limits: %+v %v", l.PostBurst, err)
	}

	// the same values again: no write, no audit; the stored state is applied
	// again (saving again retries an Apply that failed)
	resp, body = save(`{"set":{"NDAY_DISCUSS_POST_BURST":"9"},"unset":["NDAY_DISCUSS_EDIT_BURST"]}`)
	sexpect(t, "unchanged", resp, body, 200, "")
	if a := decodeAnswer(t, body); len(a.Changed) != 0 || a.Settings["NDAY_DISCUSS_POST_BURST"].Source != "db" {
		t.Errorf("unchanged answer: %s", redact(body))
	}
	if len(h.settingsAudit()) != 1 {
		t.Error("no change wrote an audit row")
	}
	if _, n := rt.last(); n != 2 {
		t.Errorf("no change: applied %d times, want 2 (a retry)", n)
	}

	// unset: one row, unset list
	scheck(t, "unset", 200, "")(save(`{"unset":["NDAY_DISCUSS_POST_BURST"]}`))
	rows = h.settingsAudit()
	if len(rows) != 2 || rows[1] != (auditRow{audit.SettingsUpdate, audit.TargetSetting, "NDAY_DISCUSS_POST_BURST",
		`{"unset": ["NDAY_DISCUSS_POST_BURST"]}`}) {
		t.Errorf("audit after unset: %+v", rows)
	}
	if n := h.settingRows(); n != 1 {
		t.Errorf("rows after unset: %d", n)
	}

	// every plain key at once fits the audit row's details
	var set []string
	for _, d := range settings.Defs() {
		if !d.Secret && d.Key != auth.EnvPasskeys && d.Key != auth.EnvPasskeySignup {
			v := "5"
			switch {
			case d.Key == "NDAY_DISCUSS", d.Key == "NDAY_DISCUSS_GUEST_READ":
				v = "on"
			case strings.HasSuffix(d.Key, "_EVERY"), strings.HasSuffix(d.Key, "_AGE"), strings.HasSuffix(d.Key, "_WINDOW"):
				v = "1m"
			}
			set = append(set, fmt.Sprintf("%q:%q", d.Key, v))
		}
	}
	scheck(t, "all keys", 200, "")(save(`{"set":{` + strings.Join(set, ",") + `}}`))
	rows = h.settingsAudit()
	if last := rows[len(rows)-1]; last.TargetID != "settings" || len(last.Details) > audit.MaxDetails {
		t.Errorf("all keys: target %s, %d bytes of details", last.TargetID, len(last.Details))
	}

	// apply fails: stored, 500 not_applied, ERROR logged with key names only
	rt.applyErr = errors.New("auth: NDAY_AUTH_SESSION_IDLE: cannot apply")
	resp, body = save(`{"set":{"NDAY_DISCUSS_REPORT_DAILY":"21"}}`)
	sexpect(t, "apply fails", resp, body, 500, "not_applied")
	if !strings.Contains(string(body), `"keys":["NDAY_AUTH_SESSION_IDLE"]`) || !strings.Contains(string(body), `"changed":["NDAY_DISCUSS_REPORT_DAILY"]`) {
		t.Errorf("not applied: %s", redact(body))
	}
	if h.count(`SELECT count(*) FROM app_settings WHERE key = 'NDAY_DISCUSS_REPORT_DAILY' AND value = '21'`) != 1 {
		t.Error("a change that could not be applied was not stored")
	}
	if !strings.Contains(h.logs.String(), "settings stored but not applied") || strings.Contains(h.logs.String(), "cannot apply") {
		t.Error("apply failure log")
	}
	// the not_applied answer carries the stored state (the page shows it)
	var na struct {
		Error struct {
			Settings map[string]struct {
				Source string  `json:"source"`
				Value  *string `json:"value"`
			} `json:"settings"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &na); err != nil {
		t.Fatal(err)
	}
	if st := na.Error.Settings["NDAY_DISCUSS_REPORT_DAILY"]; st.Source != "db" || st.Value == nil || *st.Value != "21" ||
		len(na.Error.Settings) != len(settings.Defs()) {
		t.Errorf("not_applied state: %s", redact(body))
	}
	noSecrets(t, "not_applied answer", string(body))
	// saving again with nothing changed is a retry: no write, no audit, applied
	rt.applyErr = nil
	_, before := rt.last()
	audits := len(h.settingsAudit())
	resp, body = save(`{"set":{},"unset":[]}`)
	sexpect(t, "retry", resp, body, 200, "")
	if snap, n := rt.last(); n != before+1 || len(h.settingsAudit()) != audits {
		t.Errorf("retry: applied %d -> %d, audit rows %d -> %d", before, n, audits, len(h.settingsAudit()))
	} else if v, _ := snap.Lookup(nil)("NDAY_DISCUSS_REPORT_DAILY"); v != "21" {
		t.Errorf("retry applied %q", v)
	}
	noSecrets(t, "logs", h.logs.String())
}

// TestSettingsSecrets: storing, replacing and clearing secrets; the value
// never appears in an answer, an audit row, a log line or the page.
func TestSettingsSecrets(t *testing.T) {
	h, rt := settingsHarness(t, true)
	adm := h.user("kim", "admin")
	var all strings.Builder
	post := func(path, body string) (*http.Response, []byte) {
		resp, b := adm.post(path, body)
		all.Write(b)
		return resp, b
	}
	secret := func(key, value string) (*http.Response, []byte) {
		return post("/api/admin/settings/secret", `{"key":"`+key+`","value":"`+value+`"}`)
	}
	scheck(t, "plain key", 400, "not_secret")(secret("NDAY_DISCUSS", secretX))
	scheck(t, "unknown key", 400, "unknown_setting")(secret("NDAY_AUTH_SECRET", secretX))
	scheck(t, "empty", 400, "bad_secret")(secret("NDAY_X_BEARER_TOKEN", "  "))
	scheck(t, "too large", 413, "too_large")(secret("NDAY_X_BEARER_TOKEN", strings.Repeat("a", 17<<10)))
	scheck(t, "clear plain", 400, "not_secret")(post("/api/admin/settings/secret/clear", `{"key":"NDAY_DISCUSS"}`))

	resp, body := secret("NDAY_X_BEARER_TOKEN", secretX)
	sexpect(t, "set", resp, body, 200, "")
	a := decodeAnswer(t, body)
	if s := a.Settings["NDAY_X_BEARER_TOKEN"]; strings.Join(a.Changed, ",") != "NDAY_X_BEARER_TOKEN" || s.Source != "db" ||
		s.Set == nil || !*s.Set || s.Hint == nil || *s.Hint != "wxyz" || s.Value != nil {
		t.Errorf("set answer: %s", redact(body))
	}
	// the stored row is ciphertext
	if h.count(`SELECT count(*) FROM app_settings WHERE key = 'NDAY_X_BEARER_TOKEN' AND value IS NULL
		AND position(convert_to($1, 'UTF8') in secret) = 0`, secretX) != 1 {
		t.Error("the secret is not stored sealed")
	}
	if snap, _ := rt.last(); snap == nil {
		t.Fatal("not applied")
	} else if v, _ := snap.Lookup(nil)("NDAY_X_BEARER_TOKEN"); v != secretX {
		t.Error("the applied snapshot does not serve the new secret")
	}
	// the same value again is written and audited like any other: the
	// answer must not tell whether it equals the stored secret
	resp, body = secret("NDAY_X_BEARER_TOKEN", " "+secretX+" ")
	if sexpect(t, "same", resp, body, 200, ""); strings.Join(decodeAnswer(t, body).Changed, ",") != "NDAY_X_BEARER_TOKEN" {
		t.Errorf("same secret: %s", redact(body))
	}
	scheck(t, "replace", 200, "")(secret("NDAY_X_BEARER_TOKEN", secretX2))
	scheck(t, "client secret", 200, "")(secret("NDAY_AUTH_GITHUB_CLIENT_SECRET", secretGH))
	rows := h.settingsAudit()
	want := []auditRow{{audit.SettingsSecretSet, audit.TargetSetting, "NDAY_X_BEARER_TOKEN", `{"keys": ["NDAY_X_BEARER_TOKEN"]}`},
		{audit.SettingsSecretSet, audit.TargetSetting, "NDAY_X_BEARER_TOKEN", `{"keys": ["NDAY_X_BEARER_TOKEN"]}`},
		{audit.SettingsSecretSet, audit.TargetSetting, "NDAY_X_BEARER_TOKEN", `{"keys": ["NDAY_X_BEARER_TOKEN"]}`},
		{audit.SettingsSecretSet, audit.TargetSetting, "NDAY_AUTH_GITHUB_CLIENT_SECRET", `{"keys": ["NDAY_AUTH_GITHUB_CLIENT_SECRET"]}`}}
	if fmt.Sprint(rows) != fmt.Sprint(want) {
		t.Errorf("audit: %+v", rows)
	}

	// the page: state and hint, never a value (secret or environment)
	for _, p := range []string{"/admin/settings", "/zh-hans/admin/settings"} {
		resp, page := adm.do("GET", p, "")
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		s := string(page)
		all.WriteString(s)
		if !strings.Contains(s, "qrst") || strings.Contains(s, envGHSAReqs) {
			t.Errorf("%s: hint missing or environment value shown", p)
		}
	}

	// clearing (separately and together with a plain change in one save)
	resp, body = post("/api/admin/settings/secret/clear", `{"key":"NDAY_X_BEARER_TOKEN"}`)
	sexpect(t, "clear", resp, body, 200, "")
	if s := decodeAnswer(t, body).Settings["NDAY_X_BEARER_TOKEN"]; s.Stored || s.Source != "default" {
		t.Errorf("after clear: %+v", s)
	}
	scheck(t, "clear again", 200, "")(post("/api/admin/settings/secret/clear", `{"key":"NDAY_X_BEARER_TOKEN"}`))
	scheck(t, "batch", 200, "")(post("/api/admin/settings", `{"set":{"NDAY_AUTH_GITHUB_CLIENT_ID":"cid"},"unset":["NDAY_AUTH_GITHUB_CLIENT_SECRET"]}`))
	rows = h.settingsAudit()
	want = append(want, auditRow{audit.SettingsSecretClear, audit.TargetSetting, "NDAY_X_BEARER_TOKEN", `{"keys": ["NDAY_X_BEARER_TOKEN"]}`},
		auditRow{audit.SettingsSecretClear, audit.TargetSetting, "NDAY_AUTH_GITHUB_CLIENT_SECRET", `{"keys": ["NDAY_AUTH_GITHUB_CLIENT_SECRET"]}`},
		auditRow{audit.SettingsUpdate, audit.TargetSetting, "NDAY_AUTH_GITHUB_CLIENT_ID", `{"set": ["NDAY_AUTH_GITHUB_CLIENT_ID"]}`})
	if fmt.Sprint(rows) != fmt.Sprint(want) {
		t.Errorf("audit after clear: %+v", rows)
	}
	if n := h.settingRows(); n != 1 {
		t.Errorf("rows: %d", n)
	}
	// the audit page shows the rows, links them to the settings page
	_, page := adm.do("GET", "/admin/audit", "")
	all.Write(page)
	if !strings.Contains(string(page), `href="/admin/settings#s-NDAY_X_BEARER_TOKEN"`) {
		t.Error("audit page: no link to the setting")
	}
	noSecrets(t, "answers and pages", all.String())
	noSecrets(t, "logs", h.logs.String())
	var details strings.Builder
	for _, r := range h.settingsAudit() {
		details.WriteString(r.Details)
	}
	noSecrets(t, "audit", details.String())
}

// TestSettingsNoMasterKey: without NDAY_SETTINGS_KEY secrets are refused
// (and the page disables their inputs); a stored secret can be cleared.
func TestSettingsNoMasterKey(t *testing.T) {
	h, _ := settingsHarness(t, false)
	adm := h.user("kim", "admin")
	resp, body := adm.post("/api/admin/settings/secret", `{"key":"NDAY_X_BEARER_TOKEN","value":"`+secretX+`"}`)
	sexpect(t, "no key", resp, body, 409, "no_master_key")
	noSecrets(t, "answer", string(body))
	if n := h.settingRows(); n != 0 {
		t.Errorf("stored %d rows", n)
	}
	// a secret sealed with some other key: unreadable here, still clearable
	if err := settings.SetSecret(context.Background(), h.db.Conn, "NDAY_X_BEARER_TOKEN", secretX, newKey(t)); err != nil {
		t.Fatal(err)
	}
	resp, page := adm.do("GET", "/admin/settings", "")
	s := string(page)
	if resp.StatusCode != 200 || !strings.Contains(s, "NDAY_SETTINGS_KEY is not set on this server") ||
		!strings.Contains(s, `id="in-NDAY_X_BEARER_TOKEN" type="password" autocomplete="off" spellcheck="false" autocapitalize="none" dir="ltr" disabled=""`) ||
		!strings.Contains(s, "stored, cannot be decrypted") || !strings.Contains(s, "stored encrypted but NDAY_SETTINGS_KEY is not set") {
		t.Errorf("page without key: %d", resp.StatusCode)
	}
	noSecrets(t, "page", s)
	scheck(t, "clear", 200, "")(adm.post("/api/admin/settings/secret/clear", `{"key":"NDAY_X_BEARER_TOKEN"}`))
	if n := h.settingRows(); n != 0 {
		t.Errorf("rows after clear: %d", n)
	}
}

// TestSettingsPage: three groups, source badges, Restart marks, on/off
// selects, secrets as password inputs (the .p8 key as a text area), stored
// plain values shown, environment values never; both written locales.
func TestSettingsPage(t *testing.T) {
	h, rt := settingsHarness(t, true)
	adm := h.user("kim", "admin")
	ctx := context.Background()
	if _, err := settings.Set(ctx, h.db.Conn, "NDAY_DISCUSS_POST_DAILY", "77"); err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Set(ctx, h.db.Conn, "NDAY_AUTH_PASSKEY_SIGNUP", "on"); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSecret(ctx, h.db.Conn, "NDAY_AUTH_APPLE_KEY", "-----BEGIN PRIVATE KEY-----\nXSECRET\n-----END PRIVATE KEY-----", rt.key); err != nil {
		t.Fatal(err)
	}
	resp, body := adm.do("GET", "/admin/settings", "")
	s := string(body)
	if resp.StatusCode != 200 {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	for _, w := range []string{
		`id="set-collectors"`, `id="set-discuss"`, `id="set-auth"`,
		`<h2 class="h2" id="h-set-collectors"><span class="h" aria-hidden="true"># </span>Collectors</h2>`,
		`id="in-NDAY_DISCUSS_POST_DAILY" data-in="" type="text" value="77"`,
		`<span class="adm-st db" data-src="">database</span>`,
		`<span class="adm-st env" data-src="">environment</span>`,
		`<span class="adm-st default" data-src="">default</span>`,
		`applies after a restart`,
		`<option value="on" selected="">on</option>`,
		`id="in-NDAY_GITHUB_TOKEN" type="password" autocomplete="off"`,
		`<textarea class="acct-in adm-ta adm-import" id="in-NDAY_AUTH_APPLE_KEY"`,
		`data-clear="NDAY_AUTH_APPLE_KEY"`,
		`bearer token: the xposts collector`,
		`id="reauth"`,
		// the name first, the variable name next to it, when a change applies
		`<label for="in-NDAY_DISCUSS_POST_DAILY">Comments per day (established accounts)</label> <code class="adm-skey" dir="ltr">NDAY_DISCUSS_POST_DAILY</code>`,
		`<label for="in-NDAY_AUTH_APPLE_KEY">Apple sign-in: private key</label> <code class="adm-skey" dir="ltr">NDAY_AUTH_APPLE_KEY</code>`,
		`<span class="dim">applies from the next collector run</span>`,
		`<span class="dim">applies at once</span>`,
		`<span class="dim">collector: from its next run; /admin/x lookups: at once</span>`,
		`<nav class="seg adm-jump" aria-label="Groups on this page">`,
		`<a href="#set-collectors">Collectors</a>`, `<a href="#set-hot">Hot list</a>`,
	} {
		if !strings.Contains(s, w) {
			t.Errorf("page lacks %s", w)
		}
	}
	if strings.Count(s, `adm-setform"`) != 4 || strings.Count(s, `class="acct-form adm-field adm-secret"`) != 6 ||
		strings.Count(s, `<span class="dim">applies after a restart</span>`) != 1 {
		t.Errorf("page structure: %d forms, %d secrets, %d restart marks", strings.Count(s, `adm-setform"`),
			strings.Count(s, `class="acct-form adm-field adm-secret"`), strings.Count(s, `<span class="dim">applies after a restart</span>`))
	}
	if strings.Contains(s, envGHSAReqs) || strings.Contains(s, "PRIVATE KEY") {
		t.Error("the page shows an environment value or a secret")
	}
	noSecrets(t, "page", s)
	if p := checkHTML(s, adminElems); len(p) > 0 {
		t.Errorf("page HTML: %v", p)
	}
	resp, body = adm.do("GET", "/zh-hans/admin/settings", "")
	if s := string(body); resp.StatusCode != 200 || !strings.Contains(s, "采集器") || !strings.Contains(s, ">库</span>") ||
		!strings.Contains(s, "重启后生效") || strings.Contains(s, envGHSAReqs) ||
		!strings.Contains(s, `<label for="in-NDAY_DISCUSS_POST_DAILY">老账号每日评论上限</label>`) || !strings.Contains(s, "下次采集运行起生效") {
		t.Errorf("zh-hans page: %d", resp.StatusCode)
	}
	if p := checkHTML(string(body), adminElems); len(p) > 0 {
		t.Errorf("zh-hans page HTML: %v", p)
	}
}
