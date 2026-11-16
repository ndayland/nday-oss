package cli_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/kev"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xlookup/xfake"
)

func masterKey(t *testing.T) (string, *settings.Key) {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	s := base64.StdEncoding.EncodeToString(b)
	k, err := settings.ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return s, k
}

// probeEnv runs the real kev collector on the fixture and records what the
// factory's Env said for the probed keys; a value "BAD..." makes the
// factory fail with a message that quotes it (like the real constructors).
type probe struct {
	mu   sync.Mutex
	seen []map[string]string
}

func (p *probe) env(t *testing.T, keys ...string) cli.Env {
	e := kevEnv(t, time.Now().UTC())
	e.Factories = map[string]collector.Factory{kev.Name: func(d collector.Deps) (collector.Collector, error) {
		got := map[string]string{}
		for _, k := range keys {
			v, ok := d.LookupEnv(k)
			if ok {
				got[k] = v
			}
			if strings.HasPrefix(v, "BAD") {
				return nil, fmt.Errorf("%s must be an integer, got %q", k, v)
			}
		}
		p.mu.Lock()
		p.seen = append(p.seen, got)
		p.mu.Unlock()
		return kev.Factory(d)
	}}
	return e
}

func (p *probe) last() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.seen) == 0 {
		return nil
	}
	return p.seen[len(p.seen)-1]
}

func TestCollectReadsDatabaseSettings(t *testing.T) {
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	t.Setenv(settings.EnvKey, "")
	t.Setenv("NDAY_CVELIST_MAX_FILES", "7")
	t.Setenv("NDAY_GITHUB_TOKEN", "env-token")
	t.Chdir(t.TempDir())
	p := &probe{}
	env := p.env(t, "NDAY_CVELIST_MAX_FILES", "NDAY_GITHUB_TOKEN", "NDAY_GHSA_MAX_REQUESTS")

	// nothing stored: the environment, exactly as before
	if code, _, errOut := runCLI(t, env, "collect", "kev"); code != 0 || strings.Contains(errOut, "settings") {
		t.Fatalf("collect: %d %q", code, errOut)
	}
	if got := p.last(); got["NDAY_CVELIST_MAX_FILES"] != "7" || got["NDAY_GITHUB_TOKEN"] != "env-token" {
		t.Fatalf("env only: %v", got)
	}

	// a stored plain value wins over the environment
	if code, out, errOut := runCLI(t, env, "settings-set", "NDAY_CVELIST_MAX_FILES", "9", "--yes"); code != 0 ||
		out != "settings-set: NDAY_CVELIST_MAX_FILES stored in the database\n" {
		t.Fatalf("settings-set: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runCLI(t, env, "collect", "kev"); code != 0 || p.last()["NDAY_CVELIST_MAX_FILES"] != "9" {
		t.Fatalf("db value: %d %q %v", code, errOut, p.last())
	}

	// a stored secret (master key in the environment) wins too, and never shows
	keyText, k := masterKey(t)
	t.Setenv(settings.EnvKey, keyText)
	const tok = "ghp_DB-SECRET-token-55aa"
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_GITHUB_TOKEN", tok, k); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, env, "collect", "kev")
	if code != 0 || p.last()["NDAY_GITHUB_TOKEN"] != tok || strings.Contains(out+errOut, tok) {
		t.Fatalf("db secret: %d %q", code, errOut)
	}
	// a wrong master key: the secret falls back to the environment, with a warning naming the key
	wrong, _ := masterKey(t)
	t.Setenv(settings.EnvKey, wrong)
	code, out, errOut = runCLI(t, env, "collect", "kev")
	if code != 0 || p.last()["NDAY_GITHUB_TOKEN"] != "env-token" || !strings.Contains(errOut, "NDAY_GITHUB_TOKEN: stored secret cannot be decrypted") ||
		strings.Contains(out+errOut, tok) {
		t.Fatalf("wrong key: %d %q %v", code, errOut, p.last())
	}
	t.Setenv(settings.EnvKey, keyText)

	// a bad stored value: warn (key only) and use the environment alone
	if _, err := d.Conn.Exec(ctx, `UPDATE app_settings SET value = 'BAD-stored-17' WHERE key = 'NDAY_CVELIST_MAX_FILES'`); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runCLI(t, env, "collect", "kev")
	if code != 0 || p.last()["NDAY_CVELIST_MAX_FILES"] != "7" || p.last()["NDAY_GITHUB_TOKEN"] != "env-token" ||
		!strings.Contains(errOut, "NDAY_CVELIST_MAX_FILES: invalid value") || strings.Contains(out+errOut, "BAD-stored") ||
		strings.Contains(out+errOut, tok) {
		t.Fatalf("bad stored value: %d %q %v", code, errOut, p.last())
	}
	if _, err := d.Conn.Exec(ctx, `DELETE FROM app_settings`); err != nil {
		t.Fatal(err)
	}

	// ./.env never provides collector settings (docs/go.md), stored or not
	t.Setenv("NDAY_GHSA_MAX_REQUESTS", "")
	os.Unsetenv("NDAY_GHSA_MAX_REQUESTS")
	if err := os.WriteFile(filepath.Join(".", ".env"), []byte("NDAY_GHSA_MAX_REQUESTS=55\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCLI(t, env, "collect", "kev"); code != 0 {
		t.Fatalf(".env: %d %q", code, errOut)
	}
	if v, ok := p.last()["NDAY_GHSA_MAX_REQUESTS"]; ok {
		t.Errorf(".env value reached the collector: %q", v)
	}
	os.Unsetenv("NDAY_GHSA_MAX_REQUESTS") // loaded into this process by the run above

	// no table (migration 0014 not applied): warn and use the environment
	if _, err := d.Conn.Exec(ctx, `DROP TABLE app_settings`); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCLI(t, env, "collect", "kev"); code != 0 || p.last()["NDAY_CVELIST_MAX_FILES"] != "7" ||
		!strings.Contains(errOut, "cannot read the database settings") {
		t.Fatalf("no table: %d %q", code, errOut)
	}
}

func TestSettingsCommands(t *testing.T) {
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	t.Chdir(t.TempDir())
	keyText, k := masterKey(t)
	t.Setenv(settings.EnvKey, keyText)
	t.Setenv("NDAY_DISCUSS_POST_DAILY", "70")
	const tok = "xtok-SECRET-value-0123-abcd" // 24+ characters: listed with its hint
	for _, k := range []string{"NDAY_X_BEARER_TOKEN", "NDAY_GITHUB_TOKEN", "NDAY_DISCUSS_POST_BURST", "NDAY_DISCUSS",
		"NDAY_GHSA_MAX_REQUESTS", "NDAY_AUTH_GITHUB_CLIENT_ID", "NDAY_AUTH_GOOGLE_CLIENT_ID", "NDAY_AUTH_X_CLIENT_ID",
		"NDAY_AUTH_APPLE_SERVICES_ID", "NDAY_AUTH_APPLE_KEY", "NDAY_AUTH_APPLE_KEY_FILE"} {
		t.Setenv(k, "")
	}
	env := cli.Env{}

	// usage errors (exit 2), nothing echoed that could be a value
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"settings-set", "NDAY_DISCUSS", "off"}, "--yes"},
		{[]string{"settings-set", "NDAY_X_BEARER_TOKEN", tok, "--yes"}, "is a secret: set it on the admin pages"},
		{[]string{"settings-set", tok, "1", "--yes"}, "not a setting managed in the database"},
		{[]string{"settings-set", "NDAY_DATABASE_URL", "postgres://x", "--yes"}, "not a setting managed"},
		{[]string{"settings-set", "NDAY_DISCUSS", "a\x01b", "--yes"}, "argument VALUE"},
		{[]string{"settings-set", "NDAY_DISCUSS", "--yes"}, "usage: nday settings"},
		{[]string{"settings-unset", "NDAY_DISCUSS"}, "--yes"},
		{[]string{"settings-unset", tok, "--yes"}, "not a setting managed"},
		{[]string{"settings", "extra"}, "unrecognized arguments"},
	} {
		code, out, errOut := runCLI(t, env, c.args...)
		if code != 2 || !strings.Contains(errOut, c.want) || strings.Contains(out+errOut, tok) {
			t.Errorf("%q: %d %q", c.args, code, errOut)
		}
	}

	// refused by validation (exit 1): the error names the key, not the value
	code, _, errOut := runCLI(t, env, "settings-set", "NDAY_DISCUSS", "maybe-xyz", "--yes")
	if code != 1 || !strings.Contains(errOut, "NDAY_DISCUSS must be on or off") || strings.Contains(errOut, "maybe-xyz") {
		t.Errorf("invalid: %d %q", code, errOut)
	}
	code, _, errOut = runCLI(t, env, "settings-set", "NDAY_GHSA_MAX_REQUESTS", "lots-xyz", "--yes")
	if code != 1 || !strings.Contains(errOut, "NDAY_GHSA_MAX_REQUESTS: invalid value") || strings.Contains(errOut, "lots-xyz") {
		t.Errorf("invalid collector value: %d %q", code, errOut)
	}
	// sign-in on without the website's env files (nday.env alone): refused,
	// with a hint to load web.env and auth.env (no value in it)
	t.Setenv("NDAY_AUTH_PASSKEYS", "on")
	t.Setenv("NDAY_PUBLIC_URL", "")
	t.Setenv("NDAY_AUTH_SECRET", "")
	code, _, errOut = runCLI(t, env, "settings-set", "NDAY_TERMS_VERSION", "v2", "--yes")
	if code != 1 || !strings.Contains(errOut, "NDAY_PUBLIC_URL") ||
		!strings.Contains(errOut, "hint: the check needs the website's whole environment; load /etc/nday/web.env and /etc/nday/auth.env") {
		t.Errorf("missing env files: %d %q", code, errOut)
	}
	if code, _, errOut = runCLI(t, env, "settings-set", "NDAY_DISCUSS", "maybe-xyz", "--yes"); strings.Contains(errOut, "hint:") &&
		!strings.Contains(errOut, "NDAY_PUBLIC_URL") {
		t.Errorf("hint without a missing env file: %q", errOut)
	}
	// turning sign-in off entirely is refused
	t.Setenv("NDAY_PUBLIC_URL", "https://www.nday.land")
	b := make([]byte, 48)
	_, _ = rand.Read(b)
	t.Setenv("NDAY_AUTH_SECRET", base64.StdEncoding.EncodeToString(b))
	if code, _, errOut = runCLI(t, env, "settings-set", "NDAY_AUTH_PASSKEYS", "off", "--yes"); code != 1 || !strings.Contains(errOut, "turn sign-in off") {
		t.Errorf("sign-in off: %d %q", code, errOut)
	}
	var n int
	_ = d.Conn.QueryRow(ctx, `SELECT count(*) FROM app_settings`).Scan(&n)
	if n != 0 {
		t.Fatalf("refused changes wrote %d rows", n)
	}

	// set, unchanged, list, unset
	if code, out, errOut := runCLI(t, env, "settings-set", "NDAY_DISCUSS", " off ", "--yes"); code != 0 ||
		out != "settings-set: NDAY_DISCUSS stored in the database (the website applies it after a restart)\n" {
		t.Fatalf("set: %d %q %q", code, out, errOut)
	}
	if code, out, _ := runCLI(t, env, "settings-set", "NDAY_DISCUSS", "off", "--yes"); code != 0 || out != "settings-set: NDAY_DISCUSS unchanged\n" {
		t.Fatalf("unchanged: %d %q", code, out)
	}
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_X_BEARER_TOKEN", tok, k); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, env, "settings")
	if code != 0 || strings.Contains(out+errOut, tok) {
		t.Fatalf("settings: %d %q", code, errOut)
	}
	lines := strings.Split(out, "\n")
	if len(lines) != len(settings.Defs())+4+1 || lines[0] != "[discuss]" { // one line per key, four group headings, the final newline
		t.Errorf("settings lists %d lines:\n%s", len(lines), out)
	}
	for _, re := range []string{
		`  NDAY_DISCUSS                         db      "off" at 20`,
		`  NDAY_DISCUSS_POST_DAILY              env     -` + "\n",
		`  NDAY_DISCUSS_POST_BURST              default -` + "\n",
		`  NDAY_X_BEARER_TOKEN                  db      secret set, ends "abcd" at 20`,
		`  NDAY_GITHUB_TOKEN                    default -` + "\n",
		"[collectors]\n", "[auth]\n",
	} {
		if !strings.Contains(out, re) {
			t.Errorf("settings lacks %q:\n%s", re, out)
		}
	}
	if !strings.Contains(out, "[restart]\n") {
		t.Error("no restart mark")
	}
	// without the master key the secret is listed as unreadable
	t.Setenv(settings.EnvKey, "")
	code, out, errOut = runCLI(t, env, "settings")
	if code != 0 || !strings.Contains(out, `  NDAY_X_BEARER_TOKEN                  default secret set, ends "abcd" (cannot be read) at 20`) ||
		!strings.Contains(errOut, "warning: NDAY_X_BEARER_TOKEN: stored encrypted but NDAY_SETTINGS_KEY is not set") || strings.Contains(out+errOut, tok) {
		t.Errorf("no key: %d %q %q", code, out, errOut)
	}
	t.Setenv(settings.EnvKey, keyText)

	// x-accounts-import takes the token from the database settings
	f := xfake.New(tok)
	f.Add("2244994945", "XDevelopers")
	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("@xdevelopers\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runCLI(t, cli.Env{Transport: f.Transport()}, "x-accounts-import", file)
	if code != 0 || !strings.Contains(out, "inserted 2244994945 @XDevelopers (id looked up)") || strings.Contains(out+errOut, tok) {
		t.Errorf("import with db token: %d %q %q", code, out, errOut)
	}

	if code, out, _ := runCLI(t, env, "settings-unset", "NDAY_X_BEARER_TOKEN", "--yes"); code != 0 ||
		out != "settings-unset: NDAY_X_BEARER_TOKEN removed from the database\n" {
		t.Fatalf("unset: %d %q", code, out)
	}
	if code, out, _ := runCLI(t, env, "settings-unset", "NDAY_X_BEARER_TOKEN", "--yes"); code != 0 ||
		out != "settings-unset: NDAY_X_BEARER_TOKEN was not set in the database\n" {
		t.Fatalf("unset again: %d %q", code, out)
	}

	rows, err := d.Conn.Query(ctx, `SELECT action || ' ' || target_type || '/' || target_id || ' ' || actor_role || ' ' || details::text
        FROM admin_audit WHERE target_type = 'setting' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		got = append(got, s)
	}
	want := []string{`settings.update setting/NDAY_DISCUSS cli {"keys": ["NDAY_DISCUSS"]}`,
		`settings.unset setting/NDAY_X_BEARER_TOKEN cli {"keys": ["NDAY_X_BEARER_TOKEN"]}`}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit:\n%s", strings.Join(got, "\n"))
	}
}
