package cli_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/testutil"
)

// served is one running `nday serve` with what the hooks received.
type served struct {
	base string
	logs *lockedBuf
	auth *auth.Service
	ds   *discuss.Service
	adm  *admin.Service
	stop func() int
}

func serveCapture(t *testing.T) *served {
	t.Helper()
	s := &served{logs: &lockedBuf{}}
	addrc := make(chan net.Addr, 1)
	cli.ServeReady = func(a net.Addr) { addrc <- a }
	cli.AuthHook = func(a *auth.Service) { s.auth = a }
	cli.DiscussHook = func(d *discuss.Service) { s.ds = d }
	cli.AdminHook = func(a *admin.Service) { s.adm = a }
	t.Cleanup(func() { cli.ServeReady, cli.AuthHook, cli.DiscussHook, cli.AdminHook = nil, nil, nil, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- cli.Main(ctx, []string{"serve", "--listen", "127.0.0.1:0"}, cli.Env{Stdout: io.Discard, Stderr: s.logs})
	}()
	select {
	case a := <-addrc:
		s.base = "http://" + a.String()
		var once sync.Once
		code := 0
		s.stop = func() int { once.Do(func() { cancel(); code = <-done }); return code }
		t.Cleanup(func() { s.stop() })
	case c := <-done:
		cancel()
		t.Fatalf("serve exited %d: %s", c, s.logs.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("server did not start")
	}
	return s
}

func (s *served) me(t *testing.T) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", s.base+"/api/me", nil)
	req.Host = "localhost:8080"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// settingsServeEnv: a database and sign-in in the environment (GitHub).
func settingsServeEnv(t *testing.T, signIn bool) *testutil.TestDB {
	t.Helper()
	clearAuthEnv(t)
	for _, k := range []string{"NDAY_AUTH_APPLE_KEY", settings.EnvKey, "NDAY_X_BEARER_TOKEN", "NDAY_DISCUSS",
		"NDAY_DISCUSS_READ_BURST", "NDAY_DISCUSS_POST_BURST", "NDAY_TLS_CLIENT_CA", "NDAY_LOG_DIR"} {
		t.Setenv(k, "")
	}
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	t.Setenv("NDAY_PUBLIC_URL", "http://localhost:8080")
	sec := make([]byte, 48)
	_, _ = rand.Read(sec)
	t.Setenv("NDAY_AUTH_SECRET", base64.StdEncoding.EncodeToString(sec))
	t.Setenv("NDAY_AUTH_RP_ID", "localhost")
	if signIn {
		t.Setenv("NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.env")
		t.Setenv("NDAY_AUTH_GITHUB_CLIENT_SECRET", "env-secret")
	}
	return d
}

func setPlain(t *testing.T, d *testutil.TestDB, kv ...string) {
	t.Helper()
	for i := 0; i+1 < len(kv); i += 2 {
		if _, err := settings.Set(context.Background(), d.Conn, kv[i], kv[i+1]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestServeLayersDatabaseSettings(t *testing.T) {
	d := settingsServeEnv(t, true)
	ctx := context.Background()

	// nothing stored: the environment, and no settings warning
	s := serveCapture(t)
	if s.auth.Config().TermsVersion != "" || s.ds.Limits() != discuss.DefaultLimits() || s.adm.XLookupAvailable() {
		t.Fatalf("env only: %+v", s.auth.Config())
	}
	if strings.Contains(s.logs.String(), "settings:") {
		t.Errorf("settings log without rows:\n%s", s.logs.String())
	}
	s.stop()

	// stored values win: sign-in, discussion limits, the X lookup token
	keyText, k := masterKey(t)
	t.Setenv(settings.EnvKey, keyText)
	setPlain(t, d, "NDAY_TERMS_VERSION", "v7", "NDAY_DISCUSS_READ_BURST", "77", "NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.db")
	const xtok = "DB-X-bearer-token-9f3e"
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_X_BEARER_TOKEN", xtok, k); err != nil {
		t.Fatal(err)
	}
	s = serveCapture(t)
	cfg := s.auth.Config()
	if cfg.TermsVersion != "v7" || cfg.Providers[auth.GitHub].ClientID != "Iv1.db" ||
		cfg.Providers[auth.GitHub].ClientSecret != "env-secret" || s.ds.Limits().ReadBurst != 77 || !s.adm.XLookupAvailable() {
		t.Fatalf("db values: %+v %+v", cfg, s.ds.Limits())
	}
	if strings.Contains(s.logs.String(), xtok) {
		t.Error("token logged")
	}
	s.stop()

	// a bad stored value: warn (key only), the environment for that part
	if _, err := d.Conn.Exec(ctx, `INSERT INTO app_settings (key, value) VALUES ('NDAY_AUTH_SESSION_IDLE', 'BAD-stored-42'), ('NDAY_DISCUSS_POST_BURST', 'BAD-stored-43')`); err != nil {
		t.Fatal(err)
	}
	s = serveCapture(t)
	logs := s.logs.String()
	if s.auth.Config().TermsVersion != "" || s.auth.Config().Providers[auth.GitHub].ClientID != "Iv1.env" ||
		s.ds.Limits() != discuss.DefaultLimits() || !s.adm.XLookupAvailable() {
		t.Errorf("bad values did not fall back: %+v %+v", s.auth.Config(), s.ds.Limits())
	}
	if !strings.Contains(logs, "sign-in rejects the database settings") || !strings.Contains(logs, "NDAY_AUTH_SESSION_IDLE") ||
		!strings.Contains(logs, "discussions reject the database settings") || !strings.Contains(logs, "NDAY_DISCUSS_POST_BURST") ||
		strings.Contains(logs, "BAD-stored") || strings.Contains(logs, xtok) || strings.Contains(logs, "env-secret") {
		t.Errorf("warnings:\n%s", logs)
	}
	if code, body := s.me(t); code != 200 || !strings.Contains(body, `"providers":["github"]`) {
		t.Errorf("/api/me %d %s", code, body)
	}
	s.stop()

	// the database would switch sign-in off: refused, the environment
	if _, err := d.Conn.Exec(ctx, `DELETE FROM app_settings; INSERT INTO app_settings (key, value) VALUES ('NDAY_AUTH_PASSKEYS', 'off')`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("NDAY_AUTH_PASSKEYS", "on")
	s = serveCapture(t)
	if s.auth == nil || !s.auth.Config().Passkeys || !strings.Contains(s.logs.String(), "would turn sign-in off entirely") {
		t.Errorf("sign-in off from the database:\n%s", s.logs.String())
	}
	s.stop()

	// no table (migration 0014 not applied): warn, the environment
	if _, err := d.Conn.Exec(ctx, `DROP TABLE app_settings`); err != nil {
		t.Fatal(err)
	}
	s = serveCapture(t)
	if s.auth == nil || !strings.Contains(s.logs.String(), "cannot read the database settings; using the environment only") {
		t.Errorf("no table:\n%s", s.logs.String())
	}
}

// Sign-in configured only in the database is enabled at start-up.
func TestServeSignInFromDatabaseOnly(t *testing.T) {
	d := settingsServeEnv(t, false)
	keyText, k := masterKey(t)
	t.Setenv(settings.EnvKey, keyText)
	setPlain(t, d, "NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.db")
	const sec = "db-github-secret-71c2"
	if err := settings.SetSecret(context.Background(), d.Conn, "NDAY_AUTH_GITHUB_CLIENT_SECRET", sec, k); err != nil {
		t.Fatal(err)
	}
	s := serveCapture(t)
	if s.auth == nil {
		t.Fatalf("sign-in not enabled:\n%s", s.logs.String())
	}
	if code, body := s.me(t); code != 200 || !strings.Contains(body, `"providers":["github"]`) {
		t.Errorf("/api/me %d %s", code, body)
	}
	if strings.Contains(s.logs.String(), sec) {
		t.Error("secret logged")
	}
}

func TestSettingsRuntimeValidateApply(t *testing.T) {
	d := settingsServeEnv(t, true)
	ctx := context.Background()
	keyText, k := masterKey(t)
	t.Setenv(settings.EnvKey, keyText)
	s := serveCapture(t)
	rt := s.adm.Settings()
	if rt == nil || rt.Key() == nil {
		t.Fatal("no settings runtime / key")
	}
	if v, ok := rt.Env()("NDAY_AUTH_GITHUB_CLIENT_ID"); !ok || v != "Iv1.env" {
		t.Errorf("Env: %q %v", v, ok)
	}
	load := func() *settings.Snapshot {
		snap, err := settings.LoadSnapshot(ctx, d.Conn, rt.Key())
		if err != nil {
			t.Fatal(err)
		}
		return snap
	}
	// store + apply: terms, provider credentials, discussion limits, X token
	const xtok = "RT-X-bearer-token-4d1a"
	const gsec = "rt-github-secret-8b20"
	cand := load().With("NDAY_TERMS_VERSION", "v8").With("NDAY_DISCUSS_READ_BURST", "9").
		With("NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.rt").With("NDAY_AUTH_GITHUB_CLIENT_SECRET", gsec).
		With("NDAY_X_BEARER_TOKEN", xtok)
	if err := rt.Validate(cand); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	setPlain(t, d, "NDAY_TERMS_VERSION", "v8", "NDAY_DISCUSS_READ_BURST", "9", "NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.rt")
	for key, v := range map[string]string{"NDAY_AUTH_GITHUB_CLIENT_SECRET": gsec, "NDAY_X_BEARER_TOKEN": xtok} {
		if err := settings.SetSecret(ctx, d.Conn, key, v, k); err != nil {
			t.Fatal(err)
		}
	}
	if err := rt.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	cfg := s.auth.Config()
	if cfg.TermsVersion != "v8" || cfg.Providers[auth.GitHub].ClientID != "Iv1.rt" || cfg.Providers[auth.GitHub].ClientSecret != gsec ||
		s.ds.Limits().ReadBurst != 9 || !s.adm.XLookupAvailable() {
		t.Fatalf("after Apply: %+v %+v x=%v", cfg, s.ds.Limits(), s.adm.XLookupAvailable())
	}
	req, _ := http.NewRequest("GET", s.base+"/auth/github/start", nil)
	req.Host = "localhost:8080"
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "client_id=Iv1.rt") {
		t.Errorf("start after Apply: %d %s", resp.StatusCode, loc)
	}

	// the X token cleared: the lookup is off again (no token in the environment)
	if _, err := settings.Unset(ctx, d.Conn, "NDAY_X_BEARER_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if err := rt.Apply(ctx); err != nil || s.adm.XLookupAvailable() {
		t.Fatalf("token cleared: %v %v", err, s.adm.XLookupAvailable())
	}

	// refusals name keys, never values; nothing changes
	before := s.auth.Config()
	for _, c := range []struct {
		snap *settings.Snapshot
		want string
		rows map[string]string // the same, stored (bypassing validation) for Apply
	}{
		{load().With("NDAY_AUTH_SESSION_IDLE", "BAD-value-77"), "NDAY_AUTH_SESSION_IDLE",
			map[string]string{"NDAY_AUTH_SESSION_IDLE": "BAD-value-77"}},
		{load().With("NDAY_DISCUSS_READ_BURST", "BAD-value-78"), "NDAY_DISCUSS_READ_BURST",
			map[string]string{"NDAY_DISCUSS_READ_BURST": "BAD-value-78"}},
		{load().With("NDAY_AUTH_PASSKEYS", "off").With("NDAY_AUTH_GITHUB_CLIENT_ID", "").
			With("NDAY_AUTH_GITHUB_CLIENT_SECRET", ""), "sign-in off entirely",
			map[string]string{"NDAY_AUTH_PASSKEYS": "off", "NDAY_AUTH_GITHUB_CLIENT_ID": ""}},
	} {
		err := rt.Validate(c.snap)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "BAD-value") {
			t.Errorf("Validate: %v (want %q)", err, c.want)
		}
		var saved []string
		for k, v := range c.rows {
			var old *string
			if err := d.Conn.QueryRow(ctx, `SELECT value FROM app_settings WHERE key = $1`, k).Scan(&old); err == nil && old != nil {
				saved = append(saved, k, *old)
			}
			if _, err := d.Conn.Exec(ctx, `INSERT INTO app_settings (key, value) VALUES ($1, $2)
				ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, secret = NULL, hint = NULL`, k, v); err != nil {
				t.Fatal(err)
			}
		}
		if err := rt.Apply(ctx); err == nil || strings.Contains(err.Error(), "BAD-value") {
			t.Errorf("Apply accepted: %v", err)
		}
		for k := range c.rows {
			if _, err := settings.Unset(ctx, d.Conn, k); err != nil {
				t.Fatal(err)
			}
		}
		setPlain(t, d, saved...)
	}
	if s.auth.Config() != before {
		t.Error("a refused Apply changed the configuration")
	}
	if strings.Contains(s.logs.String(), xtok) || strings.Contains(s.logs.String(), gsec) || strings.Contains(s.logs.String(), "BAD-value") {
		t.Errorf("logs hold a value:\n%s", s.logs.String())
	}
	if !strings.Contains(s.logs.String(), "settings: applied to the running site") {
		t.Error("no apply log line")
	}
}

// serveFails runs `nday serve` expecting it to stop at start-up.
func serveFails(t *testing.T) (int, string) {
	t.Helper()
	code, _, errOut := runCLI(t, cli.Env{}, "serve", "--listen", "127.0.0.1:0")
	return code, errOut
}

// p8PEM returns a fresh Apple .p8 key as PEM text.
func p8PEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// The environment alone is invalid (a client ID whose secret was moved
// into the database, Apple's IDs whose key was moved, a discussion limit
// the database overrides): start-up uses the layered configuration when it
// is valid; without usable rows, or still invalid, it stops with the
// environment's own error as before.
func TestServeEnvCompletedByDatabase(t *testing.T) {
	d := settingsServeEnv(t, false)
	ctx := context.Background()
	keyText, k := masterKey(t)
	t.Setenv(settings.EnvKey, keyText)
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.env")
	_, envErr := auth.FromEnv(nil)
	if envErr == nil {
		t.Fatal("the environment should be invalid")
	}

	// no row: refused exactly as before
	if code, errOut := serveFails(t); code != 1 || !strings.Contains(errOut, envErr.Error()) {
		t.Fatalf("no rows: %d %q", code, errOut)
	}
	// a row that does not complete it: still the environment's error
	setPlain(t, d, "NDAY_TERMS_VERSION", "v3")
	if code, errOut := serveFails(t); code != 1 || !strings.Contains(errOut, envErr.Error()) {
		t.Fatalf("unrelated row: %d %q", code, errOut)
	}
	// the secret in the database: starts, ID from the environment, secret from the database
	const sec = "db-github-secret-5e1a-0f3c"
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_AUTH_GITHUB_CLIENT_SECRET", sec, k); err != nil {
		t.Fatal(err)
	}
	s := serveCapture(t)
	if s.auth == nil {
		t.Fatalf("sign-in not enabled:\n%s", s.logs.String())
	}
	cfg := s.auth.Config()
	if p := cfg.Providers[auth.GitHub]; p.ClientID != "Iv1.env" || p.ClientSecret != sec || cfg.TermsVersion != "v3" {
		t.Errorf("layered: %+v", cfg)
	}
	if code, body := s.me(t); code != 200 || !strings.Contains(body, `"providers":["github"]`) {
		t.Errorf("/api/me %d %s", code, body)
	}
	logs := s.logs.String()
	if !strings.Contains(logs, "the environment alone is not a valid sign-in configuration; the database settings complete it") ||
		strings.Contains(logs, sec) {
		t.Errorf("logs:\n%s", logs)
	}
	s.stop()

	// the secret unreadable (no master key): the environment's error again
	t.Setenv(settings.EnvKey, "")
	if code, errOut := serveFails(t); code != 1 || !strings.Contains(errOut, envErr.Error()) || strings.Contains(errOut, sec) {
		t.Fatalf("unreadable secret: %d %q", code, errOut)
	}
	t.Setenv(settings.EnvKey, keyText)

	// Apple: the IDs in the environment, the key (PEM) in the database
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_ID", "")
	if _, err := d.Conn.Exec(ctx, `DELETE FROM app_settings`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NDAY_AUTH_APPLE_SERVICES_ID", "land.nday.signin")
	t.Setenv("NDAY_AUTH_APPLE_TEAM_ID", "ABCDE12345")
	t.Setenv("NDAY_AUTH_APPLE_KEY_ID", "KEY1234567")
	_, appleErr := auth.FromEnv(nil)
	if code, errOut := serveFails(t); appleErr == nil || code != 1 || !strings.Contains(errOut, appleErr.Error()) {
		t.Fatalf("apple without key: %d %q", code, errOut)
	}
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_AUTH_APPLE_KEY", p8PEM(t), k); err != nil {
		t.Fatal(err)
	}
	s = serveCapture(t)
	if s.auth == nil || s.auth.Config().Providers[auth.Apple].AppleKey == nil {
		t.Fatalf("apple not enabled:\n%s", s.logs.String())
	}
	if strings.Contains(s.logs.String(), "PRIVATE KEY") {
		t.Error("key logged")
	}
	s.stop()

	// discussions: an invalid limit in the environment that the database overrides
	// (sign-in stays as above: the Apple key row)
	t.Setenv("NDAY_DISCUSS_POST_BURST", "BAD-env-41")
	if code, errOut := serveFails(t); code != 1 || !strings.Contains(errOut, "error: NDAY_DISCUSS_POST_BURST must be an integer") || strings.Contains(errOut, "BAD-env") {
		t.Fatalf("bad env limit, no discussion row: %d %q", code, errOut)
	}
	setPlain(t, d, "NDAY_DISCUSS_POST_BURST", "6")
	s = serveCapture(t)
	if s.ds == nil || s.ds.Limits().PostBurst != 6 {
		t.Fatalf("discussions: %v\n%s", s.ds, s.logs.String())
	}
	if logs := s.logs.String(); !strings.Contains(logs, "the database settings complete it") || strings.Contains(logs, "BAD-env") {
		t.Errorf("logs:\n%s", logs)
	}
}

// A stored sign-in value that cannot be used (a client secret sealed with
// another master key) drops only that provider's stored settings: the
// other providers, passkeys and the rest of the database settings stay.
// When sign-in ends up off although sign-in rows are stored, an ERROR says
// how to recover.
func TestServeDropsBrokenProviderSettings(t *testing.T) {
	d := settingsServeEnv(t, false)
	ctx := context.Background()
	keyText, k := masterKey(t)
	_, lost := masterKey(t)
	t.Setenv(settings.EnvKey, keyText)
	const gsec, ghsec = "db-google-secret-77aa-12bc", "db-github-secret-88bb-34cd"
	setPlain(t, d, "NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.db", "NDAY_AUTH_GOOGLE_CLIENT_ID", "google.db",
		"NDAY_AUTH_PASSKEYS", "on", "NDAY_TERMS_VERSION", "v9")
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_AUTH_GITHUB_CLIENT_SECRET", ghsec, lost); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_AUTH_GOOGLE_CLIENT_SECRET", gsec, k); err != nil {
		t.Fatal(err)
	}
	s := serveCapture(t)
	if s.auth == nil {
		t.Fatalf("sign-in off:\n%s", s.logs.String())
	}
	cfg := s.auth.Config()
	if _, gh := cfg.Providers[auth.GitHub]; gh || cfg.Providers[auth.Google].ClientSecret != gsec || !cfg.Passkeys || cfg.TermsVersion != "v9" {
		t.Errorf("degraded: providers %v passkeys %v terms %q", s.auth.Enabled(), cfg.Passkeys, cfg.TermsVersion)
	}
	logs := s.logs.String()
	if !strings.Contains(logs, "sign-in ignores the database settings of provider github") ||
		!strings.Contains(logs, "NDAY_AUTH_GITHUB_CLIENT_ID") || strings.Contains(logs, "level=ERROR") ||
		strings.Contains(logs, gsec) || strings.Contains(logs, ghsec) || strings.Contains(logs, "Iv1.db") {
		t.Errorf("logs:\n%s", logs)
	}
	s.stop()

	// only the broken provider is stored: sign-in ends up off, with an ERROR
	for _, key := range []string{"NDAY_AUTH_GOOGLE_CLIENT_ID", "NDAY_AUTH_GOOGLE_CLIENT_SECRET", "NDAY_AUTH_PASSKEYS"} {
		if _, err := settings.Unset(ctx, d.Conn, key); err != nil {
			t.Fatal(err)
		}
	}
	s = serveCapture(t)
	logs = s.logs.String()
	if s.auth != nil || !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, "sign-in is OFF although sign-in settings are stored") ||
		!strings.Contains(logs, "settings-unset") || strings.Contains(logs, ghsec) {
		t.Errorf("sign-in off: auth=%v\n%s", s.auth != nil, logs)
	}
	s.stop()

	// sign-in off on purpose, only non-enabling sign-in rows stored: no ERROR
	if _, err := d.Conn.Exec(ctx, `DELETE FROM app_settings`); err != nil {
		t.Fatal(err)
	}
	setPlain(t, d, "NDAY_TERMS_VERSION", "v9", "NDAY_AUTH_PASSKEYS", "off")
	s = serveCapture(t)
	if logs := s.logs.String(); s.auth != nil || strings.Contains(logs, "level=ERROR") {
		t.Errorf("intended off: auth=%v\n%s", s.auth != nil, logs)
	}
}

// gatedRuntime holds the first Apply until release is closed.
type gatedRuntime struct {
	settings.Runtime
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (g *gatedRuntime) Apply(ctx context.Context) error {
	if g.calls.Add(1) == 1 {
		close(g.entered)
		<-g.release
	}
	return g.Runtime.Apply(ctx)
}

// Two saves whose Apply calls run in the opposite order of their commits
// (the first one held after its commit while the second commits and
// applies): the running site ends at what is stored last.
func TestSettingsApplyConcurrentSaves(t *testing.T) {
	d := settingsServeEnv(t, true)
	ctx := context.Background()
	keyText, _ := masterKey(t)
	t.Setenv(settings.EnvKey, keyText)
	s := serveCapture(t)
	pc, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(pc, dbpool.Options{Size: 3, Dial: testutil.Dial(pc)})
	t.Cleanup(pool.Close)
	g := &gatedRuntime{Runtime: s.adm.Settings(), entered: make(chan struct{}), release: make(chan struct{})}
	adm, err := admin.New(admin.Options{Auth: s.auth, AuthDB: pool, ReadDB: pool, Settings: g})
	if err != nil {
		t.Fatal(err)
	}
	var uid string
	if err := d.Conn.QueryRow(ctx, `INSERT INTO users (display_name, role) VALUES ('Ada', 'admin') RETURNING id::text`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() {
		_, err := adm.SaveSettings(ctx, uid, map[string]string{"NDAY_TERMS_VERSION": "v1", "NDAY_DISCUSS_READ_BURST": "11"}, nil)
		first <- err
	}()
	select {
	case <-g.entered: // committed, Apply held
	case err := <-first:
		t.Fatalf("first save returned early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("first save did not reach Apply")
	}
	if _, err := adm.SaveSettings(ctx, uid, map[string]string{"NDAY_TERMS_VERSION": "v2", "NDAY_DISCUSS_READ_BURST": "22"}, nil); err != nil {
		t.Fatalf("second save: %v", err)
	}
	if v := s.auth.Config().TermsVersion; v != "v2" {
		t.Fatalf("after the second save: %q", v)
	}
	close(g.release)
	if err := <-first; err != nil {
		t.Fatalf("first save: %v", err)
	}
	snap, err := settings.LoadSnapshot(ctx, d.Conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := snap.Value("NDAY_TERMS_VERSION")
	if v := s.auth.Config().TermsVersion; stored != "v2" || v != stored || s.ds.Limits().ReadBurst != 22 {
		t.Errorf("running site at terms %q, read burst %d; stored %q", v, s.ds.Limits().ReadBurst, stored)
	}
}
