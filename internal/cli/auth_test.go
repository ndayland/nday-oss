package cli_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
)

func clearAuthEnv(t *testing.T) {
	for _, k := range []string{"NDAY_PUBLIC_URL", "NDAY_AUTH_SECRET", "NDAY_AUTH_SECRET_PREVIOUS", "NDAY_AUTH_GITHUB_CLIENT_ID",
		"NDAY_AUTH_GITHUB_CLIENT_SECRET", "NDAY_AUTH_GOOGLE_CLIENT_ID", "NDAY_AUTH_GOOGLE_CLIENT_SECRET", "NDAY_AUTH_X_CLIENT_ID",
		"NDAY_AUTH_X_CLIENT_SECRET", "NDAY_AUTH_APPLE_SERVICES_ID", "NDAY_AUTH_APPLE_TEAM_ID", "NDAY_AUTH_APPLE_KEY_ID",
		"NDAY_AUTH_APPLE_KEY_FILE", "NDAY_AUTH_PASSKEYS", "NDAY_AUTH_PASSKEY_SIGNUP", "NDAY_AUTH_RP_ID", "NDAY_AUTH_ORIGINS",
		"NDAY_TERMS_VERSION", "NDAY_AUTH_SESSION_IDLE", "NDAY_AUTH_SESSION_MAX", "NDAY_AUTH_HANDLE_HOLD",
		"NDAY_AUTH_SENSITIVE_WINDOW", "NDAY_AUTH_MAX_PASSKEYS", "NDAY_AUTH_PASSKEY_SIGNUP_DAILY", "NDAY_AUTH_PASSKEY_SIGNUP_INTERVAL"} {
		t.Setenv(k, "")
	}
}

func TestAuthAdminCommands(t *testing.T) {
	clearAuthEnv(t)
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	ctx := context.Background()
	var id string
	if err := d.Conn.QueryRow(ctx, `INSERT INTO users (display_name) VALUES ('Ada') RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO namespaces (name, kind) VALUES ('ada', 'user');
		UPDATE users SET handle = 'Ada', handle_key = 'ada'`); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI(t, cli.Env{}, "auth-role", "ADA", "moderator", "--yes"); code != 0 || !strings.HasSuffix(out, "\nauth-role: "+id+" user -> moderator\n") {
		t.Fatalf("role: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runCLI(t, cli.Env{}, "auth-role", id, "god"); code != 2 || !strings.Contains(errOut, "invalid choice: 'god'") {
		t.Errorf("bad role: %d %q", code, errOut)
	}
	if code, _, errOut := runCLI(t, cli.Env{}, "auth-role", "nobody", "admin"); code != 1 || !strings.Contains(errOut, `no user with id or handle "nobody"`) {
		t.Errorf("unknown user: %d %q", code, errOut)
	}
	if code, out, errOut := runCLI(t, cli.Env{}, "auth-suspend", id, "--for", "7d", "--reason", "spam"); code != 0 || !strings.Contains(out, "\nauth-suspend: "+id+" suspended until ") {
		t.Fatalf("suspend: %d %q %q", code, out, errOut)
	}
	var status, reason string
	var until time.Time
	_ = d.Conn.QueryRow(ctx, `SELECT role || '/' || status, status_reason, suspended_until FROM users`).Scan(&status, &reason, &until)
	if status != "moderator/suspended" || reason != "spam" || until.Before(time.Now().Add(6*24*time.Hour)) {
		t.Errorf("%s %s %v", status, reason, until)
	}
	if code, _, _ := runCLI(t, cli.Env{}, "auth-suspend", id, "--for", "7d", "--until", "2030-01-01T00:00:00Z"); code != 2 {
		t.Error("--for and --until")
	}
	if code, out, _ := runCLI(t, cli.Env{}, "auth-suspend", "ada", "--yes"); code != 0 || !strings.Contains(out, "indefinitely") {
		t.Errorf("indefinite: %q", out)
	}
	if code, out, _ := runCLI(t, cli.Env{}, "auth-unsuspend", "ada", "--yes"); code != 0 || !strings.HasSuffix(out, "\nauth-unsuspend: "+id+" active\n") {
		t.Errorf("unsuspend: %q", out)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (sha256('x'), $1, now() - interval '1 s'),
		(sha256('y'), $1, now() + interval '1 day')`, id); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI(t, cli.Env{}, "auth-gc"); code != 0 || out != "auth-gc: sessions=1 flows=0 names=0 unsuspended=0\n" {
		t.Errorf("gc: %d %q %q", code, out, errOut)
	}
	if code, _, _ := runCLI(t, cli.Env{}, "auth-gc", "extra"); code != 2 {
		t.Error("gc extra arg")
	}
}

func serveOnce(t *testing.T) (string, func() int) {
	addrc := make(chan net.Addr, 1)
	cli.ServeReady = func(a net.Addr) { addrc <- a }
	t.Cleanup(func() { cli.ServeReady = nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- cli.Main(ctx, []string{"serve", "--listen", "127.0.0.1:0"}, cli.Env{Stdout: io.Discard, Stderr: io.Discard})
	}()
	select {
	case a := <-addrc:
		return "http://" + a.String(), func() int { cancel(); return <-done }
	case c := <-done:
		cancel()
		t.Fatalf("serve exited %d", c)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}
	return "", nil
}

func TestServeWithAuth(t *testing.T) {
	clearAuthEnv(t)
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)

	// inert: no provider configured -> /api/me does not exist, as before
	base, stop := serveOnce(t)
	resp, err := http.Get(base + "/api/me")
	if err != nil || resp.StatusCode != 404 {
		t.Fatalf("inert /api/me: %v %v", resp, err)
	}
	resp.Body.Close()
	if stop() != 0 {
		t.Fatal("serve exit")
	}

	t.Setenv("NDAY_PUBLIC_URL", "http://localhost:8080")
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	t.Setenv("NDAY_AUTH_SECRET", base64.StdEncoding.EncodeToString(sec))
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.test")
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_SECRET", "test-secret")
	t.Setenv("NDAY_AUTH_RP_ID", "localhost")
	base, stop = serveOnce(t)
	req, _ := http.NewRequest("GET", base+"/api/me", nil)
	req.Host = "localhost:8080" // the configured public origin (other hosts get 421)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" ||
		string(b) != `{"signed_in":false,"providers":["github"],"passkeys":{"enabled":true,"signup":false,"max_per_user":20}}`+"\n" {
		t.Errorf("/api/me %d %s", resp.StatusCode, b)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ = http.NewRequest("GET", base+"/auth/github/start?return=/hot", nil)
	req.Host = "localhost:8080"
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), "https://github.com/login/oauth/authorize?") {
		t.Errorf("start: %v %v", resp, err)
	}
	resp.Body.Close()
	if stop() != 0 {
		t.Fatal("serve exit")
	}

	// startup validation: partial configuration refuses to start
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_SECRET", "")
	code, _, errOut := runCLI(t, cli.Env{}, "serve", "--listen", "127.0.0.1:0")
	if code != 1 || !strings.Contains(errOut, "provider github is partly configured") || strings.Contains(errOut, "Iv1.test") {
		t.Errorf("partial config: %d %q", code, errOut)
	}
}
