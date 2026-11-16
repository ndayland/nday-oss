package cli_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
)

// A handle may have changed hands,
// so auth-role/auth-suspend/auth-unsuspend print the resolved user and need
// --yes unless the user was given by id.
func TestAuthAdminCommandsConfirmHandle(t *testing.T) {
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
	role := func() string {
		var r string
		_ = d.Conn.QueryRow(ctx, `SELECT role || '/' || status FROM users`).Scan(&r)
		return r
	}
	for _, args := range [][]string{{"auth-role", "ada", "admin"}, {"auth-suspend", "ada"}, {"auth-unsuspend", "ada"}} {
		code, out, errOut := runCLI(t, cli.Env{}, args...)
		if code == 0 || !strings.Contains(errOut, "--yes") || !strings.Contains(out, id) || !strings.Contains(out, "handle=Ada") ||
			!strings.Contains(out, "created=") || !strings.Contains(out, "last_seen=") {
			t.Errorf("%v without --yes: %d %q %q", args, code, out, errOut)
		}
	}
	if r := role(); r != "user/active" {
		t.Fatalf("changed without --yes: %s", r)
	}
	if code, out, errOut := runCLI(t, cli.Env{}, "auth-role", "ada", "moderator", "--yes"); code != 0 ||
		!strings.Contains(out, "handle=Ada") || !strings.HasSuffix(out, "auth-role: "+id+" user -> moderator\n") {
		t.Errorf("--yes: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := runCLI(t, cli.Env{}, "auth-suspend", id); code != 0 || !strings.Contains(out, "suspended indefinitely") {
		t.Errorf("by id: %d %q %q", code, out, errOut)
	}
	if r := role(); r != "moderator/suspended" {
		t.Errorf("role/status %s", r)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// Sign-in enabled without an origin client CA logs one clear warning.
func TestServeWarnsWithoutClientCA(t *testing.T) {
	clearAuthEnv(t)
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	t.Setenv("NDAY_TLS_CLIENT_CA", "")
	t.Setenv("NDAY_PUBLIC_URL", "http://localhost:8080")
	sec := make([]byte, 48)
	_, _ = rand.Read(sec)
	t.Setenv("NDAY_AUTH_SECRET", base64.StdEncoding.EncodeToString(sec))
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.test")
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_SECRET", "test-secret")
	t.Setenv("NDAY_AUTH_RP_ID", "localhost")
	logs := &lockedBuf{}
	addrc := make(chan net.Addr, 1)
	cli.ServeReady = func(a net.Addr) { addrc <- a }
	t.Cleanup(func() { cli.ServeReady = nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- cli.Main(ctx, []string{"serve", "--listen", "127.0.0.1:0"}, cli.Env{Stdout: logs, Stderr: logs})
	}()
	select {
	case <-addrc:
	case c := <-done:
		cancel()
		t.Fatalf("serve exited %d: %s", c, logs.String())
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}
	cancel()
	<-done
	if n := strings.Count(logs.String(), "CF-Connecting-IP"); n != 1 || !strings.Contains(logs.String(), "NDAY_TLS_CLIENT_CA") {
		t.Errorf("want one warning about CF-Connecting-IP and NDAY_TLS_CLIENT_CA, got %d:\n%s", n, logs.String())
	}
}
