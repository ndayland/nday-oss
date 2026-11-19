package cli_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/web/webtest"
)

func TestRefreshStateAndServe(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	code, out, _ := runCLI(t, cli.Env{}, "refresh-state")
	if code != 0 || !strings.HasPrefix(out, "refresh-state: refreshes=1 ") {
		t.Fatalf("refresh-state: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, cli.Env{}, "refresh-state", "x"); code != 2 {
		t.Errorf("extra arg: %d", code)
	}

	addrc := make(chan net.Addr, 1)
	cli.ServeReady = func(a net.Addr) { addrc <- a }
	t.Cleanup(func() { cli.ServeReady = nil })
	// no sign-in configured here, so no real API token exists: the stand-in
	// authenticator accepts the test token (internal/auth has the real one)
	cli.ServeHook = func(s *web.Server) { s.SetAPIAuth(webtest.BearerAuth{}) }
	t.Cleanup(func() { cli.ServeHook = nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- cli.Main(ctx, []string{"serve", "--listen", "127.0.0.1:0"}, cli.Env{Stdout: io.Discard, Stderr: io.Discard})
	}()
	var addr net.Addr
	select {
	case addr = <-addrc:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}
	resp, err := http.Get("http://" + addr.String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Empty database: DB ok, no successful run yet -> stale.
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"db":"ok"`) || !strings.Contains(string(b), `"status":"stale"`) {
		t.Errorf("healthz %d %s", resp.StatusCode, b)
	}
	hot := "http://" + addr.String() + "/api/hot?since=30d&min_stage=patch"
	resp, err = http.Get(hot)
	if err != nil || resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != `Bearer realm="nday"` {
		t.Errorf("hot without a token %v %v", resp, err)
	}
	resp.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, hot, nil)
	req.Header.Set("Authorization", "Bearer "+webtest.TestAPIToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Errorf("hot %v %v", resp, err)
	}
	resp.Body.Close()
	cancel()
	if c := <-done; c != 0 {
		t.Errorf("serve exit %d", c)
	}
}

func TestServeTLSFlags(t *testing.T) {
	t.Setenv("NDAY_TLS_CERT", "")
	t.Setenv("NDAY_TLS_KEY", "")
	t.Setenv("NDAY_TLS_CLIENT_CA", "")
	code, _, errOut := runCLI(t, cli.Env{}, "serve", "--tls-cert", "/x.pem")
	if code != 2 || !strings.Contains(errOut, "both a certificate and a key") {
		t.Errorf("cert without key: %d %q", code, errOut)
	}
	code, _, errOut = runCLI(t, cli.Env{}, "serve", "--tls-client-ca", "/ca.pem")
	if code != 2 {
		t.Errorf("client CA alone: %d %q", code, errOut)
	}
	// Env equivalents; the files are loaded before the database is touched.
	t.Setenv("NDAY_TLS_CERT", "/nonexistent/cert.pem")
	t.Setenv("NDAY_TLS_KEY", "/nonexistent/key.pem")
	code, _, errOut = runCLI(t, cli.Env{}, "serve", "--listen", "127.0.0.1:0")
	if code != 1 || !strings.Contains(errOut, "loading certificate/key") {
		t.Errorf("missing files via env: %d %q", code, errOut)
	}
}
