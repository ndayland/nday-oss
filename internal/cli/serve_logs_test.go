package cli_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
)

func TestServeLogDirStartupErrors(t *testing.T) {
	for _, k := range []string{"NDAY_TLS_CERT", "NDAY_TLS_KEY", "NDAY_TLS_CLIENT_CA"} {
		t.Setenv(k, "")
	}
	missing := filepath.Join(t.TempDir(), "nope")
	for dir, want := range map[string]string{
		missing:    "NDAY_LOG_DIR: directory " + missing + " does not exist",
		"rel/logs": "NDAY_LOG_DIR must be an absolute path",
	} {
		t.Setenv("NDAY_LOG_DIR", dir)
		code, _, errOut := runCLI(t, cli.Env{}, "serve", "--listen", "127.0.0.1:0")
		if code != 1 || !strings.Contains(errOut, want) {
			t.Errorf("%s: %d %q", dir, code, errOut)
		}
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("serve created the log directory")
	}
}

// End to end: with NDAY_LOG_DIR the access line is in today's (local) file
// and not on stderr; a WARN+ record (here NDAY_API_URL without
// NDAY_PUBLIC_URL) is in both.
func TestServeLogDir(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	dir := t.TempDir()
	t.Setenv("NDAY_LOG_DIR", dir)
	t.Setenv("NDAY_PUBLIC_URL", "")
	t.Setenv("NDAY_API_URL", "http://api.nday.localhost")
	addrc := make(chan net.Addr, 1)
	cli.ServeReady = func(a net.Addr) { addrc <- a }
	t.Cleanup(func() { cli.ServeReady = nil })
	ctx, cancel := context.WithCancel(context.Background())
	stderr := &lockedBuf{}
	done := make(chan int, 1)
	go func() {
		done <- cli.Main(ctx, []string{"serve", "--listen", "127.0.0.1:0"}, cli.Env{Stdout: io.Discard, Stderr: stderr})
	}()
	var addr net.Addr
	select {
	case addr = <-addrc:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}
	day := time.Now().Format("2006-01-02")
	resp, err := http.Get("http://" + addr.String() + "/healthz?probe=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()
	if c := <-done; c != 0 {
		t.Errorf("serve exit %d", c)
	}
	acc, err := os.ReadFile(filepath.Join(dir, "access-"+day+".log"))
	if err != nil || !strings.Contains(string(acc), `"uri":"/healthz?probe=1","status":200`) {
		t.Errorf("access file %q %v", acc, err)
	}
	errf, err := os.ReadFile(filepath.Join(dir, "error-"+day+".log"))
	if err != nil || !strings.Contains(string(errf), `"level":"WARN"`) || !strings.Contains(string(errf), "NDAY_PUBLIC_URL is not") {
		t.Errorf("error file %q %v", errf, err)
	}
	se := stderr.String()
	if strings.Contains(se, "msg=http ") || !strings.Contains(se, "NDAY_PUBLIC_URL is not") || !strings.Contains(se, "msg=\"log files\"") {
		t.Errorf("stderr:\n%s", se)
	}
}
