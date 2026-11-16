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

func TestDiscussCommands(t *testing.T) {
	clearAuthEnv(t)
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	ctx := context.Background()
	var uid, cid string
	if err := d.Conn.QueryRow(ctx, `INSERT INTO users (display_name) VALUES ('Ada') RETURNING id::text`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0001')`); err != nil {
		t.Fatal(err)
	}
	if err := d.Conn.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links) VALUES ('CVE-2026-0001', false, $1, 'spam', 'en', true)
		RETURNING id::text`, uid).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO comment_reports (comment_id, reporter_id, reason) VALUES ($1, $2, 'spam')`, cid, uid); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, cli.Env{}, "discuss-hide", strings.ToUpper(cid), "--reason", "  spam link  ")
	if code != 0 || !strings.HasPrefix(out, "comment: id="+cid+" cve=CVE-2026-0001 author=- ") || !strings.Contains(out, " status=visible ") ||
		!strings.HasSuffix(out, "\ndiscuss-hide: "+cid+" hidden (resolved_reports=1)\n") || strings.Contains(out, "spam link\n") {
		t.Fatalf("hide: %d %q %q", code, out, errOut)
	}
	var status, reason string
	var by *string
	_ = d.Conn.QueryRow(ctx, `SELECT status, hidden_reason, hidden_by::text FROM comments`).Scan(&status, &reason, &by)
	if status != "hidden" || reason != "spam link" || by != nil {
		t.Errorf("after hide: %s %q %v", status, reason, by)
	}
	if code, _, errOut := runCLI(t, cli.Env{}, "discuss-hide", cid, "--reason", "again"); code != 1 || !strings.Contains(errOut, "is hidden; nothing changed") {
		t.Errorf("hide twice: %d %q", code, errOut)
	}
	if code, out, errOut := runCLI(t, cli.Env{}, "discuss-unhide", cid); code != 0 || !strings.HasSuffix(out, "\ndiscuss-unhide: "+cid+" visible\n") {
		t.Errorf("unhide: %d %q %q", code, out, errOut)
	}
	for _, args := range [][]string{
		{"discuss-hide", cid},                 // no reason
		{"discuss-hide", cid, "--reason", ""}, // empty reason
		{"discuss-hide", cid, "--reason", strings.Repeat("r", 201)},
		{"discuss-hide", "not-a-uuid", "--reason", "x"},
		{"discuss-unhide"},
		{"discuss-unhide", cid, "extra"},
	} {
		if code, _, _ := runCLI(t, cli.Env{}, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, errOut := runCLI(t, cli.Env{}, "discuss-unhide", "0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44"); code != 1 || !strings.Contains(errOut, "no comment with id") {
		t.Errorf("unknown comment: %d %q", code, errOut)
	}
	// a deleted account's comment
	if _, err := d.Conn.Exec(ctx, `DELETE FROM users`); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runCLI(t, cli.Env{}, "discuss-hide", cid, "--reason", "x"); code != 0 || !strings.Contains(out, "author=(deleted account)") {
		t.Errorf("authorless: %d %q", code, out)
	}
}

func TestServeDiscussions(t *testing.T) {
	clearAuthEnv(t)
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	if _, err := d.Conn.Exec(context.Background(), `INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0001')`); err != nil {
		t.Fatal(err)
	}
	get := func(base, path string) (int, string) {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Host = "localhost:8080"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	// accounts disabled: no discussions
	base, stop := serveOnce(t)
	if code, body := get(base, "/api/discuss/CVE-2026-0001"); code != 404 {
		t.Errorf("without accounts: %d %s", code, body)
	}
	stop()

	t.Setenv("NDAY_PUBLIC_URL", "http://localhost:8080")
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	t.Setenv("NDAY_AUTH_SECRET", base64.StdEncoding.EncodeToString(sec))
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_ID", "Iv1.test")
	t.Setenv("NDAY_AUTH_GITHUB_CLIENT_SECRET", "test-secret")
	t.Setenv("NDAY_AUTH_RP_ID", "localhost")
	t.Setenv("NDAY_TERMS_VERSION", "")
	t.Setenv("NDAY_DISCUSS", "")
	logs := &lockedBuf{}
	addrc := make(chan net.Addr, 1)
	cli.ServeReady = func(a net.Addr) { addrc <- a }
	t.Cleanup(func() { cli.ServeReady = nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- cli.Main(ctx, []string{"serve", "--listen", "127.0.0.1:0"}, cli.Env{Stdout: logs, Stderr: logs})
	}()
	var addr net.Addr
	select {
	case addr = <-addrc:
	case c := <-done:
		cancel()
		t.Fatalf("serve exited %d: %s", c, logs.String())
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}
	code, body := get("http://"+addr.String(), "/api/discuss/CVE-2026-0001")
	if code != 200 || !strings.Contains(body, `"comments":[]`) {
		t.Errorf("with accounts: %d %s", code, body)
	}
	cancel()
	<-done
	if !strings.Contains(logs.String(), "discuss: discussions enabled") || !strings.Contains(logs.String(), "NDAY_TERMS_VERSION is not set") {
		t.Errorf("serve logs:\n%s", logs.String())
	}

	// NDAY_DISCUSS=off: accounts but no discussions
	t.Setenv("NDAY_DISCUSS", "off")
	base, stop = serveOnce(t)
	if code, body := get(base, "/api/discuss/CVE-2026-0001"); code != 404 {
		t.Errorf("NDAY_DISCUSS=off: %d %s", code, body)
	}
	if code, _ := get(base, "/api/me"); code != 200 {
		t.Errorf("NDAY_DISCUSS=off broke /api/me: %d", code)
	}
	stop()

	// invalid limits refuse to start, naming the variable only
	t.Setenv("NDAY_DISCUSS", "")
	t.Setenv("NDAY_DISCUSS_POST_BURST", "lots")
	if code, _, errOut := runCLI(t, cli.Env{}, "serve", "--listen", "127.0.0.1:0"); code != 1 ||
		!strings.Contains(errOut, "NDAY_DISCUSS_POST_BURST") || strings.Contains(errOut, "lots") {
		t.Errorf("bad limit: %d %q", code, errOut)
	}
}
