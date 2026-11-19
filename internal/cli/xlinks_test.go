package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/testutil"
)

// x-links-resolve requests only t.co (through Env.Transport here, never the
// network) and x-candidates prints the pending list; bad --limit is a usage
// error.
func TestXLinksCandidatesCommands(t *testing.T) {
	d := testutil.NewDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	ft := &testutil.FakeTransport{Handler: func(r *http.Request) (int, http.Header, []byte, error) {
		return http.StatusMovedPermanently, http.Header{"Location": {"https://www.exploit-db.com/exploits/1"}}, nil, nil
	}}
	env := cli.Env{Transport: ft}
	if code, _, errs := runCLI(t, env, "migrate"); code != 0 {
		t.Fatal(errs)
	}
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO x_post_link (post_id, pos, short_url, kind, origin, status) VALUES
            ('2000000000000000001', 0, 'https://t.co/AbC1', 'other', 'api', 'pending'),
            ('2000000000000000001', 1, 'https://t.co/AbC2', 'other', 'api', 'pending')`,
		`INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at) VALUES ('3001', 'carol_re', '2026-11-10', '2026-11-12')`,
		`INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at) VALUES ('3001', '2000000000000000001', '1001', 'quoted', '2026-11-12')`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := runCLI(t, env, "x-links-resolve", "--limit", "1")
	var res struct{ Candidates, Resolved, Requests int }
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.Candidates != 1 || res.Resolved != 1 || res.Requests != 1 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if len(ft.Requests) != 1 || ft.Requests[0].URL != "https://t.co/AbC1" {
		t.Errorf("requests %+v", ft.Requests)
	}
	code, out, _ = runCLI(t, env, "x-candidates")
	if code != 0 || out != "3001 @carol_re referrers=0 refs=1 kinds=quoted first=2026-11-10 last=2026-11-12 posts=2000000000000000001\nx-candidates: 1 shown\n" {
		t.Errorf("%d %q", code, out)
	}
	// x-links-enqueue queues the resolved link (idempotent); pages-fetch
	// with only a refused row makes no request (no network here)
	code, out, errs = runCLI(t, env, "x-links-enqueue")
	if code != 0 || compactJSON(out) != `{"candidates":1,"added":1,"refused":0}` {
		t.Errorf("x-links-enqueue: %d %s %s", code, out, errs)
	}
	if code, out, _ = runCLI(t, env, "x-links-enqueue"); code != 0 || compactJSON(out) != `{"candidates":0,"added":0,"refused":0}` {
		t.Errorf("x-links-enqueue again: %d %s", code, out)
	}
	if _, err := d.Conn.Exec(ctx, `UPDATE web_page SET url = 'http://10.0.0.1/' WHERE first_source = 'xposts'`); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runCLI(t, env, "pages-fetch", "--limit", "5")
	if code != 0 || compactJSON(out) != `{"candidates":1,"ok":0,"none":1,"retry":0,"failed":0,"refused":1,"other_host":0,"panics":0,"requests":0,"published":0,"backfilled":0}` {
		t.Errorf("pages-fetch: %d %s %s", code, out, errs)
	}
	if got := jobRun(t, d, "pages-fetch"); got != `true  {"ok": 0, "none": 1, "retry": 0, "failed": 0, "panics": 0, "refused": 1, "requests": 0, "published": 0, "backfilled": 0, "candidates": 1, "other_host": 0}` {
		t.Errorf("pages-fetch job_run: %s", got)
	}
	for _, args := range [][]string{{"x-candidates", "--limit", "0"}, {"x-links-resolve", "--limit", "x"}, {"x-candidates", "extra"},
		{"pages-fetch", "--limit", "0"}, {"x-links-enqueue", "extra"}} {
		if code, _, errs := runCLI(t, env, args...); code != 2 || !strings.Contains(errs, "error") {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

// compactJSON is out (indented JSON) on one line.
func compactJSON(out string) string {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(out)); err != nil {
		return out
	}
	return b.String()
}
