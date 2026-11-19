package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/xconfig"
)

const fakeToken = "XTOKEN-SECRET-a1b2c3d4e5f6"

// xFixture: two accounts, a collector_state row with a cursor and a few
// posts (social_post events) with the given text.
func (h *harness) xFixture(text, handle, stopInfo, lastErr string) {
	h.t.Helper()
	ctx := context.Background()
	for _, a := range [][3]string{{"1001", "alice_sec", "researcher"}, {"1002", "bob_sec", ""}} {
		if err := xconfig.InsertAccount(ctx, h.db.Conn, a[0], a[1], a[2]); err != nil {
			h.t.Fatal(err)
		}
	}
	cur := map[string]any{"since_id": "1850000000000000000", "last_run": map[string]any{
		"at": "2026-11-13T11:00:00Z", "mode": "since_id", "accounts": 2, "batches": 1, "batches_done": 1, "http_requests": 3,
		"posts": 120, "kept": 4, "kept_no_cve": 100, "dropped_author": 16, "stopped": "max_requests",
		"stop_info": json.RawMessage(stopInfo)}}
	cj, _ := json.Marshal(cur)
	h.sql(`INSERT INTO collector_state (source, cursor, last_run_at, last_status, last_error, last_success_at)
		VALUES ('xposts', $1, now(), 'ok', $2, now())`, string(cj), lastErr)
	h.sql(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0002') ON CONFLICT DO NOTHING`)
	for i, cves := range [][]string{{cveA}, {cveA, "CVE-2026-0002"}, {"CVE-2026-0002"}} {
		postID := fmt.Sprintf("18500000000000000%02d", i)
		author, h2 := "1001", "alice_sec"
		if i == 2 {
			author, h2 = "1002", handle
		}
		detail, _ := json.Marshal(map[string]any{"post_id": postID, "author_id": author, "author_handle": h2, "text": text,
			"lang": "en", "cves": cves})
		for _, c := range cves {
			h.sql(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url, detail, dedupe_key)
				VALUES ($1, 'social_post', $2, $3, 'xposts', $4, $5, $6)`, c, h.clock.Now().Add(-time.Duration(i)*time.Hour),
				h.clock.Now().Add(-time.Duration(i)*time.Minute), "https://x.com/"+h2+"/status/"+postID, string(detail), postID)
		}
	}
}

// TestXAccessMatrix: /admin/x and /api/admin/x/* for every kind of
// visitor, the hosts, CSRF, cross-site and a stale sign-in.
func TestXAccessMatrix(t *testing.T) {
	h := newHarness(t, hopt{})
	h.xFixture("CVE-2026-0001 is bad", "bob_sec", `{"limit":3}`, "")
	anon := h.browser()
	user := h.user("pat", "user")
	smod := h.user("sam", "moderator")
	h.suspend(smod.id)
	sadm := h.user("sue", "admin")
	h.suspend(sadm.id)
	mod := h.user("mia", "moderator")
	adm := h.user("kim", "admin")
	who := []struct {
		name string
		b    *browser
	}{{"signed out", anon}, {"user", user}, {"suspended moderator", smod}, {"suspended admin", sadm}, {"moderator", mod}, {"admin", adm}}
	var table strings.Builder
	table.WriteString("\n| route | signed out | user | suspended moderator | suspended admin | moderator | admin |\n|---|---|---|---|---|---|---|\n")
	row := func(route string, cells []string) {
		table.WriteString("| `" + route + "` | " + strings.Join(cells, " | ") + " |\n")
	}
	var cells []string
	for _, w := range who {
		resp, _ := w.b.do("GET", "/admin/x", "")
		c := fmt.Sprint(resp.StatusCode)
		if resp.StatusCode == 302 {
			c += " → " + resp.Header.Get("Location")
		}
		cells = append(cells, c)
		want := map[string]int{"signed out": 302, "admin": 200}[w.name]
		if want == 0 {
			want = 404
		}
		if resp.StatusCode != want {
			t.Errorf("/admin/x as %s: %d, want %d", w.name, resp.StatusCode, want)
		}
	}
	row("GET /admin/x", cells)
	// the moderator does not even see the nav item
	if _, body := mod.do("GET", "/admin/moderation", ""); strings.Contains(string(body), `href="/admin/x"`) {
		t.Error("moderator sees the X nav item")
	}
	if _, body := adm.do("GET", "/admin/moderation", ""); !strings.Contains(string(body), `href="/admin/x"`) {
		t.Error("admin lacks the X nav item")
	}
	if resp, _ := adm.do("GET", "/zh-hans/admin/x", ""); resp.StatusCode != 200 {
		t.Errorf("zh-hans: %d", resp.StatusCode)
	}
	if resp, _ := anon.do("GET", "/zh-hans/admin/x", ""); resp.Header.Get("Location") != "/zh-hans/login?return=%2Fzh-hans%2Fadmin%2Fx" {
		t.Errorf("zh-hans signed out: %s", resp.Header.Get("Location"))
	}
	eps := []struct{ path, body string }{
		{"/api/admin/x/settings", `{"enabled":null,"max_posts":200,"max_requests":null,"bootstrap_days":null,"max_query_length":null}`},
		{"/api/admin/x/accounts", `{"user_id":"1003","handle":"carol","note":""}`},
		{"/api/admin/x/accounts/1003/update", `{"handle":"carol2","note":"n"}`},
		{"/api/admin/x/accounts/1003/disable", ``},
		{"/api/admin/x/accounts/1003/enable", ``},
		{"/api/admin/x/import", `{"text":"1004 dave\n","dry_run":false}`},
	}
	want := map[string]string{"signed out": "401 not_signed_in", "user": "404 not_found", "suspended moderator": "404 not_found",
		"suspended admin": "404 not_found", "moderator": "403 forbidden", "admin": "200 "}
	for _, e := range eps {
		cells = nil
		for _, w := range who {
			resp, body := w.b.post(e.path, e.body)
			got := fmt.Sprintf("%d %s", resp.StatusCode, errCode(body))
			cells = append(cells, got)
			if got != want[w.name] {
				t.Errorf("%s as %s: %s %s, want %s", e.path, w.name, got, body, want[w.name])
			}
		}
		row("POST "+e.path, cells)
	}
	if n := h.count(`SELECT count(*) FROM admin_audit WHERE action LIKE 'x.%'`); n != len(eps) {
		t.Errorf("audit rows: %d, want %d", n, len(eps))
	}
	p := "/api/admin/x/accounts/1003/disable"
	check(t, "API host POST", 405, "method_not_allowed")(adm.do("POST", p, "", "Host", apiHost, "Origin", origin, "X-CSRF-Token", adm.csrf))
	check(t, "API host GET", 404, "not_found")(adm.do("GET", "/admin/x", "", "Host", apiHost))
	// a foreign host never reaches the back office: web.Server answers it
	resp, body := adm.do("POST", p, "", "Host", "evil.example", "Origin", origin, "X-CSRF-Token", adm.csrf)
	checkForeignHost(t, "wrong host", "POST", p, resp, body)
	resp, body = adm.do("GET", "/admin/x", "", "Host", "evil.example")
	checkForeignHost(t, "page on a foreign host", "GET", "/admin/x", resp, body)
	check(t, "GET endpoint", 405, "method_not_allowed")(adm.do("GET", p, ""))
	check(t, "no CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", ""))
	check(t, "bad CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", flip(adm.csrf)))
	check(t, "cross-site", 403, "cross_site")(adm.post(p, "", "Sec-Fetch-Site", "cross-site"))
	check(t, "bad account id", 404, "not_found")(adm.post("/api/admin/x/accounts/01003/disable", ""))
	check(t, "unknown x endpoint", 404, "not_found")(adm.post("/api/admin/x/token", `{}`))
	before := h.count(`SELECT count(*) FROM admin_audit`)
	h.clock.Advance(16 * time.Minute)
	check(t, "stale session", 403, "reauth_required")(adm.post(p, ""))
	check(t, "stale session (settings)", 403, "reauth_required")(adm.post("/api/admin/x/settings", eps[0].body))
	if a, _ := xconfig.GetAccount(context.Background(), h.db.Conn, "1003"); !a.Enabled {
		t.Error("a refused request changed the account")
	}
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != before {
		t.Error("refused requests wrote audit rows")
	}
	t.Log(table.String())
}

func settingsBody(enabled, posts, reqs, days, qlen string) string {
	return `{"enabled":` + enabled + `,"max_posts":` + posts + `,"max_requests":` + reqs + `,"bootstrap_days":` + days +
		`,"max_query_length":` + qlen + `}`
}

// TestXSettings: every hard bound, defaults (null), type errors, missing and
// unknown keys; a refused body changes nothing; one audit row per change.
func TestXSettings(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	ctx := context.Background()
	stored := func() xconfig.Stored { s, _ := xconfig.LoadSettings(ctx, h.db.Conn); return s }
	audits := func() int { return h.count(`SELECT count(*) FROM admin_audit WHERE action = 'x.settings.update'`) }
	ok := []string{
		settingsBody("false", "10", "1", "1", "64"),
		settingsBody("true", "5000", "100", "7", "4096"),
		settingsBody("null", "null", "null", "null", "null"),
	}
	for i, b := range ok {
		check(t, "valid "+b, 200, "")(adm.post("/api/admin/x/settings", b))
		if audits() != i+1 {
			t.Errorf("after %s: %d audit rows", b, audits())
		}
	}
	if s := stored(); s.Enabled != nil || s.MaxPosts != nil || s.UpdatedAt == nil {
		t.Errorf("defaults not stored as NULL: %+v", s)
	}
	check(t, "no change", 409, "no_change")(adm.post("/api/admin/x/settings", ok[2]))
	h.sql(`UPDATE x_settings SET max_posts = 300`)
	before := stored()
	bad := map[string]string{
		settingsBody("null", "9", "null", "null", "null"):                                                                "max_posts",
		settingsBody("null", "5001", "null", "null", "null"):                                                             "max_posts",
		settingsBody("null", "null", "0", "null", "null"):                                                                "max_requests",
		settingsBody("null", "null", "101", "null", "null"):                                                              "max_requests",
		settingsBody("null", "null", "null", "0", "null"):                                                                "bootstrap_days",
		settingsBody("null", "null", "null", "8", "null"):                                                                "bootstrap_days",
		settingsBody("null", "null", "null", "null", "63"):                                                               "max_query_length",
		settingsBody("null", "null", "null", "null", "4097"):                                                             "max_query_length",
		settingsBody("null", "-1", "null", "null", "null"):                                                               "max_posts",
		settingsBody("null", `"100"`, "null", "null", "null"):                                                            "max_posts",
		settingsBody("null", "1e3", "null", "null", "null"):                                                              "max_posts",
		settingsBody("null", "100.5", "null", "null", "null"):                                                            "max_posts",
		settingsBody(`"yes"`, "null", "null", "null", "null"):                                                            "enabled",
		settingsBody("null", "99999999999999999999", "null", "null", "null"):                                             "max_posts",
		`{"enabled":null,"max_posts":100}`:                                                                               "bootstrap_days",
		`{"enabled":null,"max_posts":100,"max_requests":null,"bootstrap_days":null,"max_query_length":null,"token":"x"}`: "token",
	}
	for b, field := range bad {
		resp, body := adm.post("/api/admin/x/settings", b)
		var e struct {
			Error struct {
				Code   string            `json:"code"`
				Fields map[string]string `json:"fields"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if resp.StatusCode != 400 || e.Error.Code != "bad_setting" || e.Error.Fields[field] == "" {
			t.Errorf("%s: %d %s (want a %s error)", b, resp.StatusCode, body, field)
		}
	}
	// a body with one valid change and one invalid field changes nothing
	check(t, "mixed", 400, "bad_setting")(adm.post("/api/admin/x/settings", settingsBody("false", "200", "0", "null", "null")))
	if s := stored(); !s.Equal(before) || audits() != 3 {
		t.Errorf("a refused body changed something: %+v, %d audit rows", s, audits())
	}
	check(t, "not JSON", 400, "bad_request")(adm.post("/api/admin/x/settings", `{"enabled":`))
	// the audit row says what changed
	check(t, "change", 200, "")(adm.post("/api/admin/x/settings", settingsBody("false", "300", "null", "null", "null")))
	var d string
	_ = h.db.Conn.QueryRow(ctx, `SELECT details::text FROM admin_audit WHERE action = 'x.settings.update' ORDER BY id DESC LIMIT 1`).Scan(&d)
	if d != `{"enabled": {"to": false, "from": null}}` {
		t.Errorf("details %s", d)
	}
	// the page shows the cost of these settings: 300 posts x $0.005
	_, body := adm.do("GET", "/admin/x", "")
	for _, w := range []string{`id="x-worst-run">$1.50`, `id="x-worst-day">$36.00`, `id="x-worst-30">$1080.00`, `data-price="0.005"`, `data-runs="24"`} {
		if !strings.Contains(string(body), w) {
			t.Errorf("page lacks %s", w)
		}
	}
	// max_requests caps posts: 2 requests x 100 posts
	check(t, "few requests", 200, "")(adm.post("/api/admin/x/settings", settingsBody("false", "5000", "2", "null", "null")))
	if _, body := adm.do("GET", "/admin/x", ""); !strings.Contains(string(body), `id="x-worst-run">$1.00`) {
		t.Error("worst case ignores max_requests")
	}
}

// TestXAccounts: add / update / enable / disable / import including bad
// input, duplicates, a handle moved between ids, atomic import and dry run.
func TestXAccounts(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	ctx := context.Background()
	audits := func() int { return h.count(`SELECT count(*) FROM admin_audit WHERE action LIKE 'x.%'`) }
	get := func(id string) xconfig.Account { a, _ := xconfig.GetAccount(ctx, h.db.Conn, id); return a }
	check(t, "add", 200, "")(adm.post("/api/admin/x/accounts", `{"user_id":"1001","handle":"@alice","note":"first"}`))
	check(t, "add dup", 409, "exists")(adm.post("/api/admin/x/accounts", `{"user_id":"1001","handle":"other","note":""}`))
	for b, code := range map[string]string{
		`{"user_id":"01","handle":"a","note":""}`:                                "bad_user_id",
		`{"user_id":"12345678901234567890","handle":"a","note":""}`:              "bad_user_id",
		`{"user_id":"x","handle":"a","note":""}`:                                 "bad_user_id",
		`{"user_id":"5","handle":"a-b","note":""}`:                               "bad_handle",
		`{"user_id":"5","handle":"abcdefghijklmnop","note":""}`:                  "bad_handle",
		`{"user_id":"5","handle":"","note":""}`:                                  "bad_handle",
		`{"user_id":"5","handle":"a","note":"two\nlines"}`:                       "bad_note",
		`{"user_id":"5","handle":"a","note":"` + strings.Repeat("é", 501) + `"}`: "bad_note",
	} {
		check(t, "add "+b, 400, code)(adm.post("/api/admin/x/accounts", b))
	}
	if audits() != 1 || get("1001").Handle != "alice" || !get("1001").Enabled {
		t.Fatalf("after adds: %d %+v", audits(), get("1001"))
	}
	check(t, "update", 200, "")(adm.post("/api/admin/x/accounts/1001/update", `{"handle":"alice2","note":""}`))
	if a := get("1001"); a.Handle != "alice2" || a.Note != "" {
		t.Errorf("update: %+v", a)
	}
	check(t, "update same", 409, "no_change")(adm.post("/api/admin/x/accounts/1001/update", `{"handle":"alice2","note":""}`))
	check(t, "update absent", 404, "not_found")(adm.post("/api/admin/x/accounts/999/update", `{"handle":"x","note":""}`))
	check(t, "update bad", 400, "bad_handle")(adm.post("/api/admin/x/accounts/1001/update", `{"handle":"a b","note":""}`))
	check(t, "disable", 200, "")(adm.post("/api/admin/x/accounts/1001/disable", ``))
	check(t, "disable again", 409, "no_change")(adm.post("/api/admin/x/accounts/1001/disable", ``))
	check(t, "enable absent", 404, "not_found")(adm.post("/api/admin/x/accounts/999/enable", ``))
	if audits() != 3 {
		t.Errorf("audit rows: %d, want 3", audits())
	}
	imp := func(text string, dry bool) (*http.Response, []byte) {
		b, _ := json.Marshal(map[string]any{"text": text, "dry_run": dry})
		return adm.post("/api/admin/x/import", string(b))
	}
	// one bad line: nothing applied, every bad line reported
	resp, body := imp("1002 bob\n1003 bad-handle\n1001 alice3\n0004 x\n", false)
	var e struct {
		Error struct {
			Code  string `json:"code"`
			Lines []struct {
				Line int `json:"line"`
			} `json:"lines"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	if resp.StatusCode != 400 || e.Error.Code != "bad_import" || len(e.Error.Lines) != 2 || e.Error.Lines[0].Line != 2 || e.Error.Lines[1].Line != 4 {
		t.Errorf("bad import: %d %s", resp.StatusCode, body)
	}
	if get("1002").UserID != "" || get("1001").Handle != "alice2" {
		t.Error("a refused import applied something")
	}
	// dry run: counts, nothing written, no audit row
	text := "1002 bob # b\n1001 alice2\n1005 alice2 # the handle moved to a new id\n"
	resp, body = imp(text, true)
	var r struct {
		DryRun                       bool `json:"dry_run"`
		Inserted, Updated, Unchanged int
	}
	_ = json.Unmarshal(body, &r)
	if resp.StatusCode != 200 || !r.DryRun || r.Inserted != 2 || r.Unchanged != 1 || get("1002").UserID != "" || audits() != 3 {
		t.Errorf("dry run: %d %s, audits %d", resp.StatusCode, body, audits())
	}
	resp, body = imp(text, false)
	_ = json.Unmarshal(body, &r)
	if resp.StatusCode != 200 || r.DryRun || r.Inserted != 2 || r.Unchanged != 1 || audits() != 4 {
		t.Errorf("import: %d %s, audits %d", resp.StatusCode, body, audits())
	}
	// the import never re-enables 1001 and both ids carry the handle
	if a := get("1001"); a.Enabled || a.Handle != "alice2" || get("1005").Handle != "alice2" || get("1002").Note != "b" {
		t.Errorf("after import: %+v %+v", a, get("1005"))
	}
	var d string
	_ = h.db.Conn.QueryRow(ctx, `SELECT details::text FROM admin_audit WHERE action = 'x.accounts.import'`).Scan(&d)
	if d != `{"changed": ["inserted 1002 @bob", "inserted 1005 @alice2"], "updated": 0, "inserted": 2, "looked_up": 0, "unchanged": 1}` {
		t.Errorf("import details %s", d)
	}
	// re-importing the same text changes nothing and writes no row
	if resp, _ := imp(text, false); resp.StatusCode != 200 || audits() != 4 {
		t.Errorf("no-op import: %d, audits %d", resp.StatusCode, audits())
	}
	check(t, "huge import", 413, "too_large")(adm.post("/api/admin/x/import", `{"text":"`+strings.Repeat("1", 300<<10)+`","dry_run":true}`))
	var actions string
	_ = h.db.Conn.QueryRow(ctx, `SELECT string_agg(action || ':' || target_type || ':' || target_id, ' ' ORDER BY id) FROM admin_audit`).Scan(&actions)
	if actions != "x.account.add:x_account:1001 x.account.update:x_account:1001 x.account.disable:x_account:1001 x.accounts.import:x_account:import" {
		t.Errorf("audit: %s", actions)
	}
}

// TestXAuditRollback: when the audit insert fails, no X change is applied.
func TestXAuditRollback(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	ctx := context.Background()
	if err := xconfig.InsertAccount(ctx, h.db.Conn, "1001", "alice", ""); err != nil {
		t.Fatal(err)
	}
	state := func() string {
		var s string
		_ = h.db.Conn.QueryRow(ctx, `SELECT coalesce((SELECT string_agg(user_id || handle || note || enabled::text, ',' ORDER BY user_id) FROM x_accounts), '') ||
			'|' || coalesce((SELECT max_posts::text FROM x_settings), '-')`).Scan(&s)
		return s
	}
	h.sql(`CREATE FUNCTION test_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit fails'; END $$`)
	h.sql(`CREATE TRIGGER test_audit_fail BEFORE INSERT ON admin_audit FOR EACH ROW EXECUTE FUNCTION test_audit_fail()`)
	before := state()
	for _, e := range []struct{ path, body string }{
		{"/api/admin/x/settings", settingsBody("null", "100", "null", "null", "null")},
		{"/api/admin/x/accounts", `{"user_id":"1002","handle":"bob","note":""}`},
		{"/api/admin/x/accounts/1001/update", `{"handle":"alice2","note":""}`},
		{"/api/admin/x/accounts/1001/disable", ``},
		{"/api/admin/x/import", `{"text":"1003 carol\n","dry_run":false}`},
	} {
		check(t, e.path, 500, "internal")(adm.post(e.path, e.body))
	}
	if got := state(); got != before {
		t.Errorf("changes applied without their audit row:\n%s\n%s", before, got)
	}
}

// TestXHostileAndToken: tweet text, handles, notes, stop_info and the last
// error come out as text on a well-formed page; the bearer token (set in
// the environment) never appears in any response or log.
func TestXHostileAndToken(t *testing.T) {
	t.Setenv("NDAY_X_BEARER_TOKEN", fakeToken)
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")
	evil := `<script>alert(1)</script> "><img src=x onerror=alert(2)> ` + "‮RTL‬ ⁦iso ctl\x01 " + strings.Repeat("W", 3000)
	h.xFixture(evil+" CVE-2026-0001", `x"><b>x</b>`, `{"detail":`+jsonString(evil)+`}`, evil)
	h.sql(`UPDATE x_accounts SET note = $1 WHERE user_id = '1001'`, trunc(evil, 500))
	pages := []string{"/admin/x", "/admin/x?author=alice_sec", "/admin/x?cve=CVE-2026-0002", "/admin/x?author=%22%3E%3Cb%3E&cve=%3Cscript%3E&before=garbage",
		"/zh-hans/admin/x", "/admin/system"}
	var all strings.Builder
	for _, pg := range pages {
		resp, body := adm.do("GET", pg, "")
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d", pg, resp.StatusCode)
			continue
		}
		s := string(body)
		all.WriteString(s)
		for _, pr := range checkHTML(s, adminElems) {
			t.Errorf("%s: %s", pg, pr)
		}
		if strings.Contains(s, "<script>alert") || strings.Contains(s, "<img") || strings.Contains(s, "<b>x</b>") {
			t.Errorf("%s: markup injected", pg)
		}
	}
	_, body := adm.do("GET", "/admin/x", "")
	s := string(body)
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", `href="https://x.com/alice_sec" target="_blank" rel="noopener noreferrer nofollow"`,
		`href="https://x.com/alice_sec/status/1850000000000000000"`, `href="/vuln/CVE-2026-0002"`, "max_requests"} {
		if !strings.Contains(s, want) {
			t.Errorf("x page lacks %q", want)
		}
	}
	// last_run counts: kept_no_cve (stored, no CVE id) replaced dropped_no_cve
	for _, want := range []string{"<dt>kept: no CVE id yet (not shown anywhere)</dt><dd>100</dd>", "<dt>kept: names a CVE id</dt><dd>4</dd>"} {
		if !strings.Contains(s, want) {
			t.Errorf("x page lacks %q", want)
		}
	}
	if strings.Contains(s, "dropped: no CVE id") {
		t.Error("x page still shows dropped_no_cve")
	}
	// the invalid handle is text, never a link
	if strings.Contains(s, `href="https://x.com/x&#34;`) || strings.Contains(s, `https://x.com/x%22`) {
		t.Error("a link was built from an invalid handle")
	}
	// the token appears nowhere: pages, every endpoint, the logs
	for _, e := range []struct{ path, body string }{
		{"/api/admin/x/settings", settingsBody("null", "100", "null", "null", "null")},
		{"/api/admin/x/accounts", `{"user_id":"1003","handle":"carol","note":""}`},
		{"/api/admin/x/accounts/1003/update", `{"handle":"carol","note":"n"}`},
		{"/api/admin/x/accounts/1003/disable", ``},
		{"/api/admin/x/import", `{"text":"1004 dave\n","dry_run":true}`},
		{"/api/admin/x/settings", `{"bad":1}`},
	} {
		_, b := adm.post(e.path, e.body)
		all.Write(b)
	}
	for _, pg := range []string{"/admin", "/admin/moderation", "/admin/users", "/admin/audit"} {
		_, b := adm.do("GET", pg, "")
		all.Write(b)
	}
	_, b := mod.do("GET", "/admin/x", "")
	all.Write(b)
	if strings.Contains(all.String(), fakeToken) || strings.Contains(h.logs.String(), fakeToken) {
		t.Error("the bearer token reached a response or the logs")
	}
	if os.Getenv("NDAY_X_BEARER_TOKEN") != fakeToken {
		t.Error("test setup")
	}
}

// TestXSystemPage: the system page lists xposts (marked not public) for
// admins; the public Sources() is unchanged and moderators get a 404.
func TestXSystemPage(t *testing.T) {
	h := newHarness(t, hopt{})
	h.xFixture("CVE-2026-0001", "bob_sec", `null`, "")
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")
	_, body := adm.do("GET", "/admin/system", "")
	if s := string(body); !strings.Contains(s, "<tr><td>xposts <span class=\"adm-st hidden\">not public</span></td>") {
		t.Error("system page lacks xposts marked not public")
	}
	if resp, _ := mod.do("GET", "/admin/system", ""); resp.StatusCode != 404 {
		t.Errorf("moderator: %d", resp.StatusCode)
	}
	src, err := site.New(site.SingleConn(h.db.Conn)).Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range src.Collectors {
		if c.Name == "xposts" {
			t.Error("public Sources() shows xposts")
		}
	}
	cs, err := h.adm.Collectors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cs {
		names = append(names, fmt.Sprintf("%s:%v", c.Name, c.Public))
	}
	if strings.Join(names, " ") != "cvelist:true kev:true ghsa:true exploitdb:true metasploit:true nuclei:true nvd:true xposts:false" {
		t.Errorf("collectors: %v", names)
	}
}

// TestXStoreRechecksActor: the X write functions refuse an actor who is
// not (or no longer) an active admin, whatever the HTTP layer did.
func TestXStoreRechecksActor(t *testing.T) {
	h := newHarness(t, hopt{})
	mod := h.user("mia", "moderator")
	sadm := h.user("sue", "admin")
	h.suspend(sadm.id)
	ctx := context.Background()
	for _, actor := range []string{mod.id, sadm.id, "00000000-0000-0000-0000-000000000001"} {
		if err := h.adm.XAddAccount(ctx, actor, "1001", "alice", ""); err == nil {
			t.Errorf("%s added an account", actor)
		}
		if _, err := h.adm.XSaveSettings(ctx, actor, xconfig.Stored{}); err == nil {
			t.Errorf("%s saved settings", actor)
		}
	}
	if n := h.count(`SELECT count(*) FROM x_accounts`) + h.count(`SELECT count(*) FROM admin_audit`); n != 0 {
		t.Errorf("refused writes left %d rows", n)
	}
}
