package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"nday.land/nday/internal/xconfig"
)

// xCandFixture: allowlisted 1001 alice; candidates referred to by it:
// 3001 carol (quoted + mentioned), 3002 without a handle, 3003 with a
// stored handle that is not valid, 3004 fay (dismissed), 3005 dave, and
// 1001 alice itself (already listed: never shown).
func (h *harness) xCandFixture() {
	h.t.Helper()
	if err := xconfig.InsertAccount(context.Background(), h.db.Conn, "1001", "alice", ""); err != nil {
		h.t.Fatal(err)
	}
	for _, c := range []struct {
		id     string
		handle any
		status string
	}{{"3001", "carol", "pending"}, {"3002", nil, "pending"}, {"3003", "bad-handle<b>", "pending"}, {"3004", "fay", "dismissed"},
		{"3005", "dave", "pending"}, {"1001", "alice", "pending"}} {
		h.sql(`INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at, status) VALUES ($1, $2, '2026-11-01', '2026-11-10', $3)`,
			c.id, c.handle, c.status)
		h.sql(`INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at) VALUES ($1, '11', '1001', 'quoted', '2026-11-10')`, c.id)
	}
	h.sql(`INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at) VALUES ('3001', '12', '1001', 'mentioned', '2026-11-09')`)
}

// TestXCandidatesPage: the open candidates with their actions (no add
// without a valid handle), the dismissed ones behind a toggle, allowlisted
// ids never listed; handles are text and link only when valid.
func TestXCandidatesPage(t *testing.T) {
	h := newHarness(t, hopt{})
	h.xCandFixture()
	adm := h.user("kim", "admin")
	resp, body := adm.do("GET", "/admin/x", "")
	if resp.StatusCode != 200 {
		t.Fatalf("/admin/x: %d", resp.StatusCode)
	}
	s := string(body)
	for _, pr := range checkHTML(s, adminElems) {
		t.Error(pr)
	}
	_, sec, _ := strings.Cut(s, `id="candidates"`)
	sec, _, _ = strings.Cut(sec, "</section>")
	open, dismissed, ok := strings.Cut(sec, "<details")
	if !ok {
		t.Fatalf("no dismissed toggle:\n%s", sec)
	}
	for _, w := range []string{`data-cand="3001"`, `<a href="https://x.com/carol" target="_blank" rel="noopener noreferrer nofollow">@carol</a>`,
		`data-act="xcadd" data-x="3001"`, `data-act="xcdismiss" data-x="3001"`, "mentioned · quoted",
		`data-cand="3002"`, `data-act="xcdismiss" data-x="3002"`, `data-cand="3003"`, `data-act="xcadd" data-x="3005"`} {
		if !strings.Contains(open, w) {
			t.Errorf("open list lacks %q", w)
		}
	}
	for _, w := range []string{`data-act="xcadd" data-x="3002"`, `data-act="xcadd" data-x="3003"`, "bad-handle", `data-cand="1001"`,
		`data-cand="3004"`, "xcrestore"} {
		if strings.Contains(open, w) {
			t.Errorf("open list has %q", w)
		}
	}
	for _, w := range []string{"dismissed (1)", `data-cand="3004"`, `data-act="xcrestore" data-x="3004"`} {
		if !strings.Contains(dismissed, w) {
			t.Errorf("dismissed list lacks %q", w)
		}
	}
	if strings.Contains(dismissed, "xcadd") || strings.Contains(dismissed, "xcdismiss") {
		t.Error("dismissed list offers add or dismiss")
	}
	// the open list's first row is the most referred-to (carol: 2 refs)
	if i, j := strings.Index(open, `data-cand="3001"`), strings.Index(open, `data-cand="3005"`); i < 0 || j < 0 || i > j {
		t.Errorf("order: 3001 at %d, 3005 at %d", i, j)
	}
	if _, body := adm.do("GET", "/zh-hans/admin/x", ""); !strings.Contains(string(body), "加入白名单") {
		t.Error("zh-hans: no candidate button")
	}
}

// TestXCandidateActions: add / dismiss / restore behind the same checks as
// every X action, their refusals, the rows and audit they write, and the
// open list after an add.
func TestXCandidateActions(t *testing.T) {
	h := newHarness(t, hopt{})
	h.xCandFixture()
	ctx := context.Background()
	anon := h.browser()
	user := h.user("pat", "user")
	mod := h.user("mia", "moderator")
	adm := h.user("kim", "admin")
	audits := func() int { return h.count(`SELECT count(*) FROM admin_audit`) }
	listed := func(id string) bool { _, err := xconfig.GetAccount(ctx, h.db.Conn, id); return err == nil }

	// refused before anything is read or written
	p := "/api/admin/x/candidates/3001/add"
	for _, c := range []struct {
		what   string
		b      *browser
		status int
		code   string
	}{{"signed out", anon, 401, "not_signed_in"}, {"user", user, 404, "not_found"}, {"moderator", mod, 403, "forbidden"}} {
		for _, verb := range []string{"add", "dismiss", "restore"} {
			check(t, c.what+" "+verb, c.status, c.code)(c.b.post("/api/admin/x/candidates/3004/"+verb, ""))
		}
		check(t, c.what, c.status, c.code)(c.b.post(p, ""))
	}
	check(t, "GET", 405, "method_not_allowed")(adm.do("GET", p, ""))
	check(t, "no CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", ""))
	check(t, "bad CSRF", 403, "csrf")(adm.post(p, "", "X-CSRF-Token", flip(adm.csrf)))
	check(t, "cross-site", 403, "cross_site")(adm.post(p, "", "Sec-Fetch-Site", "cross-site"))
	for _, bad := range []string{"03001", "0", "x", "12345678901234567890", "3001%20"} {
		check(t, "bad id "+bad, 404, "not_found")(adm.post("/api/admin/x/candidates/"+bad+"/add", ""))
	}
	check(t, "unknown verb", 404, "not_found")(adm.post("/api/admin/x/candidates/3001/promote", ""))
	check(t, "body", 400, "bad_request")(adm.post(p, `{"handle":"mallory"}`))
	if audits() != 0 || listed("3001") {
		t.Fatal("a refused request wrote something")
	}

	// refusals of the store
	check(t, "no handle", 422, "no_handle")(adm.post("/api/admin/x/candidates/3002/add", ""))
	check(t, "invalid handle", 422, "no_handle")(adm.post("/api/admin/x/candidates/3003/add", ""))
	check(t, "absent", 404, "not_found")(adm.post("/api/admin/x/candidates/9999/add", ""))
	check(t, "already listed", 409, "exists")(adm.post("/api/admin/x/candidates/1001/add", ""))
	if audits() != 0 || listed("3002") || listed("3003") {
		t.Fatal("a refused add wrote something")
	}

	// add: x_accounts row (enabled, stored handle), x.account.add, gone from the open list
	resp, body := adm.post(p, "")
	var r struct {
		OK     bool   `json:"ok"`
		Result string `json:"result"`
	}
	_ = json.Unmarshal(body, &r)
	if resp.StatusCode != 200 || !r.OK || r.Result != "added" || !strings.Contains(string(body), `"handle":"carol"`) {
		t.Fatalf("add: %d %s", resp.StatusCode, body)
	}
	if a, err := xconfig.GetAccount(ctx, h.db.Conn, "3001"); err != nil || a.Handle != "carol" || !a.Enabled || a.Note != "" {
		t.Errorf("listed: %+v %v", a, err)
	}
	var row string
	_ = h.db.Conn.QueryRow(ctx, `SELECT action || ' ' || target_type || '/' || target_id || ' ' || target_label || ' ' || details::text || ' ' || actor_handle
		FROM admin_audit ORDER BY id DESC LIMIT 1`).Scan(&row)
	if want := `x.account.add x_account/3001 @carol {"note": "", "handle": "carol", "lookup": false, "user_id": "3001", "candidate": true} kim`; row != want {
		t.Errorf("audit:\n%s\nwant\n%s", row, want)
	}
	check(t, "add again", 409, "exists")(adm.post(p, ""))
	if audits() != 1 {
		t.Errorf("audit rows: %d", audits())
	}
	_, page := adm.do("GET", "/admin/x", "")
	if strings.Contains(string(page), `data-cand="3001"`) {
		t.Error("an added candidate is still listed")
	}
	if n, _ := xconfig.CountCandidates(ctx, h.db.Conn, ""); n != 3 { // 3002, 3003, 3005
		t.Errorf("open candidates: %d", n)
	}

	// dismiss / restore: x.candidate.*, 409 no_change on a repeat
	check(t, "dismiss", 200, "")(adm.post("/api/admin/x/candidates/3002/dismiss", ""))
	check(t, "dismiss again", 409, "no_change")(adm.post("/api/admin/x/candidates/3002/dismiss", ""))
	check(t, "dismiss absent", 404, "not_found")(adm.post("/api/admin/x/candidates/9999/dismiss", ""))
	_, page = adm.do("GET", "/admin/x", "")
	if !strings.Contains(string(page), `data-act="xcrestore" data-x="3002"`) || !strings.Contains(string(page), "dismissed (2)") {
		t.Error("dismissed candidate not under the toggle")
	}
	check(t, "restore", 200, "")(adm.post("/api/admin/x/candidates/3002/restore", ""))
	check(t, "restore again", 409, "no_change")(adm.post("/api/admin/x/candidates/3002/restore", ""))
	check(t, "dismiss with label", 200, "")(adm.post("/api/admin/x/candidates/3005/dismiss", ""))
	var actions string
	_ = h.db.Conn.QueryRow(ctx, `SELECT string_agg(action || ':' || target_type || ':' || target_id || ':' || coalesce(target_label, '-'), ' ' ORDER BY id) FROM admin_audit`).Scan(&actions)
	if want := "x.account.add:x_account:3001:@carol x.candidate.dismiss:x_account:3002:- x.candidate.restore:x_account:3002:- x.candidate.dismiss:x_account:3005:@dave"; actions != want {
		t.Errorf("audit:\n%s\nwant\n%s", actions, want)
	}
	// the audit page names the new actions
	_, ap := adm.do("GET", "/admin/audit?action=x_candidate_dismiss", "")
	if !strings.Contains(string(ap), "dismissed an X candidate") {
		t.Error("audit page lacks the dismiss label")
	}

	// a failing audit insert rolls the change back
	h.sql(`CREATE FUNCTION test_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit fails'; END $$`)
	h.sql(`CREATE TRIGGER test_audit_fail BEFORE INSERT ON admin_audit FOR EACH ROW EXECUTE FUNCTION test_audit_fail()`)
	check(t, "add, audit fails", 500, "internal")(adm.post("/api/admin/x/candidates/3004/add", ""))
	check(t, "restore, audit fails", 500, "internal")(adm.post("/api/admin/x/candidates/3004/restore", ""))
	var st string
	_ = h.db.Conn.QueryRow(ctx, `SELECT status FROM x_account_candidate WHERE user_id = '3004'`).Scan(&st)
	if listed("3004") || st != "dismissed" {
		t.Errorf("applied without its audit row: listed %v, status %s", listed("3004"), st)
	}
}
