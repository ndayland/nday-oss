package admin_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
)

// TestWebCannotTouchAdminsOrSelf: no endpoint and no parameter lets the web
// create, change, suspend or sign out an admin, or act on oneself; nothing
// is written for a refused request.
func TestWebCannotTouchAdminsOrSelf(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	other := h.user("lee", "admin")
	usr := h.user("tom", "user")
	mod := h.user("mia", "moderator")
	snapshot := func() string {
		var s string
		_ = h.db.Conn.QueryRow(context.Background(), `SELECT string_agg(id::text || role || status || coalesce(status_reason, '-'), ',' ORDER BY id) FROM users`).Scan(&s)
		return s
	}
	sessions := func(id string) int { return h.count(`SELECT count(*) FROM sessions WHERE user_id = $1`, id) }
	before, beforeSessions := snapshot(), sessions(other.id)
	for _, target := range []string{other.id, adm.id} {
		code := "protected"
		if target == adm.id {
			code = "self"
		}
		for _, c := range []struct{ act, body string }{
			{"suspend", `{"reason":"x","duration":"1d"}`}, {"suspend", `{"reason":"x","duration":"lifted"}`},
			{"unsuspend", ``}, {"role", `{"role":"user"}`}, {"role", `{"role":"moderator"}`}, {"signout-all", ``},
		} {
			check(t, c.act+" on "+code, 403, code)(adm.post("/api/admin/users/"+target+"/"+c.act, c.body))
			check(t, c.act+" on "+code+" (upper-case id)", 403, code)(adm.post("/api/admin/users/"+strings.ToUpper(target)+"/"+c.act, c.body))
		}
	}
	// the web never grants or names the admin role, on anyone
	for _, target := range []string{usr.id, mod.id, other.id, adm.id} {
		for _, body := range []string{`{"role":"admin"}`, `{"role":"Admin"}`, `{"role":"root"}`, `{"role":""}`, `{}`, `{"role":"moderator","role":"admin"}`} {
			resp, b := adm.post("/api/admin/users/"+target+"/role", body)
			if resp.StatusCode != 400 && resp.StatusCode != 403 {
				t.Errorf("role %s on %s: %d %s", body, target, resp.StatusCode, b)
			}
		}
	}
	// bad ids, bad bodies
	check(t, "not a uuid", 404, "not_found")(adm.post("/api/admin/users/kim/role", `{"role":"user"}`))
	check(t, "unknown user", 404, "not_found")(adm.post("/api/admin/users/00000000-0000-0000-0000-000000000001/role", `{"role":"moderator"}`))
	check(t, "no reason", 400, "bad_reason")(adm.post("/api/admin/users/"+usr.id+"/suspend", `{"reason":"  ‮ ","duration":"1d"}`))
	check(t, "long reason", 400, "bad_reason")(adm.post("/api/admin/users/"+usr.id+"/suspend", `{"reason":"`+strings.Repeat("é", 501)+`","duration":"1d"}`))
	check(t, "bad duration", 400, "bad_duration")(adm.post("/api/admin/users/"+usr.id+"/suspend", `{"reason":"x","duration":"2d"}`))
	check(t, "not suspended", 409, "no_change")(adm.post("/api/admin/users/"+usr.id+"/unsuspend", ``))
	check(t, "already a member", 409, "no_change")(adm.post("/api/admin/users/"+usr.id+"/role", `{"role":"user"}`))
	if got := snapshot(); got != before || sessions(other.id) != beforeSessions {
		t.Errorf("refused requests changed accounts:\n%s\n%s", before, got)
	}
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != 0 {
		t.Errorf("refused requests wrote %d audit rows", n)
	}

	// the store refuses the same things on its own (the HTTP layer is not the only gate)
	ctx := context.Background()
	for name, f := range map[string]func() error{
		"role on admin":   func() error { _, err := h.as.StaffSetRole(ctx, adm.id, other.id, "user"); return err },
		"role admin":      func() error { _, err := h.as.StaffSetRole(ctx, adm.id, usr.id, "admin"); return err },
		"suspend admin":   func() error { _, err := h.as.StaffSuspend(ctx, adm.id, other.id, nil, "x"); return err },
		"unsuspend admin": func() error { _, err := h.as.StaffUnsuspend(ctx, adm.id, other.id); return err },
		"sign out admin":  func() error { _, err := h.as.StaffSignOutAll(ctx, adm.id, other.id); return err },
		"self role":       func() error { _, err := h.as.StaffSetRole(ctx, mod.id, mod.id, "user"); return err },
		"moderator actor": func() error { _, err := h.as.StaffSetRole(ctx, mod.id, usr.id, "moderator"); return err },
		"member actor":    func() error { _, err := h.as.StaffSuspend(ctx, usr.id, mod.id, nil, "x"); return err },
		"self suspend":    func() error { _, err := h.as.StaffSuspend(ctx, adm.id, adm.id, nil, "x"); return err },
		"self sign out":   func() error { _, err := h.as.StaffSignOutAll(ctx, adm.id, adm.id); return err },
		"unknown target": func() error {
			_, err := h.as.StaffSuspend(ctx, adm.id, "00000000-0000-0000-0000-000000000001", nil, "x")
			return err
		},
		"suspended actor": func() error {
			h.suspend(other.id)
			defer h.sql(`UPDATE users SET status = 'active', status_reason = NULL WHERE id = $1`, other.id)
			_, err := h.as.StaffSuspend(ctx, other.id, usr.id, nil, "x")
			return err
		},
	} {
		err := f()
		if !errors.Is(err, auth.ErrProtected) && !errors.Is(err, auth.ErrSelf) && !errors.Is(err, auth.ErrNotAdmin) && !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("store %s: %v", name, err)
		}
	}
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != 0 {
		t.Errorf("refused store calls wrote %d audit rows", n)
	}
}

// TestActionsAndAudit: each successful action changes exactly what it says
// and writes exactly one audit row, with actor snapshot and client data.
func TestActionsAndAudit(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	target := h.browser()
	target.signIn("tom")
	n := func() int { return h.count(`SELECT count(*) FROM admin_audit`) }
	steps := []struct{ act, body, action string }{
		{"suspend", `{"reason":"  spam\twave  ","duration":"7d"}`, "user.suspend"},
		{"suspend", `{"reason":"longer","duration":"lifted"}`, "user.suspend"},
		{"unsuspend", ``, "user.unsuspend"},
		{"role", `{"role":"moderator"}`, "user.role"},
		{"role", `{"role":"user"}`, "user.role"},
		{"signout-all", ``, "user.signout_all"},
	}
	for i, s := range steps {
		resp, body := adm.post("/api/admin/users/"+target.id+"/"+s.act, s.body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", s.act, resp.StatusCode, body)
		}
		if got := n(); got != i+1 {
			t.Fatalf("after %s: %d audit rows, want %d", s.act, got, i+1)
		}
		var action, handle, role, src, addr, ray, label string
		var actor *string
		if err := h.db.Conn.QueryRow(context.Background(), `SELECT action, actor_id::text, actor_handle, actor_role, source, client_addr, cf_ray, target_label
			FROM admin_audit ORDER BY id DESC LIMIT 1`).Scan(&action, &actor, &handle, &role, &src, &addr, &ray, &label); err != nil {
			t.Fatal(err)
		}
		if action != s.action || actor == nil || *actor != adm.id || handle != "kim" || role != "admin" || src != "web" ||
			addr != "198.51.100.7" || ray != "8e0000test-SIN" || label != "tom" {
			t.Errorf("%s audit row: %s %v %s %s %s %s %s %s", s.act, action, actor, handle, role, src, addr, ray, label)
		}
	}
	var reason string
	_ = h.db.Conn.QueryRow(context.Background(), `SELECT reason FROM admin_audit WHERE action = 'user.suspend' ORDER BY id LIMIT 1`).Scan(&reason)
	if reason != "spam wave" {
		t.Errorf("stored reason %q", reason)
	}
	if h.count(`SELECT count(*) FROM sessions WHERE user_id = $1`, target.id) != 0 {
		t.Error("sign-out-everywhere left sessions")
	}
	// the signed-out target is really signed out
	if resp, body := target.do("GET", "/api/me", ""); resp.StatusCode != 200 || strings.Contains(string(body), `"signed_in":true`) {
		t.Errorf("target still signed in: %s", body)
	}
	check(t, "sign out with no sessions", 409, "no_change")(adm.post("/api/admin/users/"+target.id+"/signout-all", ``))
}

// TestRoleChangeAtomic: concurrent grants and revokes (and a CLI promotion
// to admin in the middle) never leave a state the audit log does not
// explain, and the web never touches the account once it is an admin.
func TestRoleChangeAtomic(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	target := h.user("tom", "user")
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, protected := 0, 0
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			role := "moderator"
			if i%2 == 1 {
				role = "user"
			}
			if i == 12 {
				if err := h.as.SetRole(ctx, target.id, "admin"); err != nil { // the CLI
					t.Error(err)
				}
				return
			}
			_, err := h.as.StaffSetRole(ctx, adm.id, target.id, role)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, auth.ErrProtected):
				protected++
			case errors.Is(err, auth.ErrNoChange):
			default:
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	var final string
	_ = h.db.Conn.QueryRow(ctx, `SELECT role FROM users WHERE id = $1`, target.id).Scan(&final)
	if final != "admin" {
		t.Errorf("final role %s, want admin (the CLI promotion is never undone by the web)", final)
	}
	// replay the audit log: every web row's "from" is the previous "to"
	rows, err := h.db.Conn.Query(ctx, `SELECT source, details->>'from', details->>'to' FROM admin_audit WHERE action = 'user.role' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	type step struct{ src, from, to string }
	steps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (step, error) {
		var s step
		return s, r.Scan(&s.src, &s.from, &s.to)
	})
	if err != nil {
		t.Fatal(err)
	}
	cur, web := "user", 0
	for _, s := range steps {
		if s.from != cur {
			t.Errorf("audit chain broken: %+v after %s", s, cur)
		}
		cur = s.to
		if s.src == "web" {
			web++
			if s.from == "admin" || s.to == "admin" {
				t.Errorf("web row touching admin: %+v", s)
			}
		}
	}
	if cur != final || web != ok {
		t.Errorf("audit replay ends at %s with %d web rows; table says %s, %d successes", cur, web, final, ok)
	}
	t.Logf("web successes %d, refused as protected %d, audit rows %d", ok, protected, len(steps))
}

// TestAuditAtomic: when the audit insert fails, no action is applied (web
// user actions, discussion moderation endpoints, and the store calls the
// CLI uses); the table itself refuses UPDATE, DELETE and TRUNCATE.
func TestAuditAtomic(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")
	target := h.user("tom", "user")
	c1 := h.comment(target.id, "first comment")
	c2 := h.comment(target.id, "second comment")
	h.sql(`UPDATE comments SET status = 'hidden', hidden_reason = 'x', hidden_at = now() WHERE id = $1`, c2)
	rep := h.report(c2, mod.id, "spam", nil)
	state := func() string {
		var s string
		_ = h.db.Conn.QueryRow(context.Background(), `SELECT
			(SELECT string_agg(role || status || coalesce(status_reason, '-'), ',' ORDER BY id) FROM users) ||
			(SELECT string_agg(status || rev, ',' ORDER BY id) FROM comments) ||
			(SELECT string_agg(coalesce(resolution, 'open'), ',' ORDER BY id) FROM comment_reports) ||
			(SELECT count(*)::text FROM sessions)`).Scan(&s)
		return s
	}
	h.sql(`CREATE FUNCTION test_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'audit insert fails (test)'; END $$`)
	h.sql(`CREATE TRIGGER test_audit_fail BEFORE INSERT ON admin_audit FOR EACH ROW EXECUTE FUNCTION test_audit_fail()`)
	before := state()
	web := []struct{ path, body string }{
		{"/api/admin/users/" + target.id + "/suspend", `{"reason":"x","duration":"1d"}`},
		{"/api/admin/users/" + target.id + "/role", `{"role":"moderator"}`},
		{"/api/admin/users/" + target.id + "/signout-all", ``},
		{"/api/discuss/comment/" + c1 + "/hide", `{"reason":"spam"}`},
		{"/api/discuss/comment/" + c2 + "/unhide", ``},
		{"/api/mod/reports/" + rep + "/resolve", `{"resolution":"dismissed"}`},
	}
	for _, w := range web {
		check(t, w.path+" with a failing audit insert", 500, "internal")(adm.post(w.path, w.body))
	}
	ctx := context.Background()
	if err := h.as.SetRole(ctx, target.id, "moderator"); err == nil {
		t.Error("CLI SetRole succeeded with a failing audit insert")
	}
	if err := h.as.Suspend(ctx, target.id, nil, "x"); err == nil {
		t.Error("CLI Suspend succeeded with a failing audit insert")
	}
	if got := state(); got != before {
		t.Errorf("an action was applied although its audit row failed:\n%s\n%s", before, got)
	}
	h.sql(`DROP TRIGGER test_audit_fail ON admin_audit`)
	for i, w := range web {
		check(t, w.path, 200, "")(adm.post(w.path, w.body))
		if n := h.count(`SELECT count(*) FROM admin_audit`); n != i+1 {
			t.Errorf("after %s: %d audit rows, want %d", w.path, n, i+1)
		}
	}
	var acts string
	_ = h.db.Conn.QueryRow(ctx, `SELECT string_agg(action || ':' || target_type || ':' || source, ' ' ORDER BY id) FROM admin_audit`).Scan(&acts)
	if acts != "user.suspend:user:web user.role:user:web user.signout_all:user:web comment.hide:comment:web comment.unhide:comment:web report.resolve:report:web" {
		t.Errorf("audit rows: %s", acts)
	}
	// append-only
	for _, q := range []string{`UPDATE admin_audit SET reason = 'edited'`, `DELETE FROM admin_audit`, `TRUNCATE admin_audit`} {
		if _, err := h.db.Conn.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: %v", q, err)
		}
	}
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != len(web) {
		t.Errorf("rows after the refused changes: %d", n)
	}
	// a deleted actor account does not touch the log (no foreign key)
	h.sql(`DELETE FROM users WHERE id = $1`, mod.id)
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != len(web) {
		t.Errorf("rows after deleting an account: %d", n)
	}
}
