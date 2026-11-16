package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/web"
)

func TestHandles(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	a, b := h.browser(), h.browser()
	a.login(auth.GitHub, acct("ha"), "")
	b.login(auth.GitHub, acct("hb"), "")
	if a.me().User.Handle != nil {
		t.Fatal("handle derived from provider")
	}
	set := func(br *browser, handle string) (int, string) {
		resp, body := br.post("/account/handle", `{"handle":"`+handle+`"}`)
		return resp.StatusCode, errCode(t, body)
	}
	for _, c := range []struct {
		h    string
		st   int
		code string
	}{
		{"ab", 400, "invalid_handle"}, {"-alice", 400, "invalid_handle"}, {"al ice", 400, "invalid_handle"},
		{"Admin", 409, "handle_reserved"}, {"zh-hans", 409, "handle_reserved"}, {"settings", 409, "handle_reserved"},
		{"Alice_1", 200, ""},
	} {
		if st, code := set(a, c.h); st != c.st || code != c.code {
			t.Errorf("%q: %d %s", c.h, st, code)
		}
	}
	m := a.me()
	if *m.User.Handle != "Alice_1" || m.User.HandleChangeableAt == nil {
		t.Fatalf("%+v", m.User)
	}
	if st, code := set(b, "ALICE_1"); st != 409 || code != "handle_taken" {
		t.Errorf("case-insensitive uniqueness: %d %s", st, code)
	}
	if st, _ := set(a, "alice_1"); st != 200 || *a.me().User.Handle != "alice_1" {
		t.Error("case-only change")
	}
	if st, code := set(a, "alice_2"); st != 409 || code != "handle_change_too_soon" {
		t.Errorf("30-day rule: %d %s", st, code)
	}
	h.clock.Advance(auth.HandleChangeInterval + time.Minute)
	a.login(auth.GitHub, acct("ha"), "") // sessions would have idled out
	b.login(auth.GitHub, acct("hb"), "")
	if st, _ := set(a, "alice_2"); st != 200 {
		t.Fatal("change after 30 days")
	}
	// the old name is held: nobody else may take it, the previous owner may
	if st, code := set(b, "alice_1"); st != 409 || code != "handle_taken" {
		t.Errorf("held name taken: %d %s", st, code)
	}
	if h.count(`SELECT count(*) FROM namespaces WHERE name = 'alice_1' AND kind = 'held'`) != 1 {
		t.Error("not held")
	}
	h.clock.Advance(auth.HandleChangeInterval + time.Minute)
	a.login(auth.GitHub, acct("ha"), "")
	b.login(auth.GitHub, acct("hb"), "")
	if st, _ := set(a, "Alice_1"); st != 200 {
		t.Error("previous owner reclaims held name")
	}
	// one namespace for users (and later organisations)
	if h.count(`SELECT count(*) FROM namespaces WHERE kind = 'user'`) != 1 {
		t.Error("namespace rows")
	}
	// the DB itself refuses a user handle pointing at a held or missing namespace
	_, err := h.db.Conn.Exec(context.Background(), `UPDATE users SET handle = 'zzz', handle_key = 'zzz' WHERE handle IS NULL`)
	if err == nil {
		t.Error("handle without namespace row accepted by the schema")
	}
	// GC frees expired holds
	h.clock.Advance(91 * 24 * time.Hour)
	if r, err := h.store.GC(context.Background(), h.cfg.SessionIdle); err != nil || r.Names != 1 {
		t.Errorf("gc %+v %v", r, err)
	}
}

func TestRolesStatusAndRequire(t *testing.T) {
	var svc *auth.Service
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, register: func(h *harness, srv *web.Server) {
		svc = h.svc
		echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := auth.CurrentUser(r)
			if u == nil {
				_, _ = w.Write([]byte("anon"))
				return
			}
			_, _ = w.Write([]byte(u.Role + ":" + u.ID))
		})
		srv.Handle("/feature/load", svc.Load(echo))
		srv.Handle("/feature/user", svc.RequireUser(echo))
		srv.Handle("/feature/write", svc.RequireActive(echo))
		srv.Handle("/feature/mod", svc.RequireRole(auth.RoleModerator)(echo))
	}})
	b := h.browser()
	anon := h.browser()
	if _, body := anon.do("GET", "/feature/load", ""); string(body) != "anon" {
		t.Error("CurrentUser of anonymous request")
	}
	if resp, _ := anon.do("GET", "/feature/user", ""); resp.StatusCode != 401 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("RequireUser anon")
	}
	b.login(auth.GitHub, acct("r"), "")
	id := b.me().User.ID
	if _, body := b.do("GET", "/feature/user", ""); string(body) != "user:"+id {
		t.Errorf("RequireUser: %s", body)
	}
	// writes through RequireActive need same-origin + CSRF
	if resp, _ := b.do("POST", "/feature/write", "", "Origin", origin); resp.StatusCode != 403 {
		t.Error("RequireActive POST without CSRF")
	}
	if resp, _ := b.post("/feature/write", ""); resp.StatusCode != 200 {
		t.Error("RequireActive POST")
	}
	if resp, _ := b.do("GET", "/feature/mod", ""); resp.StatusCode != 403 {
		t.Error("RequireRole as user")
	}
	ctx := context.Background()
	if err := h.store.SetRole(ctx, id, auth.RoleModerator); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetRole(ctx, id, "god"); err == nil {
		t.Error("bad role accepted")
	}
	if _, body := b.do("GET", "/feature/mod", ""); string(body) != "moderator:"+id {
		t.Errorf("RequireRole: %s", body)
	}
	// suspension: can read, sign in, sign out, delete; cannot write
	until := h.clock.Now().Add(7 * 24 * time.Hour)
	if err := h.store.Suspend(ctx, id, &until, "spam"); err != nil {
		t.Fatal(err)
	}
	m := b.me()
	if m.User.Status != "suspended" || m.User.StatusReason == nil || *m.User.StatusReason != "spam" || m.User.SuspendedUntil == nil {
		t.Errorf("me %+v", m.User)
	}
	if resp, body := b.post("/feature/write", ""); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Error("suspended user wrote")
	}
	if resp, _ := b.do("GET", "/feature/mod", ""); resp.StatusCode != 403 {
		t.Error("suspended moderator")
	}
	if resp, _ := b.post("/auth/signout", ""); resp.StatusCode != 200 {
		t.Error("suspended sign-out")
	}
	b.login(auth.GitHub, acct("r"), "")
	if !b.me().SignedIn {
		t.Error("suspended sign-in")
	}
	// elapsed suspension counts as active, and GC normalises it
	h.clock.Advance(8 * 24 * time.Hour)
	if resp, _ := b.post("/feature/write", ""); resp.StatusCode != 200 {
		t.Error("elapsed suspension")
	}
	if r, _ := h.store.GC(ctx, h.cfg.SessionIdle); r.Unsuspended != 1 {
		t.Errorf("gc unsuspend %+v", r)
	}
	if err := h.store.Suspend(ctx, id, nil, ""); err != nil {
		t.Fatal(err)
	}
	b.reauth(auth.GitHub, "r") // deleting needs a recent sign-in (reauth ticket)
	if resp, _ := b.post("/account/delete", `{"confirm":true}`); resp.StatusCode != 200 {
		t.Error("suspended user cannot delete")
	}
	// nil service (feature disabled) is safe
	var none *auth.Service
	rec := httptestRecorder()
	none.RequireUser(http.NotFoundHandler()).ServeHTTP(rec, mustReq("/x"))
	if rec.Code != 404 {
		t.Error("nil service")
	}
}

func TestTerms(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, terms: "2026-11-01"})
	b := h.browser()
	b.login(auth.GitHub, acct("t"), "")
	m := b.me()
	if m.User.Terms.AcceptedVersion != nil || m.User.Terms.UpToDate || *m.User.Terms.CurrentVersion != "2026-11-01" {
		t.Fatalf("first sign-in auto-accepted: %+v", m.User.Terms)
	}
	if resp, body := b.post("/account/accept-terms", `{"version":"2025-01-01"}`); resp.StatusCode != 409 ||
		errCode(t, body) != "terms_version_mismatch" {
		t.Error("old version accepted")
	}
	if resp, _ := b.post("/account/accept-terms", `{"version":"2026-11-01"}`); resp.StatusCode != 200 {
		t.Fatal("accept")
	}
	if m := b.me(); !m.User.Terms.UpToDate || *m.User.Terms.AcceptedVersion != "2026-11-01" {
		t.Errorf("%+v", m.User.Terms)
	}
}

func TestHousekeeping(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b1, b2 := h.browser(), h.browser()
	b1.login(auth.GitHub, acct("g1"), "")
	h.clock.Advance(10 * 24 * time.Hour)
	b2.login(auth.GitHub, acct("g2"), "")
	h.clock.Advance(5 * 24 * time.Hour) // b1 idle 15 d (> 14), b2 idle 5 d
	r, err := h.store.GC(context.Background(), h.cfg.SessionIdle)
	if err != nil || r.Sessions != 1 || r.Flows != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if !b2.me().SignedIn || h.count(`SELECT count(*) FROM sessions`) != 1 || h.count(`SELECT count(*) FROM auth_flow_used`) != 0 {
		t.Error("gc removed too much / too little")
	}
	// the in-process loop runs once immediately and stops with its context
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.svc.RunHousekeeping(ctx, time.Hour); close(done) }()
	cancel()
	<-done
	if strings.Contains(h.logs.String(), "housekeeping failed") {
		t.Error(h.logs.String())
	}
}

func httptestRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func mustReq(path string) *http.Request { return httptest.NewRequest("GET", path, nil) }
