package auth_test

// Hardening regression tests for the auth package: suspension limits,
// suspensions kept across account deletion, rate limiter behaviour, cache
// headers, last-method rule, passkey counters, recent sign-in, host checks,
// impersonation handles, weak secrets, session lookup limits, passkey caps,
// the iss parameter and link tickets.

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/webauthn"
	"nday.land/nday/internal/auth/webauthn/softauthn"
	"nday.land/nday/internal/web"
)

// ticket asks for a single-use start ticket and returns the start URL.
func (b *browser) ticket(provider, intent, ret string) (string, *http.Response, []byte) {
	b.h.t.Helper()
	resp, body := b.post("/auth/"+provider+"/ticket", fmt.Sprintf(`{"intent":%q,"return":%q}`, intent, ret))
	var t struct {
		StartURL string `json:"start_url"`
	}
	_ = json.Unmarshal(body, &t)
	return t.StartURL, resp, body
}

// linkVia links provider/acct to the signed-in account through a ticket and
// returns the final Location of the callback.
func (b *browser) linkVia(provider string, sub string) string {
	b.h.t.Helper()
	su, resp, body := b.ticket(provider, "link", "/")
	if resp.StatusCode != 200 || su == "" {
		b.h.t.Fatalf("ticket %s: %d %s", provider, resp.StatusCode, body)
	}
	au := b.startURL(su)
	cb, err := b.h.idp.Approve(provider, au, acct(sub))
	if err != nil {
		b.h.t.Fatal(err)
	}
	return b.callback(cb)
}

// startURL follows a start URL (path + query) and returns the provider URL.
func (b *browser) startURL(path string) string {
	b.h.t.Helper()
	resp, body := b.do("GET", path, "", "Sec-Fetch-Site", "same-origin")
	if resp.StatusCode != http.StatusFound {
		b.h.t.Fatalf("start %s: %d %s", path, resp.StatusCode, body)
	}
	return resp.Header.Get("Location")
}

// A suspended user cannot change the handle, link identities or add
// passkeys; the documented allowed list keeps working.
func TestSuspendedUserBuiltinWrites(t *testing.T) {
	h := newHarness(t, harnessOpt{terms: "2026-11-01"})
	b := h.browser()
	b.login(auth.GitHub, acct("susp"), "")
	_, resp, body := b.addPasskey(webauthn.AlgES256, "before", softauthn.Opts{})
	if resp.StatusCode != 200 {
		t.Fatalf("passkey before suspension: %d %s", resp.StatusCode, body)
	}
	if loc := b.linkVia(auth.Apple, "susp-apple"); loc != "/?auth=linked" {
		t.Fatalf("link before suspension: %s", loc)
	}
	id := b.me().User.ID
	if err := h.store.Suspend(context.Background(), id, nil, "abuse"); err != nil {
		t.Fatal(err)
	}
	if resp, body := b.post("/account/handle", `{"handle":"Evader_1"}`); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Errorf("suspended POST /account/handle -> %d %s", resp.StatusCode, body)
	}
	if resp, body := b.post("/auth/passkey/register/begin", ""); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Errorf("suspended passkey register/begin -> %d %s", resp.StatusCode, body)
	}
	if resp, body := b.post("/auth/passkey/register/finish", "{}"); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Errorf("suspended passkey register/finish -> %d %s", resp.StatusCode, body)
	}
	if _, resp, body := b.ticket(auth.Google, "link", "/"); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Errorf("suspended link ticket -> %d %s", resp.StatusCode, body)
	}
	// unlinking would free the identity to sign up again as an active account
	if resp, body := b.post("/auth/apple/unlink", ""); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Errorf("suspended unlink -> %d %s", resp.StatusCode, body)
	}
	// starting a link with the CSRF token in the URL must not work either
	if r, _ := b.do("GET", "/auth/google/start?intent=link&csrf="+url.QueryEscape(b.me().CSRFToken), ""); r.StatusCode == http.StatusFound {
		au := r.Header.Get("Location")
		cb, _ := h.idp.Approve(auth.Google, au, acct("susp-google"))
		t.Errorf("suspended link via csrf URL -> %s", b.callback(cb))
	}
	if n := h.count(`SELECT count(*) FROM identities WHERE user_id = $1`, id); n != 2 {
		t.Errorf("identities = %d, want 2 (github + apple)", n)
	}
	if n := h.count(`SELECT count(*) FROM passkeys WHERE user_id = $1`, id); n != 1 {
		t.Errorf("passkeys = %d, want 1", n)
	}
	// allowed while suspended
	pid := b.me().User.Passkeys[0].ID
	for _, c := range []struct{ path, body string }{
		{"/account/locale", `{"locale":"ja"}`},
		{"/account/accept-terms", `{"version":"2026-11-01"}`},
		{"/account/passkeys/" + pid + "/rename", `{"name":"renamed"}`},
		{"/account/passkeys/" + pid + "/delete", ""},
	} {
		if resp, body := b.post(c.path, c.body); resp.StatusCode != 200 {
			t.Errorf("suspended %s -> %d %s (must stay allowed)", c.path, resp.StatusCode, body)
		}
	}
	if m := b.me(); m.User.Status != "suspended" {
		t.Errorf("/api/me status %q", m.User.Status)
	}
	if resp, _ := b.clone().post("/auth/signout-all", ""); resp.StatusCode != 200 {
		t.Error("suspended signout-all")
	}
	b.login(auth.GitHub, acct("susp"), "")
	if resp, _ := b.post("/account/delete", `{"confirm":true}`); resp.StatusCode != 200 {
		t.Error("suspended delete")
	}
}

// deleteAccount deletes the signed-in account (the session must be recent).
func (b *browser) deleteAccount() {
	b.h.t.Helper()
	if resp, body := b.post("/account/delete", `{"confirm":true}`); resp.StatusCode != 200 {
		b.h.t.Fatalf("delete: %d %s", resp.StatusCode, body)
	}
}

// Deleting a suspended account and signing in again with the same identity
// gives a new account that is suspended until the same time. The kept row
// is used up, so lifting that suspension sticks.
func TestSuspensionSurvivesDeletion(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	ctx := context.Background()
	b := h.browser()
	b.login(auth.GitHub, acct("evader"), "")
	if loc := b.linkVia(auth.Apple, "evader-apple"); loc != "/?auth=linked" {
		t.Fatalf("link: %s", loc)
	}
	old := b.me().User.ID
	until := h.clock.Now().Add(30 * 24 * time.Hour)
	if err := h.store.Suspend(ctx, old, &until, "spam"); err != nil {
		t.Fatal(err)
	}
	b.deleteAccount()
	if n := h.count(`SELECT count(*) FROM suspended_identities`); n != 2 {
		t.Fatalf("suspended_identities = %d, want 2 (github + apple)", n)
	}

	b2 := h.browser()
	b2.login(auth.GitHub, acct("evader"), "")
	u := b2.me().User
	if u.ID == old {
		t.Fatal("the deleted account came back")
	}
	if u.Status != auth.StatusSuspended || u.SuspendedUntil == nil {
		t.Fatalf("new account: status %q until %v, want suspended", u.Status, u.SuspendedUntil)
	}
	if got, _ := time.Parse(time.RFC3339, *u.SuspendedUntil); !got.Equal(until) {
		t.Errorf("suspended_until %s, want %s", *u.SuspendedUntil, until.Format(time.RFC3339))
	}
	if u.StatusReason != nil {
		t.Errorf("status_reason %q carried over", *u.StatusReason)
	}
	if resp, body := b2.post("/account/handle", `{"handle":"evader_2"}`); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Errorf("suspended POST /account/handle -> %d %s", resp.StatusCode, body)
	}
	if n := h.count(`SELECT count(*) FROM suspended_identities WHERE provider = 'github'`); n != 0 {
		t.Errorf("github row not used up: %d", n)
	}

	// lifted the usual way: later sign-ins don't bring the suspension back
	if err := h.store.Unsuspend(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	b3 := h.browser()
	b3.login(auth.GitHub, acct("evader"), "")
	if m := b3.me().User; m.ID != u.ID || m.Status != auth.StatusActive {
		t.Errorf("after unsuspend: id %s status %q, want %s active", m.ID, m.Status, u.ID)
	}
}

// Deleting an active account keeps nothing, and the next sign-in is a
// plain active account.
func TestDeleteActiveKeepsNoSuspension(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	b := h.browser()
	b.login(auth.GitHub, acct("clean"), "")
	old := b.me().User.ID
	b.deleteAccount()
	if n := h.count(`SELECT count(*) FROM suspended_identities`); n != 0 {
		t.Errorf("suspended_identities = %d after deleting an active account", n)
	}
	b2 := h.browser()
	b2.login(auth.GitHub, acct("clean"), "")
	if u := b2.me().User; u.ID == old || u.Status != auth.StatusActive {
		t.Errorf("re-sign-in: id %s status %q", u.ID, u.Status)
	}
}

// A timed suspension that has ended by the next sign-in is ignored, and
// housekeeping removes its row.
func TestEndedSuspensionIgnored(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	ctx := context.Background()
	b := h.browser()
	b.login(auth.GitHub, acct("short"), "")
	until := h.clock.Now().Add(time.Hour)
	if err := h.store.Suspend(ctx, b.me().User.ID, &until, ""); err != nil {
		t.Fatal(err)
	}
	b.deleteAccount()
	if n := h.count(`SELECT count(*) FROM suspended_identities`); n != 1 {
		t.Fatalf("suspended_identities = %d, want 1", n)
	}
	h.clock.Advance(2 * time.Hour)
	b2 := h.browser()
	b2.login(auth.GitHub, acct("short"), "")
	if u := b2.me().User; u.Status != auth.StatusActive || u.SuspendedUntil != nil {
		t.Errorf("after the end: status %q until %v, want active", u.Status, u.SuspendedUntil)
	}
	r, err := h.store.GC(ctx, h.cfg.SessionIdle)
	if err != nil || r.SuspendedIdentities != 1 {
		t.Errorf("gc %+v %v, want SuspendedIdentities 1", r, err)
	}
	if n := h.count(`SELECT count(*) FROM suspended_identities`); n != 0 {
		t.Errorf("suspended_identities = %d after gc", n)
	}
}

// While the kept suspension is live, the identity can't be linked to
// another account either (say a fresh passkey-only one).
func TestSuspendedIdentityCannotBeLinked(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	ctx := context.Background()
	b := h.browser()
	b.login(auth.GitHub, acct("hopper"), "")
	if err := h.store.Suspend(ctx, b.me().User.ID, nil, "abuse"); err != nil {
		t.Fatal(err)
	}
	b.deleteAccount()

	other := h.browser()
	other.login(auth.Google, acct("fresh"), "")
	id := other.me().User.ID
	if loc := other.linkVia(auth.GitHub, "hopper"); loc != "/?auth=conflict" {
		t.Errorf("link of a suspended identity -> %s, want /?auth=conflict", loc)
	}
	if n := h.count(`SELECT count(*) FROM identities WHERE provider = 'github'`); n != 0 {
		t.Errorf("github identities = %d, want 0", n)
	}
	if n := h.count(`SELECT count(*) FROM suspended_identities`); n != 1 {
		t.Errorf("suspended_identities = %d, a refused link must not use the row up", n)
	}
	if u := other.me().User; u.ID != id || u.Status != auth.StatusActive {
		t.Errorf("linking account changed: %s %q", u.ID, u.Status)
	}
	if !strings.Contains(h.logs.String(), "reason=identity_suspended") {
		t.Error("no identity_suspended in the log")
	}
}

// The kept row holds an HMAC under its own key derived from the server
// secret, not the subject or a plain hash of it.
func TestSuspendedIdentityHashed(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	ctx := context.Background()
	a := acct("hashed")
	sub := a.Subject
	b := h.browser()
	b.login(auth.GitHub, a, "")
	if err := h.store.Suspend(ctx, b.me().User.ID, nil, ""); err != nil {
		t.Fatal(err)
	}
	b.deleteAccount()
	var hash []byte
	if err := h.db.Conn.QueryRow(ctx, `SELECT subject_hash FROM suspended_identities WHERE provider = 'github'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	plain := sha256.Sum256([]byte(sub))
	plainP := sha256.Sum256([]byte("github\x00" + sub))
	if len(hash) != 32 || bytes.Contains(hash, []byte(sub)) || bytes.Equal(hash, plain[:]) || bytes.Equal(hash, plainP[:]) {
		t.Errorf("subject_hash %x is not a keyed hash of %q", hash, sub)
	}
	key, err := hkdf.Key(sha256.New, h.cfg.Secrets[0], nil, "nday auth suspended identity v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("suspended identity:github\x00" + sub))
	if !hmac.Equal(hash, m.Sum(nil)) {
		t.Errorf("subject_hash %x is not the HMAC under the derived key", hash)
	}
	if n := h.count(`SELECT count(*) FROM suspended_identities WHERE position($1::bytea IN subject_hash) > 0`, []byte(sub)); n != 0 {
		t.Error("raw subject stored")
	}
}

// A full rate-limit table neither fails closed for a new client nor
// sweeps the whole table on every call.
func TestRateLimiterFullTable(t *testing.T) {
	l := auth.NewRateLimiter(10, 6*time.Second)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.Now = func() time.Time { return now }
	for i := 0; i < l.MaxKeys; i++ {
		l.Allow(fmt.Sprintf("2001:db8:%x:%x::/64", i>>16, i&0xffff))
	}
	if ok, _ := l.Allow("203.0.113.1"); !ok {
		t.Fatal("brand-new client refused by a full table")
	}
	st := time.Now()
	for i := 0; i < 2000; i++ {
		l.Allow(fmt.Sprintf("198.51.100.%d", i%250))
		l.Allow(fmt.Sprintf("2001:db8:ffff:%x::/64", i))
	}
	if d := time.Since(st); d > 500*time.Millisecond {
		t.Errorf("4000 Allow() calls on a full table took %v (O(n) per call?)", d)
	}
	// the limit itself still holds for a client that stays active
	for i := 0; i < 10; i++ {
		l.Allow("192.0.2.77")
	}
	if ok, _ := l.Allow("192.0.2.77"); ok {
		t.Error("burst exceeded on a full table")
	}
}

func BenchmarkRateLimiterFullTable(b *testing.B) {
	l := auth.NewRateLimiter(10, 6*time.Second)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.Now = func() time.Time { return now }
	for i := 0; i < l.MaxKeys; i++ {
		l.Allow(fmt.Sprintf("2001:db8:%x:%x::/64", i>>16, i&0xffff))
	}
	keys := make([]string, 4096)
	for i := range keys {
		keys[i] = fmt.Sprintf("2001:db9:%x::/64", i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Allow(keys[i%len(keys)]) // mostly brand-new keys: evictions
	}
}

// Load/RequireUser force no-store (and drop validators, add Vary:
// Cookie) on the final response even when the handler asks for public
// caching.
func TestNoStoreCannotBeOverridden(t *testing.T) {
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Cache-Control", "public, max-age=60")
		hd.Set("ETag", `W/"abc"`)
		hd.Set("Last-Modified", "Wed, 11 Nov 2026 10:00:00 GMT")
		if r.Header.Get("If-None-Match") == `W/"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.URL.Query().Has("panic") {
			panic("boom")
		}
		who := "anon"
		if u := auth.CurrentUser(r); u != nil {
			who = u.ID
		}
		_, _ = io.WriteString(w, "hello "+who)
	})
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, register: func(h *harness, srv *web.Server) {
		srv.Handle("GET /fix/load", h.svc.Load(page))
		srv.Handle("GET /fix/user", h.svc.RequireUser(page))
	}})
	b := h.browser()
	b.login(auth.GitHub, acct("cache"), "")
	check := func(name string, resp *http.Response) {
		t.Helper()
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q", name, cc)
		}
		if resp.Header.Get("ETag") != "" || resp.Header.Get("Last-Modified") != "" {
			t.Errorf("%s: validators kept: %q %q", name, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"))
		}
		if !strings.Contains(resp.Header.Get("Vary"), "Cookie") {
			t.Errorf("%s: Vary %q", name, resp.Header.Get("Vary"))
		}
	}
	for _, p := range []string{"/fix/load", "/fix/user"} {
		resp, body := b.do("GET", p, "")
		check(p, resp)
		if !strings.HasPrefix(string(body), "hello ") || strings.HasSuffix(string(body), "anon") {
			t.Errorf("%s: %s", p, body)
		}
		// a conditional request with a session is answered in full, never 304
		resp, _ = b.do("GET", p, "", "If-None-Match", `W/"abc"`)
		check(p+" (If-None-Match)", resp)
		if resp.StatusCode != 200 {
			t.Errorf("%s conditional: %d", p, resp.StatusCode)
		}
		resp, _ = b.do("GET", p+"?panic=1", "")
		check(p+" (panic)", resp)
	}
	// a stale session cookie still means "personal": no-store
	stale := h.browser()
	stale.jar[auth.SessionCookie] = &http.Cookie{Name: auth.SessionCookie, Value: strings.Repeat("A", 43)}
	resp, _ := stale.do("GET", "/fix/load", "")
	check("stale cookie", resp)
	// no cookie at all: the handler's own caching stands (the page is anonymous)
	resp, _ = h.browser().do("GET", "/fix/load", "")
	if resp.Header.Get("Cache-Control") != "public, max-age=60" {
		t.Errorf("anonymous Load page: %q", resp.Header.Get("Cache-Control"))
	}
}

// Only usable methods count for the last-method rule.
func TestLastUsableMethod(t *testing.T) {
	t.Run("passkeys off", func(t *testing.T) {
		h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, noPasskey: true})
		b := h.browser()
		b.login(auth.GitHub, acct("lock"), "")
		id := b.me().User.ID
		if _, err := h.db.Conn.Exec(context.Background(), `INSERT INTO passkeys (user_id, credential_id, public_key, algorithm,
			backup_eligible, backed_up, name) VALUES ($1, '\x01', '\x01', -7, true, true, 'old')`, id); err != nil {
			t.Fatal(err)
		}
		if resp, body := b.post("/auth/github/unlink", ""); resp.StatusCode != 409 || errCode(t, body) != "last_usable_method" {
			t.Errorf("unlink github with only an unusable passkey left -> %d %s", resp.StatusCode, body)
		}
		if n := h.count(`SELECT count(*) FROM identities WHERE user_id = $1`, id); n != 1 {
			t.Errorf("identities left %d", n)
		}
	})
	t.Run("provider disabled", func(t *testing.T) {
		h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
		b := h.browser()
		b.login(auth.GitHub, acct("lock2"), "")
		id := b.me().User.ID
		if _, err := h.db.Conn.Exec(context.Background(), `INSERT INTO identities (provider, subject, user_id) VALUES ('x','123',$1)`, id); err != nil {
			t.Fatal(err)
		}
		if resp, body := b.post("/auth/github/unlink", ""); resp.StatusCode != 409 || errCode(t, body) != "last_usable_method" {
			t.Errorf("unlink github with only a disabled X identity left -> %d %s", resp.StatusCode, body)
		}
		// passkey + disabled X: the passkey is the last usable method
		_, resp, _ := b.addPasskey(webauthn.AlgES256, "k", softauthn.Opts{})
		if resp.StatusCode != 200 {
			t.Fatal("add passkey")
		}
		if resp, body := b.post("/auth/github/unlink", ""); resp.StatusCode != 200 {
			t.Fatalf("unlink github with a passkey left -> %d %s", resp.StatusCode, body)
		}
		pid := b.me().User.Passkeys[0].ID
		if resp, body := b.post("/account/passkeys/"+pid+"/delete", ""); resp.StatusCode != 409 || errCode(t, body) != "last_usable_method" {
			t.Errorf("delete passkey with only a disabled X identity left -> %d %s", resp.StatusCode, body)
		}
	})
}

// Two assertions with the same counter, finished concurrently, cannot
// both sign in; 0/0 (synced passkeys) keeps working.
func TestCounterAtomic(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("clone"), "")
	one := uint32(1)
	c, resp, _ := b.addPasskey(webauthn.AlgES256, "k", softauthn.Opts{SignCount: &one})
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	bothOK := 0
	for round := 0; round < 20; round++ {
		cnt := uint32(10 + round)
		type prepared struct {
			cookie *http.Cookie
			body   string
		}
		var ps []prepared
		for i := 0; i < 2; i++ {
			br := h.browser()
			opts := br.options(br.anonPost("/auth/passkey/login/begin", ""))
			ps = append(ps, prepared{br.jar[auth.CeremonyCookie], softauthn.JSON(c.Assert(opts.PublicKey.Challenge, softauthn.Opts{SignCount: &cnt}))})
		}
		codes := make([]int, 2)
		var wg sync.WaitGroup
		for i, p := range ps {
			wg.Add(1)
			go func(i int, p prepared) {
				defer wg.Done()
				req, _ := http.NewRequest("POST", h.ts.URL+"/auth/passkey/login/finish", strings.NewReader(p.body))
				req.Host = publicHost
				req.AddCookie(&http.Cookie{Name: p.cookie.Name, Value: p.cookie.Value})
				req.Header.Set("Origin", origin)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("CF-Connecting-IP", "198.51.100.9")
				r, err := http.DefaultClient.Do(req)
				if err == nil {
					codes[i] = r.StatusCode
					r.Body.Close()
				}
			}(i, p)
		}
		wg.Wait()
		if codes[0] == 200 && codes[1] == 200 {
			bothOK++
		}
	}
	if bothOK != 0 {
		t.Errorf("20 rounds of two same-counter assertions in parallel: both signed in %d times", bothOK)
	}
	// synced passkey: counter 0 forever
	z, resp, _ := b.addPasskey(webauthn.AlgES256, "synced", softauthn.Opts{})
	if resp.StatusCode != 200 {
		t.Fatal("synced passkey")
	}
	for i := 0; i < 3; i++ {
		if resp, body := h.browser().passkeyLogin(z, softauthn.Opts{}); resp.StatusCode != 200 {
			t.Fatalf("0/0 login %d: %d %s", i, resp.StatusCode, body)
		}
	}
}

// Registering a passkey, linking and deleting the account need a recent
// sign-in; /api/me says until when the session qualifies.
func TestRecentSignInForSensitiveActions(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	b := h.browser()
	b.login(auth.GitHub, acct("recent"), "")
	var m struct {
		Session *struct {
			CreatedAt         time.Time `json:"created_at"`
			RecentSignIn      bool      `json:"recent_sign_in"`
			RecentSignInUntil time.Time `json:"recent_sign_in_until"`
		} `json:"session"`
	}
	getMe := func() {
		t.Helper()
		_, body := b.do("GET", "/api/me", "")
		m.Session = nil
		if err := json.Unmarshal(body, &m); err != nil || m.Session == nil {
			t.Fatalf("/api/me session: %v %s", err, body)
		}
	}
	getMe()
	if !m.Session.RecentSignIn || !m.Session.RecentSignInUntil.Equal(m.Session.CreatedAt.Add(15*time.Minute)) {
		t.Errorf("fresh session: %+v", *m.Session)
	}
	// a passkey to delete later (allowed without a recent sign-in)
	_, resp, _ := b.addPasskey(webauthn.AlgES256, "k", softauthn.Opts{})
	if resp.StatusCode != 200 {
		t.Fatal("add passkey on a fresh session")
	}
	if loc := b.linkVia(auth.Apple, "recent-apple"); loc != "/?auth=linked" {
		t.Fatalf("link on a fresh session: %s", loc)
	}
	h.clock.Advance(16 * time.Minute)
	getMe()
	if m.Session.RecentSignIn {
		t.Error("16 min old session reported as recent")
	}
	if resp, body := b.post("/auth/passkey/register/begin", ""); resp.StatusCode != 403 || errCode(t, body) != "reauth_required" {
		t.Errorf("register/begin on an old session -> %d %s", resp.StatusCode, body)
	}
	if _, resp, body := b.ticket(auth.Google, "link", "/"); resp.StatusCode != 403 || errCode(t, body) != "reauth_required" {
		t.Errorf("link ticket on an old session -> %d %s", resp.StatusCode, body)
	}
	if resp, body := b.post("/account/delete", `{"confirm":true}`); resp.StatusCode != 403 || errCode(t, body) != "reauth_required" {
		t.Errorf("delete on an old session -> %d %s", resp.StatusCode, body)
	}
	// removing access does not need it
	pid := b.me().User.Passkeys[0].ID
	if resp, body := b.post("/account/passkeys/"+pid+"/delete", ""); resp.StatusCode != 200 {
		t.Errorf("passkey delete on an old session -> %d %s", resp.StatusCode, body)
	}
	if resp, body := b.post("/auth/apple/unlink", ""); resp.StatusCode != 200 {
		t.Errorf("unlink on an old session -> %d %s", resp.StatusCode, body)
	}
	// signing in again (same account) from our page, with a reauth ticket,
	// gives a fresh session
	if loc := b.reauth(auth.GitHub, "recent"); loc != "/?auth=ok" {
		t.Fatalf("re-sign-in: %s", loc)
	}
	getMe()
	if !m.Session.RecentSignIn {
		t.Error("re-sign-in did not refresh")
	}
	if _, resp, body := b.addPasskey(webauthn.AlgES256, "k2", softauthn.Opts{}); resp.StatusCode != 200 {
		t.Errorf("register after re-sign-in -> %d %s", resp.StatusCode, body)
	}
	// a link started inside the window but finished after it: refused
	h.clock.Advance(14 * time.Minute)
	su, resp, _ := b.ticket(auth.Google, "link", "/")
	if resp.StatusCode != 200 {
		t.Fatal("ticket")
	}
	au := b.startURL(su)
	h.clock.Advance(2 * time.Minute)
	cb, _ := h.idp.Approve(auth.Google, au, acct("recent-google"))
	if loc := b.callback(cb); loc != "/?auth=reauth_required" {
		t.Errorf("link finished after the window: %s", loc)
	}
}

// Auth routes answer only for the configured host.
func TestAuthRoutesCheckHost(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	for _, p := range []string{"/api/me", "/auth/github/start", "/account/handle", "/auth/signout"} {
		resp, body := b.do("GET", p, "", "Host", "evil.example")
		if resp.StatusCode != http.StatusMisdirectedRequest || errCode(t, body) != "wrong_host" {
			t.Errorf("%s with a foreign Host -> %d %s", p, resp.StatusCode, body)
		}
	}
	if resp, _ := b.do("GET", "/api/me", "", "Host", "www.nday.land:443"); resp.StatusCode != 200 {
		t.Errorf("explicit default port refused: %d", resp.StatusCode)
	}
	// public pages are not affected
	if resp, _ := b.do("GET", "/", "", "Host", "evil.example"); resp.StatusCode != 200 {
		t.Errorf("public page with another Host: %d", resp.StatusCode)
	}
}

// Look-alike and combined impersonation handles are reserved; ordinary
// names are not; display names cannot impersonate the site.
func TestImpersonationRules(t *testing.T) {
	for _, hnd := range []string{"admin_", "admin-", "Admin1", "adm1n", "4dmin", "nday-official", "nday_team", "ndayofficial",
		"0fficial", "root_", "support-team", "security-team", "moderator1", "ghost_", "nd4y", "nday-news", "official_nday",
		"staff-admin", "team-nday", "Support_Staff", "0fficial-team", "the-nday", "nday1"} {
		if _, err := auth.CanonicalHandle(hnd); err != auth.ErrHandleReserved {
			t.Errorf("handle %q accepted (%v)", hnd, err)
		}
	}
	for _, hnd := range []string{"sunday", "monday", "Sunday_Funday", "adminton", "teamwork", "teammate", "modern", "moderate",
		"officially", "supporter", "rootbeer", "systematic", "staffordshire", "securityresearcher", "ada_1",
		"grace-hopper", "bob123", "t0m", "linus", "abby", "ndaq", "standup"} {
		if _, err := auth.CanonicalHandle(hnd); err != nil {
			t.Errorf("ordinary handle %q refused: %v", hnd, err)
		}
	}
	h := newHarness(t, harnessOpt{providers: []string{auth.Google, auth.GitHub}, signup: true})
	b := h.browser()
	a := acct("imp")
	a.Name = "nday 官方 Admin"
	au := b.start(auth.Google, "")
	cb, _ := h.idp.Approve(auth.Google, au, a)
	b.callback(cb)
	m := b.me()
	if m.User == nil {
		t.Fatalf("impersonating provider name: /api/me has no user (sign-in failed?)")
	}
	if m.User.DisplayName != nil {
		t.Errorf("impersonating provider name kept: %q", *m.User.DisplayName)
	}
	c := h.browser()
	a2 := acct("ok")
	a2.Name = "Sunday Team Rocket"
	au = c.start(auth.Google, "")
	cb, _ = h.idp.Approve(auth.Google, au, a2)
	c.callback(cb)
	m2 := c.me()
	if m2.User == nil {
		t.Fatalf("ordinary display name: /api/me has no user (sign-in failed?)")
	}
	if m := m2; m.User.DisplayName == nil || *m.User.DisplayName != "Sunday Team Rocket" {
		t.Errorf("ordinary display name changed: %v", m.User.DisplayName)
	}
	if resp, body := h.browser().anonPost("/auth/passkey/signup/begin", `{"display_name":"NDAY Support"}`); resp.StatusCode != 400 ||
		errCode(t, body) != "display_name_reserved" {
		t.Errorf("signup with an impersonating display name -> %d %s", resp.StatusCode, body)
	}
}

// Low-entropy server secrets are refused; openssl output is accepted.
func TestWeakSecret(t *testing.T) {
	env := func(secret string) func(string) (string, bool) {
		m := map[string]string{"NDAY_PUBLIC_URL": "https://www.nday.land", "NDAY_AUTH_GITHUB_CLIENT_ID": "id",
			"NDAY_AUTH_GITHUB_CLIENT_SECRET": "s", "NDAY_AUTH_SECRET": secret}
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	for _, s := range []string{strings.Repeat("a", 44), strings.Repeat("A", 64), strings.Repeat("abcd", 16),
		strings.Repeat("0", 64), strings.Repeat("ab", 32)} {
		cfg, err := auth.FromEnv(env(s))
		if err == nil || cfg != nil || !strings.Contains(err.Error(), "NDAY_AUTH_SECRET") || strings.Contains(err.Error(), s) {
			t.Errorf("weak secret %.8s… accepted or badly reported: %v", s, err)
		}
	}
	for i := 0; i < 300; i++ {
		for _, s := range []string{opensslBase64(48), opensslHex(32)} {
			if _, err := auth.FromEnv(env(s)); err != nil {
				t.Fatalf("openssl-style secret refused: %v", err)
			}
		}
	}
}

// /api/me and the signed-in endpoints are rate limited per client;
// forged session cookies never reach the database; session lookups have a
// concurrency cap.
func TestSessionLookups(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("flood"), "")
	// forged, well-formed cookies: no database call
	before := h.dbc.calls.Load()
	for i := 0; i < 50; i++ {
		f := h.browser()
		f.ip = fmt.Sprintf("192.0.2.%d", i)
		f.jar[auth.SessionCookie] = &http.Cookie{Name: auth.SessionCookie, Value: opensslB64URL(32 + 16*(i%2))}
		if resp, body := f.do("GET", "/api/me", ""); resp.StatusCode != 200 || !strings.Contains(string(body), `"signed_in":false`) {
			t.Fatalf("forged cookie: %d %s", resp.StatusCode, body)
		}
	}
	if n := h.dbc.calls.Load() - before; n != 0 {
		t.Errorf("50 forged session cookies caused %d database calls", n)
	}
	// concurrency cap on lookups of (replayed) real cookies
	h.dbc.delay.Store(int64(20 * time.Millisecond))
	h.dbc.maxIn.Store(0)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := b.clone()
			c.ip = fmt.Sprintf("203.0.113.%d", i)
			req, _ := http.NewRequest("GET", h.ts.URL+"/api/me", nil)
			req.Host = publicHost
			req.Header.Set("CF-Connecting-IP", c.ip)
			req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: c.jar[auth.SessionCookie].Value})
			if r, err := http.DefaultClient.Do(req); err == nil {
				r.Body.Close()
			}
		}(i)
	}
	wg.Wait()
	h.dbc.delay.Store(0)
	if m := h.dbc.maxIn.Load(); m > 2 {
		t.Errorf("%d session lookups ran at once (cap 2)", m)
	}
	// per-client limit on /api/me
	limited := 0
	for i := 0; i < 1200; i++ { // the harness limiter allows a burst of 1000
		resp, body := b.do("GET", "/api/me", "")
		if resp.StatusCode == 429 && errCode(t, body) == "rate_limited" {
			limited++
		}
	}
	if limited == 0 {
		t.Error("1200 /api/me requests from one client in no time: never rate limited")
	}
}

// Passkeys per user are capped; passkey-only sign-up has its own,
// stricter per-client limit.
func TestPasskeyCaps(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, signup: true, strictSignup: true})
	b := h.browser()
	b.login(auth.GitHub, acct("many"), "")
	for i := 0; i < 20; i++ {
		if _, resp, body := b.addPasskey(webauthn.AlgES256, fmt.Sprint("k", i), softauthn.Opts{}); resp.StatusCode != 200 {
			t.Fatalf("passkey %d: %d %s", i, resp.StatusCode, body)
		}
	}
	if resp, body := b.post("/auth/passkey/register/begin", ""); resp.StatusCode != 409 || errCode(t, body) != "passkey_limit" {
		t.Errorf("21st passkey begin -> %d %s", resp.StatusCode, body)
	}
	// sign-up: the same client cannot create accounts in a burst
	s := h.browser()
	s.ip = "198.51.100.200"
	created := 0
	for i := 0; i < 6; i++ {
		opts := s.options(s.anonPost("/auth/passkey/signup/begin", ""))
		c := softauthn.NewCredential(webauthn.AlgES256, "nday.land", b64d(opts.PublicKey.User.ID))
		resp, _ := s.anonPost("/auth/passkey/signup/finish", softauthn.JSON(c.Register(opts.PublicKey.Challenge, softauthn.Opts{})))
		if resp.StatusCode == 200 {
			created++
		}
		delete(s.jar, auth.SessionCookie)
	}
	if created > 3 {
		t.Errorf("one client created %d passkey-only accounts in a burst", created)
	}
	t.Run("daily cap", func(t *testing.T) {
		h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, signup: true, signupDaily: 2})
		codes := []string{}
		for i := 0; i < 3; i++ {
			s := h.browser()
			s.ip = fmt.Sprintf("198.51.100.%d", 50+i)
			opts := s.options(s.anonPost("/auth/passkey/signup/begin", ""))
			c := softauthn.NewCredential(webauthn.AlgES256, "nday.land", b64d(opts.PublicKey.User.ID))
			resp, body := s.anonPost("/auth/passkey/signup/finish", softauthn.JSON(c.Register(opts.PublicKey.Challenge, softauthn.Opts{})))
			codes = append(codes, fmt.Sprint(resp.StatusCode, errCode(t, body)))
		}
		if strings.Join(codes, ",") != "200,200,429signup_limit" {
			t.Errorf("daily cap 2: %v", codes)
		}
		// a failed ceremony does not use up the quota
		h.clock.Advance(24 * time.Hour)
		s := h.browser()
		s.anonPost("/auth/passkey/signup/begin", "")
		if resp, _ := s.anonPost("/auth/passkey/signup/finish", `{"id":"AA","type":"public-key","response":{}}`); resp.StatusCode != 400 {
			t.Fatalf("bad finish %d", resp.StatusCode)
		}
		for i := 0; i < 2; i++ {
			s := h.browser()
			opts := s.options(s.anonPost("/auth/passkey/signup/begin", ""))
			c := softauthn.NewCredential(webauthn.AlgES256, "nday.land", b64d(opts.PublicKey.User.ID))
			if resp, body := s.anonPost("/auth/passkey/signup/finish", softauthn.JSON(c.Register(opts.PublicKey.Challenge, softauthn.Opts{}))); resp.StatusCode != 200 {
				t.Errorf("next day sign-up %d: %d %s", i, resp.StatusCode, body)
			}
		}
	})
}

// When the provider declares RFC 9207 support the iss parameter is
// required; otherwise its absence is accepted.
func TestIssParameter(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.Google, auth.Apple}, issParam: true})
	for _, p := range []string{auth.Google, auth.Apple} {
		if loc := h.browser().login(p, acct("iss-"+p), ""); loc != "/welcome?auth=ok" { // a new account
			t.Errorf("%s with iss: %s", p, loc)
		}
	}
	h.idp.OmitIss = true
	for _, p := range []string{auth.Google, auth.Apple} {
		if loc := h.browser().login(p, acct("iss-"+p), ""); loc != "/?auth=error" {
			t.Errorf("%s declared iss support but the callback had none: %s", p, loc)
		}
	}
	if !strings.Contains(h.logs.String(), "reason=iss_missing") {
		t.Error("no reason=iss_missing in the logs")
	}
	// not declared: absence accepted (the default fake, as Google/Apple today)
	t.Run("not declared", func(t *testing.T) {
		h2 := newHarness(t, harnessOpt{providers: []string{auth.Google}})
		if loc := h2.browser().login(auth.Google, acct("noiss"), ""); loc != "/welcome?auth=ok" {
			t.Errorf("no declaration, no iss: %s", loc)
		}
	})
}

// An explicit default port is normalised away.
func TestDefaultPort(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.nday.land:443":  "https://www.nday.land",
		"https://www.nday.land:":     "https://www.nday.land",
		"http://localhost:80":        "http://localhost",
		"http://[::1]:80":            "http://[::1]",
		"https://www.nday.land:8443": "https://www.nday.land:8443",
		"http://localhost:8080":      "http://localhost:8080",
	} {
		if got, err := auth.ParsePublicOrigin(in); err != nil || got != want {
			t.Errorf("ParsePublicOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	m := map[string]string{"NDAY_PUBLIC_URL": "https://www.nday.land:443", "NDAY_AUTH_GITHUB_CLIENT_ID": "id",
		"NDAY_AUTH_GITHUB_CLIENT_SECRET": "s", "NDAY_AUTH_SECRET": opensslBase64(48),
		"NDAY_AUTH_ORIGINS": "https://www.nday.land:443,https://nday.land:443"}
	cfg, err := auth.FromEnv(func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicOrigin != "https://www.nday.land" || strings.Join(cfg.Origins, ",") != "https://www.nday.land,https://nday.land" {
		t.Errorf("%q %q", cfg.PublicOrigin, cfg.Origins)
	}
}

// Linking starts with a single-use, short-lived ticket from a CSRF
// protected POST; the CSRF token never appears in a URL.
func TestLinkTicket(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	b := h.browser()
	b.login(auth.GitHub, acct("tk"), "")
	tok := b.me().CSRFToken
	if resp, _ := b.do("GET", "/auth/google/start?intent=link&csrf="+url.QueryEscape(tok), ""); resp.StatusCode == http.StatusFound {
		t.Error("link start with the CSRF token in the URL still works")
	}
	if resp, body := b.do("GET", "/auth/google/start?intent=link", ""); resp.StatusCode != 403 || errCode(t, body) != "ticket_required" {
		t.Errorf("link start without ticket -> %d %s", resp.StatusCode, body)
	}
	// the ticket endpoint needs the session's CSRF token
	if resp, body := b.do("POST", "/auth/google/ticket", `{"intent":"link"}`, "Origin", origin, "Content-Type", "application/json"); resp.StatusCode != 403 || errCode(t, body) != "csrf" {
		t.Errorf("ticket without CSRF -> %d %s", resp.StatusCode, body)
	}
	su, resp, body := b.ticket(auth.Google, "link", "/vuln/CVE-2026-1")
	if resp.StatusCode != 200 || !strings.HasPrefix(su, "/auth/google/start?") || strings.Contains(su, tok) {
		t.Fatalf("ticket -> %d %s", resp.StatusCode, body)
	}
	// cross-site navigation with a valid ticket: refused (ticket not consumed)
	if resp, _ := b.do("GET", su, "", "Sec-Fetch-Site", "cross-site"); resp.StatusCode != 403 {
		t.Errorf("cross-site ticket start -> %d", resp.StatusCode)
	}
	// another browser (other session) cannot use it
	if resp, body := h.browser().do("GET", su, ""); resp.StatusCode != 403 || errCode(t, body) != "ticket_invalid" {
		t.Errorf("ticket in another browser -> %d %s", resp.StatusCode, body)
	}
	au := b.startURL(su)
	// single use
	if resp, body := b.do("GET", su, ""); resp.StatusCode != 403 || errCode(t, body) != "ticket_invalid" {
		t.Errorf("ticket reuse -> %d %s", resp.StatusCode, body)
	}
	cb, _ := h.idp.Approve(auth.Google, au, acct("tk-google"))
	if loc := b.callback(cb); loc != "/vuln/CVE-2026-1?auth=linked" {
		t.Errorf("link via ticket: %s", loc)
	}
	// short-lived
	su, _, _ = b.ticket(auth.Apple, "link", "/")
	h.clock.Advance(3 * time.Minute)
	if resp, body := b.do("GET", su, ""); resp.StatusCode != 403 || errCode(t, body) != "ticket_invalid" {
		t.Errorf("expired ticket -> %d %s", resp.StatusCode, body)
	}
	// a ticket is bound to its provider
	su, _, _ = b.ticket(auth.Apple, "link", "/")
	if resp, body := b.do("GET", strings.Replace(su, "/auth/apple/", "/auth/x/", 1), ""); resp.StatusCode != 403 || errCode(t, body) != "ticket_invalid" {
		t.Errorf("ticket for another provider -> %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(h.logs.String(), "ticket=REDACTED") {
		t.Error("ticket not redacted in the access log")
	}
}

// A signed-in browser that starts a plain sign-in ends on the same
// account or is refused; switching needs a switch ticket.
func TestNoSilentAccountSwitch(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	b := h.browser()
	b.login(auth.GitHub, acct("me"), "")
	if loc := b.linkVia(auth.Google, "me-google"); loc != "/?auth=linked" {
		t.Fatal(loc)
	}
	me := b.me().User.ID
	users := h.count(`SELECT count(*) FROM users`)
	// cross-site navigation to start with an identity of nobody / somebody else
	for _, sub := range []string{"stranger", "me-x"} {
		au := b.start(auth.X, "")
		cb, _ := h.idp.Approve(auth.X, au, acct(sub))
		if loc := b.callback(cb); loc != "/?auth=signed_in_as_other" {
			t.Errorf("silent switch to %s: %s", sub, loc)
		}
		if m := b.me(); !m.SignedIn || m.User.ID != me {
			t.Errorf("session replaced (%s)", sub)
		}
	}
	if n := h.count(`SELECT count(*) FROM users`); n != users {
		t.Errorf("users %d -> %d: an account was created", users, n)
	}
	// the same account through another linked identity: fine
	if loc := b.login(auth.Google, acct("me-google"), ""); loc != "/?auth=ok" || b.me().User.ID != me {
		t.Errorf("same account: %s", loc)
	}
	// explicit switch through a ticket
	su, resp, body := b.ticket(auth.X, "switch", "/")
	if resp.StatusCode != 200 {
		t.Fatalf("switch ticket %d %s", resp.StatusCode, body)
	}
	au := b.startURL(su)
	cb, _ := h.idp.Approve(auth.X, au, acct("other"))
	if loc := b.callback(cb); loc != "/welcome?auth=ok" || b.me().User.ID == me { // switched to a new account
		t.Errorf("switch: %s", loc)
	}
}

// GET routes of the auth surface do not accept HEAD.
func TestNoHeadOnAuthRoutes(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	for _, p := range []string{"/auth/github/start", "/auth/github/callback?code=x&state=y", "/api/me"} {
		resp, _ := b.do("HEAD", p, "")
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET" {
			t.Errorf("HEAD %s -> %d Allow %q", p, resp.StatusCode, resp.Header.Get("Allow"))
		}
	}
}

// Rate-limit warnings are aggregated.
func TestRateLimitWarningsAggregated(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, burst: 1})
	b := h.browser()
	for i := 0; i < 40; i++ {
		b.do("GET", "/auth/github/start", "")
	}
	if n := strings.Count(h.logs.String(), `msg="auth: rate limited"`); n > 1 {
		t.Errorf("%d rate-limit warnings for 39 refused requests", n)
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// opensslBase64 is what `openssl rand -base64 n` prints.
func opensslBase64(n int) string { return base64.StdEncoding.EncodeToString(randBytes(n)) }

// opensslHex is what `openssl rand -hex n` prints.
func opensslHex(n int) string { return hex.EncodeToString(randBytes(n)) }

func opensslB64URL(n int) string { return base64.RawURLEncoding.EncodeToString(randBytes(n)) }
