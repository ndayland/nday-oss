package auth_test

// Session hardening tests: reauth tickets, dead-token caching and per-token
// limits, link callback re-checks, impersonation handles, CDN cache headers,
// coarse rate-limit mode, weak secrets and the RFC 9207 iss parameter.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/webauthn"
	"nday.land/nday/internal/auth/webauthn/softauthn"
	"nday.land/nday/internal/web"
)

// reauth signs the browser in again through a "reauth" ticket.
func (b *browser) reauth(provider, sub string) string {
	b.h.t.Helper()
	su, resp, body := b.ticket(provider, "reauth", "/")
	if resp.StatusCode != 200 || su == "" {
		b.h.t.Fatalf("reauth ticket: %d %s", resp.StatusCode, body)
	}
	au := b.startURL(su)
	cb, err := b.h.idp.Approve(provider, au, acct(sub))
	if err != nil {
		b.h.t.Fatal(err)
	}
	return b.callback(cb)
}

// A sign-in the user did not start from our page (ticketless, e.g. a
// cross-site navigation) must not refresh the session; a reauth ticket does.
func TestReauthNeedsTicket(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	b := h.browser()
	b.login(auth.GitHub, acct("r1"), "")
	cookie := b.jar[auth.SessionCookie].Value
	h.clock.Advance(time.Hour)
	if resp, body := b.post("/auth/passkey/register/begin", ""); resp.StatusCode != 403 || errCode(t, body) != "reauth_required" {
		t.Fatalf("1 h old session register/begin -> %d %s", resp.StatusCode, body)
	}
	// the attack sequence: cross-site top-level GET start, silent IdP approval
	resp, body := b.do("GET", "/auth/github/start?return=/", "", "Sec-Fetch-Site", "cross-site")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start: %d %s", resp.StatusCode, body)
	}
	cb, _ := h.idp.Approve(auth.GitHub, resp.Header.Get("Location"), acct("r1"))
	if loc := b.callback(cb); loc != "/?auth=ok" {
		t.Errorf("same-account ticketless sign-in: %s", loc)
	}
	if b.jar[auth.SessionCookie] == nil || b.jar[auth.SessionCookie].Value != cookie {
		t.Error("ticketless same-account sign-in replaced the session")
	}
	if resp, body := b.post("/auth/passkey/register/begin", ""); resp.StatusCode != 403 || errCode(t, body) != "reauth_required" {
		t.Errorf("after a cross-site ticketless sign-in register/begin -> %d %s", resp.StatusCode, body)
	}
	// re-sign-in started from our page with a reauth ticket: fresh session
	if loc := b.reauth(auth.GitHub, "r1"); loc != "/?auth=ok" {
		t.Fatalf("reauth: %s", loc)
	}
	if b.jar[auth.SessionCookie].Value == cookie {
		t.Error("reauth did not rotate the session")
	}
	if resp, body := b.post("/auth/passkey/register/begin", ""); resp.StatusCode != 200 {
		t.Errorf("after reauth register/begin -> %d %s", resp.StatusCode, body)
	}
	// a reauth ticket for another account's identity does not switch
	h.clock.Advance(time.Hour)
	su, _, _ := b.ticket(auth.Google, "reauth", "/")
	au := b.startURL(su)
	cb, _ = h.idp.Approve(auth.Google, au, acct("someone-else"))
	if loc := b.callback(cb); loc != "/?auth=signed_in_as_other" {
		t.Errorf("reauth with another account: %s", loc)
	}
	// suspended users may reauth
	if err := h.store.Suspend(context.Background(), b.me().User.ID, nil, "x"); err != nil {
		t.Fatal(err)
	}
	if loc := b.reauth(auth.GitHub, "r1"); loc != "/?auth=ok" {
		t.Errorf("suspended reauth: %s", loc)
	}
	// passkey sign-in (which does refresh the session) is same-origin only
	if resp, body := b.do("POST", "/auth/passkey/login/begin", "", "Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site",
		"Content-Type", "application/json"); resp.StatusCode != 403 || errCode(t, body) != "cross_site" {
		t.Errorf("cross-site passkey login/begin -> %d %s", resp.StatusCode, body)
	}
	if resp, body := b.do("POST", "/auth/passkey/login/finish", "{}", "Sec-Fetch-Site", "cross-site",
		"Content-Type", "application/json"); resp.StatusCode != 403 || errCode(t, body) != "cross_site" {
		t.Errorf("cross-site passkey login/finish -> %d %s", resp.StatusCode, body)
	}
}

// Revoked (but genuinely tagged) cookies stop costing database calls,
// and one cookie replayed from many addresses is throttled by itself.
func TestRevokedAndReplayedCookies(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("r2"), "")
	rv := b.jar[auth.SessionCookie].Value
	b.post("/auth/signout", "")
	before := h.dbc.calls.Load()
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", h.ts.URL+"/api/me", nil)
		req.Host = publicHost
		req.Header.Set("CF-Connecting-IP", fmt.Sprintf("192.0.2.%d", i))
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: rv})
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}
	if n := h.dbc.calls.Load() - before; n > 1 {
		t.Errorf("20 requests with a REVOKED but tagged cookie -> %d database calls", n)
	}
	// a valid cookie replayed from 400 addresses: throttled per token
	v := h.browser()
	v.login(auth.GitHub, acct("r2b"), "")
	val := v.jar[auth.SessionCookie].Value
	limited := 0
	for i := 0; i < 400; i++ {
		req, _ := http.NewRequest("GET", h.ts.URL+"/api/me", nil)
		req.Host = publicHost
		req.Header.Set("CF-Connecting-IP", fmt.Sprintf("2001:db8:%x::1", i))
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: val})
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode == 429 && errCode(t, data) == "rate_limited" {
			limited++
		}
	}
	if limited == 0 {
		t.Error("one session cookie replayed 400 times from 400 addresses: never rate limited")
	}
}

// Suspension and the recent-sign-in window are re-checked when a link
// finishes (the callback), not only when it starts.
func TestLinkCallbackRechecks(t *testing.T) {
	t.Run("suspended", func(t *testing.T) {
		h := newHarness(t, harnessOpt{})
		b := h.browser()
		b.login(auth.GitHub, acct("r3"), "")
		su, resp, _ := b.ticket(auth.Google, "link", "/")
		if resp.StatusCode != 200 {
			t.Fatal("ticket")
		}
		au := b.startURL(su)
		if err := h.store.Suspend(context.Background(), b.me().User.ID, nil, "mid-flow"); err != nil {
			t.Fatal(err)
		}
		cb, _ := h.idp.Approve(auth.Google, au, acct("r3-google"))
		if loc := b.callback(cb); loc != "/?auth=suspended" {
			t.Errorf("suspended between start and callback: %s", loc)
		}
		if n := h.count(`SELECT count(*) FROM identities`); n != 1 {
			t.Errorf("identities = %d, want 1", n)
		}
	})
	t.Run("stale", func(t *testing.T) {
		h := newHarness(t, harnessOpt{})
		b := h.browser()
		b.login(auth.GitHub, acct("r3s"), "")
		h.clock.Advance(14 * time.Minute)
		su, resp, _ := b.ticket(auth.Google, "link", "/")
		if resp.StatusCode != 200 {
			t.Fatal("ticket")
		}
		au := b.startURL(su)
		h.clock.Advance(2 * time.Minute)
		cb, _ := h.idp.Approve(auth.Google, au, acct("r3s-google"))
		if loc := b.callback(cb); loc != "/?auth=reauth_required" {
			t.Errorf("window passed between start and callback: %s", loc)
		}
		if n := h.count(`SELECT count(*) FROM identities`); n != 1 {
			t.Errorf("identities = %d, want 1", n)
		}
	})
}

// Impersonation rules.
func TestImpersonation(t *testing.T) {
	for _, hnd := range []string{"the_admin", "real-admin", "official-account", "helpdesk", "verified",
		"trust", "safety", "sysadm", "iamadmin", "webadmin", "siteadmin", "admin-real", "the-moderator", "superofficial",
		"official_bob", "the-nday", "nday-staff", "verified_user", "Admin1", "support-team"} {
		if _, err := auth.CanonicalHandle(hnd); err != auth.ErrHandleReserved {
			t.Errorf("handle %q accepted (%v)", hnd, err)
		}
	}
	for _, hnd := range []string{"kev1", "me2", "test123", "help2", "post1", "apple1", "es6", "sunday", "monday", "adminton",
		"teamwork", "teammate", "modern", "moderate", "officially", "supporter", "rootbeer", "systematic", "staffordshire",
		"securityresearcher", "flagstaff", "steam", "ada_1", "grace-hopper", "bob123", "t0m", "linus", "standup", "mistrust",
		// everyday words as a separate part are ordinary handles (rule 4 covers tokenRoleWords only)
		"monday_team", "dev-team", "red-team", "blue_team", "team-rocket", "root_cause", "root-user", "security-researcher",
		"system-of-a-down", "trust_fund", "support_vector", "staff_engineer", "staff_bot", "safety_first", "the-mod-squad",
		// rule 5 needs two characters before the suffix
		"padmin", "sadmin", "badmin"} {
		if _, err := auth.CanonicalHandle(hnd); err != nil {
			t.Errorf("ordinary handle %q refused: %v", hnd, err)
		}
	}
	for _, n := range []string{"Аdmin", "nԁay", "𝐍𝐃𝐀𝐘 Support", "Ⓝⓓⓐⓨ", "官方账号", "管理员小王", "ＮＤＡＹ", "Αdmin"} {
		if !auth.DisplayNameImpersonates(n) {
			t.Errorf("display name %q kept", n)
		}
	}
	for _, n := range []string{"Ada Lovelace", "Team Rocket", "Sunday Mod Fan", "Алексей Иванов", "王小明", "Ωmega Fan", "Νίκος"} {
		if auth.DisplayNameImpersonates(n) {
			t.Errorf("ordinary display name %q refused", n)
		}
	}
}

// CDN cache headers are removed from personal responses too.
func TestCDNCacheHeaders(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, register: func(h *harness, srv *web.Server) {
		srv.Handle("GET /r5", h.svc.Load(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("CDN-Cache-Control", "max-age=600")
			w.Header().Set("Cloudflare-CDN-Cache-Control", "max-age=600")
			w.Header().Set("Surrogate-Control", "max-age=600")
			_, _ = io.WriteString(w, "x")
		})))
	}})
	b := h.browser()
	b.login(auth.GitHub, acct("r5"), "")
	resp, _ := b.do("GET", "/r5", "")
	for _, k := range []string{"CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control"} {
		if v := resp.Header.Get(k); v != "" {
			t.Errorf("%s kept on a personal response: %q", k, v)
		}
	}
}

// Once coarse (/48) mode is on, a single /48 rotating /64s gets about
// one bucket's allowance, also after the other buckets have been swept.
func TestCoarseModeHysteresis(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := auth.NewRateLimiter(10, 6*time.Second) // the start limiter
	l.Now = func() time.Time { return now }
	l.MaxKeys = 1000
	for i := 0; i < 600; i++ { // other clients: table over half full
		l.Allow(fmt.Sprintf("198.51.%d.%d", i/250, i%250))
	}
	allowed := 0
	end := now.Add(5 * time.Minute)
	for i := 0; now.Before(end); i++ {
		if ok, _ := l.Allow(fmt.Sprintf("2001:db8:77:%x::/64", i)); ok {
			allowed++
		}
		now = now.Add(100 * time.Millisecond)
	}
	// one bucket: burst 10 + 300 s / 6 s = 60
	if allowed > 3*60 {
		t.Errorf("one /48 rotating /64s got %d requests through in 5 minutes (one bucket allows about 60)", allowed)
	}
}

// More obviously non-random secrets are refused.
func TestSecrets(t *testing.T) {
	env := func(secret string) func(string) (string, bool) {
		m := map[string]string{"NDAY_PUBLIC_URL": "https://www.nday.land", "NDAY_AUTH_GITHUB_CLIENT_ID": "id",
			"NDAY_AUTH_GITHUB_CLIENT_SECRET": "s", "NDAY_AUTH_SECRET": secret}
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	for _, s := range []string{
		strings.Repeat("changeme-", 6),
		strings.Repeat("00112233445566778899aabbccddeeff", 2),
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
		"nday-auth-secret-please-change-me-in-production",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	} {
		if cfg, err := auth.FromEnv(env(s)); err == nil || cfg != nil {
			t.Errorf("non-random secret %.12s… accepted", s)
		}
	}
}

// Google declares RFC 9207 support (discovery document, 2026-11-13);
// Apple does not.
func TestGoogleIss(t *testing.T) {
	if !auth.ProductionEndpoints[auth.Google].IssParameterSupported {
		t.Error("Google: IssParameterSupported off")
	}
	for _, p := range []string{auth.Apple, auth.GitHub, auth.X} {
		if auth.ProductionEndpoints[p].IssParameterSupported {
			t.Errorf("%s: IssParameterSupported on", p)
		}
	}
}

var _ = json.Marshal
var _ = webauthn.AlgES256
var _ = softauthn.JSON

// A reauth flow is bound to the session that got the ticket: its flow cookie
// carried to another signed-in browser of the same account is an ordinary
// ticketless sign-in there and refreshes nothing.
func TestReauthFlowBoundToSession(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	a, b := h.browser(), h.browser()
	a.login(auth.GitHub, acct("bound"), "")
	b.login(auth.GitHub, acct("bound"), "")
	cookieB := b.jar[auth.SessionCookie].Value
	h.clock.Advance(time.Hour)
	su, _, _ := a.ticket(auth.GitHub, "reauth", "/")
	au := a.startURL(su)
	cb, _ := h.idp.Approve(auth.GitHub, au, acct("bound"))
	b.jar[auth.FlowCookie] = a.jar[auth.FlowCookie]
	if loc := b.callback(cb); loc != "/?auth=ok" {
		t.Errorf("callback in the other browser: %s", loc)
	}
	if b.jar[auth.SessionCookie] == nil || b.jar[auth.SessionCookie].Value != cookieB {
		t.Error("another browser's reauth flow replaced this browser's session")
	}
	if resp, body := b.post("/auth/passkey/register/begin", ""); resp.StatusCode != 403 || errCode(t, body) != "reauth_required" {
		t.Errorf("after another browser's reauth flow register/begin -> %d %s", resp.StatusCode, body)
	}
}
