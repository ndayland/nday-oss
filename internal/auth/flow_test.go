package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"hash/fnv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/fakeidp"
	"nday.land/nday/internal/auth/jose"
)

// acct is a provider account; the subject is numeric (GitHub and X ids are).
func acct(sub string) fakeidp.Account {
	f := fnv.New64a()
	f.Write([]byte(sub))
	return fakeidp.Account{Subject: strconv.FormatUint(f.Sum64()%1e15, 10), Name: "Ada " + sub, Username: "ada_" + sub}
}

func TestHappyPathPerProvider(t *testing.T) {
	for _, p := range auth.AllProviders {
		t.Run(p, func(t *testing.T) {
			h := newHarness(t, harnessOpt{})
			b := h.browser()
			authURL := b.start(p, "return="+url.QueryEscape("/vuln?q=CVE-2026&since=7d"))

			// flow cookie: __Host-, Secure, HttpOnly, Lax, Path=/, short-lived
			fc := b.jar[auth.FlowCookie]
			if fc == nil || !fc.Secure || !fc.HttpOnly || fc.SameSite != http.SameSiteLaxMode || fc.Path != "/" ||
				fc.Domain != "" || fc.MaxAge != 600 {
				t.Fatalf("flow cookie %+v", fc)
			}
			q, _ := url.Parse(authURL)
			aq := q.Query()
			if aq.Get("redirect_uri") != origin+"/auth/"+p+"/callback" || strings.Contains(authURL, "email") {
				t.Errorf("authorize URL %s", authURL)
			}
			if aq.Has("code_challenge") != (p != auth.Apple) || aq.Has("nonce") != (p == auth.Google || p == auth.Apple) {
				t.Errorf("PKCE/nonce params %s", authURL)
			}
			cb, err := h.idp.Approve(p, authURL, acct("1001"))
			if err != nil {
				t.Fatal(err)
			}
			loc := b.callback(cb)
			// a new account: the welcome page first, the return path as next
			if loc != "/welcome?next=%2Fvuln%3Fq%3DCVE-2026%26since%3D7d&auth=ok" {
				t.Fatalf("redirect %q", loc)
			}
			if _, ok := b.jar[auth.FlowCookie]; ok {
				t.Error("flow cookie not cleared")
			}
			sc := b.jar[auth.SessionCookie]
			if sc == nil || !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" ||
				sc.Domain != "" || sc.MaxAge != int((60*24*time.Hour)/time.Second) || len(sc.Value) != 64 { // token(32)+tag(16), base64url
				t.Fatalf("session cookie %+v", sc)
			}
			m := b.me()
			if !m.SignedIn || m.User == nil || len(m.User.Identities) != 1 || m.User.Identities[0].Provider != p ||
				m.CSRFToken == "" || m.User.Role != "user" || m.User.Status != "active" || m.User.Handle != nil ||
				len(m.Providers) != 4 {
				t.Fatalf("me %+v", m)
			}
			switch p {
			case auth.Apple:
				if m.User.DisplayName != nil {
					t.Errorf("apple (no scope) must not have a name: %v", *m.User.DisplayName)
				}
				if h.idp.LastAppleSecretHeader["alg"] != "ES256" || h.idp.LastAppleSecretClaims["iss"] != "ABCDE12345" {
					t.Errorf("apple client secret %v %v", h.idp.LastAppleSecretHeader, h.idp.LastAppleSecretClaims)
				}
			default:
				if m.User.DisplayName == nil || *m.User.DisplayName != "Ada 1001" {
					t.Errorf("display name %v", m.User.DisplayName)
				}
			}
			if hd := m.User.Identities[0].Handle; (p == auth.GitHub || p == auth.X) != (hd != nil && *hd == "ada_1001") {
				t.Errorf("identity handle %v", hd)
			}
			// only a hash of the token is stored; no provider tokens anywhere
			// (cookie = base64url(token(32) || tag(16)), 64 characters, no padding)
			if h.count(`SELECT count(*) FROM sessions WHERE token_hash = sha256(substring(decode(translate($1, '-_', '+/'), 'base64') FROM 1 FOR 32))`,
				sc.Value) != 1 {
				t.Error("session row not keyed by SHA-256 of the token")
			}
			if h.count(`SELECT count(*) FROM sessions s, users u, identities i
				WHERE (s::text || u::text || i::text) LIKE '%AT-%' OR (s::text || u::text || i::text) LIKE '%' || $1 || '%'
				OR (u::text || i::text) LIKE '%@%'`, sc.Value) != 0 {
				t.Error("tokens, cookie value or e-mail stored")
			}
			first := m.User.ID

			// a ticketless sign-in of the signed-in account keeps the session
			// a reauth ticket rotates it and revokes the old one
			old := sc.Value
			b.login(p, acct("1001"), "return=/")
			if b.jar[auth.SessionCookie].Value != old {
				t.Fatal("ticketless same-account sign-in replaced the session")
			}
			b.reauth(p, "1001")
			if b.jar[auth.SessionCookie].Value == old {
				t.Fatal("session not rotated at re-sign-in")
			}
			if m2 := b.me(); m2.User.ID != first {
				t.Fatalf("second sign-in created another user")
			}
			stale := h.browser()
			stale.jar[auth.SessionCookie] = &http.Cookie{Name: auth.SessionCookie, Value: old}
			if stale.me().SignedIn {
				t.Error("pre-sign-in session still valid (fixation)")
			}
			if h.count(`SELECT count(*) FROM users`) != 1 || h.count(`SELECT count(*) FROM sessions`) != 1 {
				t.Error("row counts")
			}
			// another provider account -> another user
			b2 := h.browser()
			b2.login(p, acct("2002"), "")
			if b2.me().User.ID == first {
				t.Error("different subject mapped to same user")
			}
		})
	}
}

func TestStateAndCallbackFailures(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub, auth.Google}})
	outcome := func(loc string) string {
		u, _ := url.Parse(loc)
		return u.Query().Get("auth")
	}
	t.Run("callback without start", func(t *testing.T) {
		b := h.browser()
		if loc := b.callback(origin + "/auth/github/callback?code=abc&state=xyz"); loc != "/?auth=error" {
			t.Fatal(loc)
		}
	})
	t.Run("missing and mismatched state", func(t *testing.T) {
		for _, mutate := range []func(url.Values){
			func(q url.Values) { q.Del("state") },
			func(q url.Values) { q.Set("state", "AAAA"+q.Get("state")[4:]) },
		} {
			b := h.browser()
			au := b.start(auth.GitHub, "return=/hot")
			cb, _ := h.idp.Approve(auth.GitHub, au, acct("1"))
			u, _ := url.Parse(cb)
			q := u.Query()
			mutate(q)
			u.RawQuery = q.Encode()
			if loc := b.callback(u.String()); loc != "/hot?auth=error" {
				t.Fatal(loc)
			}
			if b.jar[auth.SessionCookie] != nil {
				t.Fatal("session issued")
			}
		}
		if strings.Count(h.logs.String(), "reason=state_mismatch") != 2 {
			t.Errorf("logs: %s", h.logs.String())
		}
	})
	t.Run("replayed state", func(t *testing.T) {
		b := h.browser()
		au := b.start(auth.GitHub, "")
		flow := *b.jar[auth.FlowCookie]
		cb, _ := h.idp.Approve(auth.GitHub, au, acct("1"))
		if outcome(b.callback(cb)) != "ok" {
			t.Fatal("first use")
		}
		attacker := h.browser()
		attacker.jar[auth.FlowCookie] = &flow // stolen cookie + callback URL
		if loc := attacker.callback(cb); outcome(loc) != "error" || attacker.jar[auth.SessionCookie] != nil {
			t.Fatal("replay accepted:", loc)
		}
		if !strings.Contains(h.logs.String(), "reason=state_replayed") {
			t.Error("replay not logged")
		}
	})
	t.Run("flow of another browser", func(t *testing.T) {
		victim, attacker := h.browser(), h.browser()
		au := attacker.start(auth.GitHub, "")
		cb, _ := h.idp.Approve(auth.GitHub, au, acct("attacker"))
		// login CSRF: the attacker's callback URL opened in the victim's browser
		if loc := victim.callback(cb); outcome(loc) != "error" || victim.jar[auth.SessionCookie] != nil {
			t.Fatal(loc)
		}
		// the victim has a flow of their own: still mismatched
		victim.start(auth.GitHub, "")
		if loc := victim.callback(cb); outcome(loc) != "error" {
			t.Fatal(loc)
		}
	})
	t.Run("expired flow", func(t *testing.T) {
		b := h.browser()
		au := b.start(auth.GitHub, "")
		cb, _ := h.idp.Approve(auth.GitHub, au, acct("1"))
		h.clock.Advance(auth.FlowTTL + time.Second)
		if outcome(b.callback(cb)) != "error" || !strings.Contains(h.logs.String(), "reason=flow_expired") {
			t.Fatal("expired flow accepted")
		}
	})
	t.Run("forged flow cookie", func(t *testing.T) {
		b := h.browser()
		au := b.start(auth.GitHub, "")
		cb, _ := h.idp.Approve(auth.GitHub, au, acct("1"))
		// Change one character in the middle: every bit of it is data, so
		// the decoded bytes always differ (replacing the last characters
		// could leave them equal and made this test fail about 1 run in 300).
		v := b.jar[auth.FlowCookie].Value
		mid, c := len(v)/2, "A"
		if v[mid] == 'A' {
			c = "B"
		}
		b.jar[auth.FlowCookie].Value = v[:mid] + c + v[mid+1:]
		if outcome(b.callback(cb)) != "error" {
			t.Fatal("forged flow accepted")
		}
	})
	t.Run("flow for another provider", func(t *testing.T) {
		b := h.browser()
		au := b.start(auth.GitHub, "")
		u, _ := url.Parse(au)
		if outcome(b.callback(origin+"/auth/google/callback?code=x&state="+u.Query().Get("state"))) != "error" {
			t.Fatal("cross-provider flow accepted")
		}
	})
	t.Run("provider denies consent", func(t *testing.T) {
		b := h.browser()
		au := b.start(auth.GitHub, "return=/src")
		if loc := b.callback(h.idp.Deny(auth.GitHub, au)); loc != "/src?auth=denied" {
			t.Fatal(loc)
		}
	})
	t.Run("provider error", func(t *testing.T) {
		b := h.browser()
		au := b.start(auth.GitHub, "")
		u, _ := url.Parse(au)
		cb := origin + "/auth/github/callback?error=server_error&error_description=SECRET-x&state=" + u.Query().Get("state")
		if outcome(b.callback(cb)) != "error" {
			t.Fatal()
		}
	})
	t.Run("iss parameter mix-up", func(t *testing.T) {
		b := h.browser()
		au := b.start(auth.Google, "")
		cb, _ := h.idp.Approve(auth.Google, au, acct("1"))
		if outcome(b.callback(cb+"&iss="+url.QueryEscape("https://evil.example"))) != "error" {
			t.Fatal("foreign iss accepted")
		}
	})
	t.Run("token endpoint failures", func(t *testing.T) {
		for _, tc := range []struct {
			status int
			body   string
			reason string
		}{
			{500, "", "token_error_server_error"},
			{502, "<html>bad gateway</html>", "token_http_502"},
			{200, "{not json", "token_bad_json"},
			{200, `{"access_token":""}`, "token_no_bearer_token"},
			{200, `{"error":"bad_verification_code","error_description":"SECRET-desc"}`, "token_error_bad_verification_code"},
		} {
			h.idp.TokenStatus, h.idp.TokenBody = tc.status, tc.body
			b := h.browser()
			au := b.start(auth.GitHub, "")
			cb, _ := h.idp.Approve(auth.GitHub, au, acct("1"))
			if outcome(b.callback(cb)) != "error" || !strings.Contains(h.logs.String(), "reason="+tc.reason) {
				t.Errorf("%v: %s", tc, h.logs.String())
			}
		}
		h.idp.TokenStatus, h.idp.TokenBody = 0, ""
		h.idp.UserStatus = 500
		b := h.browser()
		au := b.start(auth.GitHub, "")
		cb, _ := h.idp.Approve(auth.GitHub, au, acct("1"))
		if outcome(b.callback(cb)) != "error" || !strings.Contains(h.logs.String(), "reason=userinfo_http_500") {
			t.Error("userinfo failure")
		}
		h.idp.UserStatus = 0
	})
}

func TestIDTokenRejectedInFlow(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.Google, auth.Apple}})
	evil, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		name   string
		mutate func(string, map[string]any)
		sign   func(map[string]any) string
		reason string
	}{
		{"wrong aud", func(_ string, c map[string]any) { c["aud"] = "someone-else" }, nil, "id_token_claims_aud"},
		{"wrong iss", func(_ string, c map[string]any) { c["iss"] = "https://accounts.google.com.evil" }, nil, "id_token_claims_iss"},
		{"wrong nonce", func(_ string, c map[string]any) { c["nonce"] = "replayed" }, nil, "id_token_claims_nonce"},
		// measured from the harness clock: wall time minus 48h is in the fake clock's future from 2026-11-15 12:00 UTC on
		{"expired", func(_ string, c map[string]any) { c["exp"] = h.clock.Now().Add(-48 * time.Hour).Unix() }, nil, "id_token_claims_expired"},
		{"bad signature", nil, func(c map[string]any) string { s, _ := jose.SignRS256(evil, "k1", c); return s }, "id_token_signature"},
		{"alg none", nil, func(c map[string]any) string {
			s, _ := jose.SignRS256(evil, "k1", c)
			p := strings.Split(s, ".")
			return "eyJhbGciOiJub25lIn0." + p[1] + "." + p[2]
		}, "id_token_alg"},
		{"unknown kid", nil, func(c map[string]any) string { s, _ := jose.SignRS256(evil, "rogue", c); return s }, "id_token_unknown_kid"},
	}
	for _, p := range []string{auth.Google, auth.Apple} {
		for _, c := range cases {
			h.idp.MutateClaims, h.idp.SignToken = c.mutate, c.sign
			b := h.browser()
			au := b.start(p, "")
			cb, _ := h.idp.Approve(p, au, acct("1"))
			if loc := b.callback(cb); !strings.HasSuffix(loc, "auth=error") || b.jar[auth.SessionCookie] != nil {
				t.Errorf("%s/%s accepted: %s", p, c.name, loc)
			}
			if !strings.Contains(h.logs.String(), "reason="+c.reason) {
				t.Errorf("%s/%s: no reason=%s in logs", p, c.name, c.reason)
			}
		}
	}
	// key rotation at the provider: new kid is fetched and accepted
	h.idp.MutateClaims, h.idp.SignToken = nil, nil
	h.idp.Rotate("k2")
	h.clock.Advance(31 * time.Second) // unknown-kid refetches are throttled to one per 30 s
	b := h.browser()
	if loc := b.login(auth.Google, acct("1"), ""); loc != "/welcome?auth=ok" { // a new account
		t.Fatalf("after rotation: %s", loc)
	}
	if h.count(`SELECT count(*) FROM users`) != 1 {
		t.Error("users")
	}
}

func TestLinkingAndUnlinking(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	a := h.browser()
	a.login(auth.GitHub, acct("a"), "")
	userA := a.me().User.ID
	bb := h.browser()
	bb.login(auth.Google, acct("b"), "")

	link := func(br *browser, p string, ac fakeidp.Account) string {
		su, resp, body := br.ticket(p, "link", "/account")
		if resp.StatusCode != 200 {
			t.Fatalf("ticket %d %s", resp.StatusCode, body)
		}
		au := br.startURL(su)
		cb, err := h.idp.Approve(p, au, ac)
		if err != nil {
			t.Fatal(err)
		}
		return br.callback(cb)
	}
	// the account page is a valid return target (its JSON endpoints are not)
	if loc := link(a, auth.Google, acct("a-google")); loc != "/account?auth=linked" {
		t.Fatalf("link: %s", loc)
	}
	m := a.me()
	if len(m.User.Identities) != 2 || m.User.ID != userA {
		t.Fatalf("after link %+v", m.User)
	}
	// linked identity signs in to the same account
	c := h.browser()
	c.login(auth.Google, acct("a-google"), "")
	if c.me().User.ID != userA {
		t.Fatal("linked identity -> other user")
	}
	// identity owned by another user: refused, nothing moves
	if loc := link(a, auth.Google, acct("b")); loc != "/account?auth=conflict" {
		t.Fatalf("takeover: %s", loc)
	}
	if loc := link(a, auth.Apple, acct("b")); loc != "/account?auth=linked" { // apple sub "b" is a different identity
		t.Fatalf("apple: %s", loc)
	}
	if bb.me().User.Identities[0].Provider != auth.Google || len(bb.me().User.Identities) != 1 {
		t.Fatal("B's identity changed")
	}
	// second account of the same provider: refused
	if loc := link(a, auth.GitHub, acct("a2")); loc != "/account?auth=conflict" {
		t.Fatalf("2nd github: %s", loc)
	}
	// link start needs a ticket (session + CSRF, see TestLinkTicket)
	anon := h.browser()
	if resp, body := anon.do("GET", "/auth/x/start?intent=link", ""); resp.StatusCode != 403 || errCode(t, body) != "ticket_required" {
		t.Errorf("anon link %d %s", resp.StatusCode, body)
	}
	if resp, body := anon.do("POST", "/auth/x/ticket", `{"intent":"link"}`, "Origin", origin, "Content-Type", "application/json"); resp.StatusCode != 401 || errCode(t, body) != "not_signed_in" {
		t.Errorf("anon ticket %d %s", resp.StatusCode, body)
	}
	if resp, body := a.do("GET", "/auth/x/start?intent=link", ""); resp.StatusCode != 403 || errCode(t, body) != "ticket_required" {
		t.Errorf("link without ticket %d %s", resp.StatusCode, body)
	}
	su, _, _ := a.ticket(auth.X, "link", "/")
	if resp, _ := a.do("GET", su, "", "Sec-Fetch-Site", "cross-site"); resp.StatusCode != 403 {
		t.Errorf("cross-site link start %d", resp.StatusCode)
	}
	if resp, _ := a.do("GET", "/auth/x/start?intent=steal", ""); resp.StatusCode != 400 {
		t.Errorf("bad intent %d", resp.StatusCode)
	}
	// link flow finished after the session was signed out: refused
	au := a.startURL(su)
	other := a.clone()
	other.post("/auth/signout", "")
	cb, _ := h.idp.Approve(auth.X, au, acct("x"))
	if loc := a.callback(cb); loc != "/?auth=error" {
		t.Fatalf("link after signout: %s", loc)
	}

	// unlink rules
	a.login(auth.GitHub, acct("a"), "")
	if resp, body := a.post("/auth/google/unlink", ""); resp.StatusCode != 200 {
		t.Fatalf("unlink %d %s", resp.StatusCode, body)
	}
	if resp, body := a.post("/auth/google/unlink", ""); resp.StatusCode != 404 || errCode(t, body) != "not_linked" {
		t.Errorf("unlink again %d %s", resp.StatusCode, body)
	}
	if resp, _ := a.post("/auth/apple/unlink", ""); resp.StatusCode != 200 {
		t.Fatal("unlink apple")
	}
	if resp, body := a.post("/auth/github/unlink", ""); resp.StatusCode != 409 || errCode(t, body) != "last_identity" {
		t.Errorf("unlink last %d %s", resp.StatusCode, body)
	}
	if len(a.me().User.Identities) != 1 {
		t.Error("identities after unlink")
	}
	// the unlinked google identity now signs up as a new user
	d := h.browser()
	d.login(auth.Google, acct("a-google"), "")
	if d.me().User.ID == userA {
		t.Error("unlinked identity still maps to A")
	}
}

func TestSessionsLifecycle(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("s"), "")

	// sign-out revokes server-side: a copy of the cookie stops working
	stolen := b.clone()
	if !stolen.me().SignedIn {
		t.Fatal("clone")
	}
	if resp, body := b.post("/auth/signout", ""); resp.StatusCode != 200 {
		t.Fatalf("signout %d %s", resp.StatusCode, body)
	}
	if b.jar[auth.SessionCookie] != nil || stolen.me().SignedIn {
		t.Fatal("session survived sign-out")
	}
	if _, ok := stolen.jar[auth.SessionCookie]; ok {
		t.Error("stale cookie not cleared by /api/me")
	}

	// sign-out-all revokes every session of the user
	b1, b2, b3 := h.browser(), h.browser(), h.browser()
	b1.login(auth.GitHub, acct("s"), "")
	b2.login(auth.GitHub, acct("s"), "")
	b3.login(auth.GitHub, acct("other"), "")
	if resp, body := b1.post("/auth/signout-all", ""); resp.StatusCode != 200 || !strings.Contains(string(body), `"revoked_sessions":2`) {
		t.Fatalf("signout-all %d %s", resp.StatusCode, body)
	}
	if b1.me().SignedIn || b2.me().SignedIn || !b3.me().SignedIn {
		t.Fatal("signout-all scope")
	}

	// idle expiry
	b1.login(auth.GitHub, acct("s"), "")
	h.clock.Advance(13 * 24 * time.Hour)
	if !b1.me().SignedIn {
		t.Fatal("expired before idle timeout")
	}
	h.clock.Advance(13 * 24 * time.Hour) // touched above, so still within idle
	if !b1.me().SignedIn {
		t.Fatal("activity did not extend the idle timeout")
	}
	h.clock.Advance(14*24*time.Hour + time.Minute)
	if b1.me().SignedIn {
		t.Fatal("idle session still valid")
	}
	// absolute expiry despite activity
	b1.login(auth.GitHub, acct("s"), "")
	for i := 0; i < 5; i++ {
		h.clock.Advance(10 * 24 * time.Hour)
		if !b1.me().SignedIn {
			t.Fatalf("expired early at step %d", i)
		}
	}
	h.clock.Advance(10*24*time.Hour + time.Hour) // 60 d + 1 h after sign-in, last activity 10 d ago
	if b1.me().SignedIn {
		t.Fatal("absolute lifetime not enforced")
	}

	// signout without a session is harmless; cross-site signout refused
	if resp, _ := h.browser().do("POST", "/auth/signout", "", "Origin", origin); resp.StatusCode != 200 {
		t.Error("anon signout")
	}
	b1.login(auth.GitHub, acct("s"), "")
	if resp, _ := b1.do("POST", "/auth/signout", "", "Origin", "https://evil.example"); resp.StatusCode != 403 || !b1.me().SignedIn {
		t.Error("cross-site signout")
	}
	// malformed cookie values are ignored
	junk := h.browser()
	junk.jar[auth.SessionCookie] = &http.Cookie{Name: auth.SessionCookie, Value: "x' OR 1=1 --"}
	if junk.me().SignedIn {
		t.Error("junk cookie")
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("c"), "")
	tok := b.me().CSRFToken
	body := `{"locale":"zh-Hans"}`
	ct := "application/json"
	cases := []struct {
		name string
		hdr  []string
		code string
	}{
		{"missing token", []string{"Origin", origin, "Content-Type", ct}, "csrf"},
		{"wrong token", []string{"Origin", origin, "Content-Type", ct, "X-CSRF-Token", strings.Repeat("A", 43)}, "csrf"},
		{"token of another session", []string{"Origin", origin, "Content-Type", ct, "X-CSRF-Token", func() string {
			o := h.browser()
			o.login(auth.GitHub, acct("c"), "")
			return o.me().CSRFToken
		}()}, "csrf"},
		{"cross-site origin", []string{"Origin", "https://evil.example", "Content-Type", ct, "X-CSRF-Token", tok}, "cross_site"},
		{"null origin", []string{"Origin", "null", "Content-Type", ct, "X-CSRF-Token", tok}, "cross_site"},
		{"apex origin", []string{"Origin", "https://nday.land", "Content-Type", ct, "X-CSRF-Token", tok}, "cross_site"},
		{"sec-fetch-site cross-site", []string{"Sec-Fetch-Site", "cross-site", "Content-Type", ct, "X-CSRF-Token", tok}, "cross_site"},
		{"sec-fetch-site same-site", []string{"Origin", origin, "Sec-Fetch-Site", "same-site", "Content-Type", ct, "X-CSRF-Token", tok}, "cross_site"},
		{"no origin evidence", []string{"Content-Type", ct, "X-CSRF-Token", tok}, "cross_site"},
		{"form post", []string{"Origin", origin, "Content-Type", "application/x-www-form-urlencoded", "X-CSRF-Token", tok}, "bad_request"},
	}
	for _, c := range cases {
		resp, out := b.do("POST", "/account/locale", body, c.hdr...)
		if resp.StatusCode < 400 || errCode(t, out) != c.code {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, out)
		}
	}
	if m := b.me(); m.User.Locale != nil {
		t.Fatal("locale changed by a refused request")
	}
	if resp, out := b.do("POST", "/account/locale", body, "Origin", origin, "Content-Type", ct, "X-CSRF-Token", tok); resp.StatusCode != 200 {
		t.Fatalf("good request %d %s", resp.StatusCode, out)
	}
	if m := b.me(); m.User.Locale == nil || *m.User.Locale != "zh-Hans" {
		t.Fatal("locale")
	}
	if resp, _ := b.post("/account/locale", `{"locale":null}`); resp.StatusCode != 200 || b.me().User.Locale != nil {
		t.Fatal("clear locale")
	}
	for _, bad := range []string{`{"locale":"zh_Hans"}`, `{"locale":"<x>"}`, `{"locale":"en","x":1}`, `{"locale":"en"} {}`, `not json`} {
		if resp, _ := b.post("/account/locale", bad); resp.StatusCode != 400 {
			t.Errorf("%s: %d", bad, resp.StatusCode)
		}
	}
	// wrong methods
	if resp, _ := b.do("GET", "/account/delete", ""); resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
		t.Error("GET on POST endpoint")
	}
	if resp, _ := b.do("POST", "/api/me", "", "Origin", origin); resp.StatusCode != 405 {
		t.Error("POST /api/me")
	}
	// not signed in
	anon := h.browser()
	if resp, out := anon.do("POST", "/account/locale", body, "Origin", origin, "Content-Type", ct); resp.StatusCode != 401 ||
		errCode(t, out) != "not_signed_in" {
		t.Errorf("anon %d %s", resp.StatusCode, out)
	}
}

func TestOpenRedirectThroughFlow(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	for _, ret := range []string{"//evil.example", "/\\evil.example", "https://evil.example/", "%2F%2Fevil.example",
		"/%2F%2Fevil", "/%5Cevil", "/x%0d%0aLocation:%20https://evil", "/x\x00", "javascript:alert(1)", "/auth/github/start"} {
		b := h.browser()
		want := "/?auth=ok"
		if h.count(`SELECT count(*) FROM users`) == 0 {
			want = "/welcome?auth=ok" // the first sign-in creates the account
		}
		if loc := b.login(auth.GitHub, acct("r"), "return="+url.QueryEscape(ret)); loc != want {
			t.Errorf("return %q -> Location %q", ret, loc)
		}
	}
	b := h.browser()
	if loc := b.login(auth.GitHub, acct("r"), "return="+url.QueryEscape("/zh-hans/vuln/CVE-2026-0001?auth=x")); loc != "/zh-hans/vuln/CVE-2026-0001?auth=ok" {
		t.Errorf("good return: %q", loc)
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, burst: 3})
	b := h.browser()
	for i := 0; i < 3; i++ {
		b.start(auth.GitHub, "")
	}
	resp, body := b.do("GET", "/auth/github/start", "")
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" || errCode(t, body) != "rate_limited" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	other := h.browser()
	other.ip = "2001:db8::1"
	other.start(auth.GitHub, "")
	same64 := h.browser()
	same64.ip = "2001:db8::2"
	for i := 0; i < 2; i++ {
		same64.start(auth.GitHub, "")
	}
	if resp, _ := same64.do("GET", "/auth/github/start", ""); resp.StatusCode != 429 {
		t.Error("IPv6 /64 shares a bucket")
	}
	h.clock.Advance(2 * time.Second)
	b.start(auth.GitHub, "")
	// callback is limited too
	for i := 0; i < 3; i++ {
		b.do("GET", "/auth/github/callback?code=x&state=y", "")
	}
	if resp, _ := b.do("GET", "/auth/github/callback?code=x&state=y", ""); resp.StatusCode != 429 {
		t.Error("callback not rate limited")
	}
}

func TestCachingAndCookieFreePublicRoutes(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("p"), "")
	for _, p := range []string{"/", "/healthz", "/api/stats", "/api/sources", "/api/hot", "/api/nope", "/raw/kev/x.json"} {
		resp, _ := b.do("GET", p, "")
		if len(resp.Header.Values("Set-Cookie")) != 0 || strings.Contains(resp.Header.Get("Vary"), "Cookie") {
			t.Errorf("%s: Set-Cookie %v Vary %q", p, resp.Header.Values("Set-Cookie"), resp.Header.Get("Vary"))
		}
		if p == "/" && resp.Header.Get("Cache-Control") != "public, max-age=60" {
			t.Errorf("public page Cache-Control changed: %q", resp.Header.Get("Cache-Control"))
		}
	}
	// a signed-in browser gets byte-identical public responses to an anonymous one
	anon := h.browser()
	_, x := b.do("GET", "/api/stats", "")
	_, y := anon.do("GET", "/api/stats", "")
	if string(x) != string(y) {
		t.Error("public API depends on the session")
	}
	// every auth response is no-store (also asserted by browser.do for each call)
	for _, p := range []string{"/auth/github/start", "/auth/github/callback", "/auth/nope/start", "/auth/", "/account/x",
		"/api/me", "/auth/signout"} {
		resp, _ := anon.do("GET", p, "")
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %q", p, resp.Header.Get("Cache-Control"))
		}
	}
	// the access log never shows sign-in query values
	if !strings.Contains(h.logs.String(), "code=REDACTED") || strings.Contains(h.logs.String(), "state=") &&
		!strings.Contains(h.logs.String(), "state=REDACTED") {
		t.Errorf("access log: %s", h.logs.String())
	}
}

func TestDisabledProviders(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	for _, p := range []string{"/auth/google/start", "/auth/apple/callback", "/auth/x/start", "/auth/facebook/start"} {
		if resp, body := b.do("GET", p, ""); resp.StatusCode != 404 || errCode(t, body) != "not_found" {
			t.Errorf("%s: %d %s", p, resp.StatusCode, body)
		}
	}
	if m := b.me(); m.SignedIn || len(m.Providers) != 1 || m.Providers[0] != "github" || m.User != nil || m.CSRFToken != "" {
		t.Errorf("%+v", m)
	}
	b.login(auth.GitHub, acct("d"), "")
	if resp, _ := b.post("/auth/google/unlink", ""); resp.StatusCode != 404 {
		t.Error("unlink of disabled provider")
	}
}

func TestDeleteAccount(t *testing.T) {
	h := newHarness(t, harnessOpt{})
	// a future feature's table, following the documented convention
	if _, err := h.db.Conn.Exec(context.Background(), `CREATE TABLE posts (id serial PRIMARY KEY, body text,
		author_id uuid REFERENCES users (id) ON DELETE SET NULL)`); err != nil {
		t.Fatal(err)
	}
	b := h.browser()
	b.login(auth.GitHub, acct("del"), "")
	if loc := b.linkVia(auth.Google, "del-g"); loc != "/?auth=linked" {
		t.Fatalf("link: %s", loc)
	}
	if resp, body := b.post("/account/handle", `{"handle":"Deleter"}`); resp.StatusCode != 200 {
		t.Fatalf("handle %d %s", resp.StatusCode, body)
	}
	id := b.me().User.ID
	if _, err := h.db.Conn.Exec(context.Background(), `INSERT INTO posts (body, author_id) VALUES ('hello', $1)`, id); err != nil {
		t.Fatal(err)
	}
	second := b.clone()
	if resp, _ := b.post("/account/delete", `{}`); resp.StatusCode != 400 {
		t.Fatal("delete without confirm")
	}
	if resp, body := b.post("/account/delete", `{"confirm":true}`); resp.StatusCode != 200 {
		t.Fatalf("delete %d %s", resp.StatusCode, body)
	}
	if b.me().SignedIn || second.me().SignedIn {
		t.Fatal("sessions survive deletion")
	}
	for _, q := range []string{`SELECT count(*) FROM users`, `SELECT count(*) FROM identities`, `SELECT count(*) FROM sessions`} {
		if h.count(q) != 0 {
			t.Errorf("%s != 0", q)
		}
	}
	if h.count(`SELECT count(*) FROM posts WHERE author_id IS NULL AND body = 'hello'`) != 1 {
		t.Error("content not anonymised")
	}
	if h.count(`SELECT count(*) FROM namespaces WHERE name = 'deleter' AND kind = 'held' AND held_for IS NULL`) != 1 {
		t.Error("handle not held after deletion")
	}
	// the same provider identity starts afresh
	c := h.browser()
	c.login(auth.GitHub, acct("del"), "")
	if m := c.me(); m.User.ID == id || len(m.User.Identities) != 1 {
		t.Error("deleted identity resurrected")
	}
	if resp, body := c.post("/account/handle", `{"handle":"deleter"}`); resp.StatusCode != 409 || errCode(t, body) != "handle_taken" {
		t.Errorf("held handle taken over: %d %s", resp.StatusCode, body)
	}
}
