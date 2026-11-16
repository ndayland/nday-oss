package auth_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/webauthn"
	"nday.land/nday/internal/auth/webauthn/softauthn"
)

// registerCounting registers a credential that keeps a signature counter
// (starting at 10), so a write of the counter would show.
func (b *browser) registerCounting() *softauthn.Credential {
	b.h.t.Helper()
	opts := b.options(b.post("/auth/passkey/register/begin", ""))
	c := softauthn.NewCredential(webauthn.AlgES256, "nday.land", b64d(opts.PublicKey.User.ID))
	c.SignCount = 10
	if resp, body := b.post("/auth/passkey/register/finish", softauthn.JSON(c.Register(opts.PublicKey.Challenge, softauthn.Opts{}))); resp.StatusCode != 200 {
		b.h.t.Fatalf("register: %d %s", resp.StatusCode, body)
	}
	return c
}

// passkeyLoginBody runs a passkey sign-in with extra members in the finish body.
func (b *browser) passkeyLoginBody(c *softauthn.Credential, extra string) (int, []byte) {
	opts := b.options(b.anonPost("/auth/passkey/login/begin", ""))
	body := softauthn.JSON(c.Assert(opts.PublicKey.Challenge, softauthn.Opts{}))
	if extra != "" {
		body = "{" + extra + "," + strings.TrimPrefix(body, "{")
	}
	resp, rb := b.anonPost("/auth/passkey/login/finish", body)
	return resp.StatusCode, rb
}

// TestPasskeySignInDoesNotSwitchAccounts: a browser signed in to account A
// that completes a passkey sign-in with B's passkey keeps A (409
// signed_in_as_other, cookie untouched, nothing written for B) unless the
// finish body says "switch": true; A's own passkey re-signs A in with a fresh
// session; without a session nothing changes.
func TestPasskeySignInDoesNotSwitchAccounts(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	a := h.browser()
	a.login(auth.GitHub, acct("sw-a"), "")
	ca := a.registerCounting()
	b := h.browser()
	b.login(auth.GitHub, acct("sw-b"), "")
	cb := b.registerCounting()
	idA, idB := a.me().User.ID, b.me().User.ID
	ctx := context.Background()
	stored := func(c *softauthn.Credential) *auth.Passkey {
		pk, err := h.store.PasskeyByCredentialID(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return pk
	}

	// A's browser, B's passkey: refused, nothing changes.
	before := a.jar[auth.SessionCookie].Value
	status, body := a.passkeyLoginBody(cb, "")
	if status != 409 || errCode(t, body) != "signed_in_as_other" {
		t.Fatalf("other account: %d %s", status, body)
	}
	if a.jar[auth.SessionCookie] == nil || a.jar[auth.SessionCookie].Value != before {
		t.Error("session cookie changed on refusal")
	}
	if m := a.me(); !m.SignedIn || m.User.ID != idA {
		t.Errorf("after refusal signed in as %+v", m.User)
	}
	if pk := stored(cb); pk.SignCount != 10 || pk.LastUsedAt != nil {
		t.Errorf("refusal wrote for B: count %d last_used %v", pk.SignCount, pk.LastUsedAt)
	}
	// "switch": true ends on B (a new session).
	status, body = a.passkeyLoginBody(cb, `"switch":true`)
	if status != 200 || a.jar[auth.SessionCookie].Value == before {
		t.Fatalf("switch: %d %s", status, body)
	}
	if m := a.me(); m.User.ID != idB {
		t.Errorf("switch ended on %s, want B", m.User.ID)
	}
	if pk := stored(cb); pk.SignCount != 12 || pk.LastUsedAt == nil {
		t.Errorf("after switch: count %d last_used %v", pk.SignCount, pk.LastUsedAt)
	}

	// Same account: a fresh session (re-verification).
	a2 := h.browser()
	a2.login(auth.GitHub, acct("sw-a"), "")
	old := a2.jar[auth.SessionCookie].Value
	h.clock.Advance(time.Hour)
	if recentSignIn(a2) {
		t.Fatal("still recent after an hour")
	}
	if status, body := a2.passkeyLoginBody(ca, ""); status != 200 {
		t.Fatalf("same account: %d %s", status, body)
	}
	if m := a2.me(); a2.jar[auth.SessionCookie].Value == old || m.User.ID != idA || !recentSignIn(a2) {
		t.Errorf("same account: no fresh session (user %s)", m.User.ID)
	}

	// No session (and a stale cookie): unchanged, signs in.
	for _, nb := range []*browser{h.browser(), b.clone()} {
		if nb != nil && nb.jar[auth.SessionCookie] != nil {
			nb.jar[auth.SessionCookie].Value = "AAAA" + nb.jar[auth.SessionCookie].Value[4:] // breaks the tag
		}
		if status, body := nb.passkeyLoginBody(cb, ""); status != 200 || nb.me().User.ID != idB {
			t.Errorf("no session: %d %s", status, body)
		}
	}
}

func recentSignIn(b *browser) bool {
	b.h.t.Helper()
	_, body := b.do("GET", "/api/me", "")
	var m struct {
		Session struct {
			RecentSignIn bool `json:"recent_sign_in"`
		} `json:"session"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		b.h.t.Fatal(err)
	}
	return m.Session.RecentSignIn
}
