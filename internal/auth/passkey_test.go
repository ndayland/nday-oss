package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/webauthn"
	"nday.land/nday/internal/auth/webauthn/softauthn"
	"nday.land/nday/internal/web"
)

type pkOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
		PubKeyCredParams []struct {
			Alg int `json:"alg"`
		} `json:"pubKeyCredParams"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
		AllowCredentials       []any             `json:"allowCredentials"`
		AuthenticatorSelection map[string]any    `json:"authenticatorSelection"`
		Attestation            string            `json:"attestation"`
		UserVerification       string            `json:"userVerification"`
		Timeout                int               `json:"timeout"`
		Extra                  map[string]string `json:"-"`
	} `json:"publicKey"`
}

// anonPost is a same-origin JSON POST without a session/CSRF token.
func (b *browser) anonPost(path, body string, hdr ...string) (*http.Response, []byte) {
	h := append([]string{"Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json"}, hdr...)
	return b.do("POST", path, body, h...)
}

func (b *browser) options(resp *http.Response, body []byte) pkOptions {
	b.h.t.Helper()
	if resp.StatusCode != 200 {
		b.h.t.Fatalf("begin: %d %s", resp.StatusCode, body)
	}
	var o pkOptions
	if err := json.Unmarshal(body, &o); err != nil {
		b.h.t.Fatal(err)
	}
	b.h.secret(o.PublicKey.Challenge)
	return o
}

func b64d(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}

// addPasskey registers a new software credential on the signed-in account.
func (b *browser) addPasskey(alg int, name string, o softauthn.Opts) (*softauthn.Credential, *http.Response, []byte) {
	opts := b.options(b.post("/auth/passkey/register/begin", ""))
	c := softauthn.NewCredential(alg, "nday.land", b64d(opts.PublicKey.User.ID))
	r := c.Register(opts.PublicKey.Challenge, o)
	r.Name = name
	resp, body := b.post("/auth/passkey/register/finish", softauthn.JSON(r))
	return c, resp, body
}

func (b *browser) passkeyLogin(c *softauthn.Credential, o softauthn.Opts) (*http.Response, []byte) {
	opts := b.options(b.anonPost("/auth/passkey/login/begin", ""))
	return b.anonPost("/auth/passkey/login/finish", softauthn.JSON(c.Assert(opts.PublicKey.Challenge, o)))
}

func TestPasskeyRegisterAndSignIn(t *testing.T) {
	for _, alg := range []int{webauthn.AlgES256, webauthn.AlgRS256, webauthn.AlgEdDSA} {
		t.Run(map[int]string{-7: "ES256", -257: "RS256", -8: "EdDSA"}[alg], func(t *testing.T) {
			h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
			b := h.browser()
			b.login(auth.GitHub, acct("pk"), "")
			me0 := b.me()
			if !me0.Passkeys.Enabled || me0.Passkeys.Signup || len(me0.User.Passkeys) != 0 {
				t.Fatalf("%+v", me0)
			}
			opts := b.options(b.post("/auth/passkey/register/begin", ""))
			p := opts.PublicKey
			if p.RP.ID != "nday.land" || p.Attestation != "none" || p.AuthenticatorSelection["residentKey"] != "required" ||
				p.AuthenticatorSelection["userVerification"] != "required" || len(b64d(p.User.ID)) != 32 ||
				strings.Contains(p.User.ID, me0.User.ID) || len(p.ExcludeCredentials) != 0 || p.Timeout != 300000 ||
				len(p.PubKeyCredParams) != 3 || len(b64d(p.Challenge)) != 32 {
				t.Fatalf("creation options %+v", p)
			}
			c := softauthn.NewCredential(alg, "nday.land", b64d(p.User.ID))
			r := c.Register(p.Challenge, softauthn.Opts{})
			r.Name = "Laptop \u202e"
			resp, body := b.post("/auth/passkey/register/finish", softauthn.JSON(r))
			if resp.StatusCode != 200 {
				t.Fatalf("register: %d %s", resp.StatusCode, body)
			}
			if _, ok := b.jar[auth.CeremonyCookie]; ok {
				t.Error("ceremony cookie not cleared")
			}
			_, raw := b.do("GET", "/api/me", "")
			m := b.me()
			if len(m.User.Passkeys) != 1 || m.User.Passkeys[0].Name != "Laptop" || !m.User.Passkeys[0].BackedUp ||
				m.User.Passkeys[0].LastUsedAt != nil {
				t.Fatalf("passkeys %+v", m.User.Passkeys)
			}
			for _, leak := range []string{"public_key", "credential", "sign_count", r.ID} {
				if strings.Contains(string(raw), leak) {
					t.Errorf("/api/me exposes %q", leak)
				}
			}
			// excludeCredentials now lists it; the same authenticator cannot register twice
			opts = b.options(b.post("/auth/passkey/register/begin", ""))
			if len(opts.PublicKey.ExcludeCredentials) != 1 || opts.PublicKey.ExcludeCredentials[0].ID != r.ID {
				t.Fatalf("excludeCredentials %+v", opts.PublicKey.ExcludeCredentials)
			}
			again := c.Register(opts.PublicKey.Challenge, softauthn.Opts{})
			if resp, body := b.post("/auth/passkey/register/finish", softauthn.JSON(again)); resp.StatusCode != 409 ||
				errCode(t, body) != "passkey_exists" {
				t.Errorf("duplicate: %d %s", resp.StatusCode, body)
			}
			// usernameless sign-in in a fresh browser (also from the apex origin)
			for _, o := range []string{origin, "https://nday.land"} {
				nb := h.browser()
				resp, body := nb.passkeyLogin(c, softauthn.Opts{Origin: o})
				if resp.StatusCode != 200 || nb.jar[auth.SessionCookie] == nil {
					t.Fatalf("login from %s: %d %s", o, resp.StatusCode, body)
				}
				if got := nb.me(); got.User.ID != me0.User.ID || got.User.Passkeys[0].LastUsedAt == nil {
					t.Fatalf("login as %+v", got.User)
				}
			}
			// sign-in rotates an existing session
			old := b.jar[auth.SessionCookie].Value
			if resp, _ := b.passkeyLogin(c, softauthn.Opts{}); resp.StatusCode != 200 || b.jar[auth.SessionCookie].Value == old {
				t.Error("no rotation")
			}
		})
	}
}

func TestPasskeyNegatives(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	a := h.browser()
	a.login(auth.GitHub, acct("neg-a"), "")
	ca, resp, body := a.addPasskey(webauthn.AlgES256, "a", softauthn.Opts{})
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	bb := h.browser()
	bb.login(auth.GitHub, acct("neg-b"), "")
	cb, _, _ := bb.addPasskey(webauthn.AlgES256, "b", softauthn.Opts{})

	login := func(o softauthn.Opts, mutate func(*softauthn.AssertionJSON)) (int, string, *browser) {
		x := h.browser()
		opts := x.options(x.anonPost("/auth/passkey/login/begin", ""))
		as := ca.Assert(opts.PublicKey.Challenge, o)
		if mutate != nil {
			mutate(&as)
		}
		resp, body := x.anonPost("/auth/passkey/login/finish", softauthn.JSON(as))
		var e struct {
			Error struct{ Code, Message string }
		}
		_ = json.Unmarshal(body, &e)
		return resp.StatusCode, e.Error.Code + "/" + e.Error.Message, x
	}
	f := func(b byte) *byte { return &b }
	for _, tc := range []struct {
		name   string
		o      softauthn.Opts
		mutate func(*softauthn.AssertionJSON)
		want   string
	}{
		{"wrong origin", softauthn.Opts{Origin: "https://evil.example"}, nil, "passkey_rejected/origin"},
		{"wrong rp id", softauthn.Opts{RPID: "evil.example"}, nil, "passkey_rejected/rp_id_hash"},
		{"no UV", softauthn.Opts{Flags: f(webauthn.FlagUP | webauthn.FlagBE | webauthn.FlagBS)}, nil, "passkey_rejected/user_verified"},
		{"no UP", softauthn.Opts{Flags: f(webauthn.FlagUV | webauthn.FlagBE | webauthn.FlagBS)}, nil, "passkey_rejected/user_present"},
		{"wrong type", softauthn.Opts{Type: "webauthn.create"}, nil, "passkey_rejected/type"},
		{"cross origin", softauthn.Opts{CrossOrigin: true}, nil, "passkey_rejected/cross_origin"},
		{"wrong challenge", softauthn.Opts{Challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, nil, "passkey_rejected/challenge"},
		{"tampered client data", softauthn.Opts{TamperCD: true}, nil, "passkey_rejected/client_data"},
		{"tampered authenticator data", softauthn.Opts{TamperAD: true}, nil, "passkey_rejected/signature"},
		{"bad signature", softauthn.Opts{BadSig: true}, nil, "passkey_rejected/signature"},
		{"userHandle of another user", softauthn.Opts{UserHandle: cb.UserHandle}, nil, "passkey_rejected/user_handle"},
		{"no userHandle", softauthn.Opts{NoUserHandle: true}, nil, "passkey_rejected/user_handle"},
		{"unknown credential", softauthn.Opts{}, func(a *softauthn.AssertionJSON) { a.ID, a.RawID = "AAAA", "AAAA" }, "passkey_rejected/unknown_credential"},
		{"other user's credential id", softauthn.Opts{}, func(a *softauthn.AssertionJSON) {
			id := base64.RawURLEncoding.EncodeToString(cb.ID)
			a.ID, a.RawID = id, id
		}, "passkey_rejected/user_handle"},
		{"bad base64", softauthn.Opts{}, func(a *softauthn.AssertionJSON) { a.Response.Signature = "!!" }, "passkey_rejected/encoding"},
		{"id/rawId mismatch", softauthn.Opts{}, func(a *softauthn.AssertionJSON) { a.RawID = "AAAA" }, "bad_request/not a public-key credential"},
		{"wrong credential type", softauthn.Opts{}, func(a *softauthn.AssertionJSON) { a.Type = "password" }, "bad_request/not a public-key credential"},
		{"hostile authenticator data", softauthn.Opts{}, func(a *softauthn.AssertionJSON) {
			a.Response.AuthenticatorData = base64.RawURLEncoding.EncodeToString(make([]byte, 20))
		}, "passkey_rejected/authdata_length"},
	} {
		st, got, x := login(tc.o, tc.mutate)
		if st == 200 || !strings.HasPrefix(got, tc.want) || x.jar[auth.SessionCookie] != nil {
			t.Errorf("%s: %d %s (want %s)", tc.name, st, got, tc.want)
		}
	}

	// challenge: missing, replayed, expired, wrong ceremony kind
	x := h.browser()
	if resp, body := x.anonPost("/auth/passkey/login/finish", softauthn.JSON(ca.Assert("AAAA", softauthn.Opts{}))); resp.StatusCode != 400 ||
		errCode(t, body) != "ceremony_invalid" {
		t.Errorf("no ceremony: %d %s", resp.StatusCode, body)
	}
	opts := x.options(x.anonPost("/auth/passkey/login/begin", ""))
	cookie := *x.jar[auth.CeremonyCookie]
	as := softauthn.JSON(ca.Assert(opts.PublicKey.Challenge, softauthn.Opts{}))
	if resp, body := x.anonPost("/auth/passkey/login/finish", as); resp.StatusCode != 200 {
		t.Fatalf("good login %d %s", resp.StatusCode, body)
	}
	replay := h.browser()
	replay.jar[auth.CeremonyCookie] = &cookie
	if resp, body := replay.anonPost("/auth/passkey/login/finish", as); resp.StatusCode != 400 || errCode(t, body) != "ceremony_invalid" ||
		!strings.Contains(h.logs.String(), "reason=challenge_replayed") {
		t.Errorf("replay: %d %s", resp.StatusCode, body)
	}
	y := h.browser()
	opts = y.options(y.anonPost("/auth/passkey/login/begin", ""))
	h.clock.Advance(auth.CeremonyTTL + time.Second)
	if resp, _ := y.anonPost("/auth/passkey/login/finish", softauthn.JSON(ca.Assert(opts.PublicKey.Challenge, softauthn.Opts{}))); resp.StatusCode != 400 ||
		!strings.Contains(h.logs.String(), "reason=ceremony_expired") {
		t.Error("expired challenge accepted")
	}
	a.login(auth.GitHub, acct("neg-a"), "")
	bb.login(auth.GitHub, acct("neg-b"), "")
	// a login challenge cannot finish a registration
	opts = a.options(a.anonPost("/auth/passkey/login/begin", ""))
	reg := softauthn.NewCredential(webauthn.AlgES256, "nday.land", nil).Register(opts.PublicKey.Challenge, softauthn.Opts{})
	if resp, body := a.post("/auth/passkey/register/finish", softauthn.JSON(reg)); resp.StatusCode != 400 ||
		!strings.Contains(h.logs.String(), "reason=ceremony_kind") {
		t.Errorf("kind: %d %s", resp.StatusCode, body)
	}
	// B cannot register A's credential id (unique across all users)
	opts = bb.options(bb.post("/auth/passkey/register/begin", ""))
	if resp, body := bb.post("/auth/passkey/register/finish", softauthn.JSON(ca.Register(opts.PublicKey.Challenge, softauthn.Opts{}))); resp.StatusCode != 409 {
		t.Errorf("credential of another user registered: %d %s", resp.StatusCode, body)
	}
	// registration negatives through HTTP
	for name, o := range map[string]softauthn.Opts{
		"origin":      {Origin: "https://www.nday.land.evil.example"},
		"no UV":       {Flags: f(webauthn.FlagUP)},
		"rp id":       {RPID: "land"},
		"hostile key": {COSEKey: softauthn.Raw{0xbf, 0xff}},
		"attestation": {Fmt: "packed", AttStmt: softauthn.Map{"alg": -7}},
	} {
		if _, resp, body := a.addPasskey(webauthn.AlgES256, name, o); resp.StatusCode != 400 || errCode(t, body) != "passkey_rejected" {
			t.Errorf("register %s: %d %s", name, resp.StatusCode, body)
		}
	}
	// registration requires the session + CSRF
	if resp, body := a.do("POST", "/auth/passkey/register/begin", "", "Origin", origin); resp.StatusCode != 403 || errCode(t, body) != "csrf" {
		t.Errorf("register without csrf: %d %s", resp.StatusCode, body)
	}
	if resp, _ := h.browser().anonPost("/auth/passkey/register/begin", ""); resp.StatusCode != 401 {
		t.Error("anonymous register")
	}
	// cross-site and oversized
	if resp, _ := x.do("POST", "/auth/passkey/login/begin", "", "Origin", "https://evil.example"); resp.StatusCode != 403 {
		t.Error("cross-site login begin")
	}
	x.options(x.anonPost("/auth/passkey/login/begin", ""))
	if resp, body := x.anonPost("/auth/passkey/login/finish", `{"type":"public-key","id":"`+strings.Repeat("A", 70000)+`"}`); resp.StatusCode != 413 {
		t.Errorf("oversized: %d %s", resp.StatusCode, body)
	}
	if resp, _ := x.anonPost("/auth/passkey/login/finish", `{"type":`); resp.StatusCode != 400 {
		t.Error("malformed JSON")
	}
	if resp, _ := x.do("GET", "/auth/passkey/login/begin", ""); resp.StatusCode != 405 {
		t.Error("GET begin")
	}
}

func TestPasskeyCounter(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("ctr"), "")
	five := uint32(5)
	c, resp, _ := b.addPasskey(webauthn.AlgES256, "key", softauthn.Opts{SignCount: &five})
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	c.SignCount = 5
	if resp, body := h.browser().passkeyLogin(c, softauthn.Opts{}); resp.StatusCode != 200 { // 6 > 5
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp, body := h.browser().passkeyLogin(c, softauthn.Opts{SignCount: &five}); resp.StatusCode != 400 ||
		!strings.Contains(string(body), "counter_regression") {
		t.Errorf("regression accepted: %d %s", resp.StatusCode, body)
	}
	if h.count(`SELECT counter_regressions FROM passkeys`) != 1 || h.count(`SELECT sign_count::int FROM passkeys`) != 6 {
		t.Error("regression not recorded / counter changed")
	}
	// synced passkeys report 0/0: accepted every time
	z := h.browser()
	z.login(auth.GitHub, acct("zero"), "")
	c0, _, _ := z.addPasskey(webauthn.AlgEdDSA, "synced", softauthn.Opts{})
	for i := 0; i < 2; i++ {
		if resp, _ := h.browser().passkeyLogin(c0, softauthn.Opts{}); resp.StatusCode != 200 {
			t.Fatal("0/0 counter")
		}
	}
	// a counter dropping to 0 after being non-zero is refused too
	zero := uint32(0)
	if resp, _ := h.browser().passkeyLogin(c, softauthn.Opts{SignCount: &zero}); resp.StatusCode != 400 {
		t.Error("counter reset to 0 accepted")
	}
	// backup eligibility cannot change after registration
	be := byte(webauthn.FlagUP | webauthn.FlagUV)
	c.SignCount = 100
	if resp, body := h.browser().passkeyLogin(c, softauthn.Opts{Flags: &be}); resp.StatusCode != 400 ||
		!strings.Contains(string(body), "backup_eligibility_changed") {
		t.Errorf("BE change: %d %s", resp.StatusCode, body)
	}
}

func TestPasskeySignupAndLastMethod(t *testing.T) {
	t.Run("switched off", func(t *testing.T) {
		off := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
		ob := off.browser()
		if resp, _ := ob.anonPost("/auth/passkey/signup/begin", ""); resp.StatusCode != 404 {
			t.Error("signup available while switched off")
		}
		if m := ob.me(); !m.Passkeys.Enabled || m.Passkeys.Signup {
			t.Errorf("%+v", m.Passkeys)
		}
	})
	t.Run("switched on", func(t *testing.T) { testSignupOn(t) })
}

func testSignupOn(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, signup: true})
	b := h.browser()
	if !b.me().Passkeys.Signup {
		t.Fatal("signup not reported")
	}
	opts := b.options(b.anonPost("/auth/passkey/signup/begin", `{"display_name":"  Grace\u0000 Hopper "}`))
	if opts.PublicKey.User.DisplayName != "Grace Hopper" || len(b64d(opts.PublicKey.User.ID)) != 32 {
		t.Fatalf("%+v", opts.PublicKey.User)
	}
	c := softauthn.NewCredential(webauthn.AlgRS256, "nday.land", b64d(opts.PublicKey.User.ID))
	if resp, body := b.anonPost("/auth/passkey/signup/finish", softauthn.JSON(c.Register(opts.PublicKey.Challenge, softauthn.Opts{}))); resp.StatusCode != 200 {
		t.Fatalf("signup %d %s", resp.StatusCode, body)
	}
	m := b.me()
	if !m.SignedIn || len(m.User.Identities) != 0 || len(m.User.Passkeys) != 1 || *m.User.DisplayName != "Grace Hopper" {
		t.Fatalf("%+v", m.User)
	}
	if h.count(`SELECT count(*) FROM users`) != 1 {
		t.Fatal("users")
	}
	pid := m.User.Passkeys[0].ID
	// sign in again with it
	if resp, _ := h.browser().passkeyLogin(c, softauthn.Opts{}); resp.StatusCode != 200 {
		t.Fatal("login after signup")
	}
	// last method: the only passkey cannot be deleted
	if resp, body := b.post("/account/passkeys/"+pid+"/delete", ""); resp.StatusCode != 409 || errCode(t, body) != "last_identity" {
		t.Errorf("delete last passkey: %d %s", resp.StatusCode, body)
	}
	// link GitHub, then the passkey may go; then GitHub is last
	if loc := b.linkVia(auth.GitHub, "grace"); loc != "/?auth=linked" {
		t.Fatal(loc)
	}
	if resp, _ := b.post("/account/passkeys/"+pid+"/rename", `{"name":"YubiKey 5"}`); resp.StatusCode != 200 || b.me().User.Passkeys[0].Name != "YubiKey 5" {
		t.Error("rename")
	}
	if resp, _ := b.post("/account/passkeys/"+pid+"/rename", `{"name":"   "}`); resp.StatusCode != 400 {
		t.Error("empty rename")
	}
	if resp, body := b.post("/account/passkeys/"+pid+"/delete", ""); resp.StatusCode != 200 {
		t.Fatalf("delete passkey with identity left: %d %s", resp.StatusCode, body)
	}
	if resp, _ := b.post("/auth/github/unlink", ""); resp.StatusCode != 409 {
		t.Error("unlinked the last method")
	}
	// add a passkey back: now GitHub can be unlinked
	b.addPasskey(webauthn.AlgES256, "new", softauthn.Opts{})
	if resp, body := b.post("/auth/github/unlink", ""); resp.StatusCode != 200 {
		t.Errorf("unlink with passkey left: %d %s", resp.StatusCode, body)
	}
	// someone else's passkey id: 404
	o := h.browser()
	o.login(auth.GitHub, acct("other"), "")
	other := b.me().User.Passkeys[0].ID
	if resp, _ := o.post("/account/passkeys/"+other+"/delete", ""); resp.StatusCode != 404 {
		t.Error("deleted another user's passkey")
	}
	if resp, _ := o.post("/account/passkeys/"+other+"/rename", `{"name":"x"}`); resp.StatusCode != 404 {
		t.Error("renamed another user's passkey")
	}
	if resp, _ := o.post("/account/passkeys/not-a-uuid/delete", ""); resp.StatusCode != 404 {
		t.Error("bad id")
	}
	// suspended users can still sign in with a passkey
	id := b.me().User.ID
	if err := h.store.Suspend(context.Background(), id, nil, "test"); err != nil {
		t.Fatal(err)
	}
	// account deletion removes passkeys too
	if resp, _ := b.post("/account/delete", `{"confirm":true}`); resp.StatusCode != 200 || h.count(`SELECT count(*) FROM passkeys`) != 0 {
		t.Error("passkeys survive account deletion")
	}
}

func TestPasskeySuspendedSignIn(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("susp"), "")
	c, _, _ := b.addPasskey(webauthn.AlgES256, "k", softauthn.Opts{})
	if err := h.store.Suspend(context.Background(), b.me().User.ID, nil, "abuse"); err != nil {
		t.Fatal(err)
	}
	n := h.browser()
	if resp, _ := n.passkeyLogin(c, softauthn.Opts{}); resp.StatusCode != 200 || n.me().User.Status != "suspended" {
		t.Error("suspended passkey sign-in")
	}
}

func TestPasskeysDisabledAndHeaders(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, noPasskey: true})
	b := h.browser()
	for _, p := range []string{"/auth/passkey/login/begin", "/auth/passkey/register/begin", "/account/passkeys/x/delete"} {
		if resp, _ := b.anonPost(p, ""); resp.StatusCode != 404 {
			t.Errorf("%s with passkeys off: %d", p, resp.StatusCode)
		}
	}
	if b.me().Passkeys.Enabled {
		t.Error("me reports passkeys")
	}
	for _, p := range []string{"/", "/api/me", "/healthz"} {
		resp, _ := b.do("GET", p, "")
		if resp.Header.Get("Permissions-Policy") != web.PermissionsPolicy {
			t.Errorf("%s Permissions-Policy %q", p, resp.Header.Get("Permissions-Policy"))
		}
	}
}

func TestPasskeyRateLimit(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, burst: 2, signup: true})
	b := h.browser()
	b.anonPost("/auth/passkey/login/begin", "")
	b.anonPost("/auth/passkey/signup/begin", "")
	if resp, _ := b.anonPost("/auth/passkey/login/finish", "{}"); resp.StatusCode != 429 {
		t.Errorf("passkey endpoints not rate limited: %d", resp.StatusCode)
	}
}
