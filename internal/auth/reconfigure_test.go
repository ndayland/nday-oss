package auth_test

import (
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/fakeidp"
)

// current returns a deep enough copy of the service's configuration to
// edit for Reconfigure.
func current(h *harness) *auth.Config {
	c := *h.svc.Config()
	c.Providers = maps.Clone(c.Providers)
	return &c
}

func reconfigure(t *testing.T, h *harness, edit func(*auth.Config)) {
	t.Helper()
	c := current(h)
	edit(c)
	if err := h.svc.Reconfigure(c); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}
}

// rawMe is /api/me as a generic map (the session part included).
func (b *browser) rawMe() map[string]any {
	b.h.t.Helper()
	resp, body := b.do("GET", "/api/me", "")
	if resp.StatusCode != 200 {
		b.h.t.Fatalf("/api/me: %d %s", resp.StatusCode, body)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		b.h.t.Fatal(err)
	}
	if tok, _ := m["csrf_token"].(string); tok != "" {
		b.h.secret(tok)
	}
	return m
}

func TestReconfigureProviderCredentials(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub, auth.X}})
	const newSecret = "CLIENTSECRET-github-rotated"
	h.secret(newSecret)
	h.idp.Register(auth.GitHub, fakeidp.Client{ID: "client-github-2", Secret: newSecret, RedirectURI: h.cfg.RedirectURI(auth.GitHub)})
	reconfigure(t, h, func(c *auth.Config) {
		c.Providers[auth.GitHub] = auth.ProviderCredentials{ClientID: "client-github-2", ClientSecret: newSecret}
		delete(c.Providers, auth.X)
	})
	b := h.browser()
	authURL := b.start(auth.GitHub, "return=/hot")
	u, _ := url.Parse(authURL)
	if got := u.Query().Get("client_id"); got != "client-github-2" {
		t.Fatalf("client_id %q after Reconfigure", got)
	}
	cb, err := h.idp.Approve(auth.GitHub, authURL, acct("r1"))
	if err != nil {
		t.Fatal(err)
	}
	if loc := b.callback(cb); loc != "/welcome?next=%2Fhot&auth=ok" {
		t.Fatalf("callback with the new secret: %q", loc)
	}
	// the removed provider: its endpoints are gone at once
	for _, p := range []string{"/auth/x/start", "/auth/x/callback"} {
		if resp, body := b.do("GET", p, ""); resp.StatusCode != 404 || errCode(t, body) != "not_found" {
			t.Errorf("%s after removal: %d %s", p, resp.StatusCode, body)
		}
	}
	if m := b.me(); len(m.Providers) != 1 || m.Providers[0] != auth.GitHub {
		t.Errorf("providers %v", m.Providers)
	}
	if got := h.svc.Enabled(); len(got) != 1 || got[0] != auth.GitHub {
		t.Errorf("Enabled %v", got)
	}
	// and back: x answers again
	reconfigure(t, h, func(c *auth.Config) {
		c.Providers[auth.X] = auth.ProviderCredentials{ClientID: "client-x", ClientSecret: "CLIENTSECRET-x-value"}
	})
	b.start(auth.X, "")
}

func TestReconfigureSettingsSeenAtOnce(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, terms: "v1"})
	b := h.browser()
	b.login(auth.GitHub, acct("s1"), "")

	// sensitive window: 20 minutes after sign-in the default (15m) has passed
	h.clock.Advance(20 * time.Minute)
	if s := b.rawMe()["session"].(map[string]any); s["recent_sign_in"] != false {
		t.Fatalf("recent before: %v", s)
	}
	reconfigure(t, h, func(c *auth.Config) { c.SensitiveWindow = time.Hour })
	if s := b.rawMe()["session"].(map[string]any); s["recent_sign_in"] != true {
		t.Fatalf("recent after a longer window: %v", s)
	}

	// terms version
	reconfigure(t, h, func(c *auth.Config) { c.TermsVersion = "v2" })
	terms := b.rawMe()["user"].(map[string]any)["terms"].(map[string]any)
	if terms["current_version"] != "v2" {
		t.Fatalf("terms %v", terms)
	}
	if resp, body := b.post("/account/accept-terms", `{"version":"v1"}`); resp.StatusCode != 409 ||
		errCode(t, body) != "terms_version_mismatch" {
		t.Errorf("old version: %d %s", resp.StatusCode, body)
	}
	if resp, body := b.post("/account/accept-terms", `{"version":"v2"}`); resp.StatusCode != 200 {
		t.Errorf("new version: %d %s", resp.StatusCode, body)
	}

	// passkeys off: the passkey endpoints are gone, /api/me says so
	reconfigure(t, h, func(c *auth.Config) { c.Passkeys, c.PasskeySignup = false, false })
	if m := b.me(); m.Passkeys.Enabled {
		t.Error("passkeys still enabled in /api/me")
	}
	if resp, _ := b.do("POST", "/auth/passkey/login/begin", "", "Origin", origin, "Sec-Fetch-Site", "same-origin"); resp.StatusCode != 404 {
		t.Errorf("passkey login with passkeys off: %d", resp.StatusCode)
	}
	reconfigure(t, h, func(c *auth.Config) { c.Passkeys, c.PasskeySignup = true, true })
	if m := b.me(); !m.Passkeys.Enabled || !m.Passkeys.Signup {
		t.Errorf("passkeys back on: %+v", m.Passkeys)
	}
	if resp, body := b.do("POST", "/auth/passkey/login/begin", "", "Origin", origin, "Sec-Fetch-Site", "same-origin"); resp.StatusCode != 200 {
		t.Errorf("passkey login back on: %d %s", resp.StatusCode, body)
	}

	// session idle: two hours idle is fine with 14 days, not with 1 hour
	h.clock.Advance(2 * time.Hour)
	if !b.me().SignedIn {
		t.Fatal("signed out too early")
	}
	h.clock.Advance(2 * time.Hour)
	reconfigure(t, h, func(c *auth.Config) { c.SessionIdle = time.Hour })
	if b.me().SignedIn {
		t.Error("session still valid after a shorter idle time")
	}
	if got := h.svc.Config().SessionIdle; got != time.Hour {
		t.Errorf("Config().SessionIdle %v", got)
	}
}

func TestReconfigureRefusesFixedSettings(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	before := h.svc.Config()
	for name, edit := range map[string]func(*auth.Config){
		"origin":  func(c *auth.Config) { c.PublicOrigin = "https://evil.example" },
		"secrets": func(c *auth.Config) { c.Secrets = [][]byte{[]byte("0123456789abcdef0123456789abcdef")} },
		"rpid":    func(c *auth.Config) { c.RPID = "example.org" },
		"origins": func(c *auth.Config) { c.Origins = []string{origin} },
		"off":     func(c *auth.Config) { c.Providers = map[string]auth.ProviderCredentials{}; c.Passkeys = false },
	} {
		c := current(h)
		c.TermsVersion = "changed"
		edit(c)
		err := h.svc.Reconfigure(c)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if name == "off" {
			if !errors.Is(err, auth.ErrReconfigureDisabled) {
				t.Errorf("%s: %v", name, err)
			}
		} else if !errors.Is(err, auth.ErrReconfigureFixed) {
			t.Errorf("%s: %v", name, err)
		}
		if h.svc.Config() != before {
			t.Errorf("%s: the configuration changed", name)
		}
	}
	if err := h.svc.Reconfigure(nil); !errors.Is(err, auth.ErrReconfigureDisabled) {
		t.Errorf("nil: %v", err)
	}
	// passkeys off in the new configuration: RP id / origins are not compared
	c := current(h)
	c.Passkeys, c.RPID, c.Origins = false, "", nil
	if err := h.svc.Reconfigure(c); err != nil {
		t.Errorf("passkeys off: %v", err)
	}
}

// TestReconfigureConcurrent: requests and reconfigurations at once (run
// with -race).
func TestReconfigureConcurrent(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub, auth.Google}})
	a := current(h)
	bcfg := current(h)
	delete(bcfg.Providers, auth.Google)
	bcfg.TermsVersion, bcfg.Passkeys, bcfg.SignupInterval = "v9", false, 2*time.Minute
	stop := make(chan struct{})
	writer := make(chan struct{})
	go func() {
		defer close(writer)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c := a
			if i%2 == 1 {
				c = bcfg
			}
			if err := h.svc.Reconfigure(c); err != nil {
				t.Error(err)
				return
			}
			_ = h.svc.Enabled()
			_ = h.svc.Config().TermsVersion
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := h.browser()
			for i := 0; i < 40; i++ {
				if resp, _ := b.do("GET", "/api/me", ""); resp.StatusCode != 200 {
					t.Errorf("/api/me %d", resp.StatusCode)
				}
				if resp, _ := b.do("GET", "/auth/google/start", ""); resp.StatusCode != 302 && resp.StatusCode != 404 {
					t.Errorf("google start %d", resp.StatusCode)
				}
				resp, _ := b.do("POST", "/auth/passkey/login/begin", "", "Origin", origin, "Sec-Fetch-Site", "same-origin")
				if resp.StatusCode != 200 && resp.StatusCode != 404 {
					t.Errorf("passkey begin %d", resp.StatusCode)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-writer
}
