package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"maps"
	"testing"
	"time"
)

// TestReconfigureKeepsCaches: a provider whose credentials did not change
// is kept (JWKS and Apple client-secret caches survive); a changed one is
// rebuilt but shares the JWKS cache; the sign-up limiter is replaced only
// when SignupInterval changes; the caller's Config is not modified.
func TestReconfigureKeepsCaches(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := &Config{PublicOrigin: "https://www.nday.land", Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)},
		Providers: map[string]ProviderCredentials{
			Google: {ClientID: "g", ClientSecret: "gs"},
			Apple:  {ClientID: "land.nday.web", TeamID: "ABCDE12345", KeyID: "KEYID12345", AppleKey: k1},
		}, SessionIdle: time.Hour, SessionMax: 2 * time.Hour}
	s, err := New(cfg, Options{Store: &Store{}})
	if err != nil {
		t.Fatal(err)
	}
	st0 := s.state.Load()
	edit := func(f func(*Config)) *authState {
		t.Helper()
		c := *s.Config()
		c.Providers = maps.Clone(c.Providers)
		f(&c)
		before := c
		if err := s.Reconfigure(&c); err != nil {
			t.Fatal(err)
		}
		if c.TermsVersion != before.TermsVersion || c.SignupDaily != before.SignupDaily {
			t.Fatal("Reconfigure changed the caller's Config")
		}
		return s.state.Load()
	}

	st1 := edit(func(c *Config) { c.TermsVersion = "v2"; c.SignupDaily = 0 })
	if st1.providers[Google] != st0.providers[Google] || st1.providers[Apple] != st0.providers[Apple] {
		t.Error("unchanged providers were rebuilt")
	}
	if st1.signupRL != st0.signupRL {
		t.Error("sign-up limiter replaced although the interval did not change")
	}
	if st1.cfg.SignupDaily != DefaultSignupDaily {
		t.Errorf("defaults not applied: SignupDaily %d", st1.cfg.SignupDaily)
	}

	st2 := edit(func(c *Config) {
		c.Providers[Google] = ProviderCredentials{ClientID: "g2", ClientSecret: "gs"}
		a := c.Providers[Apple]
		a.AppleKey = k2
		c.Providers[Apple] = a
		c.SignupInterval = 5 * time.Minute
	})
	for _, p := range []string{Google, Apple} {
		if st2.providers[p] == st1.providers[p] {
			t.Errorf("%s: changed credentials, same provider", p)
		}
		if st2.providers[p].jwks != st1.providers[p].jwks {
			t.Errorf("%s: JWKS cache not shared", p)
		}
	}
	if st2.providers[Google].creds.ClientID != "g2" {
		t.Error("new client id not used")
	}
	if st2.signupRL == st1.signupRL || st2.signupRL.Every != 5*time.Minute {
		t.Error("sign-up limiter not rebuilt for the new interval")
	}
	// a provider removed and added again starts fresh
	st3 := edit(func(c *Config) { delete(c.Providers, Google) })
	if st3.providers[Google] != nil || len(st3.enabled) != 1 {
		t.Fatalf("google still enabled: %v", st3.enabled)
	}
	st4 := edit(func(c *Config) { c.Providers[Google] = ProviderCredentials{ClientID: "g2", ClientSecret: "gs"} })
	if st4.providers[Google] == nil || st4.providers[Google].jwks == nil {
		t.Fatal("google not rebuilt")
	}

	// an injected sign-up limiter (Options.SignupLimit) is never replaced
	fixed := NewRateLimiter(1, time.Second)
	s2, err := New(&Config{PublicOrigin: "https://www.nday.land", Secrets: cfg.Secrets, Passkeys: true}, Options{Store: &Store{}, SignupLimit: fixed})
	if err != nil {
		t.Fatal(err)
	}
	c := *s2.Config()
	c.SignupInterval = time.Minute
	if err := s2.Reconfigure(&c); err != nil {
		t.Fatal(err)
	}
	if s2.state.Load().signupRL != fixed {
		t.Error("injected sign-up limiter replaced")
	}
}
