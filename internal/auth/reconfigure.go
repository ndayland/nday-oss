package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"nday.land/nday/internal/auth/jose"
)

// authState is everything derived from the replaceable configuration. It
// is immutable once stored: Reconfigure builds a new one and swaps the
// pointer, so a request that took it once (cur) sees one consistent
// configuration even while a reconfiguration happens.
type authState struct {
	cfg       *Config
	providers map[string]*provider
	enabled   []string     // provider names in AllProviders order
	signupRL  *RateLimiter // per-client passkey sign-up limit (SignupInterval)
}

// stateKey is the request context key of the authState a request uses.
type stateKey struct{}

// cur returns the configuration state of the request whose context is ctx
// (taken once by ServeHTTP), else the current one.
func (s *Service) cur(ctx context.Context) *authState {
	if ctx != nil {
		if st, ok := ctx.Value(stateKey{}).(*authState); ok && st != nil {
			return st
		}
	}
	return s.state.Load()
}

// applyDefaults fills the zero values that mean "default".
func applyDefaults(cfg *Config) {
	if cfg.SensitiveWindow <= 0 {
		cfg.SensitiveWindow = DefaultSensitiveWindow
	}
	if cfg.MaxPasskeys <= 0 {
		cfg.MaxPasskeys = DefaultMaxPasskeys
	}
	if cfg.SignupDaily <= 0 {
		cfg.SignupDaily = DefaultSignupDaily
	}
	if cfg.SignupInterval <= 0 {
		cfg.SignupInterval = DefaultSignupInterval
	}
}

// newState derives the state of cfg (defaults applied). prev (nil at New)
// is the state being replaced: a provider whose credentials did not change
// is kept as it is (its JWKS cache and Apple client-secret JWT survive), a
// changed one is rebuilt but shares the previous JWKS cache (the keys
// belong to the provider, not to the client). The sign-up limiter is kept
// while SignupInterval stays the same (or when fixed is given / was given
// to New).
func (s *Service) newState(cfg *Config, prev *authState, fixed *RateLimiter) *authState {
	st := &authState{cfg: cfg, providers: map[string]*provider{}}
	for _, name := range AllProviders {
		creds, ok := cfg.Providers[name]
		if !ok {
			continue
		}
		var old *provider
		if prev != nil {
			old = prev.providers[name]
		}
		var p *provider
		switch {
		case old != nil && sameCreds(old.creds, creds):
			p = old
		default:
			ep := ProductionEndpoints[name]
			if o, ok := s.endpoints[name]; ok {
				ep = o
			}
			p = &provider{name: name, creds: creds, ep: ep}
			if p.oidc() {
				if old != nil && old.jwks != nil {
					p.jwks = old.jwks
				} else {
					p.jwks = &jose.JWKS{URL: ep.JWKSURL, Client: s.hc, Now: s.now}
				}
			}
		}
		st.providers[name] = p
		st.enabled = append(st.enabled, name)
	}
	switch {
	case fixed != nil:
		st.signupRL = fixed
	case prev != nil && (s.signupFixed || prev.cfg.SignupInterval == cfg.SignupInterval):
		st.signupRL = prev.signupRL
	default:
		st.signupRL = NewRateLimiter(SignupBurst, cfg.SignupInterval)
	}
	return st
}

func sameCreds(a, b ProviderCredentials) bool {
	if a.ClientID != b.ClientID || a.ClientSecret != b.ClientSecret || a.TeamID != b.TeamID || a.KeyID != b.KeyID {
		return false
	}
	if a.AppleKey == nil || b.AppleKey == nil {
		return a.AppleKey == nil && b.AppleKey == nil
	}
	return a.AppleKey.Equal(b.AppleKey)
}

// Errors of CheckReconfigure / Reconfigure. They name the setting, never a
// value.
var (
	ErrReconfigureDisabled = errors.New("auth: the new configuration turns sign-in off entirely; that needs a restart")
	ErrReconfigureFixed    = errors.New("auth: the new configuration changes a setting that is fixed while the site runs")
)

// CheckReconfigure reports whether Reconfigure would accept cfg (it does
// not change anything). The parts that are fixed for the life of the
// service must be equal: NDAY_PUBLIC_URL (PublicOrigin), NDAY_AUTH_SECRET
// and NDAY_AUTH_SECRET_PREVIOUS (Secrets), and, when passkeys are on in both
// configurations, NDAY_AUTH_RP_ID and NDAY_AUTH_ORIGINS (RPID, Origins). A
// nil or disabled cfg is refused (sign-in is mounted at start-up).
func (s *Service) CheckReconfigure(cfg *Config) error {
	if !cfg.Enabled() {
		return ErrReconfigureDisabled
	}
	cur := s.state.Load().cfg
	var bad []error
	fixed := func(name string) {
		bad = append(bad, fmt.Errorf("%w: %s", ErrReconfigureFixed, name))
	}
	if cfg.PublicOrigin != cur.PublicOrigin {
		fixed(EnvPublicURL)
	}
	if !slices.EqualFunc(cfg.Secrets, cur.Secrets, bytes.Equal) {
		fixed(EnvSecret + " / " + EnvSecretPrevious)
	}
	// RPID and Origins are derived from environment-only variables; they
	// are empty while passkeys are off, so only two configurations with
	// passkeys on are compared.
	if cfg.Passkeys && cur.Passkeys {
		if cfg.RPID != cur.RPID {
			fixed(EnvRPID)
		}
		if !slices.Equal(cfg.Origins, cur.Origins) {
			fixed(EnvOrigins)
		}
	}
	return errors.Join(bad...)
}

// Reconfigure replaces the configuration of the running service: the
// providers and their credentials, passkeys on/off, passkey sign-up and its
// limits, MaxPasskeys, TermsVersion, the session lifetimes, the sensitive
// window and the handle hold. Requests that already started finish with
// the configuration they began with; new requests see cfg at once. The
// server secrets, the public origin, the WebAuthn RP id and origins, the
// pools, the other rate limiters and the session lookup slots stay as
// they are (CheckReconfigure). cfg is copied; the caller's value is not
// changed.
func (s *Service) Reconfigure(cfg *Config) error {
	s.reconfMu.Lock()
	defer s.reconfMu.Unlock()
	if err := s.CheckReconfigure(cfg); err != nil {
		return err
	}
	c := *cfg
	c.Providers = make(map[string]ProviderCredentials, len(cfg.Providers))
	for k, v := range cfg.Providers {
		c.Providers[k] = v
	}
	c.Origins = slices.Clone(cfg.Origins)
	c.Secrets = slices.Clone(cfg.Secrets)
	applyDefaults(&c)
	s.state.Store(s.newState(&c, s.state.Load(), nil))
	return nil
}
