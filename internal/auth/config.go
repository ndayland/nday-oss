package auth

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/auth/jose"
	"nday.land/nday/internal/auth/webauthn"
)

// Provider names (also the URL segment and the identities.provider value).
const (
	Google = "google"
	Apple  = "apple"
	GitHub = "github"
	X      = "x"
)

// AllProviders in display order.
var AllProviders = []string{Google, Apple, GitHub, X}

// Env variable names (see deploy/auth.env.example and docs/auth.md).
const (
	EnvPublicURL      = "NDAY_PUBLIC_URL"
	EnvSecret         = "NDAY_AUTH_SECRET"
	EnvSecretPrevious = "NDAY_AUTH_SECRET_PREVIOUS"
	EnvTermsVersion   = "NDAY_TERMS_VERSION"
	EnvSessionIdle    = "NDAY_AUTH_SESSION_IDLE"
	EnvSessionMax     = "NDAY_AUTH_SESSION_MAX"
	EnvHandleHold     = "NDAY_AUTH_HANDLE_HOLD"
	EnvPasskeys       = "NDAY_AUTH_PASSKEYS"
	EnvPasskeySignup  = "NDAY_AUTH_PASSKEY_SIGNUP"
	EnvRPID           = "NDAY_AUTH_RP_ID"
	EnvOrigins        = "NDAY_AUTH_ORIGINS"
	// Sensitive-action window and passkey limits.
	EnvSensitiveWindow = "NDAY_AUTH_SENSITIVE_WINDOW"
	EnvMaxPasskeys     = "NDAY_AUTH_MAX_PASSKEYS"
	EnvSignupDaily     = "NDAY_AUTH_PASSKEY_SIGNUP_DAILY"
	EnvSignupInterval  = "NDAY_AUTH_PASSKEY_SIGNUP_INTERVAL"

	EnvGoogleClientID     = "NDAY_AUTH_GOOGLE_CLIENT_ID"
	EnvGoogleClientSecret = "NDAY_AUTH_GOOGLE_CLIENT_SECRET"
	EnvGitHubClientID     = "NDAY_AUTH_GITHUB_CLIENT_ID"
	EnvGitHubClientSecret = "NDAY_AUTH_GITHUB_CLIENT_SECRET"
	EnvXClientID          = "NDAY_AUTH_X_CLIENT_ID"
	EnvXClientSecret      = "NDAY_AUTH_X_CLIENT_SECRET"
	EnvAppleServicesID    = "NDAY_AUTH_APPLE_SERVICES_ID"
	EnvAppleTeamID        = "NDAY_AUTH_APPLE_TEAM_ID"
	EnvAppleKeyID         = "NDAY_AUTH_APPLE_KEY_ID"
	EnvAppleKeyFile       = "NDAY_AUTH_APPLE_KEY_FILE"
	// EnvAppleKey is the .p8 key itself (PEM text); when set it is used
	// instead of EnvAppleKeyFile.
	EnvAppleKey = "NDAY_AUTH_APPLE_KEY"
)

// ProviderCredentials are one provider's client credentials.
type ProviderCredentials struct {
	ClientID     string
	ClientSecret string // Google, GitHub, X
	// Apple: the client secret is an ES256 JWT minted from these.
	TeamID   string
	KeyID    string
	AppleKey *ecdsa.PrivateKey
}

// Config is the validated auth configuration.
type Config struct {
	// PublicOrigin is scheme://host[:port] of the site, e.g. https://www.nday.land.
	PublicOrigin string
	// Secrets: [0] is current (seals and signs), the rest are accepted when
	// opening/verifying (rotation). Each >= 32 bytes.
	Secrets [][]byte
	// Providers that are enabled (complete configuration), by name.
	Providers map[string]ProviderCredentials
	// TermsVersion is the current terms version ("" = none published yet).
	TermsVersion string
	// SessionIdle and SessionMax are the idle and absolute session lifetimes.
	SessionIdle, SessionMax time.Duration
	// HandleHold is how long a released handle stays blocked.
	HandleHold time.Duration

	// Passkeys enables WebAuthn sign-in and passkey management.
	Passkeys bool
	// PasskeySignup allows creating an account with only a passkey.
	PasskeySignup bool
	// RPID is the WebAuthn relying party id (e.g. nday.land).
	RPID string
	// Origins are the accepted WebAuthn clientDataJSON origins.
	Origins []string

	// SensitiveWindow: registering a passkey, linking an identity and
	// deleting the account need a session created at most this long ago
	// (0 = DefaultSensitiveWindow).
	SensitiveWindow time.Duration
	// MaxPasskeys per user (0 = DefaultMaxPasskeys).
	MaxPasskeys int
	// SignupDaily caps passkey-only sign-ups per UTC day, all clients
	// together (0 = DefaultSignupDaily).
	SignupDaily int
	// SignupInterval: after a burst of SignupBurst, one passkey-only sign-up
	// per client address per SignupInterval (0 = DefaultSignupInterval).
	SignupInterval time.Duration
}

// Enabled reports whether sign-in is enabled at all (a provider, or passkeys).
func (c *Config) Enabled() bool { return c != nil && (len(c.Providers) > 0 || c.Passkeys) }

// Defaults.
const (
	DefaultSessionIdle = 14 * 24 * time.Hour
	DefaultSessionMax  = 60 * 24 * time.Hour
	DefaultHandleHold  = 90 * 24 * time.Hour

	DefaultSensitiveWindow = 15 * time.Minute
	DefaultMaxPasskeys     = 20
	DefaultSignupDaily     = 200
	DefaultSignupInterval  = time.Hour
	SignupBurst            = 3
)

var (
	idRe         = regexp.MustCompile(`^[\x21-\x7e]{1,512}$`)
	appleIDRe    = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	servicesIDRe = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,255}$`)
	termsRe      = regexp.MustCompile(`^[A-Za-z0-9._\-]{1,64}$`)
)

// FromEnv reads and validates the configuration. With no provider variable
// set and passkeys not explicitly on it returns (nil, nil): the feature is
// inert. Passkeys default to on when a provider is configured. Errors name the
// variable and the problem, never the value.
func FromEnv(lookup func(string) (string, bool)) (*Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	get := func(k string) string {
		v, _ := lookup(k)
		return strings.TrimSpace(v)
	}
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	// Apple's key is given either as PEM text (NDAY_AUTH_APPLE_KEY) or as a
	// file (NDAY_AUTH_APPLE_KEY_FILE); one of them completes the provider.
	const appleKeyEither = EnvAppleKey + " or " + EnvAppleKeyFile
	type spec struct {
		name string
		vars []string
	}
	specs := []spec{
		{Google, []string{EnvGoogleClientID, EnvGoogleClientSecret}},
		{Apple, []string{EnvAppleServicesID, EnvAppleTeamID, EnvAppleKeyID, appleKeyEither}},
		{GitHub, []string{EnvGitHubClientID, EnvGitHubClientSecret}},
		{X, []string{EnvXClientID, EnvXClientSecret}},
	}
	isSet := func(v string) bool {
		if v == appleKeyEither {
			return get(EnvAppleKey) != "" || get(EnvAppleKeyFile) != ""
		}
		return get(v) != ""
	}
	cfg := &Config{Providers: map[string]ProviderCredentials{}}
	for _, s := range specs {
		var set, missing []string
		for _, v := range s.vars {
			if isSet(v) {
				set = append(set, v)
			} else {
				missing = append(missing, v)
			}
		}
		if len(set) == 0 {
			continue
		}
		if len(missing) > 0 {
			bad("auth: provider %s is partly configured: %s set but %s missing (set all or none)",
				s.name, strings.Join(set, ", "), strings.Join(missing, ", "))
			continue
		}
		var pc ProviderCredentials
		switch s.name {
		case Apple:
			pc.ClientID = get(EnvAppleServicesID)
			pc.TeamID = get(EnvAppleTeamID)
			pc.KeyID = get(EnvAppleKeyID)
			if !servicesIDRe.MatchString(pc.ClientID) {
				bad("auth: %s must be the Services ID (letters, digits, '.', '-')", EnvAppleServicesID)
			}
			if !appleIDRe.MatchString(pc.TeamID) {
				bad("auth: %s must be the 10-character Team ID (A-Z, 0-9)", EnvAppleTeamID)
			}
			if !appleIDRe.MatchString(pc.KeyID) {
				bad("auth: %s must be the 10-character Key ID (A-Z, 0-9)", EnvAppleKeyID)
			}
			src, b := EnvAppleKey, []byte(get(EnvAppleKey))
			if len(b) == 0 {
				src = EnvAppleKeyFile
				var err error
				if b, err = os.ReadFile(get(EnvAppleKeyFile)); err != nil {
					bad("auth: %s: cannot read the .p8 key file: %v", EnvAppleKeyFile, errors.Unwrap(err))
					break
				}
			}
			// (ParseP8's errors describe the structure, never the bytes)
			k, err := jose.ParseP8(b)
			if err != nil {
				bad("auth: %s: %v", src, err)
				break
			}
			pc.AppleKey = k
		default:
			pc.ClientID = get(s.vars[0])
			pc.ClientSecret = get(s.vars[1])
			if !idRe.MatchString(pc.ClientID) {
				bad("auth: %s must be 1-512 printable ASCII characters without spaces", s.vars[0])
			}
			if !idRe.MatchString(pc.ClientSecret) {
				bad("auth: %s must be 1-512 printable ASCII characters without spaces", s.vars[1])
			}
		}
		cfg.Providers[s.name] = pc
	}
	onOff := func(k string, def bool) bool {
		switch strings.ToLower(get(k)) {
		case "":
			return def
		case "on", "1", "true", "yes":
			return true
		case "off", "0", "false", "no":
			return false
		}
		bad("auth: %s must be on or off", k)
		return false
	}
	cfg.Passkeys = onOff(EnvPasskeys, len(cfg.Providers) > 0)
	if len(cfg.Providers) == 0 && !cfg.Passkeys && len(errs) == 0 {
		return nil, nil
	}
	cfg.PasskeySignup = onOff(EnvPasskeySignup, false)
	if cfg.PasskeySignup && !cfg.Passkeys {
		bad("auth: %s=on needs passkeys (%s is off)", EnvPasskeySignup, EnvPasskeys)
	}

	origin, err := ParsePublicOrigin(get(EnvPublicURL))
	if err != nil {
		bad("auth: %s: %v", EnvPublicURL, err)
	}
	cfg.PublicOrigin = origin
	if cfg.Passkeys && err == nil {
		host := hostOf(origin)
		cfg.RPID = get(EnvRPID)
		if cfg.RPID == "" {
			cfg.RPID = strings.TrimPrefix(host, "www.")
		}
		if err := webauthn.ValidRPID(cfg.RPID, host); err != nil {
			bad("auth: %s: %v", EnvRPID, err)
		}
		cfg.Origins = []string{origin}
		if v := get(EnvOrigins); v != "" {
			cfg.Origins = nil
			for _, o := range strings.Split(v, ",") {
				po, err := ParsePublicOrigin(strings.TrimSpace(o))
				if err != nil {
					bad("auth: %s: %q %v", EnvOrigins, strings.TrimSpace(o), err)
					continue
				}
				if err := webauthn.ValidRPID(cfg.RPID, hostOf(po)); err != nil {
					bad("auth: %s: %v", EnvOrigins, err)
					continue
				}
				cfg.Origins = append(cfg.Origins, po)
			}
		}
	}

	for i, k := range []string{EnvSecret, EnvSecretPrevious} {
		v := get(k)
		if v == "" {
			if i == 0 {
				bad("auth: %s is required when a sign-in provider is configured (generate: openssl rand -base64 48)", k)
			}
			continue
		}
		s, err := decodeSecret(v)
		if err != nil {
			bad("auth: %s: %v", k, err)
			continue
		}
		cfg.Secrets = append(cfg.Secrets, s)
	}

	cfg.TermsVersion = get(EnvTermsVersion)
	if cfg.TermsVersion != "" && !termsRe.MatchString(cfg.TermsVersion) {
		bad("auth: %s must be 1-64 characters of A-Z a-z 0-9 . _ -", EnvTermsVersion)
	}
	dur := func(k string, def, lo, hi time.Duration) time.Duration {
		v := get(k)
		if v == "" {
			return def
		}
		d, err := parseDuration(v)
		if err != nil || d < lo || d > hi {
			bad("auth: %s must be a duration between %s and %s (e.g. 14d, 12h)", k, fmtDur(lo), fmtDur(hi))
			return def
		}
		return d
	}
	cfg.SessionIdle = dur(EnvSessionIdle, DefaultSessionIdle, 10*time.Minute, 365*24*time.Hour)
	cfg.SessionMax = dur(EnvSessionMax, DefaultSessionMax, time.Hour, 400*24*time.Hour)
	cfg.HandleHold = dur(EnvHandleHold, DefaultHandleHold, 0, 3650*24*time.Hour)
	cfg.SensitiveWindow = dur(EnvSensitiveWindow, DefaultSensitiveWindow, time.Minute, 24*time.Hour)
	cfg.SignupInterval = dur(EnvSignupInterval, DefaultSignupInterval, time.Second, 24*time.Hour)
	num := func(k string, def, lo, hi int) int {
		v := get(k)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			bad("auth: %s must be a whole number between %d and %d", k, lo, hi)
			return def
		}
		return n
	}
	cfg.MaxPasskeys = num(EnvMaxPasskeys, DefaultMaxPasskeys, 1, 100)
	cfg.SignupDaily = num(EnvSignupDaily, DefaultSignupDaily, 1, 1000000)
	if cfg.SessionIdle > cfg.SessionMax {
		bad("auth: %s must not be longer than %s", EnvSessionIdle, EnvSessionMax)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

func fmtDur(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}

// parseDuration accepts Go durations plus "<n>d".
func parseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		var d int
		if _, err := fmt.Sscanf(n, "%d", &d); err != nil || fmt.Sprint(d) != n || d < 0 || d > 100000 {
			return 0, errors.New("bad duration")
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func decodeSecret(v string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(v); err == nil {
			if len(b) < 32 {
				return nil, fmt.Errorf("decodes to %d bytes; at least 32 random bytes are required (openssl rand -base64 48)", len(b))
			}
			if err := lowEntropy(v, b); err != nil {
				return nil, err
			}
			return b, nil
		}
	}
	return nil, errors.New("must be base64 (standard or URL alphabet) of at least 32 random bytes (openssl rand -base64 48)")
}

// MinSecretDistinctBytes is the minimum number of distinct byte values in a
// decoded server secret. 32 random bytes have about 30 distinct values (the
// chance of fewer than 16 is below 1e-12); `openssl rand -hex 32` decoded as
// base64 gives 48 bytes with about 37.
const MinSecretDistinctBytes = 16

// placeholderSecrets are literal placeholders from docs and examples.
var placeholderSecrets = []string{"nday-auth-secret-please-change-me-in-production", "<base64 of at least 32 random bytes>"}

// lowEntropy refuses secrets that are obviously not random: a known
// placeholder or "change me" text; any exact periodic
// repetition (period <= half the length) or constant-step sequence in the
// text, in its base64 alphabet indices, in the decoded bytes, or in the
// hex-decoded bytes when the text is hex; or too few distinct byte values.
// Random secrets essentially never match (see TestSecretFalsePositives).
func lowEntropy(text string, b []byte) error {
	low := strings.ToLower(text)
	for _, p := range placeholderSecrets {
		if low == p {
			return errors.New("is the placeholder from the documentation; generate one with openssl rand -base64 48")
		}
	}
	for _, w := range []string{"changeme", "change-me", "change_me", "please-change"} {
		if strings.Contains(low, w) {
			return errors.New("looks like a placeholder (\"change me\"); generate one with openssl rand -base64 48")
		}
	}
	t := strings.TrimRight(text, "=")
	seqs := [][]byte{[]byte(t), b}
	for _, alpha := range []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"} {
		if idx, ok := alphabetIndices(t, alpha); ok {
			seqs = append(seqs, idx)
		}
	}
	if h, err := hex.DecodeString(t); err == nil {
		seqs = append(seqs, h)
	}
	for _, q := range seqs {
		if p := period(q); p > 0 {
			return fmt.Errorf("repeats a %d-element pattern, not random (openssl rand -base64 48)", p)
		}
		if constantStep(q) {
			return errors.New("is a constant-step sequence, not random (openssl rand -base64 48)")
		}
	}
	seen := map[byte]bool{}
	for _, c := range b {
		seen[c] = true
	}
	if len(seen) < MinSecretDistinctBytes {
		return fmt.Errorf("has only %d distinct byte values after decoding (random secrets have about 30); generate it with openssl rand -base64 48", len(seen))
	}
	return nil
}

func alphabetIndices(s, alpha string) ([]byte, bool) {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		j := strings.IndexByte(alpha, s[i])
		if j < 0 {
			return nil, false
		}
		out[i] = byte(j)
	}
	return out, true
}

// period returns the smallest p <= len/2 with q[i] == q[i-p] for all i >= p,
// or 0.
func period(q []byte) int {
	for p := 1; p <= len(q)/2; p++ {
		i := p
		for i < len(q) && q[i] == q[i-p] {
			i++
		}
		if i == len(q) {
			return p
		}
	}
	return 0
}

// constantStep reports whether q (at least 3 elements) has one constant
// difference (mod 256) between neighbours.
func constantStep(q []byte) bool {
	if len(q) < 3 {
		return false
	}
	d := q[1] - q[0]
	for i := 2; i < len(q); i++ {
		if q[i]-q[i-1] != d {
			return false
		}
	}
	return true
}

// ParsePublicOrigin validates the site origin. It must be https (http only
// for localhost / 127.0.0.1 / [::1] development), with no path beyond "/",
// no query, fragment or user info.
func ParsePublicOrigin(v string) (string, error) {
	if v == "" {
		return "", errors.New("is required when a sign-in provider is configured (e.g. https://www.nday.land)")
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", errors.New("must be an absolute URL like https://www.nday.land")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("must be an origin only (scheme://host[:port]) without path, query or user info")
	}
	host := u.Hostname()
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && local:
	default:
		return "", errors.New("must use https (http is allowed only for localhost)")
	}
	if strings.ToLower(u.Host) != u.Host {
		return "", errors.New("host must be lower case")
	}
	return u.Scheme + "://" + canonicalHost(u.Scheme, u.Host), nil
}

// canonicalHost drops an explicit default port (":443" for https, ":80" for
// http) and an empty port, so the configured origin equals what browsers
// send in Origin and clientDataJSON.
func canonicalHost(scheme, host string) string {
	def := map[string]string{"https": "443", "http": "80"}[scheme]
	if h, ok := strings.CutSuffix(host, ":"); ok {
		return h
	}
	if def != "" {
		if h, ok := strings.CutSuffix(host, ":"+def); ok && (!strings.Contains(h, ":") || strings.HasSuffix(h, "]")) {
			return h
		}
	}
	return host
}

func hostOf(origin string) string {
	u, _ := url.Parse(origin)
	return u.Hostname()
}

// RedirectURI is the callback URL registered with the provider.
func (c *Config) RedirectURI(provider string) string {
	return c.PublicOrigin + "/auth/" + provider + "/callback"
}
