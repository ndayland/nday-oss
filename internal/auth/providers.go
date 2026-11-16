package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"nday.land/nday/internal/auth/jose"
)

// Endpoints of one provider. The production values are below (each backed
// by the provider documentation quoted in docs/auth.md); tests point them at
// httptest servers.
type Endpoints struct {
	AuthURL  string
	TokenURL string
	UserURL  string   // GitHub, X: "who am I"
	JWKSURL  string   // Google, Apple: ID token keys
	Issuers  []string // Google, Apple: accepted iss values
	// IssParameterSupported: the provider declares RFC 9207
	// authorization_response_iss_parameter_supported, so the callback must
	// carry iss. Set only after checking the provider's discovery
	// document; false for every production provider until then.
	IssParameterSupported bool
	// AppleAudience is the aud of the Apple client-secret JWT.
	AppleAudience string
}

// ProductionEndpoints, verified against the providers' documentation and
// discovery documents on 2026-11-13 (docs/auth.md).
var ProductionEndpoints = map[string]Endpoints{
	Google: {
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
		Issuers:  []string{"https://accounts.google.com", "accounts.google.com"},
		// https://accounts.google.com/.well-known/openid-configuration has
		// "authorization_response_iss_parameter_supported": true (fetched
		// with curl by the owner on 2026-11-13). Apple's discovery document
		// has no such field (same day), so Apple stays off.
		IssParameterSupported: true,
	},
	Apple: {
		AuthURL:       "https://appleid.apple.com/auth/authorize",
		TokenURL:      "https://appleid.apple.com/auth/token",
		JWKSURL:       "https://appleid.apple.com/auth/keys",
		Issuers:       []string{"https://appleid.apple.com"},
		AppleAudience: "https://appleid.apple.com",
	},
	GitHub: {
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
		UserURL:  "https://api.github.com/user",
	},
	X: {
		AuthURL:  "https://x.com/i/oauth2/authorize",
		TokenURL: "https://api.x.com/2/oauth2/token",
		UserURL:  "https://api.x.com/2/users/me",
	},
}

// UserAgent is the generic User-Agent sent to providers (GitHub requires one).
const UserAgent = "nday-auth/1.0"

// MaxProviderResponse caps every provider response body.
const MaxProviderResponse = 1 << 20

// NewProviderClient returns the HTTP client used for provider calls:
// 10 s overall timeout, redirects are never followed, TLS 1.2+ with normal
// certificate verification, no cookies.
func NewProviderClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = 10 * time.Second
	tr.MaxResponseHeaderBytes = 64 << 10
	return &http.Client{
		Transport:     tr,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// providerIdentity is what a completed provider flow yields.
type providerIdentity struct {
	Subject     string
	Handle      string // provider-side handle, display only
	DisplayName string // sanitised
}

// providerError is a failure talking to the provider. Code is a short,
// sanitised machine code for logs; provider-supplied text is never kept.
type providerError struct {
	Step string // token, userinfo, id_token
	Code string
}

func (e *providerError) Error() string { return "provider " + e.Step + ": " + e.Code }

var codeRe = regexp.MustCompile(`^[a-z0-9_.\-]{1,64}$`)

// safeCode keeps a provider error code only if it looks like one.
func safeCode(s string) string {
	s = strings.ToLower(s)
	if codeRe.MatchString(s) {
		return s
	}
	return "unrecognised"
}

// provider is one configured provider.
type provider struct {
	name  string
	creds ProviderCredentials
	ep    Endpoints
	jwks  *jose.JWKS

	appleMu     sync.Mutex
	appleSecret string
	appleExp    time.Time
}

func (p *provider) oidc() bool { return p.name == Google || p.name == Apple }

// pkce reports whether the provider gets a PKCE challenge. Apple documents
// no code_challenge parameter, so none is sent there (state + nonce + the
// client secret protect that flow).
func (p *provider) pkce() bool { return p.name != Apple }

// authURL builds the authorization request.
func (p *provider) authURL(redirectURI, state, nonce, verifier string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.creds.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	switch p.name {
	case Google:
		q.Set("scope", "openid profile")
		q.Set("nonce", nonce)
	case Apple:
		// No scope: Apple then allows response_mode=query, so the callback
		// is a top-level GET and no cross-site POST is needed. The price is
		// that Apple never sends a name (it only does so via form_post).
		q.Set("response_mode", "query")
		q.Set("nonce", nonce)
	case GitHub:
		// No scope: read-only access to public information is enough for GET /user.
	case X:
		q.Set("scope", "users.read tweet.read")
	}
	if p.pkce() {
		q.Set("code_challenge", pkceChallenge(verifier))
		q.Set("code_challenge_method", "S256")
	}
	return p.ep.AuthURL + "?" + q.Encode()
}

// clientSecret returns the client secret, minting the Apple ES256 JWT when
// needed (valid 1 hour, regenerated 5 minutes before expiry).
func (p *provider) clientSecret(now time.Time) (string, error) {
	if p.name != Apple {
		return p.creds.ClientSecret, nil
	}
	p.appleMu.Lock()
	defer p.appleMu.Unlock()
	if p.appleSecret != "" && now.Before(p.appleExp.Add(-5*time.Minute)) {
		return p.appleSecret, nil
	}
	tok, exp, err := AppleClientSecret(p.creds.AppleKey, p.creds.TeamID, p.creds.KeyID, p.creds.ClientID, p.ep.AppleAudience, now)
	if err != nil {
		return "", err
	}
	p.appleSecret, p.appleExp = tok, exp
	return tok, nil
}

// AppleClientSecretLifetime is how long a minted Apple client secret is valid
// (Apple allows up to 15777000 s; short-lived is safer).
const AppleClientSecretLifetime = time.Hour

// AppleClientSecret mints the Sign in with Apple client secret: an ES256 JWT
// with header {alg: ES256, kid: keyID} and claims iss=teamID, iat, exp,
// aud=https://appleid.apple.com, sub=servicesID.
func AppleClientSecret(key *ecdsa.PrivateKey, teamID, keyID, servicesID, aud string, now time.Time) (string, time.Time, error) {
	if aud == "" {
		aud = "https://appleid.apple.com"
	}
	exp := now.Add(AppleClientSecretLifetime)
	tok, err := jose.SignES256(key, keyID, map[string]any{
		"iss": teamID, "iat": now.Unix(), "exp": exp.Unix(), "aud": aud, "sub": servicesID,
	})
	return tok, exp, err
}

// exchange runs the token request and returns the identity.
func (p *provider) exchange(ctx context.Context, hc *http.Client, code, redirectURI, verifier, nonce string, now time.Time) (*providerIdentity, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	if p.pkce() {
		form.Set("code_verifier", verifier)
	}
	secret, err := p.clientSecret(now)
	if err != nil {
		return nil, &providerError{"client_secret", "mint_failed"}
	}
	basic := p.name == X // X: confidential clients authenticate with HTTP Basic
	if !basic {
		form.Set("client_id", p.creds.ClientID)
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.ep.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &providerError{"token", "request"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if basic {
		req.SetBasicAuth(url.QueryEscape(p.creds.ClientID), url.QueryEscape(secret))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
	}
	status, err := doJSON(hc, req, &tok)
	if err != nil {
		return nil, &providerError{"token", err.Error()}
	}
	if tok.Error != "" {
		return nil, &providerError{"token", "error_" + safeCode(tok.Error)}
	}
	if status != http.StatusOK {
		return nil, &providerError{"token", "http_" + strconv.Itoa(status)}
	}
	if p.oidc() {
		if tok.IDToken == "" {
			return nil, &providerError{"token", "no_id_token"}
		}
		c, err := jose.Verify(ctx, tok.IDToken, p.jwks, jose.Expect{
			Issuers: p.ep.Issuers, Audience: p.creds.ClientID, Nonce: nonce, Now: now})
		if err != nil {
			return nil, &providerError{"id_token", idTokenCode(err)}
		}
		id := &providerIdentity{Subject: c.Sub}
		if p.name == Google {
			id.DisplayName = SanitizeDisplayName(c.Name)
		}
		return id, nil
	}
	if tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "bearer") {
		return nil, &providerError{"token", "no_bearer_token"}
	}
	return p.whoami(ctx, hc, tok.AccessToken)
}

func idTokenCode(err error) string {
	for _, e := range []struct {
		err  error
		code string
	}{{jose.ErrAlgorithm, "alg"}, {jose.ErrUnknownKey, "unknown_kid"}, {jose.ErrSignature, "signature"},
		{jose.ErrClaims, "claims"}, {jose.ErrMalformed, "malformed"}} {
		if errors.Is(err, e.err) {
			if e.err == jose.ErrClaims {
				// "jose: claim check failed: aud" -> claims_aud
				if after, ok := strings.CutPrefix(err.Error(), jose.ErrClaims.Error()+": "); ok {
					return "claims_" + safeCode(after)
				}
			}
			return e.code
		}
	}
	return "invalid"
}

// whoami calls GitHub's GET /user or X's GET /2/users/me.
func (p *provider) whoami(ctx context.Context, hc *http.Client, accessToken string) (*providerIdentity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.ep.UserURL, nil)
	if err != nil {
		return nil, &providerError{"userinfo", "request"}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", UserAgent)
	if p.name == GitHub {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	switch p.name {
	case GitHub:
		var u struct {
			ID    json.Number `json:"id"`
			Login string      `json:"login"`
			Name  *string     `json:"name"`
		}
		if err := userCall(hc, req, &u); err != nil {
			return nil, err
		}
		if _, err := strconv.ParseInt(u.ID.String(), 10, 64); err != nil || u.ID.String() == "0" {
			return nil, &providerError{"userinfo", "bad_id"}
		}
		id := &providerIdentity{Subject: u.ID.String(), Handle: cleanHandle(u.Login)}
		if u.Name != nil {
			id.DisplayName = SanitizeDisplayName(*u.Name)
		}
		if id.DisplayName == "" {
			id.DisplayName = SanitizeDisplayName(id.Handle)
		}
		return id, nil
	default: // X
		var u struct {
			Data struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Username string `json:"username"`
			} `json:"data"`
		}
		if err := userCall(hc, req, &u); err != nil {
			return nil, err
		}
		if !digitsRe.MatchString(u.Data.ID) {
			return nil, &providerError{"userinfo", "bad_id"}
		}
		return &providerIdentity{Subject: u.Data.ID, Handle: cleanHandle(u.Data.Username),
			DisplayName: SanitizeDisplayName(u.Data.Name)}, nil
	}
}

var digitsRe = regexp.MustCompile(`^[0-9]{1,30}$`)

func cleanHandle(s string) string {
	s = SanitizeDisplayName(s)
	if len(s) > 100 {
		return ""
	}
	return s
}

func userCall(hc *http.Client, req *http.Request, v any) error {
	status, err := doJSON(hc, req, v)
	if err != nil {
		return &providerError{"userinfo", err.Error()}
	}
	if status != http.StatusOK {
		return &providerError{"userinfo", "http_" + strconv.Itoa(status)}
	}
	return nil
}

// doJSON performs req and decodes a JSON body of at most
// MaxProviderResponse bytes into v. Returned errors are short codes.
func doJSON(hc *http.Client, req *http.Request, v any) (int, error) {
	resp, err := hc.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Timeout") {
			return 0, errors.New("timeout")
		}
		return 0, errors.New("transport")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxProviderResponse+1))
	if err != nil {
		return resp.StatusCode, errors.New("read")
	}
	if len(body) > MaxProviderResponse {
		return resp.StatusCode, errors.New("too_large")
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, fmt.Errorf("redirect_%d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, v); err != nil {
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, fmt.Errorf("http_%d", resp.StatusCode)
		}
		return resp.StatusCode, errors.New("bad_json")
	}
	return resp.StatusCode, nil
}
