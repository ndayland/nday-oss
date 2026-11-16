// Package fakeidp is an in-process fake of the four sign-in providers
// (Google, Apple, GitHub, X) for tests. It runs on an httptest server and
// enforces what the real providers enforce for nday's flows: registered
// client id and redirect URI, client authentication (client_secret_post;
// HTTP Basic for X; an ES256 client-secret JWT for Apple), single-use
// authorization codes, PKCE S256 (all but Apple), and it echoes the nonce
// into RS256-signed ID tokens (Google, Apple).
package fakeidp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/jose"
)

// Client is a registered client at the fake.
type Client struct {
	ID, Secret  string
	RedirectURI string
	// Apple: verify the client-secret JWT with this key.
	ApplePub    *ecdsa.PublicKey
	AppleTeamID string
	AppleKeyID  string
}

// Account is a provider-side user.
type Account struct {
	Subject  string
	Name     string // Google name claim, GitHub name, X name
	Username string // GitHub login, X username
}

type grant struct {
	provider  string
	client    string
	redirect  string
	challenge string
	nonce     string
	account   Account
	issued    time.Time
}

// IDP is the fake. Mutate the knobs before use; they are read under mu.
type IDP struct {
	Server *httptest.Server
	Key    *rsa.PrivateKey
	Kid    string
	Now    func() time.Time

	mu      sync.Mutex
	clients map[string]Client // provider -> client
	codes   map[string]*grant
	tokens  map[string]Account // access token -> account (GitHub, X)

	// Knobs (tests).
	TokenStatus  int                                          // non-zero: token endpoint answers this status
	TokenBody    string                                       // non-empty: token endpoint answers this raw body
	MutateClaims func(provider string, claims map[string]any) // edit ID token claims
	SignToken    func(claims map[string]any) string           // replace ID token signing entirely
	UserStatus   int                                          // non-zero: user endpoint answers this status
	// IssParam: Google and Apple declare RFC 9207 support (Endpoints sets
	// IssParameterSupported) and their callbacks carry iss, unless OmitIss.
	IssParam, OmitIss bool

	// Seen records (tests assert on them).
	TokenRequests                                int
	LastAppleSecretHeader, LastAppleSecretClaims map[string]any
	LastAuthorizeQuery                           url.Values
}

// New starts a fake; close it with t.Cleanup(idp.Server.Close).
func New() *IDP {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	f := &IDP{Key: k, Kid: "k1", clients: map[string]Client{}, codes: map[string]*grant{}, tokens: map[string]Account{},
		Now: time.Now}
	mux := http.NewServeMux()
	for _, p := range auth.AllProviders {
		p := p
		mux.HandleFunc("/"+p+"/token", func(w http.ResponseWriter, r *http.Request) { f.token(w, r, p) })
		mux.HandleFunc("/"+p+"/jwks", f.jwks)
	}
	mux.HandleFunc("/github/user", func(w http.ResponseWriter, r *http.Request) { f.user(w, r, auth.GitHub) })
	mux.HandleFunc("/x/users/me", func(w http.ResponseWriter, r *http.Request) { f.user(w, r, auth.X) })
	f.Server = httptest.NewServer(mux)
	return f
}

// Issuer of the fake's ID tokens for provider.
func (f *IDP) Issuer(p string) string { return f.Server.URL + "/" + p }

// Endpoints for auth.Options.Endpoints.
func (f *IDP) Endpoints() map[string]auth.Endpoints {
	u := f.Server.URL
	return map[string]auth.Endpoints{
		auth.Google: {AuthURL: u + "/google/authorize", TokenURL: u + "/google/token", JWKSURL: u + "/google/jwks",
			Issuers: []string{f.Issuer(auth.Google)}, IssParameterSupported: f.IssParam},
		auth.Apple: {AuthURL: u + "/apple/authorize", TokenURL: u + "/apple/token", JWKSURL: u + "/apple/jwks",
			Issuers: []string{f.Issuer(auth.Apple)}, AppleAudience: f.Issuer(auth.Apple), IssParameterSupported: f.IssParam},
		auth.GitHub: {AuthURL: u + "/github/authorize", TokenURL: u + "/github/token", UserURL: u + "/github/user"},
		auth.X:      {AuthURL: u + "/x/authorize", TokenURL: u + "/x/token", UserURL: u + "/x/users/me"},
	}
}

// Register registers the client for provider.
func (f *IDP) Register(provider string, c Client) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients[provider] = c
}

// Approve plays the user consenting at the provider: it validates the
// authorization request URL produced by nday and returns the callback URL
// the provider would redirect the browser to (with code and state).
func (f *IDP) Approve(provider, authorizeURL string, acct Account) (string, error) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.LastAuthorizeQuery = q
	c, ok := f.clients[provider]
	if !ok || q.Get("client_id") != c.ID {
		return "", errors.New("fake: unknown client_id")
	}
	if q.Get("redirect_uri") != c.RedirectURI {
		return "", errors.New("fake: redirect_uri mismatch")
	}
	if q.Get("response_type") != "code" || q.Get("state") == "" {
		return "", errors.New("fake: bad response_type/state")
	}
	g := &grant{provider: provider, client: c.ID, redirect: c.RedirectURI, nonce: q.Get("nonce"), account: acct, issued: f.Now()}
	switch provider {
	case auth.Apple:
		if q.Get("response_mode") != "query" || q.Get("scope") != "" {
			return "", errors.New("fake: apple query mode needs no scope")
		}
		if q.Get("code_challenge") != "" {
			return "", errors.New("fake: apple does not document PKCE")
		}
	default:
		if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 {
			return "", errors.New("fake: PKCE S256 required")
		}
		g.challenge = q.Get("code_challenge")
	}
	if (provider == auth.Google || provider == auth.Apple) && g.nonce == "" {
		return "", errors.New("fake: nonce required")
	}
	if provider == auth.Google && q.Get("scope") != "openid profile" {
		return "", errors.New("fake: google scope must be 'openid profile'")
	}
	if provider == auth.X && q.Get("scope") != "users.read tweet.read" {
		return "", errors.New("fake: x scope")
	}
	if provider == auth.GitHub && q.Has("scope") {
		return "", errors.New("fake: github: no scope expected")
	}
	code := randStr()
	f.codes[code] = g
	cb, _ := url.Parse(c.RedirectURI)
	cq := url.Values{"code": {code}, "state": {q.Get("state")}}
	if f.IssParam && !f.OmitIss && (provider == auth.Google || provider == auth.Apple) {
		cq.Set("iss", f.Issuer(provider))
	}
	cb.RawQuery = cq.Encode()
	return cb.String(), nil
}

// Deny returns the callback URL for a refused consent.
func (f *IDP) Deny(provider, authorizeURL string) string {
	u, _ := url.Parse(authorizeURL)
	q := u.Query()
	cb, _ := url.Parse(q.Get("redirect_uri"))
	cb.RawQuery = url.Values{"error": {"access_denied"}, "state": {q.Get("state")},
		"error_description": {"The user <b>denied</b> SECRET-DESCRIPTION"}}.Encode()
	return cb.String()
}

func randStr() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *IDP) jwks(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	k, kid := f.Key, f.Kid
	f.mu.Unlock()
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, 200, map[string]any{"keys": []any{jose.JWK(&k.PublicKey, kid)}})
}

// Rotate replaces the signing key (new kid).
func (f *IDP) Rotate(kid string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	f.Key, f.Kid = k, kid
	f.mu.Unlock()
}

func (f *IDP) token(w http.ResponseWriter, r *http.Request, p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.TokenRequests++
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "invalid_request"})
		return
	}
	if f.TokenStatus != 0 || f.TokenBody != "" {
		st := f.TokenStatus
		if st == 0 {
			st = 200
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		body := f.TokenBody
		if body == "" {
			body = `{"error":"server_error","error_description":"SECRET-PROVIDER-TEXT"}`
		}
		_, _ = w.Write([]byte(body))
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	c := f.clients[p]
	fail := func(code string) {
		writeJSON(w, 400, map[string]string{"error": code, "error_description": "SECRET-PROVIDER-TEXT"})
	}
	// client authentication
	switch p {
	case auth.X:
		id, sec, ok := r.BasicAuth()
		if !ok || r.PostForm.Has("client_secret") {
			fail("invalid_client")
			return
		}
		id, _ = url.QueryUnescape(id)
		sec, _ = url.QueryUnescape(sec)
		if id != c.ID || sec != c.Secret {
			fail("invalid_client")
			return
		}
	case auth.Apple:
		if r.PostForm.Get("client_id") != c.ID || !f.checkAppleSecret(c, r.PostForm.Get("client_secret")) {
			fail("invalid_client")
			return
		}
	default:
		if r.PostForm.Get("client_id") != c.ID || r.PostForm.Get("client_secret") != c.Secret {
			fail("invalid_client")
			return
		}
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		fail("unsupported_grant_type")
		return
	}
	g := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code")) // single use
	if g == nil || g.provider != p || g.redirect != r.PostForm.Get("redirect_uri") || f.Now().Sub(g.issued) > 5*time.Minute {
		fail("invalid_grant")
		return
	}
	if g.challenge != "" {
		v := r.PostForm.Get("code_verifier")
		h := sha256.Sum256([]byte(v))
		if len(v) < 43 || base64.RawURLEncoding.EncodeToString(h[:]) != g.challenge {
			fail("invalid_grant")
			return
		}
	} else if r.PostForm.Has("code_verifier") {
		fail("invalid_request")
		return
	}
	at := "AT-" + randStr()
	resp := map[string]any{"access_token": at, "token_type": "bearer", "expires_in": 3600}
	if p == auth.Google || p == auth.Apple {
		now := f.Now()
		claims := map[string]any{"iss": f.Issuer(p), "aud": c.ID, "sub": g.account.Subject,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": g.nonce}
		if p == auth.Google && g.account.Name != "" {
			claims["name"] = g.account.Name
		}
		if f.MutateClaims != nil {
			f.MutateClaims(p, claims)
		}
		var tok string
		if f.SignToken != nil {
			tok = f.SignToken(claims)
		} else {
			var err error
			if tok, err = jose.SignRS256(f.Key, f.Kid, claims); err != nil {
				fail("server_error")
				return
			}
		}
		resp["id_token"] = tok
		resp["refresh_token"] = "RT-" + randStr()
	} else {
		f.tokens[at] = g.account
	}
	writeJSON(w, 200, resp)
}

func (f *IDP) checkAppleSecret(c Client, tok string) bool {
	hdr, payload, err := jose.VerifyES256(c.ApplePub, tok)
	if err != nil {
		return false
	}
	var h, cl map[string]any
	if json.Unmarshal(hdr, &h) != nil || json.Unmarshal(payload, &cl) != nil {
		return false
	}
	f.LastAppleSecretHeader, f.LastAppleSecretClaims = h, cl
	now := f.Now().Unix()
	exp, _ := cl["exp"].(float64)
	iat, _ := cl["iat"].(float64)
	return h["alg"] == "ES256" && h["kid"] == c.AppleKeyID && cl["iss"] == c.AppleTeamID && cl["sub"] == c.ID &&
		cl["aud"] == f.Issuer(auth.Apple) && int64(iat) <= now+60 && int64(exp) > now && exp-iat <= 15777000
}

func (f *IDP) user(w http.ResponseWriter, r *http.Request, p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.UserStatus != 0 {
		writeJSON(w, f.UserStatus, map[string]string{"message": "SECRET-PROVIDER-TEXT"})
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	acct, known := f.tokens[tok]
	if !ok || !known || r.Header.Get("User-Agent") == "" {
		writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
		return
	}
	switch p {
	case auth.GitHub:
		var name any
		if acct.Name != "" {
			name = acct.Name
		}
		var id json.Number = json.Number(acct.Subject)
		writeJSON(w, 200, map[string]any{"id": id, "login": acct.Username, "name": name, "email": "should-not-be-stored@example.com"})
	default:
		writeJSON(w, 200, map[string]any{"data": map[string]any{"id": acct.Subject, "name": acct.Name, "username": acct.Username}})
	}
}

// String for debugging.
func (f *IDP) String() string { return fmt.Sprintf("fakeidp(%s)", f.Server.URL) }
