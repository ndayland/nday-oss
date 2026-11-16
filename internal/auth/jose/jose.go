// Package jose is the small subset of JOSE that sign-in needs, written on
// the standard library only:
//
//   - verifying OpenID Connect ID tokens (compact JWS, RS256 only) against a
//     provider's JWKS, with caching, rotation (unknown kid -> one rate-limited
//     refetch) and strict claim checks (iss, aud/azp, exp, iat, nonce, sub);
//   - signing an ES256 JWT (the Sign in with Apple client secret).
//
// The algorithm allow-list is fixed: a token whose header says anything but
// RS256 ("none", HS256, ES256, ...) is rejected before any key is looked at,
// so an RSA public key can never be used as an HMAC secret.
package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Errors returned by Verify (wrapped; test with errors.Is).
var (
	ErrMalformed  = errors.New("jose: malformed token")
	ErrAlgorithm  = errors.New("jose: algorithm not allowed")
	ErrUnknownKey = errors.New("jose: no key for kid")
	ErrSignature  = errors.New("jose: bad signature")
	ErrClaims     = errors.New("jose: claim check failed")
)

var b64 = base64.RawURLEncoding

// MaxTokenBytes bounds the size of a token we are willing to parse.
const MaxTokenBytes = 16 << 10

type header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// Claims are the ID token claims nday looks at. Name is optional (Google
// "profile" scope); everything else is checked by Verify.
type Claims struct {
	Iss   string      `json:"iss"`
	Sub   string      `json:"sub"`
	Aud   Audience    `json:"aud"`
	Azp   string      `json:"azp,omitempty"`
	Exp   NumericDate `json:"exp"`
	Iat   NumericDate `json:"iat"`
	Nonce string      `json:"nonce,omitempty"`
	Name  string      `json:"name,omitempty"`
}

// Audience accepts the JSON string or array form of "aud".
type Audience []string

// UnmarshalJSON implements json.Unmarshaler.
func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = Audience{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*a = l
	return nil
}

// NumericDate is seconds since the epoch (integer or decimal JSON number).
type NumericDate struct{ time.Time }

// UnmarshalJSON implements json.Unmarshaler.
func (d *NumericDate) UnmarshalJSON(b []byte) error {
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil || f < 0 || f > 1e11 {
		return fmt.Errorf("bad NumericDate %s", b)
	}
	d.Time = time.Unix(int64(f), 0).UTC()
	return nil
}

// Expect is what Verify requires of the token.
type Expect struct {
	Issuers  []string // any of these exact strings
	Audience string   // our client id
	Nonce    string   // the nonce we sent (required, compared in constant time)
	Now      time.Time
	Skew     time.Duration // allowed clock skew (default 60s)
	MaxAge   time.Duration // iat must be within MaxAge of Now (default 10m)
}

// Verify checks the token's signature with keys and its claims against exp.
func Verify(ctx context.Context, token string, keys *JWKS, exp Expect) (*Claims, error) {
	if len(token) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: too large", ErrMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: want 3 non-empty parts", ErrMalformed)
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, fmt.Errorf("%w: header json", ErrMalformed)
	}
	if h.Alg != "RS256" {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, trunc(h.Alg))
	}
	if len(h.Crit) > 0 {
		return nil, fmt.Errorf("%w: crit header not supported", ErrMalformed)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	pub, err := keys.Key(ctx, h.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, ErrSignature
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(pb))
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrMalformed)
	}
	if err := checkClaims(&c, exp); err != nil {
		return nil, err
	}
	return &c, nil
}

func checkClaims(c *Claims, exp Expect) error {
	skew := exp.Skew
	if skew <= 0 {
		skew = 60 * time.Second
	}
	maxAge := exp.MaxAge
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	now := exp.Now
	if now.IsZero() {
		now = time.Now()
	}
	okIss := false
	for _, i := range exp.Issuers {
		if c.Iss == i {
			okIss = true
		}
	}
	if !okIss {
		return fmt.Errorf("%w: iss", ErrClaims)
	}
	okAud := false
	for _, a := range c.Aud {
		if a == exp.Audience && a != "" {
			okAud = true
		}
	}
	if !okAud {
		return fmt.Errorf("%w: aud", ErrClaims)
	}
	// OIDC Core 3.1.3.7: with several audiences, azp must be us; if present it must be us.
	if (len(c.Aud) > 1 || c.Azp != "") && c.Azp != exp.Audience {
		return fmt.Errorf("%w: azp", ErrClaims)
	}
	if c.Exp.IsZero() || !now.Before(c.Exp.Add(skew)) {
		return fmt.Errorf("%w: expired", ErrClaims)
	}
	if c.Iat.IsZero() || c.Iat.After(now.Add(skew)) || c.Iat.Before(now.Add(-maxAge)) {
		return fmt.Errorf("%w: iat", ErrClaims)
	}
	if exp.Nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(exp.Nonce)) != 1 {
		return fmt.Errorf("%w: nonce", ErrClaims)
	}
	if c.Sub == "" || len(c.Sub) > 255 {
		return fmt.Errorf("%w: sub", ErrClaims)
	}
	return nil
}

func trunc(s string) string {
	if len(s) > 20 {
		return s[:20]
	}
	return s
}

// JWKS is a cached JSON Web Key Set fetched from URL.
//
// Keys are cached for the response's Cache-Control max-age clamped to
// [MinTTL, MaxTTL] (DefaultTTL when absent or no-store). A kid that is not in
// the cache triggers one refetch, at most once per RefetchInterval, so a
// flood of tokens with random kids cannot turn into a flood of requests to
// the provider. A failed refresh keeps the previous keys, which keep being
// served, and no fetch is tried again before RefetchInterval has passed.
// The mutex is never held across the network call: concurrent callers that
// need a refresh share one fetch (singleflight) and wait for it without the
// lock, each bounded by its own context.
type JWKS struct {
	URL    string
	Client *http.Client
	Now    func() time.Time

	MinTTL, MaxTTL, DefaultTTL, RefetchInterval time.Duration

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expires   time.Time
	retryAt   time.Time // no fetch before this (back-off after a failure)
	lastFetch time.Time
	lastMiss  time.Time // last refetch caused by an unknown kid
	fetches   int
	inflight  *jwksFetch
}

// jwksFetch is one fetch shared by every caller waiting for it.
type jwksFetch struct{ done chan struct{} }

// MaxJWKSBytes caps the JWKS response size.
const MaxJWKSBytes = 64 << 10

func (j *JWKS) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// Fetches is the number of HTTP fetches so far (tests).
func (j *JWKS) Fetches() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.fetches
}

func (j *JWKS) refetchInterval() time.Duration {
	if j.RefetchInterval > 0 {
		return j.RefetchInterval
	}
	return 30 * time.Second
}

// Key returns the RSA key for kid, refreshing the set when needed.
func (j *JWKS) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	j.mu.Lock()
	now := j.now()
	if (j.keys == nil || now.After(j.expires)) && !now.Before(j.retryAt) {
		j.refresh(ctx, now)
	}
	if k, ok := j.keys[kid]; ok {
		j.mu.Unlock()
		return k, nil
	}
	if (j.lastMiss.IsZero() || now.Sub(j.lastMiss) >= j.refetchInterval()) && !now.Before(j.retryAt) {
		j.lastMiss = now
		j.refresh(ctx, now)
		if k, ok := j.keys[kid]; ok {
			j.mu.Unlock()
			return k, nil
		}
	}
	j.mu.Unlock()
	return nil, ErrUnknownKey
}

// refresh fetches the set, or waits for a fetch already in flight. It is
// called and returns with j.mu held, but releases it during the fetch.
func (j *JWKS) refresh(ctx context.Context, now time.Time) {
	if f := j.inflight; f != nil {
		j.mu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
		}
		j.mu.Lock()
		return
	}
	f := &jwksFetch{done: make(chan struct{})}
	j.inflight = f
	j.lastFetch = now
	j.fetches++
	j.mu.Unlock()
	// The fetch serves every waiter, so one caller's cancellation must not
	// fail it; the client's own timeout bounds it.
	keys, ttl, err := j.fetch(context.WithoutCancel(ctx))
	j.mu.Lock()
	j.inflight = nil
	close(f.done)
	if err != nil {
		// keep (and keep serving) the stale keys; no new fetch before
		// RefetchInterval
		if j.keys == nil {
			j.keys = map[string]*rsa.PublicKey{}
		}
		j.retryAt = now.Add(j.refetchInterval())
		return
	}
	j.keys = keys
	j.expires = now.Add(ttl)
	j.retryAt = time.Time{}
}

func (j *JWKS) fetch(ctx context.Context) (map[string]*rsa.PublicKey, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > MaxJWKSBytes {
		return nil, 0, errors.New("jwks: response too large")
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return nil, 0, err
	}
	return keys, j.ttl(resp.Header.Get("Cache-Control")), nil
}

func (j *JWKS) ttl(cc string) time.Duration {
	minT, maxT, def := j.MinTTL, j.MaxTTL, j.DefaultTTL
	if minT <= 0 {
		minT = 5 * time.Minute
	}
	if maxT <= 0 {
		maxT = 24 * time.Hour
	}
	if def <= 0 {
		def = time.Hour
	}
	t := def
	for _, d := range strings.Split(cc, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		if v, ok := strings.CutPrefix(d, "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				t = time.Duration(n) * time.Second
			}
		}
	}
	return min(max(t, minT), maxT)
}

// ParseJWKS extracts the usable RSA signing keys (kty RSA, use sig or
// absent, alg RS256 or absent, modulus >= 2048 bits) by kid.
func ParseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") || k.Kid == "" {
			continue
		}
		nb, err1 := b64.DecodeString(k.N)
		eb, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(eb) == 0 || len(eb) > 4 {
			continue
		}
		n := new(big.Int).SetBytes(nb)
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if n.BitLen() < 2048 || e < 3 || e%2 == 0 {
			continue
		}
		out[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no usable RS256 keys")
	}
	return out, nil
}

// ParseP8 reads a PKCS#8 PEM private key (Apple .p8) and returns it if it
// is an ECDSA P-256 key.
func ParseP8(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PEM \"PRIVATE KEY\" block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PKCS#8: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve.Params().Name != "P-256" {
		return nil, errors.New("key is not an ECDSA P-256 key")
	}
	return ec, nil
}

// SignES256 returns a compact JWS (header {"alg":"ES256","kid":kid}) over
// the JSON encoding of claims, with the raw 64-byte r||s signature JWS uses.
func SignES256(key *ecdsa.PrivateKey, kid string, claims any) (string, error) {
	hb, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{"ES256", kid})
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64.EncodeToString(sig), nil
}

// VerifyES256 checks a compact ES256 JWS and returns its header and payload
// (tests and the fake Apple provider).
func VerifyES256(pub *ecdsa.PublicKey, token string) (hdr, payload []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, nil, ErrMalformed
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, nil, ErrSignature
	}
	if hdr, err = b64.DecodeString(parts[0]); err != nil {
		return nil, nil, ErrMalformed
	}
	if payload, err = b64.DecodeString(parts[1]); err != nil {
		return nil, nil, ErrMalformed
	}
	return hdr, payload, nil
}

// SignRS256 signs claims with an RSA key (the fake providers in tests).
func SignRS256(key *rsa.PrivateKey, kid string, claims any) (string, error) {
	return SignWithHeader(key, map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}, claims)
}

// SignWithHeader signs claims with RS256 under an arbitrary header (tests
// use it to forge headers).
func SignWithHeader(key *rsa.PrivateKey, hdr map[string]any, claims any) (string, error) {
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64.EncodeToString(sig), nil
}

// JWK renders an RSA public key as a JWKS entry (tests).
func JWK(pub *rsa.PublicKey, kid string) map[string]string {
	e := big.NewInt(int64(pub.E)).Bytes()
	return map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": b64.EncodeToString(pub.N.Bytes()), "e": b64.EncodeToString(e)}
}
