package jose_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/auth/jose"
)

var b64 = base64.RawURLEncoding

type keyServer struct {
	mu   sync.Mutex
	keys []map[string]string
	cc   string
	hits int
	ts   *httptest.Server
}

func newKeyServer(t *testing.T) *keyServer {
	ks := &keyServer{cc: "public, max-age=3600"}
	ks.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ks.mu.Lock()
		defer ks.mu.Unlock()
		ks.hits++
		w.Header().Set("Cache-Control", ks.cc)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": ks.keys})
	}))
	t.Cleanup(ks.ts.Close)
	return ks
}

func (ks *keyServer) set(keys ...map[string]string) {
	ks.mu.Lock()
	ks.keys = keys
	ks.mu.Unlock()
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var now = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func claims() map[string]any {
	return map[string]any{"iss": "https://issuer.example", "aud": "client-1", "sub": "1234567890",
		"iat": now.Unix() - 5, "exp": now.Add(time.Hour).Unix(), "nonce": "nonce-1", "name": "Ada"}
}

func expect() jose.Expect {
	return jose.Expect{Issuers: []string{"https://issuer.example", "issuer.example"}, Audience: "client-1", Nonce: "nonce-1", Now: now}
}

func setup(t *testing.T) (*rsa.PrivateKey, *keyServer, *jose.JWKS, *time.Time) {
	k := rsaKey(t)
	ks := newKeyServer(t)
	ks.set(jose.JWK(&k.PublicKey, "k1"))
	clock := now
	j := &jose.JWKS{URL: ks.ts.URL, Client: ks.ts.Client(), Now: func() time.Time { return clock }}
	return k, ks, j, &clock
}

func TestVerifyOK(t *testing.T) {
	k, _, j, _ := setup(t)
	tok, _ := jose.SignRS256(k, "k1", claims())
	c, err := jose.Verify(context.Background(), tok, j, expect())
	if err != nil || c.Sub != "1234567890" || c.Name != "Ada" {
		t.Fatalf("%v %+v", err, c)
	}
	// aud as array containing us, azp us
	cl := claims()
	cl["aud"] = []string{"client-1", "other"}
	cl["azp"] = "client-1"
	tok, _ = jose.SignRS256(k, "k1", cl)
	if _, err := jose.Verify(context.Background(), tok, j, expect()); err != nil {
		t.Fatal(err)
	}
	// second accepted issuer form (Google's "accounts.google.com")
	cl = claims()
	cl["iss"] = "issuer.example"
	tok, _ = jose.SignRS256(k, "k1", cl)
	if _, err := jose.Verify(context.Background(), tok, j, expect()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyNegatives(t *testing.T) {
	k, _, j, _ := setup(t)
	other := rsaKey(t)
	pubDER := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubDER})
	hs256 := func(secret []byte) string {
		h, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": "k1"})
		p, _ := json.Marshal(claims())
		in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(in))
		return in + "." + b64.EncodeToString(m.Sum(nil))
	}
	with := func(f func(map[string]any)) string {
		c := claims()
		f(c)
		tok, _ := jose.SignRS256(k, "k1", c)
		return tok
	}
	good, _ := jose.SignRS256(k, "k1", claims())
	parts := strings.Split(good, ".")
	noneHdr, _ := json.Marshal(map[string]string{"alg": "none", "kid": "k1"})
	es, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	esTok, _ := jose.SignES256(es, "k1", claims())
	badSig, _ := jose.SignRS256(other, "k1", claims())
	cases := []struct {
		name string
		tok  string
		want error
	}{
		{"bad signature (other key, same kid)", badSig, jose.ErrSignature},
		{"tampered payload", parts[0] + "." + b64.EncodeToString([]byte(`{"sub":"evil"}`)) + "." + parts[2], jose.ErrSignature},
		{"alg none", b64.EncodeToString(noneHdr) + "." + parts[1] + ".", jose.ErrMalformed},
		{"alg none with sig", b64.EncodeToString(noneHdr) + "." + parts[1] + "." + parts[2], jose.ErrAlgorithm},
		{"HS256 with the RSA public key (PEM) as secret", hs256(pubPEM), jose.ErrAlgorithm},
		{"HS256 with the RSA public key (DER) as secret", hs256(pubDER), jose.ErrAlgorithm},
		{"ES256", esTok, jose.ErrAlgorithm},
		{"wrong aud", with(func(c map[string]any) { c["aud"] = "client-2" }), jose.ErrClaims},
		{"aud array without us", with(func(c map[string]any) { c["aud"] = []string{"a", "b"} }), jose.ErrClaims},
		{"aud array, azp not us", with(func(c map[string]any) { c["aud"] = []string{"client-1", "b"}; c["azp"] = "b" }), jose.ErrClaims},
		{"wrong iss", with(func(c map[string]any) { c["iss"] = "https://evil.example" }), jose.ErrClaims},
		{"expired", with(func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() }), jose.ErrClaims},
		{"no exp", with(func(c map[string]any) { delete(c, "exp") }), jose.ErrClaims},
		{"iat in the future", with(func(c map[string]any) { c["iat"] = now.Add(5 * time.Minute).Unix() }), jose.ErrClaims},
		{"iat too old", with(func(c map[string]any) { c["iat"] = now.Add(-time.Hour).Unix() }), jose.ErrClaims},
		{"wrong nonce", with(func(c map[string]any) { c["nonce"] = "nonce-2" }), jose.ErrClaims},
		{"missing nonce", with(func(c map[string]any) { delete(c, "nonce") }), jose.ErrClaims},
		{"empty sub", with(func(c map[string]any) { c["sub"] = "" }), jose.ErrClaims},
		{"two parts", parts[0] + "." + parts[1], jose.ErrMalformed},
		{"garbage", "a.b.c", jose.ErrMalformed},
		{"huge", strings.Repeat("a", jose.MaxTokenBytes+1), jose.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := jose.Verify(context.Background(), c.tok, j, expect())
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	// Small clock skew is tolerated.
	tok := with(func(c map[string]any) { c["exp"] = now.Add(-30 * time.Second).Unix() })
	if _, err := jose.Verify(context.Background(), tok, j, expect()); err != nil {
		t.Errorf("30s skew: %v", err)
	}
}

func TestJWKSRotationAndCaching(t *testing.T) {
	k, ks, j, clock := setup(t)
	tok, _ := jose.SignRS256(k, "k1", claims())
	for i := 0; i < 3; i++ {
		if _, err := jose.Verify(context.Background(), tok, j, expect()); err != nil {
			t.Fatal(err)
		}
	}
	if j.Fetches() != 1 {
		t.Fatalf("cached: fetches=%d", j.Fetches())
	}
	// Provider rotates to k2: unknown kid -> one refetch -> verifies.
	k2 := rsaKey(t)
	ks.set(jose.JWK(&k.PublicKey, "k1"), jose.JWK(&k2.PublicKey, "k2"))
	tok2, _ := jose.SignRS256(k2, "k2", claims())
	if _, err := jose.Verify(context.Background(), tok2, j, expect()); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if j.Fetches() != 2 {
		t.Fatalf("refetch on unknown kid: fetches=%d", j.Fetches())
	}
	// A flood of unknown kids does not refetch more than once per interval.
	bogus, _ := jose.SignRS256(k2, "nope", claims())
	for i := 0; i < 5; i++ {
		if _, err := jose.Verify(context.Background(), bogus, j, expect()); !errors.Is(err, jose.ErrUnknownKey) {
			t.Fatalf("unknown kid: %v", err)
		}
	}
	if j.Fetches() != 2 {
		t.Fatalf("refetch storm: fetches=%d", j.Fetches())
	}
	*clock = clock.Add(31 * time.Second)
	_, _ = jose.Verify(context.Background(), bogus, j, expect())
	if j.Fetches() != 3 {
		t.Fatalf("refetch after interval: fetches=%d", j.Fetches())
	}
	// Expiry (max-age 3600) -> refetch; a failed refetch keeps old keys.
	ks.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	*clock = clock.Add(2 * time.Hour)
	if _, err := jose.Verify(context.Background(), tok2, j, expect2(*clock)); err != nil {
		t.Fatalf("stale keys kept on fetch failure: %v", err)
	}
}

func expect2(at time.Time) jose.Expect {
	e := expect()
	e.Now = at
	e.MaxAge = 24 * time.Hour
	e.Skew = 24 * time.Hour
	return e
}

func TestParseJWKSFilters(t *testing.T) {
	k := rsaKey(t)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	good := jose.JWK(&k.PublicKey, "good")
	weak := jose.JWK(&small.PublicKey, "weak")
	enc := jose.JWK(&k.PublicKey, "enc")
	enc["use"] = "enc"
	ps := jose.JWK(&k.PublicKey, "ps")
	ps["alg"] = "PS256"
	b, _ := json.Marshal(map[string]any{"keys": []any{good, weak, enc, ps, map[string]string{"kty": "EC", "kid": "ec"}}})
	keys, err := jose.ParseJWKS(b)
	if err != nil || len(keys) != 1 || keys["good"] == nil {
		t.Fatalf("%v %v", err, keys)
	}
}

func TestES256AndP8(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := jose.ParseP8(p8)
	if err != nil || !parsed.Equal(k) {
		t.Fatalf("ParseP8: %v", err)
	}
	if _, err := jose.ParseP8([]byte("not pem")); err == nil {
		t.Error("garbage accepted")
	}
	r := rsaKey(t)
	rder, _ := x509.MarshalPKCS8PrivateKey(r)
	if _, err := jose.ParseP8(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rder})); err == nil {
		t.Error("RSA key accepted as .p8")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKCS8PrivateKey(p384)
	if _, err := jose.ParseP8(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der384})); err == nil {
		t.Error("P-384 key accepted")
	}
	tok, err := jose.SignES256(parsed, "ABC123DEFG", map[string]any{"iss": "TEAM", "sub": "svc"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	sig, _ := b64.DecodeString(parts[2])
	if len(sig) != 64 {
		t.Fatalf("JWS ES256 signature must be raw r||s (64 bytes), got %d", len(sig))
	}
	h, p, err := jose.VerifyES256(&k.PublicKey, tok)
	if err != nil || string(h) != `{"alg":"ES256","kid":"ABC123DEFG"}` || !strings.Contains(string(p), `"iss":"TEAM"`) {
		t.Fatalf("%v %s %s", err, h, p)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, _, err := jose.VerifyES256(&other.PublicKey, tok); err == nil {
		t.Error("verified with wrong key")
	}
}
