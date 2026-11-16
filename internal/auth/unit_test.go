package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth/jose"
)

func TestSafeReturnPath(t *testing.T) {
	good := []string{"/", "/vuln/CVE-2026-1234", "/zh-hans/hot", "/vuln?q=%E4%B8%AD+x&since=7d", "/a/b.c/d_e~f-g",
		"/hot?auth=ok"}
	for _, p := range good {
		if SafeReturnPath(p) != p {
			t.Errorf("rejected good %q", p)
		}
	}
	bad := []string{
		"", "//evil.example", "//evil.example/x", "/\\evil.example", "\\\\evil", "/\\/evil",
		"https://evil.example", "http:evil", "javascript:alert(1)", "evil.example", "///evil",
		"/%2F%2Fevil", "/%2f/evil", "/%5Cevil", "/%5c%5cevil", "/x?y=%0d%0aSet-Cookie:a", "/x?y=%00",
		"/x?y=%5C", "/x?y=%C2%85", "/ok\r\nLocation: //evil", "/ok\x00", "/ok\t", "/ok x", "/a#frag",
		"/./x", "/../x", "/a/../../x", "/auth/github/start", "/auth", "/account/delete", "/api/me",
		"/x?y=%zz", "/x?y=<script>", "/" + strings.Repeat("a", MaxReturnPath), "/é", "/@evil",
		" /x", "/x\\", "/x?a=b\\c",
	}
	for _, p := range bad {
		if got := SafeReturnPath(p); got != "/" {
			t.Errorf("accepted bad %q -> %q", p, got)
		}
	}
	// The account page itself is a target; its JSON endpoints and the other
	// sign-in trees are not (exact path only, case-sensitive like the routes).
	for p, want := range map[string]bool{
		"/account": true, "/account?x=1": true, "/account?auth=ok&x=1": true,
		"/accountx": true, "/Account": true, "/zh-hans/account": true,
		"/account/": false, "/account/handle": false, "/account/passkeys/x/delete": false, "/account%2Fhandle": false,
		"/account/?x=1": false, "/auth": false, "/auth?x=1": false, "/auth/": false, "/auth/x/start": false,
		"/api": false, "/api?x=1": false, "/api/": false, "/api/me": false, "//account": false, "/./account": false,
	} {
		if got := SafeReturnPath(p) == p; got != want {
			t.Errorf("SafeReturnPath(%q) accepted=%v, want %v", p, got, want)
		}
	}
	if got := withOutcome("/x?auth=ok&q=1", "error"); got != "/x?q=1&auth=error" {
		t.Errorf("withOutcome: %q", got)
	}
	if got := withOutcome("/", "ok"); got != "/?auth=ok" {
		t.Errorf("withOutcome: %q", got)
	}
}

func TestHandleRules(t *testing.T) {
	ok := map[string]string{"Alice": "alice", "bob_42": "bob_42", "9lives": "9lives", "a-b": "a-b",
		strings.Repeat("x", 30): strings.Repeat("x", 30)}
	for h, key := range ok {
		if k, err := CanonicalHandle(h); err != nil || k != key {
			t.Errorf("%q: %q %v", h, k, err)
		}
	}
	for _, h := range []string{"ab", "_abc", "-abc", "abc!", "ab c", "émile", "a.b.c", strings.Repeat("x", 31), "", "abc\n"} {
		if _, err := CanonicalHandle(h); err != ErrHandleFormat {
			t.Errorf("%q: %v", h, err)
		}
	}
	for _, h := range []string{"Admin", "ROOT", "nday", "Support", "zh-Hans", "zh-hant", "settings", "login", "papers",
		"incidents", "www", "status", "help", "users", "org", "orgs", "pt-br", "en-us", "api", "vuln", "static", "about"} {
		if _, err := CanonicalHandle(h); err != ErrHandleReserved {
			t.Errorf("%q: want reserved, got %v", h, err)
		}
	}
}

// TestReservedCoversRoutes checks the reserved list against names that
// must never be handles. The complete check of the routes the server really
// registers is TestRoutesReservedAsHandles in internal/webui (this package
// can't import the UI); this list just keeps the planned and well-known
// names from being dropped by accident.
func TestReservedCoversRoutes(t *testing.T) {
	routes := []string{
		// internal/web
		"/healthz", "/api/hot", "/raw/x", "/v1/hot", // internal/webui
		"/hot", "/discussed", "/vuln", "/src", "/stats", "/about", "/rules", "/tags", "/tag/x", "/feed.xml",
		"/robots.txt", "/sitemap.xml", "/sitemap/x", "/favicon.ico", "/og/vuln/x", "/static/x", "/__i18n/", "/admin/x",
		// internal/auth
		"/auth/x", "/account/x",
		// internal/webui first-sign-in page
		"/welcome",
		// locale prefixes (internal/webui/i18n/locales.json)
		"/zh-hans/", "/zh-hant/", "/ja/", "/ko/", "/es/", "/fr/", "/en/",
		// brief: names a root-level namespace must never take
		"/u", "/org", "/orgs", "/user", "/users", "/settings", "/new", "/login", "/signin", "/signup", "/logout",
		"/join", "/papers", "/incidents", "/posts", "/collections", "/discussions", "/docs", "/blog", "/pricing",
		"/terms", "/privacy", "/www", "/mail", "/cdn", "/status", "/help",
		"/admin", "/root", "/nday", "/support", "/security", "/moderator",
	}
	for _, r := range routes {
		seg := strings.SplitN(strings.TrimPrefix(r, "/"), "/", 2)[0]
		if !reservedSet[seg] {
			t.Errorf("top-level segment %q of %s is not in ReservedNames", seg, r)
		}
	}
	seen := map[string]bool{}
	for _, n := range ReservedNames {
		if n != strings.ToLower(n) || seen[n] {
			t.Errorf("ReservedNames entry %q: must be lower case and unique", n)
		}
		seen[n] = true
	}
}

func TestSanitizeDisplayName(t *testing.T) {
	cases := map[string]string{
		"  Ada   Lovelace ":             "Ada Lovelace",
		"Ada\u202eecalevoL":             "AdaecalevoL", // RLO stripped
		"a\u2066b\u2069c\u200fd\u061ce": "abcde",
		"zero\u200bwidth\ufeff":         "zerowidth",
		"tab\tnew\nline\x00nul\x1b[31m": "tab new linenul[31m",
		"李\u3000雷":                      "李 雷",
		"\u00a0\u2028":                  "",
		strings.Repeat("é", 100):        strings.Repeat("é", MaxDisplayName),
		"bad\xffutf8":                   "badutf8",
		"emoji 🙂 ok":                    "emoji 🙂 ok",
		"\ue000private":                 "private",
	}
	for in, want := range cases {
		if got := SanitizeDisplayName(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewRateLimiter(2, 10*time.Second)
	l.Now = func() time.Time { return now }
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal(1)
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal(2)
	}
	ok, wait := l.Allow("a")
	if ok || wait <= 0 || wait > 10*time.Second {
		t.Fatalf("3rd: %v %v", ok, wait)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other key")
	}
	now = now.Add(10 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("refill")
	}
	l.MaxKeys = 3
	l.Allow("c")
	if ok, _ := l.Allow("d"); !ok {
		t.Fatal("full table must evict the least recently used bucket, not fail closed")
	}
	if l.Len() != 3 || l.buckets["b"] != nil || l.buckets["a"] == nil {
		t.Fatalf("eviction order: %d buckets", l.Len())
	}
	now = now.Add(time.Hour) // sweep frees stale buckets
	if ok, _ := l.Allow("e"); !ok || l.Len() != 1 {
		t.Fatalf("after sweep: %d buckets", l.Len())
	}
	// IPv6 is counted per /48 while the table is at least half full
	l = NewRateLimiter(1, time.Hour)
	l.Now = func() time.Time { return now }
	l.MaxKeys = 4
	l.Allow("192.0.2.1")
	l.Allow("192.0.2.2")
	if ok, _ := l.Allow("2001:db8:1:1::/64"); !ok {
		t.Fatal("first /64")
	}
	if ok, _ := l.Allow("2001:db8:1:2::/64"); ok {
		t.Fatal("second /64 of the same /48 under pressure")
	}
}

// The sweep only walks idle buckets at the LRU tail, and only once per
// SweepEvery; a full table costs O(1) per call.
func TestRateLimiterSweepIsBounded(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewRateLimiter(1, time.Second)
	l.Now = func() time.Time { return now }
	l.MaxKeys = 1000
	for i := 0; i < 1000; i++ {
		l.Allow(fmt.Sprint("k", i))
	}
	now = now.Add(30 * time.Second) // all idle, but no sweep before a minute has passed since the last
	l.Allow("fresh")
	if l.Len() != 1000 {
		t.Fatalf("swept early: %d", l.Len())
	}
	now = now.Add(31 * time.Second)
	l.Allow("fresh2")
	if l.Len() != 1 {
		t.Fatalf("sweep left %d buckets", l.Len())
	}
}

func TestClientAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	if ClientAddr(r) != "10.0.0.1" {
		t.Error(ClientAddr(r))
	}
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if ClientAddr(r) != "203.0.113.9" {
		t.Error(ClientAddr(r))
	}
	r.Header.Set("CF-Connecting-IP", "2001:db8:1:2:3:4:5:6")
	if ClientAddr(r) != "2001:db8:1:2::/64" {
		t.Error(ClientAddr(r))
	}
	r.Header.Set("CF-Connecting-IP", "not-an-ip, 1.2.3.4")
	if ClientAddr(r) != "10.0.0.1" {
		t.Error("garbage header must fall back to the socket address:", ClientAddr(r))
	}
}

func TestSealAndCSRF(t *testing.T) {
	s1, s2 := make([]byte, 32), make([]byte, 32)
	s1[0], s2[0] = 1, 2
	old, _ := newKeyset([][]byte{s1})
	rotated, _ := newKeyset([][]byte{s2, s1})
	other, _ := newKeyset([][]byte{s2})
	blob := old.sealB64("p", []byte("hello"))
	if pt, err := rotated.openB64("p", blob); err != nil || string(pt) != "hello" {
		t.Fatalf("previous key must still open: %v", err)
	}
	if _, err := other.openB64("p", blob); err == nil {
		t.Fatal("unknown key opened")
	}
	if _, err := old.openB64("q", blob); err == nil {
		t.Fatal("purpose not bound")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(blob)
	raw[len(raw)-1] ^= 1
	if _, err := old.openB64("p", base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("tampered blob opened")
	}
	h := sha256Bytes("session")
	tok := old.csrfToken(h)
	if !rotated.checkCSRF(h, tok) || other.checkCSRF(h, tok) || old.checkCSRF(sha256Bytes("other"), tok) ||
		old.checkCSRF(h, "") || old.checkCSRF(h, tok+"x") {
		t.Fatal("csrf checks")
	}
}

func writeP8(t *testing.T) (string, *ecdsa.PrivateKey) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p := filepath.Join(t.TempDir(), "AuthKey_ABCDEFGHIJ.p8")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, k
}

func TestConfigFromEnv(t *testing.T) {
	p8, _ := writeP8(t)
	secret := randomSecret()
	full := map[string]string{
		EnvPublicURL: "https://www.nday.land", EnvSecret: secret,
		EnvGitHubClientID: "Iv1.abc", EnvGitHubClientSecret: "s3cr3t-GH-VALUE",
		EnvAppleServicesID: "land.nday.web", EnvAppleTeamID: "ABCDE12345", EnvAppleKeyID: "ABCDEFGHIJ", EnvAppleKeyFile: p8,
	}
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	cfg, err := FromEnv(env(full))
	if err != nil || !cfg.Enabled() || len(cfg.Providers) != 2 || cfg.Providers[Apple].AppleKey == nil ||
		cfg.SessionIdle != DefaultSessionIdle || cfg.RedirectURI(GitHub) != "https://www.nday.land/auth/github/callback" {
		t.Fatalf("%v %+v", err, cfg)
	}
	// nothing configured: inert
	if cfg, err := FromEnv(env(map[string]string{EnvPublicURL: "https://x.example"})); cfg != nil || err != nil {
		t.Fatalf("inert: %v %v", cfg, err)
	}
	mod := func(f func(m map[string]string)) map[string]string {
		m := map[string]string{}
		for k, v := range full {
			m[k] = v
		}
		f(m)
		return m
	}
	cases := []struct {
		name string
		m    map[string]string
		want string
	}{
		{"partial github", mod(func(m map[string]string) { delete(m, EnvGitHubClientSecret) }),
			"provider github is partly configured: NDAY_AUTH_GITHUB_CLIENT_ID set but NDAY_AUTH_GITHUB_CLIENT_SECRET missing"},
		{"no secret", mod(func(m map[string]string) { delete(m, EnvSecret) }), "NDAY_AUTH_SECRET is required"},
		{"short secret", mod(func(m map[string]string) { m[EnvSecret] = base64.StdEncoding.EncodeToString(make([]byte, 16)) }),
			"decodes to 16 bytes"},
		{"secret not base64", mod(func(m map[string]string) { m[EnvSecret] = "not base64!!" }), "must be base64"},
		{"no public url", mod(func(m map[string]string) { delete(m, EnvPublicURL) }), "NDAY_PUBLIC_URL: is required"},
		{"http public url", mod(func(m map[string]string) { m[EnvPublicURL] = "http://www.nday.land" }), "must use https"},
		{"public url with path", mod(func(m map[string]string) { m[EnvPublicURL] = "https://www.nday.land/x" }), "origin only"},
		{"bad team id", mod(func(m map[string]string) { m[EnvAppleTeamID] = "abc" }), "NDAY_AUTH_APPLE_TEAM_ID must be the 10-character Team ID"},
		{"missing key file", mod(func(m map[string]string) { m[EnvAppleKeyFile] = "/nonexistent/k.p8" }), "cannot read the .p8 key file"},
		{"bad key file", mod(func(m map[string]string) { m[EnvAppleKeyFile] = os.Args[0] }), "NDAY_AUTH_APPLE_KEY_FILE: not a PEM"},
		{"idle > max", mod(func(m map[string]string) { m[EnvSessionIdle] = "90d"; m[EnvSessionMax] = "30d" }), "must not be longer"},
		{"bad duration", mod(func(m map[string]string) { m[EnvSessionIdle] = "soon" }), "NDAY_AUTH_SESSION_IDLE must be a duration"},
		{"bad terms", mod(func(m map[string]string) { m[EnvTermsVersion] = "v 1" }), "NDAY_TERMS_VERSION"},
		{"space in client id", mod(func(m map[string]string) { m[EnvGitHubClientID] = "a b" }), "NDAY_AUTH_GITHUB_CLIENT_ID must be"},
	}
	for _, c := range cases {
		_, err := FromEnv(env(c.m))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		// never echo a secret value
		for _, v := range []string{"s3cr3t-GH-VALUE", secret} {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: error leaks a secret: %v", c.name, err)
			}
		}
	}
	// the .p8 key as PEM text (NDAY_AUTH_APPLE_KEY): used instead of the file
	pemText, err := os.ReadFile(p8)
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]map[string]string{
		"key only":  mod(func(m map[string]string) { delete(m, EnvAppleKeyFile); m[EnvAppleKey] = string(pemText) }),
		"key wins":  mod(func(m map[string]string) { m[EnvAppleKeyFile] = "/nonexistent/k.p8"; m[EnvAppleKey] = string(pemText) }),
		"blank key": mod(func(m map[string]string) { m[EnvAppleKey] = "  " }),
		"padded key": mod(func(m map[string]string) {
			delete(m, EnvAppleKeyFile)
			m[EnvAppleKey] = "\n  " + string(pemText) + "  \n"
		}),
	} {
		cfg, err := FromEnv(env(m))
		if err != nil || cfg.Providers[Apple].AppleKey == nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	const pemLeak = "-----BEGIN PRIVATE KEY-----\nTEFBS0VELVNFQ1JFVC1LRVk=\n-----END PRIVATE KEY-----\n"
	for _, c := range []struct {
		name string
		m    map[string]string
		want string
	}{
		{"bad key text", mod(func(m map[string]string) { m[EnvAppleKey] = pemLeak }), "NDAY_AUTH_APPLE_KEY: PKCS#8"},
		{"not pem", mod(func(m map[string]string) { m[EnvAppleKey] = "LEAKED-SECRET-KEY-TEXT" }), "NDAY_AUTH_APPLE_KEY: not a PEM"},
		{"no key at all", mod(func(m map[string]string) { delete(m, EnvAppleKeyFile) }),
			"provider apple is partly configured: NDAY_AUTH_APPLE_SERVICES_ID, NDAY_AUTH_APPLE_TEAM_ID, NDAY_AUTH_APPLE_KEY_ID set but NDAY_AUTH_APPLE_KEY or NDAY_AUTH_APPLE_KEY_FILE missing"},
		{"key without ids", map[string]string{EnvPublicURL: "https://www.nday.land", EnvSecret: secret, EnvAppleKey: string(pemText)},
			"NDAY_AUTH_APPLE_KEY or NDAY_AUTH_APPLE_KEY_FILE set but NDAY_AUTH_APPLE_SERVICES_ID, NDAY_AUTH_APPLE_TEAM_ID, NDAY_AUTH_APPLE_KEY_ID missing"},
	} {
		_, err := FromEnv(env(c.m))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		for _, leak := range []string{"TEFBS0VELVNFQ1JFVC1LRVk", "LEAKED-SECRET", string(pemText)} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error leaks the key: %v", c.name, err)
			}
		}
	}
	if o, err := ParsePublicOrigin("http://localhost:8080"); err != nil || o != "http://localhost:8080" {
		t.Errorf("localhost: %v", err)
	}
}

func TestAppleClientSecretShape(t *testing.T) {
	_, k := writeP8(t)
	now := time.Unix(1_800_000_000, 0)
	tok, exp, err := AppleClientSecret(k, "ABCDE12345", "ABCDEFGHIJ", "land.nday.web", "", now)
	if err != nil {
		t.Fatal(err)
	}
	h, p, err := jose.VerifyES256(&k.PublicKey, tok)
	if err != nil {
		t.Fatal(err)
	}
	var hdr, cl map[string]any
	_ = json.Unmarshal(h, &hdr)
	_ = json.Unmarshal(p, &cl)
	if len(hdr) != 2 || hdr["alg"] != "ES256" || hdr["kid"] != "ABCDEFGHIJ" {
		t.Errorf("header %v", hdr)
	}
	if len(cl) != 5 || cl["iss"] != "ABCDE12345" || cl["sub"] != "land.nday.web" || cl["aud"] != "https://appleid.apple.com" ||
		cl["iat"] != float64(now.Unix()) || cl["exp"] != float64(now.Add(time.Hour).Unix()) || !exp.Equal(now.Add(time.Hour)) {
		t.Errorf("claims %v", cl)
	}
	if int64(cl["exp"].(float64)-cl["iat"].(float64)) > 15777000 {
		t.Error("exp beyond Apple's 6-month limit")
	}
	// cached and re-minted shortly before expiry
	p0 := &provider{name: Apple, creds: ProviderCredentials{ClientID: "land.nday.web", TeamID: "ABCDE12345", KeyID: "ABCDEFGHIJ", AppleKey: k}}
	a, _ := p0.clientSecret(now)
	b, _ := p0.clientSecret(now.Add(30 * time.Minute))
	c, _ := p0.clientSecret(now.Add(56 * time.Minute))
	if a != b || a == c {
		t.Error("client secret caching")
	}
}

func TestAuthorizeURLs(t *testing.T) {
	for _, name := range AllProviders {
		p := &provider{name: name, creds: ProviderCredentials{ClientID: "cid"}, ep: ProductionEndpoints[name]}
		u := p.authURL("https://www.nday.land/auth/"+name+"/callback", "STATE", "NONCE", "VERIFIER")
		for _, s := range []string{"response_type=code", "client_id=cid", "state=STATE"} {
			if !strings.Contains(u, s) {
				t.Errorf("%s: %s lacks %s", name, u, s)
			}
		}
		if strings.Contains(u, "email") {
			t.Errorf("%s requests e-mail: %s", name, u)
		}
		if (name == Apple) == strings.Contains(u, "code_challenge=") {
			t.Errorf("%s PKCE: %s", name, u)
		}
		if strings.Contains(u, "VERIFIER") {
			t.Errorf("%s leaks the PKCE verifier: %s", name, u)
		}
	}
}

func TestConfigPasskeys(t *testing.T) {
	secret := randomSecret()
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	base := func(extra ...string) map[string]string {
		m := map[string]string{EnvPublicURL: "https://www.nday.land", EnvSecret: secret,
			EnvGitHubClientID: "id", EnvGitHubClientSecret: "sec"}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i]] = extra[i+1]
		}
		return m
	}
	cfg, err := FromEnv(env(base()))
	if err != nil || !cfg.Passkeys || cfg.PasskeySignup || cfg.RPID != "nday.land" ||
		len(cfg.Origins) != 1 || cfg.Origins[0] != "https://www.nday.land" {
		t.Fatalf("defaults: %v %+v", err, cfg)
	}
	cfg, err = FromEnv(env(base(EnvOrigins, "https://www.nday.land, https://nday.land", EnvPasskeySignup, "on")))
	if err != nil || len(cfg.Origins) != 2 || !cfg.PasskeySignup {
		t.Fatalf("origins: %v %+v", err, cfg)
	}
	cfg, err = FromEnv(env(base(EnvPasskeys, "off")))
	if err != nil || cfg.Passkeys {
		t.Fatalf("off: %v", err)
	}
	// passkeys only, no social provider
	cfg, err = FromEnv(env(map[string]string{EnvPublicURL: "https://www.nday.land", EnvSecret: secret, EnvPasskeys: "on"}))
	if err != nil || !cfg.Enabled() || len(cfg.Providers) != 0 {
		t.Fatalf("passkeys only: %v %+v", err, cfg)
	}
	for _, c := range []struct {
		m    map[string]string
		want string
	}{
		{base(EnvRPID, "evil.example"), "NDAY_AUTH_RP_ID: origin host \"www.nday.land\" is not \"evil.example\""},
		{base(EnvRPID, "land"), "must be a registrable domain"},
		{base(EnvOrigins, "https://evil.example"), "NDAY_AUTH_ORIGINS"},
		{base(EnvOrigins, "http://nday.land"), "must use https"},
		{base(EnvPasskeySignup, "maybe"), "NDAY_AUTH_PASSKEY_SIGNUP must be on or off"},
		{base(EnvPasskeys, "off", EnvPasskeySignup, "on"), "needs passkeys"},
	} {
		if _, err := FromEnv(env(c.m)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v", c.m, err)
		}
	}
}

// randomSecret is what `openssl rand -base64 48` prints.
func randomSecret() string {
	b := make([]byte, 48)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Coarse (/48) mode starts at half full and ends only under a quarter full
// and CoarseHold after it started.
func TestRateLimiterCoarseHysteresis(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewRateLimiter(1, time.Second)
	l.Now = func() time.Time { return now }
	l.MaxKeys = 8
	for i := 0; i < 4; i++ {
		l.Allow(fmt.Sprint("192.0.2.", i))
	}
	l.Allow("10.0.0.1")
	if !l.coarse {
		t.Fatal("not coarse at half full")
	}
	now = now.Add(2 * time.Minute) // everything idle: swept below a quarter
	l.Allow("10.0.0.2")
	if !l.coarse {
		t.Fatal("left coarse mode before CoarseHold")
	}
	now = now.Add(9 * time.Minute)
	l.Allow("10.0.0.3")
	if l.coarse {
		t.Fatal("still coarse after CoarseHold under a quarter full")
	}
}

// Random secrets in every documented encoding are never refused.
// NDAY_SECRET_FP_N raises the count per encoding (200000 was run once
// as a one-off soak).
func TestSecretFalsePositives(t *testing.T) {
	n := 2000
	if v := os.Getenv("NDAY_SECRET_FP_N"); v != "" {
		fmt.Sscan(v, &n)
	}
	enc := map[string]func([]byte) string{
		"hex":       hex.EncodeToString,
		"base64":    base64.StdEncoding.EncodeToString,
		"base64url": base64.RawURLEncoding.EncodeToString,
	}
	for name, f := range enc {
		for _, size := range []int{32, 48} {
			refused := 0
			b := make([]byte, size)
			for i := 0; i < n; i++ {
				_, _ = rand.Read(b)
				if _, err := decodeSecret(f(b)); err != nil {
					refused++
					if refused < 3 {
						t.Errorf("%s/%d refused: %v", name, size, err)
					}
				}
			}
			t.Logf("%s of %d random bytes: %d secrets, %d refused", name, size, n, refused)
		}
	}
}

// The dead-token cache is bounded.
func TestDeadTokensBounded(t *testing.T) {
	d := newDeadTokens(3, time.Hour)
	for i := 0; i < 5; i++ {
		d.add([]byte{byte(i)})
	}
	if d.len() != 3 || d.has([]byte{0}) || d.has([]byte{1}) || !d.has([]byte{4}) {
		t.Fatalf("eviction: len %d", d.len())
	}
	e := newDeadTokens(3, -time.Second) // already expired
	e.add([]byte{9})
	if e.has([]byte{9}) {
		t.Fatal("expired entry still answered")
	}
}
