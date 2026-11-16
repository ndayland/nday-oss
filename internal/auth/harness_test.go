package auth_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/fakeidp"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
)

const (
	origin     = "https://www.nday.land"
	publicHost = "www.nday.land"
)

// countingDB wraps the auth store's connection source: it counts calls,
// tracks how many run at once and can slow each call down (load tests).
type countingDB struct {
	inner    auth.ConnSource
	calls    atomic.Int64
	inflight atomic.Int64
	maxIn    atomic.Int64
	delay    atomic.Int64 // nanoseconds added to every call
}

func (c *countingDB) WithConn(ctx context.Context, fn func(*pgx.Conn) error) error {
	c.calls.Add(1)
	n := c.inflight.Add(1)
	defer c.inflight.Add(-1)
	for {
		m := c.maxIn.Load()
		if n <= m || c.maxIn.CompareAndSwap(m, n) {
			break
		}
	}
	if d := c.delay.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
	return c.inner.WithConn(ctx, fn)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type harness struct {
	t     *testing.T
	ts    *httptest.Server
	idp   *fakeidp.IDP
	svc   *auth.Service
	store *auth.Store
	db    *testutil.TestDB
	logs  *syncBuf
	clock *clock
	cfg   *auth.Config
	srv   *web.Server
	start *auth.RateLimiter
	dbc   *countingDB
	// secrets: every sensitive value seen during the test (logs must not contain them)
	mu      sync.Mutex
	secrets []string
}

func (h *harness) secret(s string) {
	if s == "" {
		return
	}
	h.mu.Lock()
	h.secrets = append(h.secrets, s)
	h.mu.Unlock()
}

type harnessOpt struct {
	providers []string
	terms     string
	register  func(h *harness, srv *web.Server)
	burst     int
	signup    bool
	noPasskey bool
	issParam  bool // fake Google/Apple declare and send RFC 9207 iss
	// strictSignup keeps the production passkey sign-up limits
	strictSignup bool
	signupDaily  int
}

func newHarness(t *testing.T, o harnessOpt) *harness {
	t.Helper()
	t.Parallel()
	if o.providers == nil {
		o.providers = auth.AllProviders
	}
	d := testutil.NewMigratedDB(t)
	pc, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(pc, dbpool.Options{Size: 3, Dial: testutil.Dial(pc)})
	t.Cleanup(pool.Close)
	ck := &clock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	idp := fakeidp.New()
	t.Cleanup(idp.Server.Close)
	idp.Now = ck.Now
	idp.IssParam = o.issParam
	appleKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := &harness{t: t, idp: idp, db: d, logs: &syncBuf{}, clock: ck}
	cfg := &auth.Config{PublicOrigin: origin, Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)},
		Providers: map[string]auth.ProviderCredentials{}, TermsVersion: o.terms,
		SessionIdle: 14 * 24 * time.Hour, SessionMax: 60 * 24 * time.Hour, HandleHold: 90 * 24 * time.Hour,
		Passkeys: !o.noPasskey, PasskeySignup: o.signup && !o.noPasskey, RPID: "nday.land",
		Origins: []string{origin, "https://nday.land"}, SignupDaily: o.signupDaily}
	for _, p := range o.providers {
		pcred := auth.ProviderCredentials{ClientID: "client-" + p, ClientSecret: "CLIENTSECRET-" + p + "-value"}
		fc := fakeidp.Client{ID: pcred.ClientID, Secret: pcred.ClientSecret, RedirectURI: cfg.RedirectURI(p)}
		if p == auth.Apple {
			pcred = auth.ProviderCredentials{ClientID: "land.nday.web", TeamID: "ABCDE12345", KeyID: "KEYID12345", AppleKey: appleKey}
			fc = fakeidp.Client{ID: pcred.ClientID, RedirectURI: cfg.RedirectURI(p), ApplePub: &appleKey.PublicKey,
				AppleTeamID: "ABCDE12345", AppleKeyID: "KEYID12345"}
		}
		cfg.Providers[p] = pcred
		idp.Register(p, fc)
		h.secret(pcred.ClientSecret)
	}
	h.cfg = cfg
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.dbc = &countingDB{inner: pool}
	h.store = &auth.Store{DB: h.dbc, Now: ck.Now}
	burst := o.burst
	if burst == 0 {
		burst = 1000
	}
	h.start = auth.NewRateLimiter(burst, time.Second)
	h.start.Now = ck.Now
	cb := auth.NewRateLimiter(burst, time.Second)
	cb.Now = ck.Now
	pk := auth.NewRateLimiter(burst, time.Second)
	pk.Now = ck.Now
	acctRL := auth.NewRateLimiter(burst, time.Second)
	acctRL.Now = ck.Now
	var signupRL *auth.RateLimiter // nil: production default (burst auth.SignupBurst)
	if !o.strictSignup {
		signupRL = auth.NewRateLimiter(burst, time.Second)
		signupRL.Now = ck.Now
	}
	svc, err := auth.New(cfg, auth.Options{Store: h.store, Logger: log, Client: idp.Server.Client(),
		Endpoints: idp.Endpoints(), Now: ck.Now, StartLimit: h.start, CallbackLimit: cb, PasskeyLimit: pk,
		AccountLimit: acctRL, SignupLimit: signupRL})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	srv := web.New(web.Config{Store: site.New(pool), Logger: log})
	h.srv = srv
	svc.Register(srv)
	// stand-in for a public HTML page (internal/webui registers the real ones)
	srv.Handle("GET /{$}", web.GetOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "<!doctype html><p>hot</p>")
	})))
	if o.register != nil {
		o.register(h, srv)
	}
	h.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(h.ts.Close)
	t.Cleanup(func() { h.checkLogs() })
	return h
}

// checkLogs fails the test if any secret seen during it reached the logs.
func (h *harness) checkLogs() {
	logs := h.logs.String()
	if h.t.Failed() {
		// the service's own account of what went wrong ("reason=…")
		h.t.Logf("service log:\n%s", logs)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.secrets {
		if len(s) >= 8 && strings.Contains(logs, s) {
			h.t.Errorf("logs contain a secret value %.6s…", s)
		}
	}
	for _, s := range []string{"SECRET-", "CLIENTSECRET", "AT-", "RT-", "eyJ", "should-not-be-stored"} {
		if strings.Contains(logs, s) {
			h.t.Errorf("logs contain %q", s)
		}
	}
}

// local maps a public-origin URL to the test server.
func (h *harness) local(u string) string {
	return strings.Replace(u, origin, "", 1)
}

type browser struct {
	h       *harness
	jar     map[string]*http.Cookie
	ip      string
	cookies []*http.Cookie // every Set-Cookie seen
}

func (h *harness) browser() *browser {
	return &browser{h: h, jar: map[string]*http.Cookie{}, ip: "198.51.100.7"}
}

// do sends a request with the jar's cookies and applies Set-Cookie.
func (b *browser) do(method, path string, body string, hdr ...string) (*http.Response, []byte) {
	b.h.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, b.h.ts.URL+path, rd)
	if err != nil {
		b.h.t.Fatal(err)
	}
	for _, c := range b.jar {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	req.Header.Set("CF-Connecting-IP", b.ip)
	req.Host = publicHost // what browsers send behind Cloudflare
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
			continue
		}
		req.Header.Set(hdr[i], hdr[i+1])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	for _, c := range resp.Cookies() {
		b.cookies = append(b.cookies, c)
		if c.MaxAge < 0 {
			delete(b.jar, c.Name)
		} else {
			b.jar[c.Name] = c
			b.h.secret(c.Value)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" && (strings.HasPrefix(path, "/auth/") ||
		strings.HasPrefix(path, "/account/") || strings.HasPrefix(path, "/api/me")) {
		b.h.t.Errorf("%s %s: Cache-Control %q, want no-store", method, path, resp.Header.Get("Cache-Control"))
	}
	return resp, data
}

// startURL begins a flow and returns the provider authorize URL.
func (b *browser) start(provider, query string) string {
	b.h.t.Helper()
	resp, body := b.do("GET", "/auth/"+provider+"/start?"+query, "")
	if resp.StatusCode != http.StatusFound {
		b.h.t.Fatalf("start %s: %d %s", provider, resp.StatusCode, body)
	}
	loc := resp.Header.Get("Location")
	u, _ := url.Parse(loc)
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		b.h.secret(u.Query().Get(k))
	}
	return loc
}

// callback follows the provider's redirect back to nday; it returns the
// final Location.
func (b *browser) callback(cbURL string) string {
	b.h.t.Helper()
	u, _ := url.Parse(cbURL)
	b.h.secret(u.Query().Get("code"))
	resp, body := b.do("GET", b.h.local(cbURL), "")
	if resp.StatusCode != http.StatusSeeOther {
		b.h.t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" {
		b.h.t.Errorf("callback Referrer-Policy %q", resp.Header.Get("Referrer-Policy"))
	}
	return resp.Header.Get("Location")
}

// login runs a complete flow and returns the final Location.
func (b *browser) login(provider string, acct fakeidp.Account, query string) string {
	b.h.t.Helper()
	authURL := b.start(provider, query)
	cb, err := b.h.idp.Approve(provider, authURL, acct)
	if err != nil {
		b.h.t.Fatalf("approve %s: %v", provider, err)
	}
	return b.callback(cb)
}

type me struct {
	SignedIn bool `json:"signed_in"`
	User     *struct {
		ID                 string  `json:"id"`
		DisplayName        *string `json:"display_name"`
		Handle             *string `json:"handle"`
		HandleChangeableAt *string `json:"handle_changeable_at"`
		Locale             *string `json:"locale"`
		Role               string  `json:"role"`
		Status             string  `json:"status"`
		SuspendedUntil     *string `json:"suspended_until"`
		StatusReason       *string `json:"status_reason"`
		Terms              struct {
			AcceptedVersion *string `json:"accepted_version"`
			CurrentVersion  *string `json:"current_version"`
			UpToDate        bool    `json:"up_to_date"`
		} `json:"terms"`
		Identities []struct {
			Provider string  `json:"provider"`
			Handle   *string `json:"handle"`
			LinkedAt string  `json:"linked_at"`
		} `json:"identities"`
		Passkeys []struct {
			ID         string  `json:"id"`
			Name       string  `json:"name"`
			BackedUp   bool    `json:"backed_up"`
			CreatedAt  string  `json:"created_at"`
			LastUsedAt *string `json:"last_used_at"`
		} `json:"passkeys"`
	} `json:"user"`
	CSRFToken string   `json:"csrf_token"`
	Providers []string `json:"providers"`
	Passkeys  struct {
		Enabled bool `json:"enabled"`
		Signup  bool `json:"signup"`
	} `json:"passkeys"`
}

func (b *browser) me() me {
	b.h.t.Helper()
	resp, body := b.do("GET", "/api/me", "")
	if resp.StatusCode != 200 {
		b.h.t.Fatalf("/api/me: %d %s", resp.StatusCode, body)
	}
	var m me
	if err := json.Unmarshal(body, &m); err != nil {
		b.h.t.Fatalf("%v %s", err, body)
	}
	b.h.secret(m.CSRFToken)
	return m
}

// post sends a same-origin JSON POST with the session's CSRF token.
func (b *browser) post(path, body string) (*http.Response, []byte) {
	b.h.t.Helper()
	tok := b.me().CSRFToken
	return b.do("POST", path, body, "Origin", origin, "Sec-Fetch-Site", "same-origin",
		"Content-Type", "application/json", "X-CSRF-Token", tok)
}

func errCode(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

func (h *harness) count(sql string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.Conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func (b *browser) clone() *browser {
	c := b.h.browser()
	for k, v := range b.jar {
		cp := *v
		c.jar[k] = &cp
	}
	return c
}
