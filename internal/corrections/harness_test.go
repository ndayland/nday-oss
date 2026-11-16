package corrections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/fakeidp"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
)

// The harness follows internal/discuss's: a migrated database, the real
// auth service with a fake identity provider, and the corrections service
// on a web.Server in two-host mode.

const (
	origin     = "https://www.nday.land"
	publicHost = "www.nday.land"
	apiHost    = "api.nday.land"
	cveA       = "CVE-2026-0001"
	cveB       = "CVE-2026-0002"
	terms      = "2026-11-01"
)

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
	as    *auth.Store
	cs    *corrections.Service
	site  *site.Store
	db    *testutil.TestDB
	logs  *syncBuf
	clock *clock
	n     int
	// newAcct is the discussion's limits the service reads at each
	// submission (Options.NewAccount); by default no account counts as new
	newAcct atomic.Pointer[discuss.Limits]
}

func newHarness(t *testing.T, terms string, lim *corrections.Limits) *harness {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	pc, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(pc, dbpool.Options{Size: 3, Dial: testutil.Dial(pc)})
	t.Cleanup(pool.Close)
	if _, err := d.Conn.Exec(context.Background(), `INSERT INTO vuln (cve_id) VALUES ($1), ($2)`, cveA, cveB); err != nil {
		t.Fatal(err)
	}
	ck := &clock{t: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	idp := fakeidp.New()
	t.Cleanup(idp.Server.Close)
	idp.Now = ck.Now
	h := &harness{t: t, idp: idp, db: d, logs: &syncBuf{}, clock: ck}
	noNew := discuss.DefaultLimits()
	noNew.NewAccountAge, noNew.NewAccountComments = 0, 0
	h.newAcct.Store(&noNew)
	cfg := &auth.Config{PublicOrigin: origin, Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)},
		Providers: map[string]auth.ProviderCredentials{}, TermsVersion: terms,
		SessionIdle: 14 * 24 * time.Hour, SessionMax: 60 * 24 * time.Hour, HandleHold: 90 * 24 * time.Hour,
		RPID: "nday.land", Origins: []string{origin}}
	creds := auth.ProviderCredentials{ClientID: "client-github", ClientSecret: "CLIENTSECRET-github-value"}
	cfg.Providers[auth.GitHub] = creds
	idp.Register(auth.GitHub, fakeidp.Client{ID: creds.ClientID, Secret: creds.ClientSecret, RedirectURI: cfg.RedirectURI(auth.GitHub)})
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.as = &auth.Store{DB: pool, Now: ck.Now}
	big := func() *auth.RateLimiter { l := auth.NewRateLimiter(100000, time.Millisecond); l.Now = ck.Now; return l }
	svc, err := auth.New(cfg, auth.Options{Store: h.as, Logger: log, Client: idp.Server.Client(),
		Endpoints: idp.Endpoints(), Now: ck.Now, StartLimit: big(), CallbackLimit: big(), PasskeyLimit: big(),
		AccountLimit: big(), TokenLimit: big(), SessionLookups: 4})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	if lim == nil {
		l := corrections.DefaultLimits()
		l.Daily, l.OpenPerVuln, l.OpenPerUser, l.Burst = 1000, 1000, 1000, 1000
		lim = &l
	}
	h.cs, err = corrections.New(corrections.Options{Store: &corrections.Store{DB: pool, Now: ck.Now}, Auth: svc, Logger: log,
		Limits: lim, Now: ck.Now, NewAccount: func() discuss.Limits { return *h.newAcct.Load() }})
	if err != nil {
		t.Fatal(err)
	}
	h.site = site.New(pool)
	srv := web.New(web.Config{Store: h.site, Logger: log, PublicURL: origin, APIURL: "https://" + apiHost})
	svc.Register(srv)
	h.cs.Register(srv)
	h.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(h.ts.Close)
	t.Cleanup(h.checkLogs)
	return h
}

// checkLogs: submitted texts, links and notes never reach the logs.
func (h *harness) checkLogs() {
	logs := h.logs.String()
	for _, s := range []string{"SECRET-BODY", "SECRET-NOTE", "secret-link", "CLIENTSECRET", "__Host-nday_session="} {
		if strings.Contains(logs, s) {
			h.t.Errorf("logs contain %q", s)
		}
	}
}

type browser struct {
	h    *harness
	jar  map[string]*http.Cookie
	ip   string
	id   string
	csrf string
}

func (h *harness) browser() *browser {
	return &browser{h: h, jar: map[string]*http.Cookie{}, ip: "198.51.100.7"}
}

func (b *browser) do(method, path, body string, hdr ...string) (*http.Response, []byte) {
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
	req.Host = publicHost
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
		if c.MaxAge < 0 {
			delete(b.jar, c.Name)
		} else {
			b.jar[c.Name] = c
		}
	}
	if strings.HasPrefix(path, "/api/corrections/") && req.Host == publicHost {
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			b.h.t.Errorf("%s %s: Cache-Control %q, want no-store", method, path, cc)
		}
		if !strings.Contains(strings.Join(resp.Header.Values("Vary"), ","), "Cookie") {
			b.h.t.Errorf("%s %s: no Vary: Cookie", method, path)
		}
	}
	return resp, data
}

func (b *browser) signIn(name string) string {
	h := b.h
	h.t.Helper()
	h.n++
	resp, body := b.do("GET", "/auth/github/start?return=/", "")
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("start: %d %s", resp.StatusCode, body)
	}
	cb, err := h.idp.Approve(auth.GitHub, resp.Header.Get("Location"), fakeidp.Account{Subject: strconv.Itoa(1000 + h.n), Name: name, Username: name})
	if err != nil {
		h.t.Fatal(err)
	}
	u, _ := url.Parse(cb)
	resp, body = b.do("GET", u.RequestURI(), "")
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
	b.refresh()
	return b.id
}

func (b *browser) refresh() {
	resp, body := b.do("GET", "/api/me", "")
	var m struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		CSRF string `json:"csrf_token"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &m) != nil {
		b.h.t.Fatalf("/api/me: %d %s", resp.StatusCode, body)
	}
	b.id, b.csrf = m.User.ID, m.CSRF
}

// member signs in, sets a handle and accepts the current terms.
func (h *harness) member(name string) *browser {
	h.t.Helper()
	b := h.browser()
	id := b.signIn(name)
	ctx := context.Background()
	key, err := auth.CanonicalHandle(name)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.as.SetHandle(ctx, id, name, key, 0); err != nil {
		h.t.Fatal(err)
	}
	if v := h.svc.Config().TermsVersion; v != "" {
		if err := h.as.AcceptTerms(ctx, id, v); err != nil {
			h.t.Fatal(err)
		}
	}
	return b
}

func (h *harness) moderator(name string) *browser {
	h.t.Helper()
	b := h.member(name)
	if err := h.as.SetRole(context.Background(), b.id, auth.RoleModerator); err != nil {
		h.t.Fatal(err)
	}
	return b
}

// post is a same-origin JSON POST with the session's CSRF token.
func (b *browser) post(path, body string) (*http.Response, []byte) {
	b.h.t.Helper()
	return b.do("POST", path, body, "Origin", origin, "Sec-Fetch-Site", "same-origin",
		"Content-Type", "application/json", "X-CSRF-Token", b.csrf)
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

type correction struct {
	ID          string  `json:"id"`
	CVE         string  `json:"cve"`
	Category    string  `json:"category"`
	Body        string  `json:"body"`
	EvidenceURL *string `json:"evidence_url"`
	Status      string  `json:"status"`
	DecidedAt   *string `json:"decided_at"`
	PublicNote  *string `json:"public_note"`
}

// submit posts a correction and returns it (fatal unless 201).
func (b *browser) submit(cve, category, text string, link *string) correction {
	b.h.t.Helper()
	req := map[string]any{"category": category, "body": text}
	if link != nil {
		req["evidence_url"] = *link
	}
	resp, body := b.post("/api/corrections/"+cve, jsonOf(req))
	if resp.StatusCode != http.StatusCreated {
		b.h.t.Fatalf("submit: %d %s", resp.StatusCode, body)
	}
	var r struct {
		OK         bool       `json:"ok"`
		Correction correction `json:"correction"`
	}
	if err := json.Unmarshal(body, &r); err != nil || !r.OK {
		b.h.t.Fatalf("submit: %v %s", err, body)
	}
	return r.Correction
}

func (b *browser) mine(query string) []correction {
	b.h.t.Helper()
	resp, body := b.do("GET", "/api/corrections/mine"+query, "")
	if resp.StatusCode != 200 {
		b.h.t.Fatalf("mine: %d %s", resp.StatusCode, body)
	}
	var r struct {
		Corrections []correction `json:"corrections"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		b.h.t.Fatal(err)
	}
	return r.Corrections
}

func errCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

func expect(t *testing.T, what string, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status || (code != "" && errCode(body) != code) {
		t.Errorf("%s: %d %s, want %d %s", what, resp.StatusCode, bytes.TrimSpace(body), status, code)
	}
}

func (h *harness) count(sql string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.Conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func ptr(s string) *string { return &s }
