package discuss_test

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
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/fakeidp"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
)

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
	ds    *discuss.Store
	dsvc  *discuss.Service
	db    *testutil.TestDB
	logs  *syncBuf
	clock *clock
	n     int
}

type hopt struct {
	terms  string
	limits *discuss.Limits
}

func newHarness(t *testing.T, o hopt) *harness {
	t.Helper()
	// Not parallel: the whole repository's tests share one PostgreSQL
	// (max_connections 100); these tests are quick when run one by one.
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
	ck := &clock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	idp := fakeidp.New()
	t.Cleanup(idp.Server.Close)
	idp.Now = ck.Now
	h := &harness{t: t, idp: idp, db: d, logs: &syncBuf{}, clock: ck}
	cfg := &auth.Config{PublicOrigin: origin, Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)},
		Providers: map[string]auth.ProviderCredentials{}, TermsVersion: o.terms,
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
	h.ds = &discuss.Store{DB: pool, Now: ck.Now}
	lim := o.limits
	if lim == nil {
		// generous by default; rate-limit tests pass their own
		l := discuss.DefaultLimits()
		l.PostBurst, l.NewPostBurst, l.AddrBurst, l.EditBurst, l.ReadBurst = 1000, 1000, 1000, 1000, 1000
		l.PostDaily, l.NewPostDaily, l.ReportDaily = 1000, 1000, 1000
		// the older tests check the outline fallback (signed-out reading
		// off); guestread_test.go turns it on
		l.GuestRead = false
		lim = &l
	}
	h.dsvc, err = discuss.New(discuss.Options{Store: h.ds, Auth: svc, Logger: log, Now: ck.Now, Limits: lim,
		Locales: []string{"en", "zh-Hans", "ja"},
		CVEPath: func(locale, cve string) string {
			if locale == "en" {
				return "/vuln/" + cve
			}
			return "/" + strings.ToLower(locale) + "/vuln/" + cve
		}})
	if err != nil {
		t.Fatal(err)
	}
	srv := web.New(web.Config{Store: site.New(pool), Logger: log, PublicURL: origin, APIURL: "https://" + apiHost})
	svc.Register(srv)
	h.dsvc.Register(srv)
	h.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(h.ts.Close)
	t.Cleanup(h.checkLogs)
	return h
}

// checkLogs: comment bodies and session secrets never reach the logs.
func (h *harness) checkLogs() {
	logs := h.logs.String()
	for _, s := range []string{"SECRET-BODY", "CLIENTSECRET", "__Host-nday_session="} {
		if strings.Contains(logs, s) {
			h.t.Errorf("logs contain %q", s)
		}
	}
}

type browser struct {
	h    *harness
	jar  map[string]*http.Cookie
	ip   string
	id   string // user id once signed in
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
	if strings.HasPrefix(path, "/api/discuss/") || strings.HasPrefix(path, "/api/mod/") {
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			b.h.t.Errorf("%s %s: Cache-Control %q, want no-store", method, path, cc)
		}
		if resp.Header.Get("ETag") != "" || resp.Header.Get("Last-Modified") != "" {
			b.h.t.Errorf("%s %s: validators on a personal response", method, path)
		}
	}
	return resp, data
}

// signIn signs the browser in as a new GitHub persona and returns the user id.
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
	if resp.StatusCode != http.StatusSeeOther || !strings.HasSuffix(resp.Header.Get("Location"), "auth=ok") {
		h.t.Fatalf("callback: %d %s %s\n%s", resp.StatusCode, resp.Header.Get("Location"), body, h.logs.String())
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

// reader is a signed-in browser of an account without a handle: it sees
// comments as any other signed-in user (signed-out callers get only the
// outline while signed-out reading is off, docs/discuss.md §4.1).
func (h *harness) reader() *browser {
	h.t.Helper()
	b := h.browser()
	h.n++
	b.signIn("reader" + strconv.Itoa(h.n))
	return b
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

// establish makes the user's account old and gives it visible comments, so
// it no longer counts as new.
func (h *harness) establish(id string) {
	h.t.Helper()
	ctx := context.Background()
	if _, err := h.db.Conn.Exec(ctx, `UPDATE users SET created_at = $2 WHERE id = $1`, id, h.clock.Now().Add(-48*time.Hour)); err != nil {
		h.t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := h.db.Conn.Exec(ctx, `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			VALUES ($1, false, $2, $3, 'en', true, $4, $4)`, cveB, id, "seed "+string(rune('a'+i)), h.clock.Now().Add(-47*time.Hour)); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *harness) setRole(id, role string) {
	h.t.Helper()
	if err := h.as.SetRole(context.Background(), id, role); err != nil {
		h.t.Fatal(err)
	}
}

// post is a same-origin JSON POST with the session's CSRF token.
func (b *browser) post(path, body string) (*http.Response, []byte) {
	b.h.t.Helper()
	return b.do("POST", path, body, "Origin", origin, "Sec-Fetch-Site", "same-origin",
		"Content-Type", "application/json", "X-CSRF-Token", b.csrf)
}

type comment struct {
	ID         string                    `json:"id"`
	ParentID   *string                   `json:"parent_id"`
	Author     *struct{ Handle *string } `json:"author"`
	Lang       string                    `json:"lang"`
	Status     string                    `json:"status"`
	BodyHTML   string                    `json:"body_html"`
	Body       *string                   `json:"body"`
	Links      bool                      `json:"links"`
	EditedAt   *string                   `json:"edited_at"`
	CanEdit    bool                      `json:"can_edit"`
	CanDelete  bool                      `json:"can_delete"`
	CanHide    bool                      `json:"can_hide"`
	CanUnhide  bool                      `json:"can_unhide"`
	CanReport  bool                      `json:"can_report"`
	CanReply   bool                      `json:"can_reply"`
	Reported   bool                      `json:"reported"`
	Moderation *struct {
		HiddenReason *string                   `json:"hidden_reason"`
		HiddenBy     *struct{ Handle *string } `json:"hidden_by"`
		OpenReports  *int                      `json:"open_reports"`
	} `json:"moderation"`
	Replies           []comment `json:"replies"`
	RepliesTruncated  bool      `json:"replies_truncated"`
	RepliesNextCursor *string   `json:"replies_next_cursor"`
}

type stream struct {
	CVE        string    `json:"cve"`
	Count      int       `json:"count"`
	Comments   []comment `json:"comments"`
	NextCursor *string   `json:"next_cursor"`
	Cursor     *string   `json:"cursor"`
	Outline    *struct {
		Count   int `json:"count"`
		Threads []struct {
			Status      string `json:"status"`
			Size        string `json:"size"`
			MoreReplies int    `json:"more_replies"`
			Replies     []struct {
				Status string `json:"status"`
				Size   string `json:"size"`
			} `json:"replies"`
		} `json:"threads"`
		More bool `json:"more"`
	} `json:"outline"`
	Viewer struct {
		SignedIn     bool    `json:"signed_in"`
		CanPost      bool    `json:"can_post"`
		PostRefusal  *string `json:"post_refusal"`
		TermsVersion *string `json:"terms_version"`
		Links        bool    `json:"links"`
		Moderator    bool    `json:"moderator"`
	} `json:"viewer"`
}

func (b *browser) stream(cve, query string) stream {
	b.h.t.Helper()
	resp, body := b.do("GET", "/api/discuss/"+cve+query, "")
	if resp.StatusCode != 200 {
		b.h.t.Fatalf("GET stream: %d %s", resp.StatusCode, body)
	}
	var s stream
	if err := json.Unmarshal(body, &s); err != nil {
		b.h.t.Fatalf("%v %s", err, body)
	}
	return s
}

// create posts a comment and returns it (fatal unless 201).
func (b *browser) create(cve, text string, parent *string) comment {
	b.h.t.Helper()
	resp, body := b.tryCreate(cve, text, parent)
	if resp.StatusCode != http.StatusCreated {
		b.h.t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var r struct {
		Comment comment `json:"comment"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		b.h.t.Fatal(err)
	}
	return r.Comment
}

func (b *browser) tryCreate(cve, text string, parent *string) (*http.Response, []byte) {
	b.h.t.Helper()
	req := map[string]any{"body": text, "lang": "zh-Hans"}
	if parent != nil {
		req["parent_id"] = *parent
	}
	j, _ := json.Marshal(req)
	return b.post("/api/discuss/"+cve, string(j))
}

func errCode(body []byte) string {
	var e struct {
		Error struct {
			Code  string `json:"code"`
			Param string `json:"param"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

func errParam(body []byte) string {
	var e struct {
		Error struct {
			Param string `json:"param"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Param
}

func (h *harness) count(sql string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.Conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func expect(t *testing.T, what string, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status || (code != "" && errCode(body) != code) {
		t.Errorf("%s: %d %s, want %d %s", what, resp.StatusCode, bytes.TrimSpace(body), status, code)
	}
}

func ptr(s string) *string { return &s }
