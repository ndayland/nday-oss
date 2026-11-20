package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/fakeidp"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
	"nday.land/nday/internal/xlookup"
)

const (
	origin     = "https://www.nday.land"
	publicHost = "www.nday.land"
	apiHost    = "api.nday.land"
	cveA       = "CVE-2026-0001"
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
	t      *testing.T
	ts     *httptest.Server
	idp    *fakeidp.IDP
	svc    *auth.Service
	as     *auth.Store // auth write pool
	adm    *admin.Service
	srv    *web.Server
	db     *testutil.TestDB
	logs   *syncBuf
	clock  *clock
	n      int
	logDir string
}

type hopt struct {
	noDiscuss bool
	logDir    string
	loc       *time.Location
	xlookup   *xlookup.Client
	settings  settings.Runtime
	// ghLookup is admin.Options.GitHubLookup; stmtTimeout, when set, is the
	// write pool's statement_timeout (`nday serve`'s auth pool: "5000")
	ghLookup    func(context.Context, string) (int64, string, error)
	stmtTimeout string
}

func newHarness(t *testing.T, o hopt) *harness {
	t.Helper()
	// Not parallel: the repository's tests share one PostgreSQL; tiny pools.
	d := testutil.NewMigratedDB(t)
	pc, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	if o.stmtTimeout != "" {
		pc.RuntimeParams["statement_timeout"] = o.stmtTimeout
	}
	pool := dbpool.New(pc, dbpool.Options{Size: 3, Dial: testutil.Dial(pc)})
	t.Cleanup(pool.Close)
	rc := pc.Copy()
	rc.RuntimeParams["default_transaction_read_only"] = "on" // like the site pool of `nday serve`
	readPool := dbpool.New(rc, dbpool.Options{Size: 2, Dial: testutil.Dial(rc)})
	t.Cleanup(readPool.Close)
	if _, err := d.Conn.Exec(context.Background(), `INSERT INTO vuln (cve_id) VALUES ($1)`, cveA); err != nil {
		t.Fatal(err)
	}
	ck := &clock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	idp := fakeidp.New()
	t.Cleanup(idp.Server.Close)
	idp.Now = ck.Now
	h := &harness{t: t, idp: idp, db: d, logs: &syncBuf{}, clock: ck, logDir: o.logDir}
	cfg := &auth.Config{PublicOrigin: origin, Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)},
		Providers: map[string]auth.ProviderCredentials{}, TermsVersion: "",
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
		AccountLimit: big(), TokenLimit: big(), SessionLookups: 2})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	h.srv = web.New(web.Config{Store: site.New(readPool), Logger: log, PublicURL: origin, APIURL: "https://" + apiHost})
	svc.Register(h.srv)
	var ds *discuss.Service
	if !o.noDiscuss {
		lim := discuss.DefaultLimits()
		lim.ModBurst = 100000
		ds, err = discuss.New(discuss.Options{Store: &discuss.Store{DB: pool, ReadDB: readPool, Now: ck.Now}, Auth: svc, Logger: log,
			Now: ck.Now, Limits: &lim})
		if err != nil {
			t.Fatal(err)
		}
		ds.Register(h.srv)
	}
	loc := o.loc
	if loc == nil {
		loc = time.UTC
	}
	h.adm, err = admin.New(admin.Options{Auth: svc, AuthDB: pool, ReadDB: readPool, Site: site.New(readPool), Discussions: ds != nil,
		LogDir: o.logDir, Location: loc, Logger: log, Now: ck.Now, ActionLimit: big(), PageLimit: big(),
		Pools: []admin.Pool{{Name: "test", Size: 3, Stats: pool.Stats}}, XLookup: o.xlookup, Settings: o.settings,
		GitHubLookup: o.ghLookup})
	if err != nil {
		t.Fatal(err)
	}
	h.adm.Register(h.srv)
	t.Cleanup(h.adm.WaitStateRefresh) // before the pools close
	var disc webui.Discussions
	if ds != nil {
		disc = ds
	}
	if _, err := webui.New(h.srv, webui.Options{BaseURL: origin, Accounts: webui.AccountsOf(svc), Discussions: disc, Admin: h.adm,
		Now: ck.Now}); err != nil {
		t.Fatal(err)
	}
	h.ts = httptest.NewServer(h.srv.Handler())
	t.Cleanup(h.ts.Close)
	t.Cleanup(h.checkLogs)
	return h
}

// checkLogs: no session secret or client secret ever reaches the logs.
func (h *harness) checkLogs() {
	logs := h.logs.String()
	for _, s := range []string{"CLIENTSECRET", "__Host-nday_session="} {
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
	name string
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
	req.Header.Set("Cf-Ray", "8e0000test-SIN")
	req.Host = publicHost
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
			continue
		}
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
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
	if isAdminPath(path) {
		checkPersonalHeaders(b.h.t, method+" "+path, resp)
	}
	checkPagerCounts(b.h.t, method+" "+path, string(data))
	return resp, data
}

var (
	pagerPosRe = regexp.MustCompile(`(?s)<nav class="pager"[^>]*>\s*<p class="pg-pos[^"]*">(.*?)</p>`)
	firstSpan  = regexp.MustCompile(`^<span class="sr">([^<]*)</span>`)
	digitsRe   = regexp.MustCompile(`[0-9][0-9,.]*`)
)

// checkPagerCounts: every pager a page renders says how many pages its list
// has (pager.page_of: the page number and the number of pages), unless the
// page number itself is not known (no position at all).
func checkPagerCounts(t *testing.T, what, body string) {
	t.Helper()
	for _, m := range pagerPosRe.FindAllStringSubmatch(body, -1) {
		if m[1] == "" {
			continue
		}
		s := firstSpan.FindStringSubmatch(m[1])
		if s == nil || len(digitsRe.FindAllString(s[1], -1)) < 2 {
			t.Errorf("%s: a pager without the number of pages: %s", what, m[1])
		}
	}
}

// isAdminPath: the back office's own routes, in any locale.
func isAdminPath(p string) bool {
	p, _, _ = strings.Cut(p, "?")
	if strings.HasPrefix(p, "/api/admin/") {
		return true
	}
	seg := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(seg) > 0 && seg[0] == "admin" {
		return true
	}
	return len(seg) > 1 && seg[1] == "admin" && seg[0] != "api"
}

// checkPersonalHeaders: every back-office response is no-store, noindex,
// without validators, whatever the outcome (except on the API host, where
// the route does not exist at all, and on a foreign host, which web.Server
// answers itself before any back-office handler runs: see checkForeignHost).
func checkPersonalHeaders(t *testing.T, what string, resp *http.Response) {
	t.Helper()
	if resp.Request.Host != publicHost {
		return
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s: Cache-Control %q", what, cc)
	}
	if resp.Header.Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Errorf("%s: X-Robots-Tag %q", what, resp.Header.Get("X-Robots-Tag"))
	}
	if resp.Header.Get("ETag") != "" || resp.Header.Get("Last-Modified") != "" {
		t.Errorf("%s: validators on a personal response", what)
	}
}

// checkForeignHost: web.Server (foreign.go) answers a request for a host it
// is not configured for before any back-office handler runs, so the answer
// is the server's, not the admin's: GET/HEAD 308 to the same path on the
// public origin, anything else 421 wrong_host. Neither may carry a cookie
// or any page content, and the 421 must not be cacheable.
func checkForeignHost(t *testing.T, what, method, path string, resp *http.Response, body []byte) {
	t.Helper()
	if method == http.MethodGet || method == http.MethodHead {
		if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != origin+path {
			t.Errorf("%s: %d Location %q, want 308 %q", what, resp.StatusCode, resp.Header.Get("Location"), origin+path)
		}
	} else {
		expect(t, what, resp, body, http.StatusMisdirectedRequest, "wrong_host")
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q", what, cc)
		}
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 || bytes.Contains(body, []byte("<html")) {
		t.Errorf("%s: cookie or page content on a foreign host: %v", what, resp.Header)
	}
}

// signIn signs the browser in as a new GitHub persona (handle = name).
func (b *browser) signIn(name string) string {
	h := b.h
	h.t.Helper()
	h.n++
	resp, body := b.do("GET", "/auth/github/start?return=/", "")
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("start: %d %s", resp.StatusCode, body)
	}
	cb, err := h.idp.Approve(auth.GitHub, resp.Header.Get("Location"), fakeidp.Account{Subject: strconv.Itoa(9000 + h.n), Name: name, Username: name + "-gh"})
	if err != nil {
		h.t.Fatal(err)
	}
	u, _ := url.Parse(cb)
	resp, body = b.do("GET", u.RequestURI(), "")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasSuffix(resp.Header.Get("Location"), "auth=ok") {
		h.t.Fatalf("callback: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	b.refresh()
	key, err := auth.CanonicalHandle(name)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.as.SetHandle(context.Background(), b.id, name, key, 0); err != nil {
		h.t.Fatal(err)
	}
	b.name = name
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

// post is a same-origin JSON POST with the session's CSRF token.
func (b *browser) post(path, body string, hdr ...string) (*http.Response, []byte) {
	b.h.t.Helper()
	base := []string{"Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json", "X-CSRF-Token", b.csrf}
	return b.do("POST", path, body, append(base, hdr...)...)
}

// sql runs a statement on the test schema (setup only).
func (h *harness) sql(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.Conn.Exec(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *harness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.Conn.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// role sets a role directly (setup; no audit row).
func (h *harness) role(id, role string) { h.sql(`UPDATE users SET role = $2 WHERE id = $1`, id, role) }

func (h *harness) suspend(id string) {
	h.sql(`UPDATE users SET status = 'suspended', suspended_until = NULL, status_reason = 'setup' WHERE id = $1`, id)
}

// user creates a signed-in browser with a role.
func (h *harness) user(name, role string) *browser {
	b := h.browser()
	b.signIn(name)
	if role != auth.RoleUser {
		h.role(b.id, role)
	}
	return b
}

// comment inserts a comment by author and returns its id.
func (h *harness) comment(author, body string) string {
	h.t.Helper()
	var id string
	if err := h.db.Conn.QueryRow(context.Background(), `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links, created_at, updated_at)
		VALUES ($1, false, $2, $3, 'en', true, $4, $4) RETURNING id::text`, cveA, author, body, h.clock.Now()).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *harness) report(comment, reporter, reason string, note *string) string {
	h.t.Helper()
	var id string
	if err := h.db.Conn.QueryRow(context.Background(), `INSERT INTO comment_reports (comment_id, reporter_id, reason, note, created_at)
		VALUES ($1, $2, $3, $4, $5) RETURNING id::text`, comment, reporter, reason, note, h.clock.Now()).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
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

// ---- HTML checks

var voidElems = map[string]bool{"meta": true, "link": true, "input": true, "br": true, "img": true, "hr": true,
	"source": true, "wbr": true, "area": true, "base": true, "col": true, "embed": true, "track": true}

// bidiControls are the explicit directional formatting characters.
const bidiControls = "‪‫‬‭‮⁦⁧⁨⁩"

// checkHTML parses a page as XML (the pages are polyglot) and reports
// structural problems, anything the CSP forbids (inline script/style, on*
// handlers, javascript:/data: URLs), elements outside the set the admin
// templates use (an injected element shows up here), and text holding
// bidirectional controls outside an isolating element (bdi, or any element
// with a dir attribute, which HTML renders with unicode-bidi: isolate).
func checkHTML(body string, allowed map[string]bool) (problems []string) {
	dec := xml.NewDecoder(strings.NewReader(body))
	dec.Strict = true
	dec.Entity = xml.HTMLEntity
	type el struct {
		name    string
		isolate bool
	}
	var stack []el
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return append(problems, "parse: "+err.Error())
		}
		switch x := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(x.Name.Local)
			if allowed != nil && !allowed[name] {
				problems = append(problems, "unexpected element <"+name+">")
			}
			iso := name == "bdi"
			hasSrc := false
			for _, a := range x.Attr {
				an := strings.ToLower(a.Name.Local)
				v := strings.TrimSpace(strings.ToLower(a.Value))
				switch {
				case an == "style":
					problems = append(problems, "style attribute on <"+name+">")
				case strings.HasPrefix(an, "on"):
					problems = append(problems, an+" handler on <"+name+">")
				case (an == "href" || an == "src" || an == "action") && (strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "data:")):
					problems = append(problems, an+"="+a.Value)
				case an == "dir":
					iso = true
				case an == "src":
					hasSrc = true
				}
				// (the value of a form control is rendered isolated by the browser
				// and must stay exact, e.g. a stored note prefilled for editing)
				if strings.ContainsAny(a.Value, bidiControls) && !(name == "input" && an == "value") {
					problems = append(problems, "bidi control in attribute "+an+" of <"+name+">")
				}
			}
			if name == "script" && !hasSrc {
				problems = append(problems, "inline <script>")
			}
			if name == "style" {
				problems = append(problems, "<style> element")
			}
			if !voidElems[name] {
				stack = append(stack, el{name, iso})
			}
		case xml.EndElement:
			name := strings.ToLower(x.Name.Local)
			if voidElems[name] {
				continue
			}
			if len(stack) == 0 || stack[len(stack)-1].name != name {
				return append(problems, fmt.Sprintf("unbalanced </%s>", name))
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if !strings.ContainsAny(string(x), bidiControls) {
				continue
			}
			ok := false
			for _, e := range stack {
				ok = ok || e.isolate
			}
			if !ok {
				problems = append(problems, fmt.Sprintf("bidi control outside an isolate in <%s>: %q", stack[len(stack)-1].name, trunc(string(x), 60)))
			}
		}
	}
	if len(stack) != 0 {
		problems = append(problems, fmt.Sprintf("unclosed elements: %d", len(stack)))
	}
	return problems
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
