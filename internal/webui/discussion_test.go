package webui_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/web/webtest"
	"nday.land/nday/internal/webui"
	"nday.land/nday/internal/webui/i18n"
)

// fakeDisc is a Discussions with a fixed outline; it counts calls.
type fakeDisc struct {
	mu      sync.Mutex
	outline *discuss.Outline
	version string
	err     error
	vers    int // Version calls
	outs    int // Outline calls
	guest   bool
}

func (f *fakeDisc) GuestRead() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.guest
}

func (f *fakeDisc) Version(ctx context.Context, cve string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vers++
	return f.version, f.err
}

func (f *fakeDisc) Outline(ctx context.Context, cve string) (*discuss.Outline, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outs++
	if f.err != nil {
		return nil, f.err
	}
	o := *f.outline
	return &o, nil
}

func (f *fakeDisc) calls() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vers, f.outs
}

func (f *fakeDisc) set(fn func(f *fakeDisc)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// newDiscEnv is newEnvFull without t.Parallel (one database per call; the
// discussion tests run one after another to spare PostgreSQL connections).
func newDiscEnv(t *testing.T, opts webui.Options) *tenv {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 2, Dial: testutil.Dial(cfg)})
	t.Cleanup(pool.Close)
	now := func() time.Time { return sitetest.Now }
	srv := web.New(web.Config{Store: site.New(pool).WithClock(now), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv.SetAPIAuth(webtest.BearerAuth{})
	opts.Now = now
	ui, err := webui.New(srv, opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &tenv{ts: ts, ui: ui}
}

// outlineFixture: three threads (a visible one with a reply, a hidden one
// with a reply, a deleted one with a reply) of 5 visible comments, and more
// threads after them.
func outlineFixture() *discuss.Outline {
	v := func(size string) discuss.OutlineComment { return discuss.OutlineComment{Status: "visible", Size: size} }
	a := v("m")
	a.Replies = []discuss.OutlineComment{v("s")}
	b := discuss.OutlineComment{Status: "hidden", Replies: []discuss.OutlineComment{v("l")}}
	c := discuss.OutlineComment{Status: "deleted", Replies: []discuss.OutlineComment{v("s")}, MoreReplies: 3}
	return &discuss.Outline{Count: 5, Threads: []discuss.OutlineComment{a, b, c}, More: true}
}

var discAccounts = &webui.Accounts{Providers: []string{"github"}, TermsVersion: "2026-11-13"}

func gpuPath(l *i18n.Locale) string { return l.Path("/vuln/" + sitetest.GPU) }

// TestDiscussionSection: the section exists on vulnerability pages only,
// only when discussions are on; the page stays the same for every visitor
// (no cookie dependence, unchanged cache headers); it holds the outline
// only (speckle placeholders of the right sizes, placeholders of hidden and
// deleted comments, the call to sign in), never a comment; writing controls
// and discuss.js need accounts.
func TestDiscussionSection(t *testing.T) {
	f := &fakeDisc{version: "v1", outline: outlineFixture()}
	e := newDiscEnv(t, webui.Options{Accounts: discAccounts, Discussions: f})
	set := e.ui.Locales()

	t.Run("only on vulnerability pages", func(t *testing.T) {
		for _, l := range set.Enabled {
			resp, body := e.get(t, gpuPath(l))
			if resp.StatusCode != 200 || !strings.Contains(body, `id="discussion"`) || !strings.Contains(body, "/static/discuss.") {
				t.Errorf("%s: no discussion section or script", gpuPath(l))
			}
			links, problems := CheckHTML(body)
			for _, p := range problems {
				t.Errorf("%s: %s", gpuPath(l), p)
			}
			for _, lk := range links {
				if strings.HasPrefix(lk, "/auth/") {
					continue
				}
				if r, _ := e.get(t, lk); r.StatusCode != 200 {
					t.Errorf("%s: link %s -> %d", gpuPath(l), lk, r.StatusCode)
				}
			}
			if strings.Contains(body, i18n.MissingOpen) {
				t.Errorf("%s: missing message", gpuPath(l))
			}
		}
		for _, p := range []string{"/", "/about", "/vuln?q=a", "/src", "/rules", "/account", "/vuln/CVE-2099-99999"} {
			_, body := e.get(t, p)
			if strings.Contains(body, `id="discussion"`) || strings.Contains(body, "/static/discuss.") || strings.Contains(body, "disc-tpl") {
				t.Errorf("%s: discussion parts outside a vulnerability page", p)
			}
		}
	})

	t.Run("not personal", func(t *testing.T) {
		for _, p := range []string{"/vuln/" + sitetest.GPU, "/zh-hans/vuln/" + sitetest.GPU, "/vuln/" + sitetest.GPU + "?fresh=abc",
			"/vuln/" + sitetest.GPU + "?c=0b141010-ef0f-49ba-b9bd-2f476f8923bb"} {
			r1, b1 := e.get(t, p)
			r2, b2 := e.get(t, p, "Cookie", "__Host-nday_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; other=1")
			if b1 != b2 {
				t.Errorf("%s: body differs with a session cookie", p)
			}
			for _, h := range []string{"Cache-Control", "ETag", "Vary", "Set-Cookie", "Content-Security-Policy"} {
				if r1.Header.Get(h) != r2.Header.Get(h) {
					t.Errorf("%s: %s %q vs %q", p, h, r1.Header.Get(h), r2.Header.Get(h))
				}
			}
			if r1.Header.Get("Cache-Control") != "public, max-age=60" || r1.Header.Get("ETag") == "" ||
				strings.Contains(strings.Join(r1.Header.Values("Vary"), ","), "Cookie") || len(r1.Header.Values("Set-Cookie")) != 0 ||
				r1.Header.Get("Content-Security-Policy") != webui.CSP {
				t.Errorf("%s: headers %v", p, r1.Header)
			}
		}
	})

	t.Run("outline", func(t *testing.T) {
		_, body := e.get(t, "/vuln/"+sitetest.GPU)
		sec := between(t, body, `<section class="sec disc" id="discussion"`, "</section>")
		sizes := regexp.MustCompile(`<span class="spk" data-size="([sml])" aria-hidden="true"></span>`).FindAllStringSubmatch(sec, -1)
		var got []string
		for _, m := range sizes {
			got = append(got, m[1])
		}
		if strings.Join(got, ",") != "m,s,l,s" {
			t.Errorf("speckle sizes %v, want m,s,l,s", got)
		}
		for _, want := range []string{"5 comments", "Hidden by a moderator.", "3 more replies",
			"More comments follow.", "Sign in to read 5 comments.", `id="disc-veil"`,
			`aria-hidden="true"></span></a><span class="sr">A comment. Sign in to read it.</span>`,
			`<a class="spk-go" href="/login?return=%2Fvuln%2F` + sitetest.GPU + `%3Fdiscussion" tabindex="-1" aria-hidden="true">`} {
			if !strings.Contains(sec, want) {
				t.Errorf("outline: missing %q", want)
			}
		}
		for _, bad := range []string{`id="c-`, "cm-body", "data-id=", "<time", "@"} {
			if strings.Contains(sec[:strings.Index(sec, `<div class="disc-write"`)], bad) {
				t.Errorf("outline holds %q", bad)
			}
		}
	})

	t.Run("writing shell", func(t *testing.T) {
		_, body := e.get(t, "/zh-hans/vuln/"+sitetest.GPU)
		for _, want := range []string{`id="disc-new"`, `id="disc-out"`, `id="disc-nohandle"`, `id="disc-susp"`, `id="disc-tpl-acts"`,
			`id="disc-tpl-reply"`, `id="disc-tpl-edit"`, `id="disc-tpl-report"`, `id="disc-tpl-hide"`, `<noscript>`,
			`href="/zh-hans/login?return=%2Fzh-hans%2Fvuln%2F` + sitetest.GPU + `%3Fdiscussion"`, `href="/zh-hans/rules"`,
			`<option value="malicious_link">恶意链接</option>`, `data-k="disc.err.rate_limited"`, `data-k="disc.terms.needed"`,
			`data-k="disc.comment.deleted_account"`, `data-k="rsch.view_on_x"`, `data-k="acct.role.badge#moderator"`,
			`data-locale="zh-Hans"`, `data-cve="` + sitetest.GPU + `"`, `<details class="disc-md" id="disc-md" hidden="">`, `id="disc-list"`,
			`<button type="button" class="btn sm" data-act="delete" data-confirm="确认" hidden="">`} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %s", want)
			}
		}
		// the sign-in link's return target is one the sign-in flow accepts
		ret, _ := url.QueryUnescape("%2Fzh-hans%2Fvuln%2F" + sitetest.GPU + "%3Fdiscussion")
		if !regexp.MustCompile(`^/[A-Za-z0-9._~\-/]*(\?([A-Za-z0-9._~\-=&+]|%[0-9A-Fa-f]{2})*)?$`).MatchString(ret) {
			t.Errorf("return %q", ret)
		}
	})

	t.Run("version memoised", func(t *testing.T) {
		e.get(t, "/vuln/CVE-2026-1001") // (earlier subtests may have viewed it already)
		v0, s0 := f.calls()
		for i := 0; i < 5; i++ {
			e.get(t, "/vuln/CVE-2026-1001")
		}
		v1, s1 := f.calls()
		if v1 != v0 || s1 != s0 {
			t.Errorf("5 more views: %d Version and %d Outline calls, want none", v1-v0, s1-s0)
		}
		// a new version is not looked up before the TTL ...
		f.set(func(f *fakeDisc) {
			f.version = "v2"
			o := outlineFixture()
			o.Count = 6
			f.outline = o
		})
		if _, b := e.get(t, "/vuln/CVE-2026-1001"); !strings.Contains(b, "5 comments") {
			t.Error("the version was looked up again within its TTL")
		}
		// ... except after a write (?fresh=), at most once per second per CVE
		_, b := e.get(t, "/vuln/CVE-2026-1001?fresh=1")
		_, b2 := e.get(t, "/vuln/CVE-2026-1001?fresh=2")
		if !strings.Contains(b, "6 comments") || !strings.Contains(b2, "6 comments") {
			t.Error("?fresh= did not show the new outline")
		}
		if v2, _ := f.calls(); v2-v1 > 2 {
			t.Errorf("?fresh= looked the version up %d times", v2-v1)
		}
	})
}

// TestDiscussionGuestRead: with signed-out reading on, the page is still
// the same for every visitor and still holds no comment: the outline is a
// placeholder (no call to sign in on it, no sign-in links on the speckle),
// the section tells discuss.js to load the comments for everyone
// (data-guest), the sign-in state for writing explains that reading is
// open, and the forms carry the purpose drop-down. Switching it off
// changes the next page view.
func TestDiscussionGuestRead(t *testing.T) {
	f := &fakeDisc{version: "v1", outline: outlineFixture(), guest: true}
	e := newDiscEnv(t, webui.Options{Accounts: discAccounts, Discussions: f})
	for _, p := range []string{"/vuln/" + sitetest.GPU, "/zh-hans/vuln/" + sitetest.GPU, "/vuln/" + sitetest.GPU + "?c=0b141010-ef0f-49ba-b9bd-2f476f8923bb"} {
		r1, b1 := e.get(t, p)
		r2, b2 := e.get(t, p, "Cookie", "__Host-nday_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		if b1 != b2 || r1.Header.Get("Cache-Control") != "public, max-age=60" || r1.Header.Get("Cache-Control") != r2.Header.Get("Cache-Control") ||
			strings.Contains(strings.Join(r1.Header.Values("Vary"), ","), "Cookie") {
			t.Errorf("%s: personal or not cacheable: %v", p, r1.Header)
		}
		if _, problems := CheckHTML(b1); len(problems) != 0 {
			t.Errorf("%s: %v", p, problems)
		}
		if i := strings.Index(b1, i18n.MissingOpen); i >= 0 {
			t.Errorf("%s: missing message %s", p, b1[i:min(len(b1), i+80)])
		}
	}
	_, body := e.get(t, "/vuln/"+sitetest.GPU)
	sec := between(t, body, `<section class="sec disc" id="discussion"`, "</section>")
	for _, want := range []string{`data-guest="1"`, "loading 5 comments…", `id="disc-veil-t"`,
		"<noscript><p class=\"note\">Turn on JavaScript to read the comments.</p></noscript>",
		"Sign in to comment, reply or report.",
		`<select class="acct-in" data-f="purpose">`, `<option value="">not specified</option>`,
		`<option value="reproduction">reproduction report</option>`, `<option value="question">question</option>`,
		`data-k="disc.purpose#fix"`, `data-k="disc.purpose_hint#reproduction"`} {
		if !strings.Contains(body, want) {
			t.Errorf("guest page: missing %q", want)
		}
	}
	if n := strings.Count(sec, `data-f="purpose"`); n != 2 { // compose box and edit template
		t.Errorf("%d purpose drop-downs, want 2", n)
	}
	for _, bad := range []string{"Sign in to read", "spk-go", `id="c-`, "cm-body", "data-id=", "<time"} {
		if strings.Contains(sec[:strings.Index(sec, `<div class="disc-write"`)], bad) {
			t.Errorf("guest outline holds %q", bad)
		}
	}
	_, zh := e.get(t, "/zh-hans/vuln/"+sitetest.GPU)
	for _, want := range []string{"正在载入 5 条评论…", "登录后可评论、回复、举报。", `<option value="fix">修复反馈</option>`} {
		if !strings.Contains(zh, want) {
			t.Errorf("zh-Hans guest page: missing %q", want)
		}
	}
	// off: the call to sign in is back (new page view; the outline itself is cached)
	f.set(func(f *fakeDisc) { f.guest = false })
	_, body = e.get(t, "/vuln/"+sitetest.GPU)
	sec = between(t, body, `<section class="sec disc" id="discussion"`, "</section>")
	if strings.Contains(sec, "data-guest") || !strings.Contains(sec, "Sign in to read 5 comments.") || !strings.Contains(sec, "spk-go") ||
		strings.Contains(sec, "Anyone can read") {
		t.Errorf("guest reading off: %s", sec)
	}
}

// between returns s from the first from to the next to (inclusive).
func between(t *testing.T, s, from, to string) string {
	t.Helper()
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("no %q", from)
	}
	j := strings.Index(s[i:], to)
	if j < 0 {
		t.Fatalf("no %q after %q", to, from)
	}
	return s[i : i+j+len(to)]
}

// TestDiscussionReadOnlyAndFailure: without accounts the outline is shown
// without any writing parts, sign-in link or script; a failing discussion
// backend leaves the rest of the page intact.
func TestDiscussionReadOnlyAndFailure(t *testing.T) {
	f := &fakeDisc{version: "v1", outline: outlineFixture()}
	e := newDiscEnv(t, webui.Options{Discussions: f})
	_, body := e.get(t, "/vuln/"+sitetest.GPU)
	if !strings.Contains(body, `<span class="spk" data-size="m" aria-hidden="true"></span>`) {
		t.Error("read-only: no outline")
	}
	for _, bad := range []string{"disc-write", "disc-tpl", "/static/discuss.", "acct-msgs", "/login", "spk-go"} {
		if strings.Contains(body, bad) {
			t.Errorf("read-only page contains %q", bad)
		}
	}
	f.set(func(f *fakeDisc) { f.err = errors.New("db down"); f.version = "v9" })
	resp, body := e.get(t, "/vuln/CVE-2026-1001")
	if resp.StatusCode != 200 || !strings.Contains(body, "The discussion could not be loaded right now.") ||
		!strings.Contains(body, `id="evh"`) || strings.Contains(body, "cm-list") {
		t.Errorf("failure: %d", resp.StatusCode)
	}
	if _, problems := CheckHTML(body); len(problems) != 0 {
		t.Error(problems)
	}
}

// TestRulesPage: /rules in every locale (pending ones in marked English),
// the configured version line (none without a version), linked from the
// about page and the account page, public and cacheable.
func TestRulesPage(t *testing.T) {
	e := newDiscEnv(t, webui.Options{Accounts: discAccounts})
	set := e.ui.Locales()
	native := map[string][]string{
		"en": {"<h1 class=\"h1\"><span class=\"h\" aria-hidden=\"true\"># </span>Community rules</h1>", "version 2026-11-13",
			"Stay on the vulnerability.", "No help attacking systems you are not authorized to test.",
			"Use “report” on a comment to flag it.", "If you delete your account, your comments remain without your name."},
		"zh-Hans": {"社区规则", "版本 2026-11-13", "就漏洞谈漏洞。", "不求、不发目标、权限、被窃数据，不提供代打服务。",
			"看到违规内容请点评论上的“举报”。", "删除账号后，评论仍然保留，但不再显示你的名字。"},
	}
	for _, l := range set.Enabled {
		p := l.Path("/rules")
		resp, body := e.get(t, p)
		if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "public, max-age=60" || resp.Header.Get("X-Robots-Tag") != "" ||
			strings.Contains(body, `name="robots"`) {
			t.Errorf("%s: %d %v", p, resp.StatusCode, resp.Header)
		}
		if _, problems := CheckHTML(body); len(problems) != 0 {
			t.Errorf("%s: %v", p, problems)
		}
		if strings.Count(body, `<p class="rt">`) != 8 || strings.Contains(body, i18n.MissingOpen) {
			t.Errorf("%s: not 8 rules", p)
		}
		switch l.Tag {
		case "en", "zh-Hans":
			for _, want := range native[l.Tag] {
				if !strings.Contains(body, want) {
					t.Errorf("%s: missing %q", p, want)
				}
			}
		default:
			if !strings.Contains(body, `<p class="rt"><span lang="en">Stay on the vulnerability.</span></p>`) ||
				!strings.Contains(body, `<span lang="en">version 2026-11-13</span>`) {
				t.Errorf("%s: pending rules not in marked English", p)
			}
		}
		_, about := e.get(t, l.Path("/about"))
		if !strings.Contains(about, `<a href="`+p+`">`) {
			t.Errorf("%s: about page does not link the rules", l.Path("/about"))
		}
		_, acct := e.get(t, l.Path("/account"))
		if !strings.Contains(between(t, acct, `id="terms"`, "</section>"), `<a href="`+p+`">`) {
			t.Errorf("%s: account terms block does not link the rules", l.Path("/account"))
		}
	}
	// no configured version: no version line, the page still renders
	e2 := newDiscEnv(t, webui.Options{})
	resp, body := e2.get(t, "/rules")
	if resp.StatusCode != 200 || strings.Contains(body, "</h1>\n<p class=\"note\">") || !strings.Contains(body, "Be civil.") {
		t.Errorf("/rules without a version: %d", resp.StatusCode)
	}
}

// realDiscEnv is a site with the real discussion service over the test
// database (anonymous reads only; comments are inserted with SQL).
func realDiscEnv(t *testing.T) (*tenv, *pgx.Conn) {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 2, Dial: testutil.Dial(cfg)})
	t.Cleanup(pool.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	acfg := &auth.Config{PublicOrigin: "https://nday.land", Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)},
		Providers: map[string]auth.ProviderCredentials{}, Passkeys: true, RPID: "nday.land", Origins: []string{"https://nday.land"},
		SessionIdle: 24 * time.Hour, SessionMax: 48 * time.Hour, HandleHold: time.Hour}
	asvc, err := auth.New(acfg, auth.Options{Store: &auth.Store{DB: pool}, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	ds, err := discuss.New(discuss.Options{Store: &discuss.Store{DB: pool}, Auth: asvc, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return sitetest.Now }
	srv := web.New(web.Config{Store: site.New(pool).WithClock(now), Logger: log})
	srv.SetAPIAuth(webtest.BearerAuth{})
	ui, err := webui.New(srv, webui.Options{Now: now, Discussions: webui.DiscussionsOf(ds)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &tenv{ts: ts, ui: ui}, d.Conn
}

// insertComment adds a visible comment (no author: a deleted account) and
// returns its id.
func insertComment(t *testing.T, conn *pgx.Conn, cve string, parent *string, body string, at time.Time) string {
	t.Helper()
	var id string
	if err := conn.QueryRow(context.Background(), `INSERT INTO comments (cve_id, parent_id, is_reply, body, lang, links, created_at, updated_at)
		VALUES ($1, $2::uuid, $3, $4, 'en', true, $5, $5) RETURNING id::text`, cve, parent, parent != nil, body, at).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestDiscussionOutlineReal: with the real service, the public page shows
// the outline of the stored comments and none of their content (bodies,
// authors, ids), whatever the comments say; two discussions whose bodies
// differ but fall in the same size classes give byte-identical sections.
func TestDiscussionOutlineReal(t *testing.T) {
	e, conn := realDiscEnv(t)
	base := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	t1 := insertComment(t, conn, sitetest.GPU, nil, "QZCOMMENT-ALPHA <script>alert(1)</script>", base)
	r1 := insertComment(t, conn, sitetest.GPU, &t1, "QZCOMMENT-BETA "+strings.Repeat("x", 300), base.Add(time.Second))
	u1 := insertComment(t, conn, "CVE-2026-1001", nil, "zzzzzzzzzz other words entirely, same class", base)
	u2 := insertComment(t, conn, "CVE-2026-1001", &u1, "y "+strings.Repeat("q", 300), base.Add(time.Second))
	sec := func(cve string) string {
		_, body := e.get(t, "/vuln/"+cve)
		s := between(t, body, `<section class="sec disc" id="discussion"`, "</section>")
		return strings.ReplaceAll(s, cve, "CVE")
	}
	a, b := sec(sitetest.GPU), sec("CVE-2026-1001")
	for _, bad := range []string{"QZCOMMENT", "script", t1, r1, u1, u2, "zzzz"} {
		if strings.Contains(a+b, bad) {
			t.Errorf("public section contains %q", bad)
		}
	}
	if a != b {
		t.Errorf("outline depends on content:\n%s\n---\n%s", a, b)
	}
	if !strings.Contains(a, `data-size="s"`) || !strings.Contains(a, `data-size="m"`) || !strings.Contains(a, "2 comments") {
		t.Errorf("outline: %s", a)
	}
}
