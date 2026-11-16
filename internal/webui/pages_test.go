package webui_test

import (
	"context"
	"encoding/xml"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
	"nday.land/nday/internal/webui/i18n"
)

// Hostile upstream data (all of it is shaped like what collectors store).
const (
	evilCVE    = "CVE-2026-6666"
	evilTitle  = `<script>alert("t")</script> "quoted" 'single' & <b>bold</b>`
	evilVendor = `"><img src=x onerror=alert(1)>`
	evilDetail = `{"title": "</pre><script>alert('d')</script>", "kind": "exploit", "edb_id": 1,
	  "url": "javascript:alert('u')", "verified": true}`
	evilCNA    = "<img src=x onerror=alert(5)>\u202egnp.exe\u2066"
	evilModule = "exploit/<script>alert(6)</script>\u202e"
)

func seedHostile(t *testing.T, conn *pgx.Conn) {
	s := sitetest.Seeder{T: t, Conn: conn}
	s.Vuln(evilCVE, sitetest.P(evilTitle))
	s.Affected(evilCVE, evilVendor, `<svg onload=alert(2)>`)
	// a product-type type rule (vendor:tenda) matches; the stored product is hostile
	s.Affected(evilCVE, "Tenda", "AC15 <script>alert(7)</script>\u202e")
	s.Alias(evilCVE, `GHSA-"><x`, "ghsa")
	s.Event(sitetest.Ev{CVE: evilCVE, Type: "disclosed", Source: "cvelist", Occurred: sitetest.P(sitetest.Ago(3)),
		URL:    sitetest.P("javascript:alert('src')"),
		Detail: `{"state": "PUBLISHED", "assigner_short_name": "<i>cna</i>", "cvss": {"base_score": 9.1, "base_severity": "<CRIT>"}}`})
	s.Event(sitetest.Ev{CVE: evilCVE, Type: "poc_published", Source: "exploitdb", Occurred: sitetest.P(sitetest.Day(2026, 11, 11)),
		URL: sitetest.P("javascript:alert('poc')"), Key: "1", Detail: evilDetail})
	s.Event(sitetest.Ev{CVE: evilCVE, Type: "patch_released", Source: "ghsa", Key: "GHSA-evil", Backfill: true,
		URL: sitetest.P("https://github.com/advisories/GHSA-evil\"onmouseover=alert(3)"),
		Detail: `{"ghsa_id": "GHSA-evil", "packages": [{"name": "x'; rm -rf / #", "ecosystem": "pip", "first_patched_version": "1.0",
		  "vulnerable_version_range": "< 1.0 <script>"}], "fix_commit_urls": ["javascript:alert(4)", "https://github.com/a/b/commit/abcdef0123"],
		  "cwes": [{"cwe_id": "CWE-79", "name": "<script>cwe</script>"}]}`})
	// tag bases with hostile upstream strings: a CNA name and a module name
	// with markup and bidi controls (U+202E, U+2066) must render as inert text
	s.Event(sitetest.Ev{CVE: evilCVE, Type: "poc_published", Source: "metasploit", Key: evilModule, Backfill: true, Detail: `{}`})
	if _, err := conn.Exec(context.Background(), `INSERT INTO vuln_cwe (cve_id, cwe, source, source_org) VALUES ($1, 'CWE-79', 'cve-cna', $2)`,
		evilCVE, evilCNA); err != nil {
		t.Fatal(err)
	}
	s.Refresh()
}

type tenv struct {
	ts    *httptest.Server
	ui    *webui.UI
	store *site.Store
}

func newEnv(t *testing.T) *tenv { return newEnvWith(t, webui.Options{}) }

func newEnvWith(t *testing.T, opts webui.Options) *tenv { return newEnvFull(t, web.Config{}, opts) }

// newEnvFull is newEnvWith with server configuration (Store and Logger are
// filled in), e.g. PublicURL and APIURL for two-host mode.
func newEnvFull(t *testing.T, wc web.Config, opts webui.Options) *tenv {
	t.Helper()
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	seedHostile(t, d.Conn)
	sitetest.SeedTags(t, d.Conn)
	sitetest.SeedCredits(t, d.Conn)
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 3})
	t.Cleanup(pool.Close)
	now := func() time.Time { return sitetest.Now }
	store := site.New(pool).WithClock(now)
	wc.Store, wc.Logger = store, slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := web.New(wc)
	opts.Now = now
	ui, err := webui.New(srv, opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &tenv{ts: ts, ui: ui, store: store}
}

func (e *tenv) get(t *testing.T, path string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// noRedirect fetches without following redirects.
func (e *tenv) noRedirect(t *testing.T, path string) *http.Response {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(e.ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// localeOf returns the enabled locale whose prefix starts path.
func (e *tenv) localeOf(path string) *i18n.Locale {
	set := e.ui.Locales()
	seg, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	seg, _, _ = strings.Cut(seg, "?")
	if l := set.ByPrefix(seg); l != nil && seg != "" {
		return l
	}
	return set.Primary()
}

// neutral strips the locale prefix of path.
func neutral(l *i18n.Locale, path string) string {
	if l.Prefix == "" {
		return path
	}
	rest := strings.TrimPrefix(path, "/"+l.Prefix)
	if rest == "" || rest[0] != '/' {
		return "/" + rest
	}
	return rest
}

var voidElems = map[string]bool{"meta": true, "link": true, "input": true, "br": true, "img": true, "hr": true,
	"source": true, "wbr": true, "area": true, "base": true, "col": true, "embed": true, "track": true}

// CheckHTML parses a page as (X)HTML and reports structural problems and
// anything inline that the CSP forbids: style attributes, <style>, inline
// scripts, on* handler attributes, javascript: URLs; plus unbalanced tags.
// It returns the internal href/src targets.
func CheckHTML(body string) (links []string, problems []string) {
	dec := xml.NewDecoder(strings.NewReader(body))
	dec.Strict = true // the pages are polyglot: void elements self-closed, attributes quoted
	dec.Entity = xml.HTMLEntity
	var stack []string
	inScript := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			problems = append(problems, "parse: "+err.Error())
			break
		}
		switch x := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(x.Name.Local)
			if name == "style" {
				problems = append(problems, "<style> element")
			}
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
				}
				if an == "href" || an == "src" {
					hasSrc = hasSrc || an == "src"
					if strings.HasPrefix(a.Value, "/") && !strings.HasPrefix(a.Value, "//") {
						links = append(links, a.Value)
					}
				}
			}
			if name == "script" {
				if !hasSrc {
					problems = append(problems, "inline <script>")
				}
				inScript = true
			}
			if !voidElems[name] {
				stack = append(stack, name)
			}
		case xml.EndElement:
			name := strings.ToLower(x.Name.Local)
			if voidElems[name] {
				continue
			}
			if len(stack) == 0 || stack[len(stack)-1] != name {
				problems = append(problems, fmt.Sprintf("unbalanced </%s> (open: %v)", name, stack))
				return links, problems
			}
			stack = stack[:len(stack)-1]
			if name == "script" {
				inScript = false
			}
		case xml.CharData:
			if inScript && strings.TrimSpace(string(x)) != "" {
				problems = append(problems, "script with content")
			}
		}
	}
	if len(stack) != 0 {
		problems = append(problems, fmt.Sprintf("unclosed elements: %v", stack))
	}
	return links, problems
}

var pages = []string{
	"/", "/hot", "/?since=30d&min_stage=poc", "/?since=24h&min_stage=exploited&include_rejected=1",
	"/?since=366d&utm_source=x&foo=bar", "/vuln/" + sitetest.GPU, "/vuln/CVE-2026-1001", "/vuln/CVE-2026-1005",
	"/vuln/CVE-2026-1009", "/vuln/CVE-2026-1010", "/vuln/CVE-2026-1003", "/vuln/" + evilCVE, "/vuln", "/vuln?q=", "/vuln?q=a",
	"/vuln?q=tie", "/vuln?q=zzzzzz", "/vuln?q=" + url.QueryEscape("<script>"), "/src", "/stats", "/about",
	"/vuln/CVE-2099-99999", "/vuln/not-a-cve", "/no/such/page", "/?since=5m",
	"/tags", "/tag/auth-bypass", "/tag/ransomware?since=30d", "/tag/nope", "/?tag=remote-unauth&tag=auth-bypass",
	"/?tag=nope&tag=ransomware&since=30d", "/vuln?tag=network", "/vuln?q=gpu&tag=remote-unauth", "/vuln?tag=xss&tag=csrf",
}

// localized returns pages under every enabled locale's prefix.
func (e *tenv) localized() []string {
	var out []string
	for _, l := range e.ui.Locales().Enabled {
		for _, p := range pages {
			out = append(out, l.Path(p))
		}
	}
	return out
}

func TestPagesCSPAndNoInline(t *testing.T) {
	e := newEnv(t)
	seen := map[string]bool{}
	queue := e.localized()
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		resp, body := e.get(t, p)
		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "text/html") {
			continue // API, raw, static, feed
		}
		if got := resp.Header.Get("Content-Security-Policy"); got != webui.CSP {
			t.Errorf("%s: CSP %q", p, got)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", p)
		}
		links, problems := CheckHTML(body)
		for _, pr := range problems {
			t.Errorf("%s: %s", p, pr)
		}
		l := e.localeOf(resp.Request.URL.Path)
		if !strings.Contains(body, `<html lang="`+l.Tag+`">`) || !strings.Contains(body, "<title>") ||
			!strings.Contains(body, `<meta name="description"`) || !strings.Contains(body, l.Text("sbar.utc")) {
			t.Errorf("%s: missing lang %s/title/description/UTC note", p, l.Tag)
		}
		if strings.Contains(body, i18n.MissingOpen) {
			t.Errorf("%s: missing message marker in output", p)
		}
		switch resp.StatusCode {
		case 200:
			if resp.Header.Get("Cache-Control") != "public, max-age=60" || resp.Header.Get("ETag") == "" {
				t.Errorf("%s: cache headers %v", p, resp.Header)
			}
		default:
			if resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s (%d): Cache-Control %q", p, resp.StatusCode, resp.Header.Get("Cache-Control"))
			}
		}
		for _, lk := range links {
			if !seen[lk] && len(seen) < 600 {
				queue = append(queue, lk)
			}
		}
	}
	// Every internal link and asset of the crawled pages resolves.
	for p := range seen {
		resp, _ := e.get(t, p)
		want := 200
		switch n := neutral(e.localeOf(p), p); {
		case n == "/vuln/CVE-2099-99999" || n == "/no/such/page" || n == "/tag/nope":
			want = 404
		case n == "/vuln/not-a-cve" || n == "/?since=5m":
			want = 400
		}
		if resp.StatusCode != want {
			t.Errorf("%s: status %d want %d", p, resp.StatusCode, want)
		}
	}
	for _, l := range e.ui.Locales().Enabled {
		for _, must := range []string{"/feed.xml", "/about", "/src", "/stats", "/vuln/" + sitetest.GPU} {
			if !seen[l.Path(must)] {
				t.Errorf("crawl did not reach %s", l.Path(must))
			}
		}
	}
	var assets int
	for p := range seen {
		if strings.HasPrefix(p, "/static/") {
			assets++
		}
	}
	if assets < 3 { // css, js, favicon (+ preloaded font)
		t.Errorf("only %d assets referenced", assets)
	}
}

// TestPrimaryLocaleHasNoCJK: English pages carry no Han/Kana/Hangul except
// the language switcher's native names and hints (and upstream data, which
// the fixture keeps ASCII on English pages). This catches Chinese strings
// left anywhere in templates, Go view code or data attributes.
func TestPrimaryLocaleHasNoCJK(t *testing.T) {
	e := newEnv(t)
	sw := regexp.MustCompile(`(?s)<details class="langs">.*?</details>|<p class="err">.*?</p>`) // switcher; upstream collector errors
	for _, p := range pages {
		_, body := e.get(t, p)
		body = sw.ReplaceAllString(body, "")
		for _, r := range body {
			if i18n.IsWide(r) {
				i := strings.IndexRune(body, r)
				t.Errorf("%s: CJK %q in English page near %q", p, string(r), body[max(0, i-60):min(len(body), i+40)])
				break
			}
		}
	}
}

func TestHostileDataEscaped(t *testing.T) {
	e := newEnv(t)
	for _, l := range e.ui.Locales().Enabled {
		for _, p := range []string{"/vuln/" + evilCVE, "/?since=30d&min_stage=poc", "/vuln?q=" + url.QueryEscape(evilCVE[:9]), "/vuln?q=onerror"} {
			p = l.Path(p)
			resp, body := e.get(t, p)
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d", p, resp.StatusCode)
			}
			for _, bad := range []string{"<script>alert", "<img src=x", "<svg onload", `="javascript:`, "</pre><script>",
				`"onmouseover=`, "<b>bold</b>", "<i>cna</i>", "<CRIT>"} {
				if strings.Contains(body, bad) {
					t.Errorf("%s: unescaped %q", p, bad)
				}
			}
			if _, problems := CheckHTML(body); len(problems) > 0 {
				t.Errorf("%s: %v", p, problems)
			}
		}
		_, body := e.get(t, l.Path("/vuln/"+evilCVE))
		for _, want := range []string{
			"&lt;script&gt;alert(&#34;t&#34;)&lt;/script&gt; &#34;quoted&#34; &#39;single&#39; &amp; &lt;b&gt;bold&lt;/b&gt;", // title
			"&lt;/pre&gt;&lt;script&gt;alert(&#39;d&#39;)&lt;/script&gt;",                                                     // JSON detail inside <pre>
			"&#34;&gt;&lt;img src=x onerror=alert(1)&gt;",                                                                     // vendor
			"<span>cvelist</span>", // javascript: source URL -> plain text
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing escaped %q", l.Tag, want)
			}
		}
		// The hostile exploit title inside a generated sentence is escaped too.
		if !strings.Contains(body, "&lt;/pre&gt;&lt;script&gt;alert(&#39;d&#39;)&lt;/script&gt;") {
			t.Errorf("%s: event title", l.Tag)
		}
		if !strings.Contains(body, `<span>javascript:alert(4)</span>`) && strings.Contains(body, "alert(4)") {
			t.Errorf("%s: javascript: commit URL not rendered as text", l.Tag)
		}
		if !strings.Contains(body, `<a href="https://github.com/a/b/commit/abcdef0123" rel="noopener noreferrer">a/b@abcdef0</a>`) {
			t.Errorf("%s: good commit link missing", l.Tag)
		}
		if strings.Contains(body, "pip install") {
			t.Errorf("%s: upgrade command for a hostile package name", l.Tag)
		}
		extRe := regexp.MustCompile(`<a href="https?://[^"]*"[^>]*>`)
		for _, m := range extRe.FindAllString(body, -1) {
			if !strings.Contains(m, `rel="noopener noreferrer"`) {
				t.Errorf("%s: external link without rel: %s", l.Tag, m)
			}
		}
	}
}

func TestDetailContent(t *testing.T) {
	e := newEnv(t)
	set := e.ui.Locales()
	zh, en := set.ByTag("zh-Hans"), set.Primary()
	common := []string{
		"curl -s https://nday.land/api/vuln/CVE-2026-102895",
		"≤ 2026-11-09", "~ITW", "&#43;KEV",
		"pip install -U &#39;gpustack&gt;=2.2.0&#39;", "gpustack/gpustack#5346", "gpustack/gpustack@53f42a6",
		"Improper Authentication", `href="/raw/kev/CVE-2026-102895.json"`, `<details class="raw">`,
		"<main class=\"page detail\" id=\"main\">\n<div class=\"wrap\">\n<div class=\"dhead\">", `<span class="weak" aria-hidden="true">~/vuln/</span>`,
	}
	_, body := e.get(t, "/zh-hans/vuln/"+sitetest.GPU)
	for _, want := range append(common,
		"披露后第 5 天进入 KEV。已有补丁记录，修复版本是 gpustack 2.2.0。三个 PoC 库都已收录。",
		"推定，无直接来源", "日精度，来源给出", `本站 <time datetime="2026-11-12T01:00:00Z" data-lt="long">2026-11-12T01:00Z</time> 批量导入`, "时间未知",
		`<html lang="zh-Hans">`, `href="/zh-hans/src#kev"`, `lang="en"`) {
		if !strings.Contains(body, want) {
			t.Errorf("zh detail missing %q", want)
		}
	}
	_, body = e.get(t, "/vuln/"+sitetest.GPU)
	for _, want := range append(common,
		"Added to KEV 5 days after disclosure. Patched: fixed in gpustack 2.2.0. All three PoC sources list it.",
		en.Text("ev.implied.note"), en.Text("precision.note", "precision", "day"),
		string(en.HTML("ev.obs.backfill", "time", template.HTML(`<time datetime="2026-11-12T01:00:00Z" data-lt="long">2026-11-12T01:00Z</time>`))), en.Text("time.unknown"),
		`<html lang="en">`, `href="/src#kev"`) {
		if !strings.Contains(body, want) {
			t.Errorf("en detail missing %q", want)
		}
	}
	if strings.Contains(body, `lang="en"`) && strings.Contains(body, `<span lang="en">`) {
		t.Error("English page marks upstream text lang=en")
	}
	if strings.Contains(body, "npm install") {
		t.Error("npm command without a fix")
	}
	// title_zh is used on Simplified Chinese pages only.
	_, body = e.get(t, "/zh-hans/vuln/CVE-2026-1003")
	if !strings.Contains(body, "cowlib 响应拆分") {
		t.Error("zh title not shown on zh-hans page")
	}
	_, body = e.get(t, "/vuln/CVE-2026-1003")
	if strings.Contains(body, "cowlib 响应拆分") || !strings.Contains(body, "cowlib header splitting") {
		t.Error("zh title leaked into English page")
	}
	_, body = e.get(t, "/zh-hans/vuln/CVE-2026-1005")
	if !strings.Contains(body, "REJECTED") || !strings.Contains(body, `原因（原文）：<span lang="en">dup</span>`) ||
		!strings.Contains(body, `href="/zh-hans/vuln/CVE-2026-1003"`) {
		t.Error("rejected banner")
	}
	_, body = e.get(t, "/zh-hans/vuln/CVE-2026-1001")
	if !strings.Contains(body, "等待官方 CVE 记录回填") || !strings.Contains(body, "本站还没有取到这个编号的官方 CVE 记录") {
		t.Error("stub placeholders")
	}
	_, body = e.get(t, "/vuln/CVE-2026-1001")
	if !strings.Contains(body, en.Text("title.missing_no_record")) || !strings.Contains(body, en.Text("status.no_record")) {
		t.Error("en stub placeholders")
	}
	// The original-language note appears once on non-English pages, never in English.
	_, body = e.get(t, "/zh-hans/vuln/"+sitetest.GPU)
	if n := strings.Count(body, zh.Text("note.upstream_original")); n != 1 {
		t.Errorf("zh upstream note %d times", n)
	}
	_, body = e.get(t, "/vuln/"+sitetest.GPU)
	if strings.Contains(body, en.Text("note.upstream_original")) {
		t.Error("upstream note on an English page")
	}
}

func TestHotPageAndCaching(t *testing.T) {
	e := newEnv(t)
	resp, body := e.get(t, "/zh-hans/?since=30d&utm_source=newsletter")
	if resp.StatusCode != 200 {
		t.Fatalf("unknown param: %d", resp.StatusCode)
	}
	for _, want := range []string{
		"curl -s &#39;https://nday.land/api/hot?since=30d&amp;min_stage=patch&#39;", `role="heading" aria-level="2"><span aria-hidden="true">## </span>2026-11-`, "&#43;KEV",
		`aria-current="true">30 天</a>`, `href="/zh-hans/?since=30d&amp;min_stage=poc"`, "全库当前阶段", "回填中",
		"等待官方记录回填", "Barracuda Networks / Email Security Gateway (ESG)、Load Balancer ADC &#43;1",
		`role="img" aria-label="生命周期：`, `<a class="ttl" href="/zh-hans/vuln/CVE-2026-1003" tabindex="-1" aria-hidden="true">cowlib 响应拆分</a>`,
		`<a class="id" href="/zh-hans/vuln/CVE-2026-1003" aria-label="CVE-2026-1003 cowlib 响应拆分">CVE-2026-1003</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("zh hot missing %q", want)
		}
	}
	_, body = e.get(t, "/?since=30d")
	for _, want := range []string{
		`href="/?since=30d&amp;min_stage=poc"`, "Barracuda Networks / Email Security Gateway (ESG), Load Balancer ADC &#43;1",
		`role="img" aria-label="Lifecycle — `, `href="/vuln/CVE-2026-102895"`, "cowlib header splitting",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("en hot missing %q", want)
		}
	}
	if strings.Contains(body, "CVE-2026-1005") {
		t.Error("rejected listed without include_rejected")
	}
	// rows carry no tooltips that repeat the row: the title link (its text; the ID link's label has it) and
	// the tag chips (the description is on /tags and on the vulnerability page)
	if regexp.MustCompile(`<a class="ttl[^>]* title=|<span class="rtags">[^\n]*<a class="tg[^>]* title=`).MatchString(body) {
		t.Error("hot rows: a redundant title attribute")
	}
	_, body = e.get(t, "/?since=30d&include_rejected=1")
	if !strings.Contains(body, "CVE-2026-1005") || !strings.Contains(body, "REJECTED") {
		t.Error("include_rejected")
	}
	_, body = e.get(t, "/zh-hans/?since=24h&min_stage=exploited")
	if !strings.Contains(body, `此范围内没有漏洞；放宽“时间范围”或降低“至少到达”再看。`) {
		t.Error("empty state")
	}
	resp, _ = e.get(t, "/")
	etag := resp.Header.Get("ETag")
	resp, _ = e.get(t, "/", "If-None-Match", etag)
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", resp.StatusCode)
	}
	resp, _ = e.get(t, "/zh-hans/", "If-None-Match", etag)
	if resp.StatusCode != 200 {
		t.Errorf("ETag shared across locales: %d", resp.StatusCode)
	}
	// API strictness is unchanged.
	resp, _ = e.get(t, "/api/hot?utm_source=x")
	if resp.StatusCode != 400 {
		t.Errorf("API unknown param: %d", resp.StatusCode)
	}
	resp, _ = e.get(t, "/api/nope")
	if resp.StatusCode != 404 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("API 404 should stay JSON: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

var (
	hreflangRe  = regexp.MustCompile(`<link rel="alternate" hreflang="([^"]+)" href="([^"]+)"/>`)
	canonicalRe = regexp.MustCompile(`<link rel="canonical" href="([^"]+)"/>`)
	switchRe    = regexp.MustCompile(`<li><a href="([^"]+)" hreflang="([^"]+)" lang="[^"]+"( aria-current="true")?`)
)

// TestLocaleHeadAndSwitcher: every 200 page in every locale has the right
// lang, a canonical URL of its own locale, a complete and reciprocal set of
// hreflang alternates (+ x-default = English) and a switcher that keeps the
// path and the query.
func TestLocaleHeadAndSwitcher(t *testing.T) {
	e := newEnv(t)
	set := e.ui.Locales()
	if len(set.Enabled) < 2 {
		t.Fatalf("enabled locales %d", len(set.Enabled))
	}
	type page struct{ path, canon string }
	cases := []page{
		{"/", "/"}, {"/hot", "/"}, {"/?since=30d&min_stage=poc&utm_source=x", "/?since=30d&min_stage=poc"},
		{"/vuln/" + sitetest.GPU, "/vuln/" + sitetest.GPU}, {"/vuln?q=barracuda", "/vuln"}, {"/vuln", "/vuln"},
		{"/src", "/src"}, {"/stats", "/stats"}, {"/about", "/about"},
	}
	for _, c := range cases {
		alts := map[string]map[string]string{} // page locale -> hreflang -> href
		for _, l := range set.Enabled {
			p := l.Path(c.path)
			resp, body := e.get(t, p)
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d", p, resp.StatusCode)
			}
			if !strings.Contains(body, `<html lang="`+l.Tag+`">`) {
				t.Errorf("%s: lang", p)
			}
			if m := canonicalRe.FindStringSubmatch(body); m == nil || htmlUnescape(m[1]) != "https://nday.land"+l.Path(c.canon) {
				t.Errorf("%s: canonical %v want %s", p, m, "https://nday.land"+l.Path(c.canon))
			}
			got := map[string]string{}
			for _, m := range hreflangRe.FindAllStringSubmatch(body, -1) {
				if _, dup := got[m[1]]; dup {
					t.Errorf("%s: duplicate hreflang %s", p, m[1])
				}
				got[m[1]] = htmlUnescape(m[2])
			}
			if len(got) != len(set.Enabled)+1 {
				t.Errorf("%s: hreflang set %v", p, got)
			}
			for _, o := range set.Enabled {
				if got[o.Tag] != "https://nday.land"+o.Path(c.canon) {
					t.Errorf("%s: hreflang %s = %q", p, o.Tag, got[o.Tag])
				}
			}
			if got["x-default"] != "https://nday.land"+set.Primary().Path(c.canon) {
				t.Errorf("%s: x-default %q", p, got["x-default"])
			}
			alts[l.Tag] = got
			// Switcher: same path and query in every locale; the current one marked.
			sw := switchRe.FindAllStringSubmatch(body, -1)
			if len(sw) != len(set.Enabled) {
				t.Errorf("%s: switcher %v", p, sw)
			}
			for _, m := range sw {
				o := set.ByTag(m[2])
				if o == nil || htmlUnescape(m[1]) != o.Path(c.path) {
					t.Errorf("%s: switch link %q for %s, want %q", p, m[1], m[2], o.Path(c.path))
				}
				if (m[3] != "") != (o == l) {
					t.Errorf("%s: aria-current on %s", p, m[2])
				}
			}
		}
		// Reciprocal: every locale's page lists the same alternates.
		var first map[string]string
		for _, a := range alts {
			if first == nil {
				first = a
				continue
			}
			if fmt.Sprint(a) != fmt.Sprint(first) {
				t.Errorf("%s: alternates differ between locales: %v vs %v", c.path, a, first)
			}
		}
	}
	// Error pages: switcher yes, canonical/alternates no.
	_, body := e.get(t, "/zh-hans/no/such/page?x=1")
	if canonicalRe.MatchString(body) || hreflangRe.MatchString(body) || !strings.Contains(body, `href="/no/such/page?x=1" hreflang="en"`) {
		t.Error("error page head/switcher")
	}
}

// TestLocaleRouting covers prefixes, redirects and the language-neutral paths.
func TestLocaleRouting(t *testing.T) {
	e := newEnv(t)
	set := e.ui.Locales()
	for _, c := range []struct {
		path   string
		status int
		loc    string
	}{
		{"/zh-hans", 301, "/zh-hans/"}, {"/zh-hans?since=30d", 301, "/zh-hans/?since=30d"},
		{"/zh-Hans/about", 301, "/zh-hans/about"}, {"/ZH-HANS/vuln?q=x", 301, "/zh-hans/vuln?q=x"},
		{"/zh-hans/vuln/cve-2026-102895", 301, "/zh-hans/vuln/CVE-2026-102895"},
		{"/vuln/cve-2026-102895", 301, "/vuln/CVE-2026-102895"},
		{"/zh-hans/vuln?q=cve-2026-102895", 302, "/zh-hans/vuln/CVE-2026-102895"},
		{"/zh-hans/vuln/", 301, "/zh-hans/vuln"},
		{"/xx/", 404, ""}, {"/zh/", 404, ""}, {"/en/", 404, ""}, {"/zh-hans/api/hot", 404, ""},
		{"/zh-hans/static/app.css", 404, ""}, {"/zh-hans/robots.txt", 404, ""}, {"/__i18n/en", 404, ""},
	} {
		resp := e.noRedirect(t, c.path)
		if resp.StatusCode != c.status || resp.Header.Get("Location") != c.loc {
			t.Errorf("%s: %d %q, want %d %q", c.path, resp.StatusCode, resp.Header.Get("Location"), c.status, c.loc)
		}
	}
	// A registry locale without a (valid) catalog is not served.
	for _, l := range set.All {
		if !l.Enabled() {
			if resp := e.noRedirect(t, "/"+l.Prefix+"/"); resp.StatusCode != 404 {
				t.Errorf("disabled locale %s served: %d", l.Tag, resp.StatusCode)
			}
		}
	}
	// Language-neutral paths stay unprefixed and unchanged.
	for _, p := range []string{"/robots.txt", "/favicon.ico", "/api/hot", "/api/stats", "/healthz", "/raw/kev/CVE-2026-102895.json"} {
		if resp, _ := e.get(t, p); resp.StatusCode != 200 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	resp, body := e.get(t, "/api/vuln/CVE-2026-102895")
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || strings.Contains(body, "zh-hans") {
		t.Error("API changed")
	}
}

// TestDisabledLocale: a catalog that fails validation leaves its locale off
// (404), the others keep working.
func TestDisabledLocale(t *testing.T) {
	fsys := fstest.MapFS{}
	src := i18n.Embedded()
	for _, name := range []string{"locales.json", "keys.json", "catalogs/en.json", "catalogs/zh-Hans.json"} {
		b, err := fs.ReadFile(src, name)
		if err != nil {
			t.Fatal(err)
		}
		fsys[name] = &fstest.MapFile{Data: b}
	}
	b, _ := fs.ReadFile(src, "catalogs/zh-Hans.json")
	fsys["catalogs/zh-Hans.json"] = &fstest.MapFile{Data: []byte(strings.Replace(string(b), `"sbar.utc"`, `"sbar.utc_typo"`, 1))}
	set, err := i18n.Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if set.ByTag("zh-Hans").Enabled() || len(set.ByTag("zh-Hans").Problems()) < 2 {
		t.Fatalf("broken catalog enabled: %v", set.ByTag("zh-Hans").Problems())
	}
	e := newEnvWith(t, webui.Options{Locales: set})
	if resp, _ := e.get(t, "/zh-hans/"); resp.StatusCode != 404 {
		t.Errorf("disabled locale served: %d", resp.StatusCode)
	}
	resp, body := e.get(t, "/")
	if resp.StatusCode != 200 || strings.Contains(body, "/zh-hans/") || strings.Contains(body, `hreflang="zh-Hans"`) {
		t.Error("primary page links a disabled locale")
	}
}

func TestI18nDebugPage(t *testing.T) {
	e := newEnvWith(t, webui.Options{I18nDebug: true})
	for _, p := range []string{"/__i18n/", "/__i18n/en", "/__i18n/zh-Hans?ref=en", "/__i18n/ja"} {
		resp, body := e.get(t, p)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") != webui.CSP {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		if _, problems := CheckHTML(body); len(problems) > 0 {
			t.Errorf("%s: %v", p, problems)
		}
	}
	_, body := e.get(t, "/__i18n/en")
	for _, want := range []string{"status.lead.after.kev", "Added to KEV <mark>2</mark> days after disclosure.", "kev_t5_patch_0of3",
		"Added to KEV 5 days after disclosure. Patched: fixed in gpustack 2.2.0. None of the three PoC sources lists it."} {
		if !strings.Contains(body, want) {
			t.Errorf("debug page missing %q", want)
		}
	}
	if resp, _ := e.get(t, "/__i18n/xx"); resp.StatusCode != 404 {
		t.Errorf("unknown tag: %d", resp.StatusCode)
	}
}

func TestStaticFeedRobots(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/")
	links, _ := CheckHTML(body)
	n := 0
	for _, l := range links {
		if !strings.HasPrefix(l, "/static/") {
			continue
		}
		n++
		resp, _ := e.get(t, l)
		if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Errorf("%s: %d %q", l, resp.StatusCode, resp.Header.Get("Cache-Control"))
		}
		if resp.Header.Get("Content-Security-Policy") != "" && strings.HasSuffix(l, ".css") {
			t.Errorf("%s: CSP on CSS is pointless", l)
		}
	}
	if n < 3 {
		t.Errorf("static refs %d", n)
	}
	// The CSS references the hashed font files, which exist, and carries the
	// generated per-locale font stacks.
	css := ""
	for _, l := range links {
		if strings.HasSuffix(l, ".css") {
			_, css = e.get(t, l)
		}
	}
	fonts := regexp.MustCompile(`url\("(/static/[^"]+)"\)`).FindAllStringSubmatch(css, -1)
	if len(fonts) != 2 {
		t.Errorf("fonts in css: %v", fonts)
	}
	for _, f := range fonts {
		resp, _ := e.get(t, f[1])
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "font/woff2" {
			t.Errorf("font %s: %d %s", f[1], resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	for _, want := range []string{`:root:lang(zh-Hans) { --cjk: "PingFang SC"`, `:root:lang(zh-Hant) { --cjk: "PingFang TC"`,
		`:root:lang(ja) { --cjk: "Hiragino Sans"`, `:root:lang(ko) { --cjk: "Apple SD Gothic Neo"`} {
		if !strings.Contains(css, want) {
			t.Errorf("css missing %q", want)
		}
	}
	resp, _ := e.get(t, "/static/app.css")
	if resp.StatusCode != 404 {
		t.Errorf("unhashed asset served: %d", resp.StatusCode)
	}

	for _, l := range e.ui.Locales().Enabled {
		feedPath := l.Path("/feed.xml")
		resp, body = e.get(t, feedPath)
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/atom+xml") {
			t.Fatalf("feed %s %d %s", feedPath, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		var feed struct {
			XMLName xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
			Lang    string   `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
			ID      string   `xml:"id"`
			Title   string   `xml:"title"`
			Entries []struct {
				ID      string `xml:"id"`
				Title   string `xml:"title"`
				Summary string `xml:"summary"`
				Link    struct {
					Href string `xml:"href,attr"`
				} `xml:"link"`
			} `xml:"entry"`
		}
		dec := xml.NewDecoder(strings.NewReader(body))
		dec.Strict = true
		if err := dec.Decode(&feed); err != nil {
			t.Fatalf("%s is not valid XML: %v", feedPath, err)
		}
		if feed.Lang != l.Tag || len(feed.Entries) == 0 || feed.ID != "https://nday.land"+feedPath || feed.Title != l.Text("feed.title") {
			t.Errorf("feed %s: lang %q id %q title %q entries %d", feedPath, feed.Lang, feed.ID, feed.Title, len(feed.Entries))
		}
		ids := map[string]bool{}
		for _, en := range feed.Entries {
			if ids[en.ID] || !strings.HasPrefix(en.ID, "tag:nday.land,2026:transition/CVE-") {
				t.Errorf("entry id %q", en.ID)
			}
			ids[en.ID] = true
			if !strings.HasPrefix(en.Link.Href, "https://nday.land"+l.Path("/vuln/CVE-")) {
				t.Errorf("entry link %q", en.Link.Href)
			}
			if strings.Contains(en.Summary, i18n.MissingOpen) || en.Summary == "" {
				t.Errorf("entry summary %q", en.Summary)
			}
		}
		found := false
		for _, en := range feed.Entries {
			if strings.Contains(en.Title, `<script>alert("t")</script>`) {
				found = true
			}
		}
		if !found {
			t.Error("hostile title not round-tripped through XML escaping")
		}
		if strings.Contains(body, "<script>") {
			t.Error("raw <script> in feed XML")
		}
		_, body2 := e.get(t, feedPath)
		if body2 != body {
			t.Error("feed not stable between requests")
		}
	}

	resp, body = e.get(t, "/robots.txt")
	if resp.StatusCode != 200 || !strings.Contains(body, "Disallow: /raw/") {
		t.Errorf("robots %d %q", resp.StatusCode, body)
	}
	resp, _ = e.get(t, "/favicon.ico")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/svg+xml" {
		t.Errorf("favicon %d", resp.StatusCode)
	}
	if e.ui.Assets().TotalSize() < 150_000 {
		t.Errorf("assets %d bytes: fonts missing?", e.ui.Assets().TotalSize())
	}
}

func htmlUnescape(s string) string { return html.UnescapeString(s) }

func TestCheckHTMLCatches(t *testing.T) {
	for _, bad := range []string{
		`<p style="color:red">x</p>`, `<style>p{}</style>`, `<script>alert(1)</script>`,
		`<a href="/" onclick="x()">x</a>`, `<a href="javascript:alert(1)">x</a>`, `<div><p>x</div>`,
		`<img src=x onerror=alert(1)>`,
	} {
		if _, p := CheckHTML(`<!doctype html><html><body>` + bad + `</body></html>`); len(p) == 0 {
			t.Errorf("CheckHTML missed %s", bad)
		}
	}
	if _, p := CheckHTML(`<!doctype html><html><head><script src="/a.js" defer=""></script></head><body><input hidden=""/><svg><rect x="1"/></svg></body></html>`); len(p) != 0 {
		t.Errorf("false positive: %v", p)
	}
}

// TestTwoHostPages: with an API host configured, every curl line, raw JSON
// link and endpoint name on the pages points at NDAY_API_URL/v1; the API
// host itself serves no page, asset or HTML.
func TestTwoHostPages(t *testing.T) {
	e := newEnvFull(t, web.Config{PublicURL: "https://www.nday.land", APIURL: "https://api.nday.land"}, webui.Options{})
	pages := map[string][]string{
		"/?since=30d": {"curl -s &#39;https://api.nday.land/v1/hot?since=30d&amp;min_stage=patch&#39;",
			`data-raw="https://api.nday.land/v1/hot?since=30d&amp;min_stage=patch"`},
		"/zh-hans/vuln/" + sitetest.GPU: {"curl -s https://api.nday.land/v1/vuln/CVE-2026-102895",
			`href="https://api.nday.land/v1/raw/kev/CVE-2026-102895.json"`},
		"/vuln?q=barracuda": {"curl -s &#39;https://api.nday.land/v1/search?q=barracuda&#39;",
			`data-raw="https://api.nday.land/v1/search?q=barracuda"`},
		"/src":   {"curl -s https://api.nday.land/v1/sources", `data-raw="https://api.nday.land/v1/sources"`},
		"/stats": {"curl -s https://api.nday.land/v1/stats", `data-raw="https://api.nday.land/v1/stats"`},
		"/about": {"GET /v1/hot", "GET /v1/vuln/{cve}", "GET /v1/search", "GET /v1/sources", "GET /v1/stats",
			"GET /v1/raw/{source}/{key}.json", "GET /healthz", "GET /feed.xml",
			`href="https://api.nday.land/v1/hot?since=7d&amp;min_stage=patch"`,
			"curl -s &#39;https://api.nday.land/v1/hot?since=7d&amp;min_stage=patch&#39;",
			"curl -s https://api.nday.land/v1/raw/kev/CVE-2026-102895.json", "curl -s https://api.nday.land/healthz",
			"curl -s https://www.nday.land/feed.xml"},
		"/ja/about": {"GET /v1/hot", "curl -s https://api.nday.land/v1/stats", "curl -s https://www.nday.land/ja/feed.xml"},
	}
	for p, wants := range pages {
		resp, body := e.get(t, p)
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d", p, resp.StatusCode)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s: missing %q", p, w)
			}
		}
		for _, bad := range []string{"/api/", "nday.land/raw/", `"/raw/`, "GET /raw/"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: still contains %q", p, bad)
			}
		}
		if resp.Header.Get("Content-Security-Policy") != webui.CSP {
			t.Errorf("%s: CSP changed", p)
		}
	}
	// The API host serves no page, asset or site robots.txt.
	for _, p := range []string{"/static/app.css", "/about", "/zh-hans/", "/feed.xml", "/favicon.ico", "/vuln/" + sitetest.GPU} {
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+p, nil)
		req.Host = "api.nday.land"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		bb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(bb)
		if resp.StatusCode != 404 || resp.Header.Get("Content-Type") != "application/json; charset=utf-8" ||
			strings.Contains(body, "<") || len(resp.Header.Values("Set-Cookie")) != 0 {
			t.Errorf("api host %s: %d %s", p, resp.StatusCode, body)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/", nil)
	req.Host = "api.nday.land"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") ||
		!strings.Contains(string(b), `"docs":"https://www.nday.land/about#api"`) {
		t.Errorf("api host /: %d %s", resp.StatusCode, b)
	}
	req, _ = http.NewRequest(http.MethodGet, e.ts.URL+"/robots.txt", nil)
	req.Host = "api.nday.land"
	if resp, err = http.DefaultClient.Do(req); err == nil {
		b, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "User-agent: *\nDisallow: /\n" {
			t.Errorf("api robots %q", b)
		}
	}
	// The site keeps its robots.txt lines; the sitemap is on the site host only.
	if _, body := e.get(t, "/robots.txt"); body != "User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /raw/\n"+
		"Sitemap: https://www.nday.land/sitemap.xml\n" {
		t.Errorf("site robots %q", body)
	}
	for _, p := range []string{"/sitemap.xml", "/sitemap/pages.xml"} {
		req, _ = http.NewRequest(http.MethodGet, e.ts.URL+p, nil)
		req.Host = "api.nday.land"
		if resp, err = http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Errorf("api host %s: %d", p, resp.StatusCode)
			}
		}
		if _, body := e.get(t, p); !strings.Contains(body, "<loc>https://www.nday.land/") {
			t.Errorf("site %s: %q", p, body)
		}
	}
}

var (
	timeElemRe = regexp.MustCompile(`<time datetime="([^"]*)" data-lt="([^"]*)">([^<]*)</time>`)
	anyTimeRe  = regexp.MustCompile(`<time\b`)
	// a minute-precision UTC instant as the server prints it (long or short)
	minuteRe = regexp.MustCompile(`\b(?:\d{4}-)?\d\d-\d\dT\d\d:\d\dZ`)
	// what is deliberately not converted: <head> (title, meta description),
	// the lifecycle chart (labels sit on a UTC axis), the format legend of
	// /src (an example, not an instant)
	headRe   = regexp.MustCompile(`(?s)<head>.*?</head>`)
	chartRe  = regexp.MustCompile(`(?s)<div class="chart">.*?</section>`)
	legendRe = regexp.MustCompile(`(?s)<div class="conv">.*?</div>`)
)

// TestLocalTimeMarkers: every time the pages print with a time of day is a
// <time datetime="RFC 3339 UTC" data-lt="long|short"> whose text is that
// instant in the server's UTC format (app.js converts these); calendar dates,
// upper bounds and unknown times are never marked.
func TestLocalTimeMarkers(t *testing.T) {
	e := newEnv(t)
	marked := 0
	for _, p := range []string{"/", "/src", "/stats", "/vuln/" + sitetest.GPU, "/vuln/CVE-2026-1005", "/vuln/" + evilCVE,
		"/zh-hans/", "/zh-hans/src", "/zh-hans/vuln/" + sitetest.GPU, "/ja/vuln/" + sitetest.GPU} {
		_, body := e.get(t, p)
		elems := timeElemRe.FindAllStringSubmatch(body, -1)
		if n := len(anyTimeRe.FindAllString(body, -1)); n != len(elems) {
			t.Errorf("%s: %d <time> elements, %d in the expected form", p, n, len(elems))
		}
		for _, m := range elems {
			at, err := time.Parse(time.RFC3339, m[1])
			if err != nil || !strings.HasSuffix(m[1], "Z") || at.Location() != time.UTC {
				t.Errorf("%s: datetime %q is not RFC 3339 UTC", p, m[1])
				continue
			}
			want := at.Format("2006-01-02T15:04Z")
			if m[2] == "short" {
				want = at.Format("01-02T15:04Z")
			} else if m[2] != "long" {
				t.Errorf("%s: data-lt %q", p, m[2])
			}
			if m[3] != want {
				t.Errorf("%s: <time datetime=%q data-lt=%q> shows %q, want %q", p, m[1], m[2], m[3], want)
			}
			marked++
		}
		rest := timeElemRe.ReplaceAllString(body, "")
		rest = headRe.ReplaceAllString(rest, "")
		rest = chartRe.ReplaceAllString(rest, "")
		rest = legendRe.ReplaceAllString(rest, "")
		if left := minuteRe.FindAllString(rest, -1); len(left) > 0 {
			t.Errorf("%s: times of day outside <time data-lt>: %v", p, left)
		}
	}
	if marked == 0 {
		t.Fatal("no marked times at all")
	}
	// Day precision, upper bounds and unknown times stay plain text.
	_, body := e.get(t, "/vuln/"+sitetest.GPU)
	for _, plain := range []string{`<div class="when"><span>2026-11-09</span>`, `<div class="when"><span>≤ 2026-11-09</span>`} {
		if !strings.Contains(body, plain) {
			t.Errorf("vuln: missing unmarked %q", plain)
		}
	}
	for _, m := range timeElemRe.FindAllStringSubmatch(body, -1) {
		if !strings.Contains(m[3], "T") {
			t.Errorf("vuln: a date without a time of day is marked: %s", m[0])
		}
	}
	// The status-bar note for app.js: English and Simplified Chinese have
	// it; the pending locales get the English text marked lang="en".
	for p, want := range map[string]string{
		"/":         `data-t-local-time="times in your zone ({offset}); dates as published">`,
		"/zh-hans/": `data-t-local-time="时间按本地时区（{offset}）；日期按来源原样">`,
		"/zh-hant/": `data-t-local-time="times in your zone ({offset}); dates as published" data-t-local-time-lang="en">`,
		"/fr/src":   `data-t-local-time="times in your zone ({offset}); dates as published" data-t-local-time-lang="en">`,
	} {
		if _, b := e.get(t, p); !strings.Contains(b, want) || !strings.Contains(b, `<span class="utc" id="utc">`) {
			t.Errorf("%s: status-bar note: want %s", p, want)
		}
	}
	_, body = e.get(t, "/")
	if !strings.Contains(body, `data-lt="short"`) {
		t.Error("hot list: no convertible row time")
	}
	if regexp.MustCompile(`<span class="t"><time[^>]*>\d\d-\d\d</time>`).MatchString(body) {
		t.Error("hot list: a day-precision row time is marked")
	}
}

// TestHotChrome: the hot list folds its API command away, labels its filters
// in words (the query parameters stay the API's) and shows only a short
// status line (with the failing collectors, linked to the sources page);
// the sources page keeps the whole status line.
func TestHotChrome(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/")
	for _, want := range []string{
		"<details class=\"apid\">\n<summary>Get this list from the API</summary>\n<div class=\"cmd\">",
		`<span class="k">Changed in</span>`, `<span class="k">Reached at least</span>`, `<span class="k">Tags</span>`,
		`href="/?since=24h">24h</a>`, `href="/?min_stage=poc">PoC</a>`, `<a class="chk" href="/?include_rejected=1"><span class="box" aria-hidden="true"></span>`,
		`Include rejected IDs</a>`, `<a class="bad" href="/src">collectors 1/7 ok</a>`, `<div class="statusline">`,
		"\n<a class=\"skip\" href=\"#main\">Skip to content</a>\n<header class=\"top\">",
		`<a href="/" aria-current="page"><span aria-hidden="true">~/</span>hot</a>`, `<span class="mode" id="mode" aria-hidden="true">NORMAL</span>`,
		`<div class="help" id="help" role="dialog" aria-modal="false" aria-labelledby="help-t" tabindex="-1" hidden="">`,
		`<label class="hk"><input type="checkbox" id="keys-on" checked=""/> single-key shortcuts</label>`,
		`<div class="tbl-in" role="table">`, `<div class="r" role="columnheader">T+</div>`, `<div class="grp" role="rowgroup">`,
		`<div class="stc" role="cell"><svg class="strip"`,
		// one labelled image per row; its shapes reference the page's shared strip geometry (per slot: n none,
		// o hollow, k known; h the halo of the latest change)
		`<svg class="strip" role="img" aria-label="Lifecycle — exploited in the wild: inferred from KEV; added to KEV: latest change"><use href="#sl"/><use href="#n0"/><use href="#n1"/><use href="#n2"/><use href="#n3"/><use href="#o4"/><use href="#h5"/><use href="#k5"/></svg>`,
		`<div aria-hidden="true"><svg class="sdefs" width="0" height="0" aria-hidden="true"><defs><line id="sl" `,
		`<span aria-hidden="true">0/3</span><span class="sr">0/3 PoC sources listing it (of 3)</span></div>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("hot list missing %q", want)
		}
	}
	if _, sb := e.get(t, "/vuln?q=barracuda"); !strings.Contains(sb, "<details class=\"apid\">\n<summary>Get this list from the API</summary>\n<div class=\"cmd\">") {
		t.Error("search: the API command is not folded")
	}
	if _, db := e.get(t, "/discussed"); !strings.Contains(db, "<details class=\"apid\">\n<summary>Get this list from the API</summary>\n<div class=\"cmd\">") {
		t.Error("/discussed: the API command is not folded")
	}
	strip := section(body, `<div class="statusline">`, `</div>
</div>`)
	if !strings.Contains(strip, "updated ") || strings.Contains(strip, "backfill queue") || strings.Contains(strip, "vulns ") {
		t.Errorf("hot status line: %s", strip)
	}
	for _, bad := range []string{`<span class="k">--`, ">--include-rejected<"} {
		if strings.Contains(body, bad) {
			t.Errorf("hot list still shows the flag %q", bad)
		}
	}
	_, body = e.get(t, "/ja/?since=30d")
	for _, want := range []string{`<span class="k">期間</span>`, `aria-current="true">30 日</a>`, `>悪用確認</a>`, `<a class="tall" href="/ja/tags">タグ一覧</a>`} {
		if !strings.Contains(body, want) {
			t.Errorf("ja hot list missing %q", want)
		}
	}
	_, body = e.get(t, "/src")
	strip = section(body, `<div class="statusline">`, `</div>
</div>`)
	for _, want := range []string{"collectors 1/7 ok", "vulns ", "events ", "backfill queue ", "updated "} {
		if !strings.Contains(strip, want) {
			t.Errorf("sources status line missing %q: %s", want, strip)
		}
	}
}
