package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/xconfig"
)

var (
	xRowIDRe = regexp.MustCompile(`<td><code dir="ltr">([0-9]+)</code></td>`)
	xHrefRe  = regexp.MustCompile(`href="([^"]*)"`)
)

// xRows lists the user ids of the allowlist table, in page order.
func xRows(body string) string {
	var ids []string
	for _, m := range xRowIDRe.FindAllStringSubmatch(body, -1) {
		ids = append(ids, m[1])
	}
	return strings.Join(ids, ",")
}

// xLinks returns the hrefs (unescaped) ending in #frag.
func xLinks(body, frag string) []string {
	var out []string
	for _, m := range xHrefRe.FindAllStringSubmatch(body, -1) {
		if h := html.UnescapeString(m[1]); strings.HasSuffix(h, "#"+frag) {
			out = append(out, h)
		}
	}
	return out
}

// xLink returns the href ending in #frag of the links whose text is label
// ("" when there is none; several such links must agree).
func xLink(t *testing.T, body, frag, label string) string {
	t.Helper()
	re := regexp.MustCompile(`<a href="([^"]*#` + frag + `)"[^>]*>` + regexp.QuoteMeta(label) + `</a>`)
	ms := re.FindAllStringSubmatch(body, -1)
	for _, m := range ms[min(1, len(ms)):] {
		if m[1] != ms[0][1] {
			t.Errorf("%q links to #%s differ: %q %q", label, frag, ms[0][1], m[1])
		}
	}
	if len(ms) == 0 {
		return ""
	}
	return html.UnescapeString(ms[0][1])
}

// xQueryOf parses a link's query, failing on a path other than want.
func xQueryOf(t *testing.T, link, wantPath string) url.Values {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil || u.Path != wantPath {
		t.Fatalf("link %q: %v (path %q, want %q)", link, err, u.Path, wantPath)
	}
	return u.Query()
}

func xSeq(ids ...int) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = strconv.Itoa(id)
	}
	return strings.Join(s, ",")
}

func xRange(from, to int) string {
	var ids []int
	for i := from; i <= to; i++ {
		ids = append(ids, i)
	}
	return xSeq(ids...)
}

// TestXAccountsPaging: /admin/x lists the allowlist 10 per page with a
// case-insensitive, literal search on the handle; ?page= is clamped; the
// status keeps counting every account; the search, the page and the posts
// filters survive each other's links and forms and a row action.
func TestXAccountsPaging(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	ctx := context.Background()
	// 25 accounts, ids 1001..1025; every fifth is Sec_NN, the rest acctNN
	for i := 1; i <= 25; i++ {
		handle := fmt.Sprintf("acct%02d", i)
		if i%5 == 0 {
			handle = fmt.Sprintf("Sec_%02d", i)
		}
		if err := xconfig.InsertAccount(ctx, h.db.Conn, strconv.Itoa(1000+i), handle, ""); err != nil {
			t.Fatal(err)
		}
	}
	get := func(path string) string {
		t.Helper()
		resp, body := adm.do("GET", path, "")
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		s := string(body)
		for _, pr := range checkHTML(s, adminElems) {
			t.Errorf("%s: %s", path, pr)
		}
		for _, f := range []string{`id="f-xadd"`, `id="f-ximport"`} { // always offered
			if !strings.Contains(s, f) {
				t.Errorf("%s: lacks %s", path, f)
			}
		}
		return s
	}
	has := func(path, s string, wants ...string) {
		t.Helper()
		for _, w := range wants {
			if !strings.Contains(s, w) {
				t.Errorf("%s: lacks %q", path, w)
			}
		}
	}
	lacks := func(path, s string, nots ...string) {
		t.Helper()
		for _, w := range nots {
			if strings.Contains(s, w) {
				t.Errorf("%s: has %q", path, w)
			}
		}
	}
	const total = `<dd>25 / 25</dd>`

	// paging and clamping
	for _, c := range []struct {
		path, rows, pos, pageOf string
	}{
		{"/admin/x", xRange(1001, 1010), "Showing 1–10 of 25 accounts.", "page 1 of 3"},
		{"/admin/x?page=2", xRange(1011, 1020), "Showing 11–20 of 25 accounts.", "page 2 of 3"},
		{"/admin/x?page=3", xRange(1021, 1025), "Showing 21–25 of 25 accounts.", "page 3 of 3"},
		{"/admin/x?page=99", xRange(1021, 1025), "Showing 21–25 of 25 accounts.", "page 3 of 3"},
		{"/admin/x?page=99999999999999999999", xRange(1001, 1010), "Showing 1–10 of 25 accounts.", "page 1 of 3"},
		{"/admin/x?page=abc", xRange(1001, 1010), "Showing 1–10 of 25 accounts.", "page 1 of 3"},
		{"/admin/x?page=0", xRange(1001, 1010), "Showing 1–10 of 25 accounts.", "page 1 of 3"},
		{"/admin/x?page=-1", xRange(1001, 1010), "Showing 1–10 of 25 accounts.", "page 1 of 3"},
		{"/admin/x?page=2.5", xRange(1001, 1010), "Showing 1–10 of 25 accounts.", "page 1 of 3"},
	} {
		s := get(c.path)
		if got := xRows(s); got != c.rows {
			t.Errorf("%s: rows %s, want %s", c.path, got, c.rows)
		}
		has(c.path, s, c.pos, "<span>"+c.pageOf+"</span>", total)
	}
	// pager links: page 1 is no page; none past either end
	s := get("/admin/x")
	if p, n := xLink(t, s, "accounts", "previous page"), xLink(t, s, "accounts", "next page"); p != "" || n != "/admin/x?page=2#accounts" {
		t.Errorf("page 1 pager: %q %q", p, n)
	}
	s = get("/admin/x?page=2")
	if p, n := xLink(t, s, "accounts", "previous page"), xLink(t, s, "accounts", "next page"); p != "/admin/x#accounts" || n != "/admin/x?page=3#accounts" {
		t.Errorf("page 2 pager: %q %q", p, n)
	}
	s = get("/admin/x?page=99")
	if p, n := xLink(t, s, "accounts", "previous page"), xLink(t, s, "accounts", "next page"); p != "/admin/x?page=2#accounts" || n != "" {
		t.Errorf("clamped page pager: %q %q", p, n)
	}

	// search: substring, any case, one leading @ dropped, status unchanged
	for _, path := range []string{"/admin/x?q=sec", "/admin/x?q=%40SEC_", "/admin/x?q=+%40sEc+"} {
		s := get(path)
		if got := xRows(s); got != xSeq(1005, 1010, 1015, 1020, 1025) {
			t.Errorf("%s: rows %s", path, got)
		}
		has(path, s, "5 of 25 accounts have a handle containing “<bdi>", "”; showing 1–5.", total)
		lacks(path, s, `class="pager"`, "page 1 of 1") // one page: no pager
		if c := xLink(t, s, "accounts", "show all accounts"); c != "/admin/x#accounts" {
			t.Errorf("%s: clear link %q", path, c)
		}
	}
	has("@SEC_", get("/admin/x?q=%40SEC_"), `name="q" value="SEC_"`, "<bdi>SEC_</bdi>")
	// '_' is literal: "c_" matches Sec_NN only, never acctNN
	if got := xRows(get("/admin/x?q=c_")); got != xSeq(1005, 1010, 1015, 1020, 1025) {
		t.Errorf("c_: %s", got)
	}
	// one match: the singular sentence
	s = get("/admin/x?q=sec_10")
	if xRows(s) != "1010" {
		t.Errorf("sec_10: %s", xRows(s))
	}
	has("sec_10", s, "Only one handle contains “<bdi>sec_10</bdi>”.")
	// a search over several pages, clamped too
	s = get("/admin/x?q=acct&page=7")
	if got := xRows(s); got != xSeq(1013, 1014, 1016, 1017, 1018, 1019, 1021, 1022, 1023, 1024) {
		t.Errorf("acct page 2: %s", got)
	}
	has("acct", s, "20 of 25 accounts have a handle containing “<bdi>acct</bdi>”; showing 11–20.", "<span>page 2 of 2</span>", total)
	if p := xLink(t, s, "accounts", "previous page"); p != "/admin/x?q=acct#accounts" {
		t.Errorf("acct prev: %q", p)
	}

	// no match: its own message with the clear link; the table is gone
	for _, q := range []string{"zzz", "%25", "%25sec%25", "_x", "%5C"} {
		path := "/admin/x?q=" + q
		s := get(path)
		if xRows(s) != "" {
			t.Errorf("%s: rows %s", path, xRows(s))
		}
		has(path, s, "No handle contains “<bdi>", total)
		lacks(path, s, "<table class=\"aff adm-tbl adm-wide\">", "Showing ")
		if n := strings.Count(s, ">show all accounts</a>"); n != 2 { // by the field and after the message
			t.Errorf("%s: %d clear links", path, n)
		}
		if c := xLink(t, s, "accounts", "show all accounts"); c != "/admin/x#accounts" {
			t.Errorf("%s: clear link %q", path, c)
		}
	}

	// a hostile term is text: escaped, control characters made visible,
	// capped at 32 characters, no 500
	evil := "<script>alert(1)</script>%_\\\x01‮" + strings.Repeat("W", 100)
	path := "/admin/x?q=" + url.QueryEscape(evil) + "&author=" + url.QueryEscape(`"><b>`) + "&cve=%3Cx%3E"
	s = get(path)
	lacks(path, s, "<script>alert", `"><b>`)
	has(path, s, `value="&lt;script&gt;alert(1)&lt;/script&gt;%_\`+"�‮"+"WW"+`"`,
		"No handle contains “<bdi>&lt;script&gt;", total)
	// the zh-Hans page writes its own sentences and keeps its prefix
	s = get("/zh-hans/admin/x?q=sec")
	has("zh-hans", s, "25 个账号中，用户名含有“<bdi>sec</bdi>”的有 5 个，本页是第 1–5 个。", `action="/zh-hans/admin/x#accounts"`)
	if c := xLink(t, s, "accounts", "显示全部账号"); c != "/zh-hans/admin/x#accounts" {
		t.Errorf("zh-hans clear link %q", c)
	}
	has("zh-hans p2", get("/zh-hans/admin/x?page=2"), "共 25 个账号，本页是第 11–20 个。", "<span>第 2 页，共 3 页</span>")

	// cross-preservation with the posts filter and cursor (31 posts: the
	// posts list has a next page)
	for i := 0; i < 31; i++ {
		postID := fmt.Sprintf("1860000000000000%03d", i)
		detail, _ := json.Marshal(map[string]any{"post_id": postID, "author_id": "1001", "author_handle": "acct01", "text": "t",
			"lang": "en", "cves": []string{cveA}})
		h.sql(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url, detail, dedupe_key)
			VALUES ($1, 'social_post', $2, $2, 'xposts', $3, $4, $5)`, cveA, h.clock.Now().Add(-time.Duration(i)*time.Minute),
			"https://x.com/acct01/status/"+postID, string(detail), postID)
	}
	base := "/admin/x?q=acct&page=2&author=acct01&cve=" + cveA
	s = get(base)
	if got := xRows(s); !strings.HasPrefix(got, "1013,") {
		t.Errorf("filtered page 2: %s", got)
	}
	// the accounts search form carries the posts filters, not the page
	has(base, s, `<input type="hidden" name="author" value="acct01"/>`, `<input type="hidden" name="cve" value="`+cveA+`"/>`,
		`action="/admin/x#accounts"`, `action="/admin/x#posts"`)
	// the posts filter form carries the search and the page
	has(base, s, `<input type="hidden" name="q" value="acct"/>`, `<input type="hidden" name="page" value="2"/>`)
	if strings.Count(s, `name="page"`) != 1 {
		t.Error("page is carried by more than the posts form")
	}
	// posts Next keeps q and page; the accounts links keep the posts filters
	next := xLink(t, s, "posts", "next page")
	nq := xQueryOf(t, next, "/admin/x")
	if nq.Get("q") != "acct" || nq.Get("page") != "2" || nq.Get("author") != "acct01" || nq.Get("cve") != cveA || nq.Get("before") == "" {
		t.Fatalf("posts next: %q", next)
	}
	pq := xQueryOf(t, xLink(t, s, "accounts", "previous page"), "/admin/x")
	if pq.Get("q") != "acct" || pq.Has("page") || pq.Get("author") != "acct01" || pq.Get("cve") != cveA || pq.Has("before") {
		t.Errorf("accounts prev: %v", pq)
	}
	cq := xQueryOf(t, xLink(t, s, "accounts", "show all accounts"), "/admin/x")
	if cq.Has("q") || cq.Has("page") || cq.Get("author") != "acct01" || cq.Get("cve") != cveA {
		t.Errorf("clear: %v", cq)
	}
	// on the posts' second page: First keeps q and page, the accounts links keep the cursor
	s = get(next)
	fq := xQueryOf(t, xLink(t, s, "posts", "first page"), "/admin/x")
	if fq.Get("q") != "acct" || fq.Get("page") != "2" || fq.Get("author") != "acct01" || fq.Has("before") {
		t.Errorf("posts first: %v", fq)
	}
	if got := xRows(s); !strings.HasPrefix(got, "1013,") {
		t.Errorf("posts page 2 changed the accounts page: %s", got)
	}
	pq = xQueryOf(t, xLink(t, s, "accounts", "previous page"), "/admin/x")
	if pq.Get("before") != nq.Get("before") || pq.Get("q") != "acct" || pq.Get("author") != "acct01" {
		t.Errorf("accounts prev on posts page 2: %v", pq)
	}
	// every accounts link ends in #accounts and every posts link in #posts
	for _, l := range xLinks(s, "accounts") {
		if !strings.HasPrefix(l, "/admin/x") {
			t.Errorf("accounts link %q", l)
		}
	}
	// a cursor that does not decode is dropped from the accounts links
	s = get("/admin/x?q=acct&page=2&before=garbage")
	for _, l := range xLinks(s, "accounts") {
		if strings.Contains(l, "before=") {
			t.Errorf("garbage cursor kept: %q", l)
		}
	}

	// a row action (the page script reloads the same URL): the same search
	// and page come back with the new state
	const page = "/admin/x?q=acct&page=2"
	s = get(page)
	if !strings.Contains(s, `data-act="xdisable" data-x="1013"`) {
		t.Fatal("1013 is not shown enabled on the page")
	}
	check(t, "disable 1013", 200, "")(adm.post("/api/admin/x/accounts/1013/disable", ``))
	s = get(page)
	if got := xRows(s); got != xSeq(1013, 1014, 1016, 1017, 1018, 1019, 1021, 1022, 1023, 1024) {
		t.Errorf("after disable: rows %s", got)
	}
	has(page, s, `data-act="xenable" data-x="1013"`, `<dd>24 / 25</dd>`, "<span>page 2 of 2</span>",
		"20 of 25 accounts have a handle containing “<bdi>acct</bdi>”; showing 11–20.", `name="q" value="acct"`)
	lacks(page, s, `data-act="xdisable" data-x="1013"`)
	check(t, "enable 1013", 200, "")(adm.post("/api/admin/x/accounts/1013/enable", ``))
	has(page, get(page), `data-act="xdisable" data-x="1013"`, total)
	// an edit that moves the account out of the search: the page still renders
	check(t, "rename 1013", 200, "")(adm.post("/api/admin/x/accounts/1013/update", `{"handle":"renamed13","note":""}`))
	s = get(page)
	if got := xRows(s); got != xSeq(1014, 1016, 1017, 1018, 1019, 1021, 1022, 1023, 1024) {
		t.Errorf("after rename: rows %s", got)
	}
	has(page, s, "19 of 25 accounts have a handle containing “<bdi>acct</bdi>”; showing 11–19.", total)
}

// TestXAccountsEmpty: without any account the list says none and offers no
// search, whatever the query; the add and import forms stay.
func TestXAccountsEmpty(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	for _, path := range []string{"/admin/x", "/admin/x?q=abc&page=4"} {
		resp, body := adm.do("GET", path, "")
		s := string(body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		for _, w := range []string{`<dd>0 / 0</dd>`, `<p class="note">none</p>`, `id="f-xadd"`, `id="f-ximport"`} {
			if !strings.Contains(s, w) {
				t.Errorf("%s: lacks %q", path, w)
			}
		}
		for _, w := range []string{`id="in-xq"`, "No handle contains", "Showing "} {
			if strings.Contains(s, w) {
				t.Errorf("%s: has %q", path, w)
			}
		}
	}
	if admin.XAccountsPage != 10 {
		t.Errorf("page size %d", admin.XAccountsPage)
	}
}
