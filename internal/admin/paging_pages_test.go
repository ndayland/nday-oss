package admin_test

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Pagination, regions, the grouped menu, the allowlist table, the row
// pattern and the selection markup of the back office pages
// (internal/webui/admin_paging.go, docs/admin.md).

// page GETs path as b and checks the markup.
func page(t *testing.T, b *browser, path string) string {
	t.Helper()
	resp, body := b.do("GET", path, "")
	if resp.StatusCode != 200 {
		t.Fatalf("%s: %d", path, resp.StatusCode)
	}
	s := string(body)
	for _, pr := range checkHTML(s, adminElems) {
		t.Errorf("%s: %s", path, pr)
	}
	return s
}

// region is the region id of a page: from its start to the start of the
// next region or the end of its section.
func region(t *testing.T, body, id string) string {
	t.Helper()
	start := `id="` + id + `" data-page-region="` + id + `"`
	i := strings.Index(body, start)
	if i < 0 {
		t.Fatalf("no region %s", id)
	}
	r := body[i+len(start):]
	for _, end := range []string{`data-page-region="`, "</section>"} {
		if j := strings.Index(r, end); j >= 0 {
			r = r[:j]
		}
	}
	return r
}

// link is the unescaped href of the pager link with label in a region ("" none):
// its text, or its screen-reader name ("previous", "next", "page 1"; the
// button shows a glyph or the bare number).
func link(r, label string) string {
	glyph := `(?:<span[^>]*aria-hidden="true">[^<]*</span>)?`
	name := `(?:<span class="sr">)?` + regexp.QuoteMeta(label) + `(?:</span>)?`
	m := regexp.MustCompile(`<a href="([^"]*)"[^>]*>` + glyph + name + glyph + `</a>`).FindStringSubmatch(r)
	if m == nil {
		return ""
	}
	return html.UnescapeString(m[1])
}

func ids(re *regexp.Regexp, r string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(r, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestModerationPaging: the queue is numbered (?qp=), the patrol list pages
// both ways by keyset (?rc= older, ?rb= newer, ?rp= its number); each
// list's links keep the filter and the other list's position.
func TestModerationPaging(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	tom := h.user("tom", "user")
	for i := 0; i < 23; i++ {
		c := h.comment(tom.id, fmt.Sprintf("comment %02d", i))
		if i < 12 {
			h.report(c, adm.id, "spam", nil)
		}
		h.clock.Advance(time.Minute)
	}
	art := regexp.MustCompile(`<article class="cm adm-cm" id="m-([0-9a-f-]{36})">`)
	s := page(t, adm, "/admin/moderation")
	q := region(t, s, "r-queue")
	if n := len(ids(art, q)); n != 10 || !strings.Contains(q, "page 1 of 2") {
		t.Errorf("queue page 1: %d items", n)
	}
	if l := link(q, "next"); l != "/admin/moderation?qp=2#r-queue" {
		t.Errorf("queue next %q", l)
	}
	rec := region(t, s, "r-recent")
	p1 := ids(art, rec)
	if len(p1) != 10 || link(rec, "previous") != "" {
		t.Errorf("recent page 1: %d items", len(p1))
	}
	next := link(rec, "next")
	if !strings.Contains(next, "rc=") || !strings.Contains(next, "rp=2") || !strings.HasSuffix(next, "#r-recent") {
		t.Fatalf("recent next %q", next)
	}
	s = page(t, adm, strings.Replace(next, "#", "&qp=2#", 1))
	rec = region(t, s, "r-recent")
	p2 := ids(art, rec)
	if len(p2) != 10 || p2[0] == p1[0] || !strings.Contains(rec, "page 2") {
		t.Errorf("recent page 2: %v", p2)
	}
	if l := link(rec, "previous"); l != "/admin/moderation?qp=2#r-recent" {
		t.Errorf("recent previous on page 2 (the first page, the queue page kept): %q", l)
	}
	// the queue links keep the patrol position, and its page 2 holds the rest
	q = region(t, s, "r-queue")
	if n := len(ids(art, q)); n != 2 {
		t.Errorf("queue page 2: %d items", n)
	}
	if l := link(q, "previous"); !strings.Contains(l, "rc=") || strings.Contains(l, "qp=") {
		t.Errorf("queue previous %q", l)
	}
	s = page(t, adm, link(rec, "next"))
	rec = region(t, s, "r-recent")
	if n := len(ids(art, rec)); n != 3 || link(rec, "next") != "" {
		t.Errorf("recent page 3: %d items", n)
	}
	prev := link(rec, "previous")
	if !strings.Contains(prev, "rb=") || !strings.Contains(prev, "rp=2") || strings.Contains(prev, "rc=") {
		t.Fatalf("recent previous on page 3 %q", prev)
	}
	back := ids(art, region(t, page(t, adm, prev), "r-recent"))
	if strings.Join(back, ",") != strings.Join(p2, ",") {
		t.Errorf("previous of page 3: %v, want %v", back, p2)
	}
	// a filter change starts the patrol list over and keeps the queue page
	s = page(t, adm, "/admin/moderation?qp=2&status=hidden")
	if l := link(region(t, s, "r-queue"), "previous"); l != "/admin/moderation?status=hidden#r-queue" {
		t.Errorf("queue previous keeps the filter: %q", l)
	}
}

// TestAuditAndUsersPaging: the audit log and the user list page both ways
// by keyset, 10 rows a page, the filters kept.
func TestAuditAndUsersPaging(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	for i := 0; i < 25; i++ {
		h.sql(`INSERT INTO admin_audit (actor_id, actor_handle, actor_role, action, target_type, target_id, source)
			VALUES ($1, 'kim', 'admin', 'user.role', 'user', $2, 'web')`, adm.id, adm.id)
	}
	row := regexp.MustCompile(`<tr class="adm-detail" id="dt-a-([0-9]+)"`)
	s := page(t, adm, "/admin/audit?action=user_role")
	r := region(t, s, "r-audit")
	p1 := ids(row, r)
	next := link(r, "next")
	if len(p1) != 10 || !strings.Contains(next, "action=user_role") || !strings.Contains(next, "before=") {
		t.Fatalf("audit page 1: %d rows, next %q", len(p1), next)
	}
	r = region(t, page(t, adm, next), "r-audit")
	p2 := ids(row, r)
	if len(p2) != 10 || link(r, "previous") != "/admin/audit?action=user_role#r-audit" {
		t.Errorf("audit page 2: %d rows, previous %q", len(p2), link(r, "previous"))
	}
	r = region(t, page(t, adm, link(r, "next")), "r-audit")
	prev := link(r, "previous")
	if n := len(ids(row, r)); n != 5 || !strings.Contains(prev, "after=") || !strings.Contains(prev, "action=user_role") {
		t.Fatalf("audit page 3: %d rows, previous %q", n, prev)
	}
	if back := ids(row, region(t, page(t, adm, prev), "r-audit")); strings.Join(back, ",") != strings.Join(p2, ",") {
		t.Errorf("audit previous: %v, want %v", back, p2)
	}

	for i := 0; i < 22; i++ {
		h.user(fmt.Sprintf("u%02d", i), "user")
		h.clock.Advance(time.Second)
	}
	urow := regexp.MustCompile(`<tr>\s*<td><a href="/admin/users/([0-9a-f-]{36})">`)
	r = region(t, page(t, adm, "/admin/users"), "r-users")
	if n := len(ids(urow, r)); n != 10 || link(r, "previous") != "" {
		t.Errorf("users page 1: %d rows", n)
	}
	r = region(t, page(t, adm, link(r, "next")), "r-users")
	u2 := ids(urow, r)
	if len(u2) != 10 || link(r, "previous") != "/admin/users#r-users" {
		t.Errorf("users page 2: %d rows, previous %q", len(u2), link(r, "previous"))
	}
	r = region(t, page(t, adm, link(r, "next")), "r-users")
	prev = link(r, "previous")
	if n := len(ids(urow, r)); n != 3 || !strings.Contains(prev, "before=") || !strings.Contains(prev, "p=2") {
		t.Fatalf("users page 3: %d rows, previous %q", n, prev)
	}
	if back := ids(urow, region(t, page(t, adm, prev), "r-users")); strings.Join(back, ",") != strings.Join(u2, ",") {
		t.Errorf("users previous: %v, want %v", back, u2)
	}
}

// TestUserPageAndSystemPaging: the user page's lists are numbered on their
// own parameters; the system page's tables page in memory.
func TestUserPageAndSystemPaging(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	tom := h.user("tom", "user")
	for i := 0; i < 12; i++ {
		h.comment(tom.id, fmt.Sprintf("comment %02d", i))
		h.clock.Advance(time.Minute)
	}
	art := regexp.MustCompile(`<article class="cm adm-cm" id="m-`)
	s := page(t, adm, "/admin/users/"+tom.id+"?ap=3")
	r := region(t, s, "r-ucomments")
	if n := len(art.FindAllString(r, -1)); n != 10 || !strings.Contains(r, "page 1 of 2") {
		t.Errorf("comments page 1: %d", n)
	}
	// the audit page parameter (nothing to page there) is kept
	if l := link(r, "next"); l != "/admin/users/"+tom.id+"?ap=3&cp=2#r-ucomments" {
		t.Errorf("comments next %q", l)
	}
	r = region(t, page(t, adm, "/admin/users/"+tom.id+"?cp=2"), "r-ucomments")
	if n := len(art.FindAllString(r, -1)); n != 2 {
		t.Errorf("comments page 2: %d", n)
	}

	s = page(t, adm, "/admin/system?tp=99&lp=2")
	r = region(t, s, "r-tables")
	if n := strings.Count(r, "<tr><td><code>"); n < 1 || n > 10 || !strings.Contains(r, " of ") {
		t.Errorf("tables last page: %d rows", n)
	}
	if l := link(r, "page 1"); l != "/admin/system?lp=2#r-tables" {
		t.Errorf("tables page 1 %q", l)
	}
}

// TestAdminMenuGroup: X, its drafts and GitHub are one menu item, current
// on the three pages, which show them as a second-level menu; moderators
// see neither.
func TestAdminMenuGroup(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")
	for _, c := range []struct{ path, label string }{{"/admin/x", "X"}, {"/admin/x/drafts", "X drafts"}, {"/admin/github", "GitHub"}} {
		s := page(t, adm, c.path)
		nav := section(s, `<nav class="adm-nav"`, "</nav>")
		if !strings.Contains(nav, `<a href="/admin/x" aria-current="page">X · GitHub</a>`) || strings.Contains(nav, `href="/admin/github"`) {
			t.Errorf("%s: menu\n%s", c.path, nav)
		}
		sub := section(s, `<nav class="seg adm-subnav"`, "</nav>")
		for _, w := range []string{`href="/admin/x"`, `href="/admin/x/drafts"`, `href="/admin/github"`,
			`<a href="` + c.path + `" aria-current="page">` + c.label + `</a>`} {
			if !strings.Contains(sub, w) {
				t.Errorf("%s: sub-menu lacks %s\n%s", c.path, w, sub)
			}
		}
		if strings.Count(sub, "aria-current") != 1 {
			t.Errorf("%s: %d current sub-items", c.path, strings.Count(sub, "aria-current"))
		}
	}
	s := page(t, adm, "/admin/users")
	if strings.Contains(s, "adm-subnav") || !strings.Contains(s, `<a href="/admin/x">X · GitHub</a>`) {
		t.Error("/admin/users: the group is current or a sub-menu is shown")
	}
	s = page(t, mod, "/admin/moderation")
	if strings.Contains(s, "X · GitHub") || strings.Contains(s, "adm-subnav") {
		t.Error("moderator sees the X · GitHub group")
	}
	if s := page(t, adm, "/zh-hans/admin/github"); !strings.Contains(s, `<a href="/zh-hans/admin/x" aria-current="page">X · GitHub</a>`) {
		t.Error("zh-hans group link")
	}
}

// TestXAccountsTable: the allowlist's columns, no user id shown, name and
// bio escaped and clipped, the edit form in the row's detail.
func TestXAccountsTable(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	h.sql(`INSERT INTO x_accounts (user_id, handle, note, name, description) VALUES ('987654321', 'alice', 'n1', '<b>Alice</b>', '<script>x</script> bio')`)
	h.sql(`INSERT INTO x_accounts (user_id, handle) VALUES ('123123123', 'bob')`)
	s := page(t, adm, "/admin/x")
	r := region(t, s, "r-accounts")
	head := section(r, "<thead>", "</thead>")
	want := []string{"handle", "name", "bio", "state", "posts", "added", "updated", "actions"}
	got := ids(regexp.MustCompile(`<th scope="col"[^>]*>([^<]*)</th>`), head)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("columns %v, want %v", got, want)
	}
	text := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(r, " ")
	for _, id := range []string{"987654321", "123123123"} {
		if strings.Contains(text, id) {
			t.Errorf("user id %s shown as text", id)
		}
	}
	for _, w := range []string{`<span class="adm-clip s" dir="auto">&lt;b&gt;Alice&lt;/b&gt;</span>`,
		`<span class="adm-clip" dir="auto">&lt;script&gt;x&lt;/script&gt; bio</span>`,
		`data-rowx="" aria-expanded="false" aria-controls="dt-xa-987654321">edit</button>`,
		`<tr class="adm-detail" id="dt-xa-987654321" hidden=""><td colspan="8">`,
		`<form class="acct-form adm-xedit" data-x="987654321" novalidate="">`, `data-rowx-close=""`,
		`<div class="adm-rowacts">`, `data-act="xdisable" data-x="987654321"`} {
		if !strings.Contains(r, w) {
			t.Errorf("accounts table lacks %s", w)
		}
	}
	if strings.Contains(s, "<script>x") || strings.Contains(s, "<b>Alice") {
		t.Error("name or bio not escaped")
	}
}

// TestBulkMarkup: the review lists carry a checkbox per row named by the
// row, a select-all box and a hidden bar with the list's decisions.
func TestBulkMarkup(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	h.xCandFixture()
	for i := 0; i < 12; i++ {
		h.sql(`INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at) VALUES ($1, $2, '2026-11-01', $3)`,
			fmt.Sprint(5001+i), fmt.Sprintf("cand%02d", i), fmt.Sprintf("2026-10-%02d", i+1))
		h.sql(`INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at) VALUES ($1, '11', '1001', 'quoted', '2026-11-10')`,
			fmt.Sprint(5001+i))
	}
	s := page(t, adm, "/admin/x?dp=1&page=1")
	open := region(t, s, "r-xcand")
	for _, w := range []string{`data-bulk="xcand"`, `<input type="checkbox" data-pick-all="" aria-label="select all on this page"/>`,
		`<form class="acct-form adm-bulk" data-bulk-bar="" novalidate="" hidden="">`, `data-bulk-act="add" data-confirm="confirm">add to allowlist</button>`,
		`class="btn sm acct-del" data-bulk-act="dismiss" data-confirm="confirm">dismiss</button>`, `data-bulk-clear=""`,
		`data-pick="" data-id="3001" data-state="pending" aria-labelledby="lb-r-xcand-3001"`, `<td id="lb-r-xcand-3001">`,
		"page 1 of 2"} {
		if !strings.Contains(open, w) {
			t.Errorf("open candidates lack %s", w)
		}
	}
	if n := strings.Count(open, `data-pick=""`); n != 10 {
		t.Errorf("open candidates: %d boxes", n)
	}
	if l := link(open, "next"); l != "/admin/x?cp=2&dp=1#r-xcand" {
		t.Errorf("candidates next keeps the other lists: %q", l)
	}
	dis := region(t, s, "r-xcand-dismissed")
	if !strings.Contains(dis, `data-bulk-act="restore" data-confirm="confirm">restore</button>`) || !strings.Contains(dis, `data-id="3004" data-state="dismissed"`) ||
		strings.Contains(dis, `data-bulk-act="add"`) {
		t.Error("dismissed candidates bulk bar")
	}

	r := h.ghFixture()
	s = page(t, adm, "/admin/github")
	un := region(t, s, "r-gh-unverified")
	for _, w := range []string{`data-bulk="gh"`, `data-bulk-act="trust" data-confirm="confirm">trust</button>`, `acct-del" data-bulk-act="reject" data-confirm="confirm">reject</button>`,
		fmt.Sprintf(`data-pick="" data-id="%d" data-state="unverified" aria-labelledby="lb-gh-%d"`, r.poc, r.poc),
		fmt.Sprintf(`<span id="lb-gh-%d">`, r.poc)} {
		if !strings.Contains(un, w) {
			t.Errorf("unverified repositories lack %s", w)
		}
	}
	if tr := region(t, s, "r-gh-trusted"); !strings.Contains(tr, `data-bulk-act="reset"`) || !strings.Contains(tr, `data-bulk-act="reject"`) ||
		strings.Contains(tr, `data-bulk-act="trust"`) {
		t.Error("trusted repositories bulk bar")
	}

	d := h.draft("CVE-2026-0001", "kev_added", "t")
	s = page(t, adm, "/admin/x/drafts")
	pend := region(t, s, "r-xdpending")
	for _, w := range []string{`data-bulk="xd"`, `acct-del" data-bulk-act="discard" data-confirm="confirm">discard</button>`,
		`data-pick="" data-id="` + d + `" data-version="1" aria-labelledby="lb-xd-` + d + `"`, `<span id="lb-xd-` + d + `">`} {
		if !strings.Contains(pend, w) {
			t.Errorf("pending drafts lack %s", w)
		}
	}
}

// TestAdminKeysetNumbers: a keyset list's numbers (users, ~12 pages) lead
// where a walk with › gets, each marked current, each link ending in the
// region's #id; ?p= alone reaches the first and last pages, a crafted one
// is bounded (the middle is the first page, past the end the last).
func TestAdminKeysetNumbers(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	for i := 0; i < 114; i++ {
		h.user(fmt.Sprintf("w%03d", i), "user")
		h.clock.Advance(time.Second)
	}
	urow := regexp.MustCompile(`<tr>\s*<td><a href="/admin/users/([0-9a-f-]{36})">`)
	cur := regexp.MustCompile(`aria-current="page"><span aria-hidden="true">([0-9]+)</span>`)
	num := regexp.MustCompile(`<a href="([^"]+)" class="pg[^"]*"><span aria-hidden="true">([0-9]+)</span>`)
	type pg struct{ url, rows string }
	var walk []pg
	for u := "/admin/users"; u != ""; u = link(region(t, page(t, adm, u), "r-users"), "next") {
		r := region(t, page(t, adm, u), "r-users")
		if m := cur.FindStringSubmatch(r); m == nil || m[1] != fmt.Sprint(len(walk)+1) {
			t.Fatalf("%s: current %v, want %d", u, m, len(walk)+1)
		}
		walk = append(walk, pg{u, strings.Join(ids(urow, r), ",")})
		if len(walk) > 30 {
			t.Fatal("no end")
		}
	}
	if len(walk) != 12 {
		t.Fatalf("%d pages, want 12", len(walk))
	}
	for i, p := range walk {
		r := region(t, page(t, adm, p.url), "r-users")
		for _, m := range num.FindAllStringSubmatch(r, -1) {
			href := html.UnescapeString(m[1])
			var n int
			fmt.Sscan(m[2], &n)
			if !strings.HasSuffix(href, "#r-users") {
				t.Errorf("page %d: number %d %q without #r-users", i+1, n, href)
			}
			got := region(t, page(t, adm, href), "r-users")
			if c := cur.FindStringSubmatch(got); c == nil || c[1] != m[2] || strings.Join(ids(urow, got), ",") != walk[n-1].rows {
				t.Errorf("page %d: number %d (%s) shows another page", i+1, n, href)
			}
		}
	}
	for p, want := range map[string]int{"2": 2, "3": 3, "10": 10, "11": 11, "12": 12, "999999": 12, "6": 1, "-4": 1, "x": 1} {
		got := region(t, page(t, adm, "/admin/users?p="+p), "r-users")
		if c := cur.FindStringSubmatch(got); c == nil || c[1] != fmt.Sprint(want) || strings.Join(ids(urow, got), ",") != walk[want-1].rows {
			t.Errorf("?p=%s: current %v, want page %d", p, c, want)
		}
	}
}
