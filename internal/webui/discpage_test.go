package webui_test

import (
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/webui"
)

var (
	sizeRe     = regexp.MustCompile(`data-size="(.)"`)
	discNextRe = regexp.MustCompile(`<a href="([^"]+)" rel="next"`)
)

// TestDiscussionPages: the discussion outline of a vulnerability page shows
// 10 threads per page (replies stay with their thread), the numbered pager
// of the other sections with ?cmp=; counts are those of all comments; a
// permalink (?c=) opens the page of its comment (a reply: its thread's page),
// ?cmp= wins over it, and the pager's links name pages, not the comment;
// the page is the same for every visitor; ?evp= and ?cmp= are independent.
func TestDiscussionPages(t *testing.T) {
	e, conn := realDiscEnv(t)
	base := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	sizes := []string{"s", "m", "l"} // top i has size sizes[i%3]
	body := map[string]string{"s": "QZ short", "m": "QZ " + strings.Repeat("m", 200), "l": "QZ " + strings.Repeat("l", 700)}
	var tops []string
	for i := 0; i < 25; i++ {
		tops = append(tops, insertComment(t, conn, sitetest.GPU, nil, body[sizes[i%3]]+fmt.Sprint(i), base.Add(time.Duration(i)*time.Second)))
	}
	r0 := insertComment(t, conn, sitetest.GPU, &tops[0], "QZ reply", base.Add(time.Hour))
	r22 := insertComment(t, conn, sitetest.GPU, &tops[22], "QZ reply", base.Add(time.Hour+time.Second))
	if _, err := conn.Exec(t.Context(), `UPDATE comments SET status = 'hidden', hidden_at = now(), hidden_reason = 'x' WHERE id = $1::uuid`, tops[4]); err != nil {
		t.Fatal(err)
	}
	// 12 more events: the event log has two pages too
	s := sitetest.Seeder{T: t, Conn: conn}
	for i := 0; i < 12; i++ {
		s.Event(sitetest.Ev{CVE: sitetest.GPU, Type: "poc_published", Source: fmt.Sprintf("pp%02d", i), Occurred: sitetest.P(sitetest.Day(2026, 11, 10).AddDate(0, 0, i)), Backfill: true, Key: fmt.Sprintf("k%d", i)})
	}
	s.Refresh()

	path := "/vuln/" + sitetest.GPU
	threads := func(b string) []string {
		var out []string // the size of each thread's first comment; "h": a placeholder without one
		for _, chunk := range strings.Split(regionOf(b, "r-discussion"), `<li class="cm-thread">`)[1:] {
			first := chunk
			if i := strings.Index(first, `class="cm-replies"`); i >= 0 {
				first = first[:i]
			}
			if m := sizeRe.FindStringSubmatch(first); m != nil {
				out = append(out, m[1])
			} else {
				out = append(out, "h")
			}
		}
		return out
	}
	want := func(from, to int) string {
		var out []string
		for i := from; i < to; i++ {
			if i == 4 {
				out = append(out, "h") // the hidden one
				continue
			}
			out = append(out, sizes[i%3])
		}
		return strings.Join(out, ",")
	}
	_, one := e.get(t, path)
	_, two := e.get(t, path+"?cmp=2")
	_, three := e.get(t, path+"?cmp=3")
	for i, c := range []struct {
		b, sizes, pos string
	}{{one, want(0, 10), "page 1 of 3"}, {two, want(10, 20), "page 2 of 3"}, {three, want(20, 25), "page 3 of 3"}} {
		if got := strings.Join(threads(c.b), ","); got != c.sizes {
			t.Errorf("page %d: threads %s, want %s", i+1, got, c.sizes)
		}
		if pg := pocPgRe.FindString(regionOf(c.b, "r-discussion")); !strings.Contains(pg, c.pos) {
			t.Errorf("page %d: pager %q", i+1, pg)
		}
		// counts and the rest of the page use every comment (24 visible + 2 replies)
		if !strings.Contains(c.b, `id="disc-n">26 comments`) || !strings.Contains(regionOf(c.b, "r-discussion"), "Sign in to read 26 comments.") {
			t.Errorf("page %d: count", i+1)
		}
		if strings.Contains(c.b, "QZ ") {
			t.Errorf("page %d: comment text in the public page", i+1)
		}
	}
	// replies stay with their thread: one reply list on page 1 (top 0) and on page 3 (top 22)
	for i, c := range []struct {
		b string
		n int
	}{{one, 1}, {two, 0}, {three, 1}} {
		if n := strings.Count(regionOf(c.b, "r-discussion"), `class="cm-replies"`); n != c.n {
			t.Errorf("page %d: %d reply lists, want %d", i+1, n, c.n)
		}
	}
	if m := discNextRe.FindStringSubmatch(regionOf(one, "r-discussion")); m == nil || html.UnescapeString(m[1]) != path+"?cmp=2#r-discussion" {
		t.Errorf("page 1 next: %v", m)
	}
	if pg := pocPgRe.FindString(regionOf(two, "r-discussion")); !strings.Contains(pg, `href="`+path+`#r-discussion"`) || !strings.Contains(pg, `href="`+path+`?cmp=3#r-discussion"`) {
		t.Errorf("page 2 pager: %s", pg)
	}
	// outside the region the page is the same on every page
	// (the event log's pager links carry cmp, as the other pagers' links do)
	rest := func(b string) string {
		return strings.Replace(outsideRegion(b, "r-discussion"), regionOf(b, "r-events"), "EVENTS", 1)
	}
	if a, b := rest(one), rest(three); a != b {
		t.Errorf("page 1 vs 3 differ outside r-discussion:\n%s", firstDiff(a, b))
	}
	// clamped like the other pagers
	for _, c := range []struct{ q, same string }{{"?cmp=99", three}, {"?cmp=0", one}, {"?cmp=x", one}, {"?cmp=-3", one}} {
		if resp, b := e.get(t, path+c.q); resp.StatusCode != 200 || regionOf(b, "r-discussion") != regionOf(c.same, "r-discussion") {
			t.Errorf("%s: %d, not the clamped page", c.q, resp.StatusCode)
		}
	}
	// permalinks: the page of the comment, a reply's thread, a comment that is not shown, ?cmp= first
	for _, c := range []struct {
		name, q, same string
	}{
		{"top on page 2", "?c=" + tops[15], two}, {"top on page 3", "?c=" + tops[24], three},
		{"reply on page 3", "?c=" + r22, three}, {"reply on page 1", "?c=" + r0, one},
		{"hidden", "?c=" + tops[4], one}, {"unknown", "?c=00000000-0000-4000-8000-000000000000", one}, {"malformed", "?c=zz", one},
		{"cmp wins", "?c=" + tops[24] + "&cmp=1", one},
	} {
		_, b := e.get(t, path+c.q)
		if regionOf(b, "r-discussion") != regionOf(c.same, "r-discussion") && c.name != "cmp wins" {
			// the pager links of a permalink page may differ only by dropping ?c=: they must equal the plain page's
			t.Errorf("%s: not the region of the plain page", c.name)
		}
		if got := strings.Join(threads(b), ","); got != strings.Join(threads(c.same), ",") {
			t.Errorf("%s: threads %s, want %s", c.name, got, strings.Join(threads(c.same), ","))
		}
		if strings.Contains(regionOf(b, "r-discussion"), "c="+tops[15]) || strings.Contains(regionOf(b, "r-discussion"), "?c=") {
			t.Errorf("%s: the pager keeps ?c=", c.name)
		}
	}
	// the event log and the discussion page independently, each pager keeps the other's parameter
	_, both := e.get(t, path+"?evp=2&cmp=3")
	if got := strings.Join(threads(both), ","); got != want(20, 25) {
		t.Errorf("both: threads %s", got)
	}
	evpg, dpg := pocPgRe.FindString(regionOf(both, "r-events")), pocPgRe.FindString(regionOf(both, "r-discussion"))
	if !strings.Contains(evpg, "page 2 of 2") || !strings.Contains(evpg, `href="`+path+`?cmp=3#r-events"`) ||
		!strings.Contains(dpg, `href="`+path+`?cmp=2&amp;evp=2#r-discussion"`) || !strings.Contains(dpg, `href="`+path+`?evp=2#r-discussion"`) {
		t.Errorf("both: pagers\n%s\n%s", evpg, dpg)
	}
	// the same bytes for every visitor
	if _, out := e.get(t, path+"?cmp=2", "Authorization", ""); out != two {
		t.Errorf("page 2 differs without the token:\n%s", firstDiff(out, two))
	}
}

// TestDiscussScriptPages: what discuss.js must do for the numbered pages
// (the script itself is exercised in a browser): ask the API for the page
// the server drew, with the page size of the server; keep the current page
// after an edit, a deletion, a hide or an unhide, and find a new comment by
// its id; fill a region the pager loaded in place; no leftover of the
// cursor-based "first page" link.
func TestDiscussScriptPages(t *testing.T) {
	b, err := os.ReadFile("static/discuss.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{
		"page: String(pageNo()), limit: String(PER)", "const PER = 10;", "$('disc-list')", "l.dataset.page",
		"q.set('cmp', String(pageNo()))", "new window.MutationObserver", "#disc-list .cm-list.veil:not([data-failed])",
		"reload(c.id, true);", "reload(c.parent_id || c.id, true);",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("discuss.js: missing %q", want)
		}
	}
	if n := strings.Count(src, "reload(c.id, true);"); n != 3 { // edit, hide, unhide
		t.Errorf("%d keep-page reloads of c.id, want 3", n)
	}
	// a new comment (top level or reply) is found by id, not by the old page
	for _, want := range []string{"reload(j.comment && j.comment.id);"} {
		if n := strings.Count(src, want); n != 2 {
			t.Errorf("%d reloads %q, want 2", n, want)
		}
	}
	if strings.Contains(src, "state.cursor") || strings.Contains(src, "'c', c") {
		t.Error("discuss.js still picks the page by cursor or by ?c= itself")
	}
	if PER := regexp.MustCompile(`const PER = (\d+);`).FindStringSubmatch(src); PER == nil || PER[1] != fmt.Sprint(webui.DiscPageSize) {
		t.Error("the script's page size differs from the server's DiscPageSize")
	}
}
