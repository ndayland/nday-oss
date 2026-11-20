package webui_test

import (
	"context"
	"html"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// The shared pager (parts.tmpl "pager") on the public lists: the row range
// on the left, then ‹ 1 2 … 6 7 8 … 19 20 ›, each arrow a link or a
// disabled span in its place; previous pages backwards by keyset
// (?before=), and page 2 goes back to the first page; every link keeps the
// filters; next to a position ?p= only labels the page, alone it picks one
// of the first or last pages.

var (
	pagerRe    = regexp.MustCompile(`(?s)<nav class="pager" aria-label="[^"]+">.*?</nav>`)
	pagerPosRe = regexp.MustCompile(`<p class="pg-pos[^"]*">(.*?)</p>`)
	prevRe     = regexp.MustCompile(`<a href="([^"]+)" rel="prev"`)
	firstRe    = regexp.MustCompile(`<a href="([^"]+)" class="pg[^"]*"><span aria-hidden="true">1</span>`)
	numberRe   = regexp.MustCompile(`<a href="([^"]+)" class="pg[^"]*"><span aria-hidden="true">([0-9]+)</span><span class="sr">([^<]*)</span></a>`)
	currentRe  = regexp.MustCompile(`<span class="pg pg-cur[^"]*" aria-current="page"><span aria-hidden="true">([0-9]+)</span>`)
)

const (
	offPrev = `<span class="pg pg-a" aria-disabled="true"><span aria-hidden="true">‹</span><span class="sr">previous</span></span>`
	offNext = `<span class="pg pg-a" aria-disabled="true"><span aria-hidden="true">›</span><span class="sr">next</span></span>`
)

var (
	firstSpanRe = regexp.MustCompile(`^<span class="sr">([^<]*)</span>`)
	digitsRe    = regexp.MustCompile(`[0-9][0-9,.]*`)
)

// checkPagerCounts (run on every page the page tests fetch, tenv.get):
// every pager says how many pages its list has (pager.page_of: the page
// number and the number of pages, in any locale), unless the page number
// itself is not known (no position at all). The one exception, a list
// filtered by one of the broadest tags (above site.TagCountMax), is
// fetched without this check (TestHotPagerBroadTag).
func checkPagerCounts(t *testing.T, what, body string) {
	t.Helper()
	for _, nav := range regexp.MustCompile(`(?s)<nav class="pager".*?</nav>`).FindAllString(body, -1) {
		m := pagerPosRe.FindStringSubmatch(nav)
		if m == nil || m[1] == "" {
			continue
		}
		s := firstSpanRe.FindStringSubmatch(m[1])
		if s == nil || len(digitsRe.FindAllString(s[1], -1)) < 2 {
			t.Errorf("%s: a pager without the number of pages: %s", what, m[1])
		}
	}
}

// pagerOf is the page's pager markup ("" = none).
func pagerOf(body string) string { return pagerRe.FindString(body) }

func posOf(body string) string {
	if m := pagerPosRe.FindStringSubmatch(pagerOf(body)); m != nil {
		return m[1]
	}
	return ""
}

func linkOf(re *regexp.Regexp, body string) string {
	if m := re.FindStringSubmatch(pagerOf(body)); m != nil {
		return html.UnescapeString(m[1])
	}
	return ""
}

func TestCataloguePager(t *testing.T) {
	e := newCatEnv(t, catSeedPage)
	ctx := context.Background()
	st, err := e.store.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path  string
		p     site.CatalogueParams
		total int64
	}{
		{"/vuln?browse=1", site.CatalogueParams{}, st.WithEvents - st.Rejected},
		{"/vuln?include_rejected=1", site.CatalogueParams{IncludeRejected: true}, st.WithEvents},
	} {
		want := storeIDs(t, e.store, c.p)
		if len(want) <= 50 || int64(len(want)) != c.total {
			t.Fatalf("%s: precondition: %d rows, total %d", c.path, len(want), c.total)
		}
		n := strconv.Itoa(len(want))
		// page 1: previous disabled, next carries the page number
		resp, first := e.get(t, c.path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", c.path, resp.StatusCode)
		}
		pg := pagerOf(first)
		if posOf(first) != `<span class="sr">page 1 of 2</span><span>1–50 of `+n+"</span>" || !strings.Contains(pg, offPrev) ||
			strings.Contains(pg, offNext) || currentOf(first) != 1 {
			t.Errorf("%s page 1 pager:\n%s", c.path, pg)
		}
		next := linkOf(catNextRe, first)
		q := strings.TrimPrefix(strings.TrimPrefix(c.path, "/vuln"), "?browse=1")
		if q != "" {
			q = q[1:] + "&"
		}
		if !strings.HasPrefix(next, "/vuln?"+q+"cursor=") || !strings.HasSuffix(next, "&p=2") {
			t.Errorf("%s next %q", c.path, next)
		}
		// page 2 (the last): previous and page 1 link to the first page, next disabled
		_, second := e.get(t, next)
		if got := rowIDs(second); joinIDs(got) != joinIDs(want[50:]) {
			t.Errorf("%s page 2 rows %v", c.path, got)
		}
		pg = pagerOf(second)
		if posOf(second) != `<span class="sr">page 2 of 2</span><span>51–`+n+" of "+n+"</span>" || !strings.Contains(pg, offNext) ||
			strings.Contains(pg, offPrev) || currentOf(second) != 2 {
			t.Errorf("%s page 2 pager:\n%s", c.path, pg)
		}
		if f := linkOf(firstRe, second); f != c.path {
			t.Errorf("%s page 1 link %q", c.path, f)
		}
		prev := linkOf(prevRe, second)
		if prev != c.path {
			t.Errorf("%s prev %q", c.path, prev)
		}
		// previous: the first page exactly as a fresh visit
		resp, back := e.get(t, prev)
		if resp.StatusCode != 200 || joinIDs(rowIDs(back)) != joinIDs(rowIDs(first)) || pagerOf(back) != pagerOf(first) {
			t.Errorf("%s back to the first page:\n%s\nwant\n%s", c.path, pagerOf(back), pagerOf(first))
		}
		// next to a cursor ?p= only labels the page: past the last page it
		// is the last page (the rows are page 2's either way); out of range
		// it is not shown
		bare := strings.TrimSuffix(next, "&p=2")
		for p, pos := range map[string]string{"&p=9": `<span class="sr">page 2 of 2</span><span>51–` + n + " of " + n, "&p=1": "", "&p=x": "",
			"&p=999999999": `<span class="sr">page 2 of 2</span>`, "&p=99999999999999999999999": ""} {
			_, b := e.get(t, bare+p)
			if joinIDs(rowIDs(b)) != joinIDs(want[50:]) {
				t.Errorf("%s%s: rows depend on p", bare, p)
			}
			if got := posOf(b); (pos == "" && got != "") || !strings.HasPrefix(got, pos) {
				t.Errorf("%s%s: position %q", bare, p, got)
			}
		}
	}
	// a year filter that fits on one page has no pager
	_, b := e.get(t, "/vuln?year=2024")
	if pagerOf(b) != "" {
		t.Error("one page has a pager")
	}
	// bad positions are a 400, as a bad cursor
	_, first := e.get(t, "/vuln?browse=1")
	next := linkOf(catNextRe, first)
	cur := strings.TrimSuffix(strings.TrimPrefix(next, "/vuln?cursor="), "&p=2")
	for _, p := range []string{"/vuln?before=garbage", "/vuln?before=" + strings.Repeat("A", 200), "/vuln?cursor=" + cur + "&before=" + cur} {
		if resp, _ := e.get(t, p); resp.StatusCode != 400 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	// the localized page keeps its prefix and words
	_, zh := e.get(t, "/zh-hans/vuln?browse=1")
	if !strings.Contains(posOf(zh), `<span class="sr">第 1 页，共 2 页</span>`) || !strings.Contains(linkOf(catNextRe, zh), "/zh-hans/vuln?cursor=") {
		t.Errorf("zh-hans pager:\n%s", pagerOf(zh))
	}
}

// hotSeedPage adds 55 patch releases in the last three days (more than one
// page of the home list) and pins two of them (two researchers each).
func hotSeedPage(t *testing.T, conn *pgx.Conn) {
	s := sitetest.Seeder{T: t, Conn: conn}
	for i := 0; i < 55; i++ {
		c := "CVE-2026-" + strconv.Itoa(3000+i)
		s.Vuln(c, sitetest.P("bulk "+c))
		at := sitetest.Ago(0.05 * float64(i+1))
		s.Event(sitetest.Ev{CVE: c, Type: "patch_released", Source: "ghsa", Occurred: &at, Key: "GHSA-" + c})
	}
	if _, err := conn.Exec(context.Background(), `INSERT INTO x_accounts (user_id, handle, enabled) VALUES
		('7001', 'r_one', true), ('7002', 'r_two', true)`); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range []string{"CVE-2026-3010", "CVE-2026-3020"} {
		for _, a := range []string{"7001", "7002"} {
			n++
			at := sitetest.Now.Add(-time.Duration(n) * time.Hour)
			id := "1900000000000000" + strconv.Itoa(100+n)
			s.Event(sitetest.Ev{CVE: c, Type: "social_post", Source: "xposts", Occurred: &at, Observed: at, Key: id,
				Detail: `{"post_id": "` + id + `", "author_id": "` + a + `", "author_handle": "h", "text": "t", "cves": ["` + c + `"]}`})
		}
	}
	s.Refresh()
}

func TestHotPager(t *testing.T) {
	e := newCatEnv(t, hotSeedPage)
	for _, path := range []string{"/", "/?since=30d"} {
		resp, first := e.get(t, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		rows1 := rowIDs(first)
		if !strings.HasPrefix(joinIDs(rows1), "CVE-2026-3010,CVE-2026-3020,") || len(rows1) != 52 {
			t.Fatalf("%s: precondition: pinned rows first, then 50 (%d rows)", path, len(rows1))
		}
		// the first page counts its pinned rows; the total counts them once
		// and agrees with walking both pages (below)
		since := 7 * 24 * time.Hour
		if path != "/" {
			since = 30 * 24 * time.Hour
		}
		ht, ok, err := e.store.HotCount(context.Background(), site.HotParams{Since: since, Limit: 50})
		if err != nil || !ok || ht.Pins != 2 || ht.Pages(50) != 2 {
			t.Fatalf("%s: count %+v %v", path, ht, err)
		}
		hotTotal := func(string) string { return strconv.FormatInt(ht.Rows+int64(ht.Pins), 10) }
		pg := pagerOf(first)
		if posOf(first) != `<span class="sr">page 1 of 2</span><span>1–52 of `+hotTotal(path)+"</span>" || !strings.Contains(pg, offPrev) || currentOf(first) != 1 {
			t.Errorf("%s page 1 pager:\n%s", path, pg)
		}
		next := linkOf(catNextRe, first)
		q := ""
		if path != "/" {
			q = path[2:] + "&"
		}
		if !strings.HasPrefix(next, "/?"+q+"cursor=") || !strings.HasSuffix(next, "&p=2") {
			t.Fatalf("%s next %q", path, next)
		}
		// page 2: no pinned CVE again, positions after the first page's
		_, second := e.get(t, next)
		rows2 := rowIDs(second)
		seen := map[string]bool{}
		for _, id := range append(append([]string{}, rows1...), rows2...) {
			if seen[id] {
				t.Errorf("%s: %s on both pages", path, id)
			}
			seen[id] = true
		}
		if want := `<span class="sr">page 2 of 2</span><span>53–` + strconv.Itoa(52+len(rows2)) + " of " + hotTotal(path) + "</span>"; posOf(second) != want ||
			52+len(rows2) != len(seen) || strconv.Itoa(len(seen)) != hotTotal(path) {
			t.Errorf("%s page 2 position %q, want %q", path, posOf(second), want)
		}
		if f := linkOf(firstRe, second); f != path {
			t.Errorf("%s page 1 link %q", path, f)
		}
		prev := linkOf(prevRe, second)
		if prev != path {
			t.Errorf("%s prev %q", path, prev)
		}

		// back: the first page as a fresh visit, pinned rows included
		_, back := e.get(t, prev)
		if joinIDs(rowIDs(back)) != joinIDs(rows1) || pagerOf(back) != pagerOf(first) {
			t.Errorf("%s back:\n got %v\n%s\nwant %v\n%s", path, rowIDs(back), pagerOf(back), rows1, pagerOf(first))
		}
		if !strings.Contains(back, `<link rel="canonical" href="https://nday.land`+path) {
			t.Errorf("%s back: canonical", path)
		}
	}
	if resp, _ := e.get(t, "/?before=garbage"); resp.StatusCode != 400 {
		t.Errorf("bad before: %d", resp.StatusCode)
	}
}

// /discussed pages by offset: previous is exact, and so is the position.
// A hot list filtered by a broad tag (above site.TagCountMax) is not
// counted, as the catalogue: the page number and the rows' positions only.
func TestHotPagerBroadTag(t *testing.T) {
	e := newCatEnv(t, hotSeedPage, func(t *testing.T, conn *pgx.Conn) {
		ctx := context.Background()
		for _, q := range []string{
			`INSERT INTO vuln_tag (cve_id, tag, origin, rule_version)
			 SELECT cve_id, 'network', 'rule', 1 FROM vuln WHERE cve_id LIKE 'CVE-2026-30%' ON CONFLICT DO NOTHING`,
			`INSERT INTO vuln_tag_count (tag, n) VALUES ('network', ` + strconv.Itoa(site.TagCountMax+1) + `)
			 ON CONFLICT (tag) DO UPDATE SET n = EXCLUDED.n`,
		} {
			if _, err := conn.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
	})
	raw := func(path string) string { // without tenv.get's page-count check
		resp, err := http.Get(e.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	first := raw("/?tag=network")
	if got := posOf(first); got != `<span class="sr">page 1</span><span>1–52</span>` {
		t.Errorf("page 1 position %q:\n%s", got, pagerOf(first))
	}
	// not counted: the first pages and the arrows, no last pages
	if got := numbersOf(first); got != "[1] 2 …" {
		t.Errorf("page 1 numbers %q:\n%s", got, pagerOf(first))
	}
	second := raw(linkOf(catNextRe, first))
	if got := posOf(second); !strings.HasPrefix(got, `<span class="sr">page 2</span><span>53–`) || strings.Contains(got, " of ") ||
		!strings.Contains(pagerOf(second), offNext) || numbersOf(second) != "1 [2]" {
		t.Errorf("page 2 position %q:\n%s", got, pagerOf(second))
	}
	// ?p=2 alone is page 2 (from the start); past the first pages of an
	// uncounted list nothing is in reach: 404, no query
	if jumped := raw("/?tag=network&p=2"); joinIDs(rowIDs(jumped)) != joinIDs(rowIDs(second)) || currentOf(jumped) != 2 {
		t.Errorf("?p=2 rows %v, want %v", rowIDs(jumped), rowIDs(second))
	}
	for _, p := range []string{"/?tag=network&p=3", "/?tag=network&p=4", "/?tag=network&p=999999"} {
		resp, err := http.Get(e.ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	if _, ok, err := e.store.HotCount(context.Background(), site.HotParams{Since: 7 * 24 * time.Hour, Tags: []string{"network"}}); ok || err != nil {
		t.Errorf("a broad tag counted: %v %v", ok, err)
	}
}

func TestDiscussedPager(t *testing.T) {
	e := newCatEnv(t, hotSeedPage)
	_, first := e.get(t, "/discussed")
	if pagerOf(first) != "" {
		t.Error("one page has a pager")
	}
	// a page past the end: the ranking's length from the first page (one
	// page), so the empty page is the last of 2
	_, later := e.get(t, "/discussed?offset=50")
	pg := pagerOf(later)
	if posOf(later) != `<span class="sr">page 2 of 2</span>` || !strings.Contains(pg, `<a href="/discussed" rel="prev" class="pg pg-a">`) ||
		linkOf(firstRe, later) != "/discussed" || !strings.Contains(pg, offNext) {
		t.Errorf("offset 50 pager:\n%s", pg)
	}
}

// currentOf is the page number the pager marks current (0 = none).
func currentOf(body string) int {
	m := currentRe.FindStringSubmatch(pagerOf(body))
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// numbersOf writes the pager's numbers as "1 2 … [7] 8 …" (the current
// page in brackets; the gaps narrow screens add left out).
func numbersOf(body string) string {
	pg := pagerOf(body)
	item := regexp.MustCompile(`<span class="pg-gap( [a-z-]+)?" aria-hidden="true">…</span>|<span class="pg pg-cur[^"]*" aria-current="page"><span aria-hidden="true">([0-9]+)</span>|<a href="[^"]+" class="pg[^"]*"><span aria-hidden="true">([0-9]+)</span>`)
	var out []string
	for _, m := range item.FindAllStringSubmatch(pg, -1) {
		switch {
		case m[2] != "":
			out = append(out, "["+m[2]+"]")
		case m[3] != "":
			out = append(out, m[3])
		case m[1] != " pg-n":
			out = append(out, "…")
		}
	}
	return strings.Join(out, " ")
}
