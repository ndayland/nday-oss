package webui_test

import (
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"nday.land/nday/internal/site/sitetest"
)

// walkBulk is how many extra rows the walk tests add: with the seed's own
// rows, about 12 pages of 50.
const walkBulk = 560

// catSeedWalk adds walkBulk dated disclosures (one an hour from mid-2023).
func catSeedWalk(t *testing.T, conn *pgx.Conn) {
	s := sitetest.Seeder{T: t, Conn: conn}
	for i := 0; i < walkBulk; i++ {
		c := "CVE-2023-" + strconv.Itoa(10000+i)
		s.Vuln(c, sitetest.P("walk "+c))
		at := sitetest.Day(2023, 6, 1).Add(time.Duration(i) * time.Hour)
		s.Event(sitetest.Ev{CVE: c, Type: "disclosed", Source: "cvelist", Occurred: &at, Detail: `{"state": "PUBLISHED"}`, Key: c})
	}
	s.Refresh()
}

// hotSeedWalk adds walkBulk patch releases over the last six days.
func hotSeedWalk(t *testing.T, conn *pgx.Conn) {
	s := sitetest.Seeder{T: t, Conn: conn}
	for i := 0; i < walkBulk; i++ {
		c := "CVE-2026-" + strconv.Itoa(40000+i)
		s.Vuln(c, sitetest.P("walk "+c))
		at := sitetest.Ago(0.01 * float64(i+1))
		s.Event(sitetest.Ev{CVE: c, Type: "patch_released", Source: "ghsa", Occurred: &at, Key: "GHSA-" + c})
	}
	s.Refresh()
}

// walked is one page of a walk: its URL and rows.
type walked struct {
	url  string
	rows string
}

// walkPager checks a list's numbers against a sequential walk: › from
// start to the end gives every page's rows; every number shown on any of
// those pages leads to a page that marks that number current and shows
// exactly the walk's rows for it; ‹ from the last page walks back through
// the same pages. It returns the walk.
func walkPager(t *testing.T, e *tenv, start string, minPages int) []walked {
	t.Helper()
	var pages []walked
	for u := start; u != ""; {
		resp, body := e.get(t, u)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", u, resp.StatusCode)
		}
		if c := currentOf(body); c != len(pages)+1 {
			t.Fatalf("%s: current page %d, want %d\n%s", u, c, len(pages)+1, pagerOf(body))
		}
		pages = append(pages, walked{u, joinIDs(rowIDs(body))})
		u = linkOf(catNextRe, body)
		if len(pages) > 40 {
			t.Fatal("pager does not end")
		}
	}
	if len(pages) < minPages {
		t.Fatalf("%s: %d pages, want at least %d", start, len(pages), minPages)
	}
	last := len(pages)
	seen := map[string]bool{}
	for i, p := range pages {
		_, body := e.get(t, p.url)
		links := numberRe.FindAllStringSubmatch(pagerOf(body), -1)
		if len(links) == 0 {
			t.Errorf("page %d: no numbers", i+1)
		}
		shown := map[int]bool{}
		for _, m := range links {
			href := html.UnescapeString(m[1])
			n, _ := strconv.Atoi(m[2])
			shown[n] = true
			if !strings.Contains(m[3], m[2]) || m[3] == m[2] { // "page 4", "第 4 页": the number in words

				t.Errorf("page %d: number %d named %q", i+1, n, m[3])
			}
			if n < 1 || n > last {
				t.Errorf("page %d links to page %d of %d", i+1, n, last)
				continue
			}
			if seen[href] {
				continue
			}
			seen[href] = true
			resp, got := e.get(t, href)
			if resp.StatusCode != 200 || currentOf(got) != n || joinIDs(rowIDs(got)) != pages[n-1].rows {
				t.Errorf("page %d: number %d (%s): %d, current %d, rows match %v", i+1, n, href, resp.StatusCode, currentOf(got),
					joinIDs(rowIDs(got)) == pages[n-1].rows)
			}
		}
		// the window: first two, last two, current ±1
		for _, n := range []int{1, 2, last - 1, last, i, i + 2} {
			if n >= 1 && n <= last && n != i+1 && !shown[n] {
				t.Errorf("page %d of %d: no number %d (%s)", i+1, last, n, numbersOf(body))
			}
		}
	}
	// back: ‹ from the last page goes through the same pages
	u, back := pages[last-1].url, last
	for u != "" {
		_, body := e.get(t, u)
		if got := joinIDs(rowIDs(body)); got != pages[back-1].rows || currentOf(body) != back {
			t.Fatalf("back at page %d (%s): rows match %v, current %d", back, u, got == pages[back-1].rows, currentOf(body))
		}
		u = linkOf(prevRe, body)
		back--
	}
	if back != 0 {
		t.Errorf("walking back ended at page %d", back+1)
	}
	return pages
}

// withQuery is path with the query parameter k set to v.
func withQuery(t *testing.T, path, k, v string) string {
	t.Helper()
	u, err := url.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set(k, v)
	u.RawQuery = q.Encode()
	return u.String()
}

func TestPagerNumberWalkCatalogue(t *testing.T) {
	e := newCatEnv(t, catSeedPage, catSeedWalk)
	for _, start := range []string{"/vuln?browse=1", "/vuln?year=2023", "/zh-hans/vuln?browse=1"} {
		pages := walkPager(t, e, start, 12)
		last := len(pages)
		// ?p= alone: past the end is the last page, the middle is out of
		// reach, garbage is page 1; an old cursor link still works
		for p, want := range map[string]int{"999999": last, "-3": 1, "abc": 1, "1": 1, strconv.Itoa(last - 2): last - 2, "3": 3} {
			resp, body := e.get(t, withQuery(t, start, "p", p))
			if resp.StatusCode != 200 || currentOf(body) != want || joinIDs(rowIDs(body)) != pages[want-1].rows {
				t.Errorf("%s ?p=%s: %d, current %d, want page %d", start, p, resp.StatusCode, currentOf(body), want)
			}
		}
		for _, p := range []string{"4", strconv.Itoa(last / 2), strconv.Itoa(last - 3)} {
			if resp, _ := e.get(t, withQuery(t, start, "p", p)); resp.StatusCode != 404 {
				t.Errorf("%s ?p=%s (the middle): %d", start, p, resp.StatusCode)
			}
		}
		// an old link: the walk's own cursor URL of page 7, and the same
		// cursor with a page number that does not fit (labels only)
		old := pages[6].url
		if !strings.Contains(old, "cursor=") {
			t.Fatalf("page 7 %q has no cursor", old)
		}
		for _, p := range []string{"7", "999999", ""} {
			u := withQuery(t, old, "p", p)
			resp, body := e.get(t, u)
			if resp.StatusCode != 200 || joinIDs(rowIDs(body)) != pages[6].rows {
				t.Errorf("old link %s: %d, rows differ", u, resp.StatusCode)
			}
		}
		// a numbered page names the first page as canonical, as a cursor page does
		_, firstPage := e.get(t, start)
		for _, u := range []string{withQuery(t, start, "p", strconv.Itoa(last)), withQuery(t, start, "p", "2"), pages[6].url} {
			_, body := e.get(t, u)
			if c := canonicalOf(body); c == "" || c != canonicalOf(firstPage) || strings.Contains(c, "p=") || strings.Contains(c, "cursor=") {
				t.Errorf("%s: canonical %q, first page's %q", u, c, canonicalOf(firstPage))
			}
		}
	}
}

func TestPagerNumberWalkHot(t *testing.T) {
	e := newCatEnv(t, hotSeedPage, hotSeedWalk)
	pages := walkPager(t, e, "/", 12)
	last := len(pages)
	for p, want := range map[string]int{"999999": last, "-1": 1, "2": 2, strconv.Itoa(last - 1): last - 1} {
		resp, body := e.get(t, "/?p="+p)
		if resp.StatusCode != 200 || currentOf(body) != want || joinIDs(rowIDs(body)) != pages[want-1].rows {
			t.Errorf("?p=%s: %d, current %d, want page %d", p, resp.StatusCode, currentOf(body), want)
		}
	}
	if resp, _ := e.get(t, "/?p=6"); resp.StatusCode != 404 {
		t.Errorf("?p=6 (the middle): %d", resp.StatusCode)
	}
	walkPager(t, e, "/?since=30d", 12)
}

var walkCanonRe = regexp.MustCompile(`<link rel="canonical" href="([^"]+)"`)

// canonicalOf is the page's canonical URL ("" none).
func canonicalOf(body string) string {
	if m := walkCanonRe.FindStringSubmatch(body); m != nil {
		return html.UnescapeString(m[1])
	}
	return ""
}
