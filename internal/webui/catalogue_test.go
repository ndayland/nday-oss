package webui_test

import (
	"context"
	"html"
	"io"
	"log/slog"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/web/webtest"
	"nday.land/nday/internal/webui"
)

// catBulk is how many dated disclosure-only CVEs catSeedPage adds, so the
// catalogue has more than one page (50 rows).
const catBulk = 45

// catSeedPage adds, on top of sitetest.Seed, seedHostile and the tags:
//
//	CVE-2014-1000            disclosed 2014-04-07 (dated, an old year)
//	CVE-2014-0160            disclosed, unknown time   -> the undated tail
//	CVE-2014-0161            PoC, unknown time         -> the undated tail
//	CVE-2015-0001            KEV, unknown time         -> the undated tail
//	CVE-2024-2000..2044      disclosed, one hour apart in January 2024
func catSeedPage(t *testing.T, conn *pgx.Conn) {
	sitetest.SeedTags(t, conn)
	s := sitetest.Seeder{T: t, Conn: conn}
	s.Vuln("CVE-2014-1000", sitetest.P("old dated"))
	s.Event(sitetest.Ev{CVE: "CVE-2014-1000", Type: "disclosed", Source: "cvelist", Occurred: sitetest.P(sitetest.Day(2014, 4, 7)),
		Backfill: true, Detail: `{"state": "PUBLISHED"}`, Key: "CVE-2014-1000"})
	for _, u := range []struct{ cve, typ, src string }{
		{"CVE-2014-0160", "disclosed", "nvd"}, {"CVE-2014-0161", "poc_published", "exploitdb"}, {"CVE-2015-0001", "kev_added", "kev"},
	} {
		s.Vuln(u.cve, nil)
		s.Event(sitetest.Ev{CVE: u.cve, Type: u.typ, Source: u.src, Backfill: true, Key: u.cve})
	}
	for i := 0; i < catBulk; i++ {
		c := "CVE-2024-" + strconv.Itoa(2000+i)
		s.Vuln(c, sitetest.P("bulk "+c))
		at := sitetest.Day(2024, 1, 1).Add(time.Duration(i) * time.Hour)
		s.Event(sitetest.Ev{CVE: c, Type: "disclosed", Source: "cvelist", Occurred: &at, Detail: `{"state": "PUBLISHED"}`, Key: c})
	}
	s.Refresh()
}

// newCatEnv is newEnv with extra seeding before the server starts.
func newCatEnv(t *testing.T, extra ...func(*testing.T, *pgx.Conn)) *tenv {
	t.Helper()
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	seedHostile(t, d.Conn)
	for _, f := range extra {
		f(t, d.Conn)
	}
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 3})
	t.Cleanup(pool.Close)
	now := func() time.Time { return sitetest.Now }
	store := site.New(pool).WithClock(now)
	srv := web.New(web.Config{Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv.SetAPIAuth(webtest.BearerAuth{})
	ui, err := webui.New(srv, webui.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &tenv{ts: ts, ui: ui, store: store}
}

var (
	catRowRe  = regexp.MustCompile(`<div class="tr" role="row" data-row="" data-id="([^"]+)"`)
	catNextRe = regexp.MustCompile(`<a href="([^"]+)" rel="next"`)
)

// rowIDs are the data-id values of the page's list rows, in order.
func rowIDs(body string) []string {
	var out []string
	for _, m := range catRowRe.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// storeIDs is the catalogue order for p straight from the store (every page).
func storeIDs(t *testing.T, s *site.Store, p site.CatalogueParams) []string {
	t.Helper()
	p.Limit = site.MaxCatalogueLimit
	var out []string
	for {
		page, err := s.Catalogue(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Rows {
			out = append(out, r.CVEID)
		}
		if page.NextCursor == nil {
			return out
		}
		p.Cursor = *page.NextCursor
	}
}

// crawl follows the pager's "next" links from path and returns every row.
func (e *tenv) crawl(t *testing.T, path string) (ids []string, pages int) {
	t.Helper()
	for path != "" {
		resp, body := e.get(t, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		pages++
		ids = append(ids, rowIDs(body)...)
		path = ""
		if m := catNextRe.FindStringSubmatch(body); m != nil {
			path = html.UnescapeString(m[1])
		}
		if pages > 10 {
			t.Fatal("pager does not end")
		}
	}
	return ids, pages
}

func joinIDs(ids []string) string { return strings.Join(ids, ",") }

// /vuln is the catalogue: rows in the store's order (disclosure-only CVEs
// and the undated tail included), paged by cursor through every row once.
func TestCatalogueOrderAndPaging(t *testing.T) {
	e := newCatEnv(t, catSeedPage)
	want := storeIDs(t, e.store, site.CatalogueParams{})
	if len(want) <= 50 {
		t.Fatalf("fixture too small: %d rows", len(want))
	}
	resp, body := e.get(t, "/vuln?browse=1")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := rowIDs(body); joinIDs(got) != joinIDs(want[:50]) {
		t.Errorf("first page\n got %s\nwant %s", joinIDs(got), joinIDs(want[:50]))
	}
	for _, id := range []string{"CVE-2026-1004", "CVE-2024-2044"} { // disclosure-only, absent from the hot list
		if !strings.Contains(body, `data-id="`+id+`"`) {
			t.Errorf("disclosure-only %s missing", id)
		}
	}
	if strings.Contains(body, `data-id="CVE-2026-1010"`) || strings.Contains(body, `data-id="CVE-2026-1005"`) {
		t.Error("a CVE without events or a rejected one is listed")
	}
	if !strings.Contains(body, `<nav class="pager" aria-label="Pages">`) || !strings.Contains(body, `<span class="pg pg-a" aria-disabled="true"><span aria-hidden="true">‹</span>`) ||
		strings.Contains(body, `rel="prev"`) {
		t.Error("first page pager")
	}
	got, pages := e.crawl(t, "/vuln?browse=1")
	if pages != 2 || joinIDs(got) != joinIDs(want) {
		t.Errorf("crawl: %d pages\n got %s\nwant %s", pages, joinIDs(got), joinIDs(want))
	}
	seen := map[string]bool{}
	for _, id := range got {
		if seen[id] {
			t.Errorf("duplicate row %s", id)
		}
		seen[id] = true
	}
	// the second page: back to the first page, no next link, the end said,
	// canonical = the first page, still indexable (as the hot list's cursor pages)
	_, first := e.get(t, "/vuln?browse=1")
	next := html.UnescapeString(catNextRe.FindStringSubmatch(first)[1])
	if !strings.HasPrefix(next, "/vuln?cursor=") {
		t.Errorf("next link %s", next)
	}
	resp, body = e.get(t, next)
	if !strings.Contains(body, `<a href="/vuln?browse=1" class="pg"><span aria-hidden="true">1</span>`) || catNextRe.MatchString(body) ||
		!strings.Contains(body, `<span class="pg pg-a" aria-disabled="true"><span aria-hidden="true">›</span>`) {
		t.Error("last page pager")
	}
	if !strings.Contains(body, `<link rel="canonical" href="https://nday.land/vuln?browse=1"/>`) || resp.Header.Get("X-Robots-Tag") != "" ||
		strings.Contains(body, `name="robots"`) {
		t.Error("cursor page canonical/robots")
	}
	// paging a filtered list keeps the filter in every link
	got, _ = e.crawl(t, "/vuln?stage=disclosed")
	if w := storeIDs(t, e.store, site.CatalogueParams{Stage: "disclosed"}); joinIDs(got) != joinIDs(w) {
		t.Errorf("filtered crawl\n got %s\nwant %s", joinIDs(got), joinIDs(w))
	}
}

// Every filter alone and combined gives the store's rows, marks the active
// value and keeps the other filters in its links.
func TestCatalogueFilters(t *testing.T) {
	e := newCatEnv(t, catSeedPage)
	for _, c := range []struct {
		path string
		p    site.CatalogueParams
	}{
		{"/vuln?stage=kev", site.CatalogueParams{Stage: "kev"}},
		{"/vuln?stage=DIS", site.CatalogueParams{Stage: "disclosed"}},
		{"/vuln?year=2014", site.CatalogueParams{Year: 2014}},
		{"/vuln?tag=network", site.CatalogueParams{Tags: []string{"network"}}},
		{"/vuln?include_rejected=1", site.CatalogueParams{IncludeRejected: true}},
		{"/vuln?stage=poc&year=2014", site.CatalogueParams{Stage: "poc", Year: 2014}},
		{"/vuln?year=2026&tag=network&include_rejected=1", site.CatalogueParams{Year: 2026, Tags: []string{"network"}, IncludeRejected: true}},
		{"/vuln?stage=kev&year=2026&tag=network", site.CatalogueParams{Stage: "kev", Year: 2026, Tags: []string{"network"}}},
		{"/vuln?year=&stage=&tag=nope&browse=1", site.CatalogueParams{}}, // empty values and unknown tags are ignored
	} {
		resp, body := e.get(t, c.path)
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d", c.path, resp.StatusCode)
			continue
		}
		want := storeIDs(t, e.store, c.p)
		if len(want) > 50 {
			want = want[:50]
		}
		if got := rowIDs(body); joinIDs(got) != joinIDs(want) {
			t.Errorf("%s\n got %s\nwant %s", c.path, joinIDs(got), joinIDs(want))
		}
		if len(want) == 0 && !strings.Contains(body, "No vulnerability matches these filters.") {
			t.Errorf("%s: empty state", c.path)
		}
	}
	// active states and links that keep the other filters
	_, body := e.get(t, "/vuln?stage=kev&year=2026&tag=network&include_rejected=1")
	for _, want := range []string{
		`<a class="st-kev" href="/vuln?stage=kev&amp;year=2026&amp;include_rejected=1&amp;tag=network" aria-current="true"><span class="nm">KEV</span>`,
		`<a class="" href="/vuln?year=2026&amp;include_rejected=1&amp;tag=network"><span class="nm">all</span>`,
		`<a href="/vuln?stage=kev&amp;year=2026&amp;include_rejected=1&amp;tag=network" aria-current="true">2026</a>`,
		`<a href="/vuln?stage=kev&amp;include_rejected=1&amp;tag=network">all</a>`,
		`<a href="/vuln?stage=kev&amp;year=2025&amp;include_rejected=1&amp;tag=network">2025</a>`,
		`<a class="chk" href="/vuln?stage=kev&amp;year=2026&amp;tag=network" aria-current="true">`,
		`<a class="tx" href="/vuln?stage=kev&amp;year=2026&amp;include_rejected=1"`,
		`<input type="hidden" name="stage" value="kev"/>`, `<input type="hidden" name="include_rejected" value="1"/>`,
		`<input type="hidden" name="tag" value="network"/>`,
		`<details class="flt" open="" data-keep="">`,
		`<span class="k">Filters</span> <span class="sep" aria-hidden="true">·</span> 2026 <span class="sep" aria-hidden="true">·</span> Include rejected IDs <span class="sep" aria-hidden="true">·</span> network</summary>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("filtered page missing %s", want)
		}
	}
	if strings.Count(body, `aria-current="true"`) != 5 { // stage, year, score ("all"), rejected, the language
		t.Errorf("aria-current count %d", strings.Count(body, `aria-current="true"`))
	}
	// the unfiltered page: "all" is current, the filters start open (closed on phones by app.js)
	_, body = e.get(t, "/vuln?browse=1")
	for _, want := range []string{`<a class="" href="/vuln?browse=1" aria-current="true"><span class="nm">all</span>`,
		`<a href="/vuln?browse=1" aria-current="true">all</a>`, `<details class="flt" open="">`, `<option value="">—</option>`} {
		if !strings.Contains(body, want) {
			t.Errorf("unfiltered page missing %s", want)
		}
	}
	// a stage filter alone does not keep the filters open on phones
	if _, body = e.get(t, "/vuln?stage=poc"); !strings.Contains(body, `<details class="flt" open="">`) {
		t.Error("stage filter opened the filters")
	}
	// a row's tag chip adds its tag to the filter
	if _, body = e.get(t, "/vuln?stage=kev"); !strings.Contains(body, `href="/vuln?stage=kev&amp;tag=`) {
		t.Error("row chips do not add to the catalogue filter")
	}
}

// The stage row: whole-database totals from the stats, links for stages
// with vulnerabilities, a dimmed non-link for empty ones.
func TestCatalogueStageRow(t *testing.T) {
	e := newCatEnv(t, catSeedPage)
	st, err := e.store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, body := e.get(t, "/vuln?browse=1")
	row := section(body, `<nav class="cstages" aria-label="Current stage, all CVEs">`, `</nav>`)
	if row == "" {
		t.Fatal("no stage row")
	}
	if !strings.Contains(row, `<span class="n">`+strconv.FormatInt(st.WithEvents, 10)+`</span>`) {
		t.Errorf("all total\n%s", row)
	}
	zeros := 0
	for _, c := range st.ByStage {
		cls := "st-" + strings.ToLower(c.Code)
		n := strconv.FormatInt(c.Count, 10)
		if c.Count == 0 {
			zeros++
			if !regexp.MustCompile(`<span class="` + cls + ` zero"><span class="nm">[^<]+</span> <span class="n">0</span></span>`).MatchString(row) {
				t.Errorf("%s: zero stage\n%s", c.Code, row)
			}
			continue
		}
		if !regexp.MustCompile(`<a class="` + cls + `" href="/vuln\?stage=` + site.StageInfos[stageRank(c.Code)].Alias +
			`"><span class="nm">[^<]+</span> <span class="n">` + n + `</span></a>`).MatchString(row) {
			t.Errorf("%s: stage link with %s\n%s", c.Code, n, row)
		}
	}
	if zeros == 0 {
		t.Log("the fixture has no empty stage")
	}
	// an empty stage selected by URL is current, still not a link
	if zeros > 0 {
		for _, c := range st.ByStage {
			if c.Count == 0 {
				_, b := e.get(t, "/vuln?stage="+c.Code)
				if !strings.Contains(b, `zero" aria-current="true">`) || !strings.Contains(b, "No vulnerability matches these filters.") ||
					!strings.Contains(b, `<a href="/vuln?browse=1">Clear filters</a>`) {
					t.Errorf("%s selected: empty stage", c.Code)
				}
				break
			}
		}
	}
}

func stageRank(code string) int {
	for i, s := range site.StageInfos {
		if s.Code == code {
			return i
		}
	}
	return -1
}

// The year filter: links for "all", the current year and the five before
// it; the select holds every other accepted year, so together they cover
// MinCatalogueYear..MaxCatalogueYear(). The form works without script.
func TestCatalogueYears(t *testing.T) {
	e := newCatEnv(t)
	_, body := e.get(t, "/vuln?year=2003&stage=poc")
	cur := sitetest.Now.Year()
	seg := section(body, `<div class="flag cyear">`, `</form>`)
	years := map[int]int{}
	for _, m := range regexp.MustCompile(`>(\d{4})</a>`).FindAllStringSubmatch(seg, -1) {
		y, _ := strconv.Atoi(m[1])
		years[y]++
		if y > cur || y < cur-5 {
			t.Errorf("quick link for %d", y)
		}
	}
	if len(years) != 6 {
		t.Errorf("quick links %v", years)
	}
	opts := regexp.MustCompile(`<option value="(\d{4})"( selected="")?>`).FindAllStringSubmatch(seg, -1)
	for _, m := range opts {
		y, _ := strconv.Atoi(m[1])
		years[y]++
		if (m[2] != "") != (y == 2003) {
			t.Errorf("option %d selected=%q", y, m[2])
		}
	}
	for y := site.MinCatalogueYear; y <= site.MaxCatalogueYear(); y++ {
		if years[y] != 1 {
			t.Errorf("year %d offered %d times", y, years[y])
		}
	}
	if len(years) != site.MaxCatalogueYear()-site.MinCatalogueYear+1 {
		t.Errorf("years offered outside the range: %d", len(years))
	}
	for _, want := range []string{`<form class="cyf" action="/vuln" method="get">`, `<label for="cat-y">other years</label>`,
		`<select id="cat-y" name="year">`, `<input type="hidden" name="stage" value="poc"/>`, `<button type="submit" class="btn">Go</button>`} {
		if !strings.Contains(seg, want) {
			t.Errorf("year form missing %s", want)
		}
	}
	// the select's submission is an ordinary catalogue URL
	if resp, _ := e.get(t, "/vuln?year=1999&stage=poc"); resp.StatusCode != 200 {
		t.Errorf("year form target %d", resp.StatusCode)
	}
}

// Rows whose change time is unknown come last under one "time unknown"
// header; their change cell says the time is unknown instead of "+".
func TestCatalogueUndatedTail(t *testing.T) {
	e := newCatEnv(t, catSeedPage)
	ids, _ := e.crawl(t, "/vuln?year=2014") // 2014-1000 dated, then 0161 (POC) and 0160 (DIS) undated
	if joinIDs(ids) != "CVE-2014-1000,CVE-2014-0161,CVE-2014-0160" {
		t.Fatalf("rows %v", ids)
	}
	_, body := e.get(t, "/vuln?year=2014")
	hd := `<div class="dgroup nodate" role="row"><span role="cell"><span class="dgh" role="heading" aria-level="2"><span aria-hidden="true">## </span>time unknown</span></span></div>`
	if strings.Count(body, hd) != 1 || strings.Count(body, `class="dgroup`) != 2 {
		t.Errorf("group headers: %d unknown, %d in all", strings.Count(body, hd), strings.Count(body, `class="dgroup`))
	}
	i, j := strings.Index(body, hd), strings.Index(body, `data-id="CVE-2014-0161"`)
	if i < 0 || j < i || strings.Index(body, `data-id="CVE-2014-1000"`) > i {
		t.Error("the unknown-time header is not between the dated and the undated rows")
	}
	row := body[j:]
	row = row[:strings.Index(row, `<div class="vul"`)]
	if !strings.Contains(row, `<div class="chg" role="cell"><span class="c "></span><span class="t">time unknown <span></span></span></div>`) {
		t.Errorf("undated change cell\n%s", row)
	}
	// the tail on a page of its own still gets its header
	_, body = e.get(t, "/zh-hans/vuln?year=2014&stage=poc")
	if !strings.Contains(body, `<span aria-hidden="true">## </span>时间未知</span>`) {
		t.Error("zh unknown-time header")
	}
}

// /vuln?q= stays the search page; an empty q is the catalogue; tags alone
// are the catalogue filtered by them (no longer a search: paged, rejected
// CVEs and CVEs without events left out, the catalogue's order).
func TestCatalogueAndSearchURLs(t *testing.T) {
	e := newCatEnv(t, catSeedPage)
	_, body := e.get(t, "/vuln?q=tie")
	if !strings.Contains(body, `<div class="tbl list">`) || strings.Contains(body, `class="csearch"`) ||
		!strings.Contains(body, "<title>tie · search · nday</title>") {
		t.Error("search page")
	}
	for _, p := range []string{"/vuln?q=", "/vuln?q=+", "/vuln"} {
		if _, body = e.get(t, p); !strings.Contains(body, `<form class="csearch" action="/vuln" method="get" role="search">`) {
			t.Errorf("%s: not the catalogue", p)
		}
	}
	if resp := e.noRedirect(t, "/vuln?q="+sitetest.GPU); resp.StatusCode != 302 {
		t.Errorf("full id %d", resp.StatusCode)
	}
	_, body = e.get(t, "/vuln?tag=network")
	want := storeIDs(t, e.store, site.CatalogueParams{Tags: []string{"network"}})
	if got := rowIDs(body); joinIDs(got) != joinIDs(want) || len(want) == 0 {
		t.Errorf("tag only\n got %v\nwant %v", got, want)
	}
	if !strings.Contains(body, `<span class="tfc">`) || !strings.Contains(body, `<a class="tx" href="/vuln?browse=1"`) ||
		!strings.Contains(body, "<title>Vulnerabilities · nday</title>") {
		t.Error("tag only: chips")
	}
	// the search boxes keep the tag filter (as the tag search did)
	if strings.Count(body, `<input type="hidden" name="tag" value="network"/>`) != 3 { // header, catalogue box, year form
		t.Errorf("hidden tag inputs %d", strings.Count(body, `<input type="hidden" name="tag" value="network"/>`))
	}
}

// Headers as on the hot list; a filtered catalogue is noindex.
func TestCatalogueHeaders(t *testing.T) {
	e := newCatEnv(t)
	resp, body := e.get(t, "/vuln?browse=1")
	if resp.Header.Get("Cache-Control") != "public, max-age=60" || resp.Header.Get("ETag") == "" ||
		resp.Header.Get("X-Robots-Tag") != "" || strings.Contains(body, `name="robots"`) {
		t.Errorf("headers %v", resp.Header)
	}
	if !strings.Contains(body, `<link rel="canonical" href="https://nday.land/vuln?browse=1"/>`) {
		t.Error("canonical")
	}
	if r2, _ := e.get(t, "/vuln?browse=1", "If-None-Match", resp.Header.Get("ETag")); r2.StatusCode != 304 {
		t.Errorf("revalidation %d", r2.StatusCode)
	}
	resp, body = e.get(t, "/vuln?stage=kev&utm_source=x")
	if resp.Header.Get("X-Robots-Tag") != "noindex" || !strings.Contains(body, `<meta name="robots" content="noindex"/>`) ||
		!strings.Contains(body, `<link rel="canonical" href="https://nday.land/vuln?stage=kev"/>`) ||
		resp.Header.Get("Cache-Control") != "public, max-age=60" {
		t.Errorf("filtered headers %v", resp.Header)
	}
	// one h1, the skip link's target, the nav item current, j/k rows
	if strings.Count(body, "<h1") != 1 || !strings.Contains(body, `<main class="main cat" id="main">`) ||
		!strings.Contains(body, `<a href="/vuln" aria-current="page">`) || !strings.Contains(body, `data-autosel=""`) ||
		strings.Contains(body, "data-raw") || strings.Contains(body, "/api/vulns") {
		t.Error("page structure")
	}
}

// Bad filter values are the 400 page, as on the hot list.
func TestCatalogueBadParams(t *testing.T) {
	e := newCatEnv(t)
	for _, p := range []string{"/vuln?stage=bogus", "/vuln?year=abc", "/vuln?year=1998", "/vuln?year=0",
		"/vuln?year=" + strconv.Itoa(site.MaxCatalogueYear()+1), "/vuln?include_rejected=maybe", "/vuln?cursor=garbage",
		"/vuln?cursor=" + strings.Repeat("A", 200), "/zh-hans/vuln?stage=x"} {
		resp, body := e.get(t, p)
		if resp.StatusCode != 400 || !strings.Contains(body, "<code>") {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := e.get(t, "/vuln?stage=+kev+&year=+2026"); resp.StatusCode != 200 {
		t.Errorf("spaces %d", resp.StatusCode)
	}
}

// The page's words: zh-Hans, and no trace of the old search help.
func TestCatalogueText(t *testing.T) {
	e := newCatEnv(t)
	_, body := e.get(t, "/zh-hans/vuln?browse=1")
	for _, want := range []string{"<title>漏洞 · nday</title>", `<span class="h" aria-hidden="true"># </span>漏洞</h1>`,
		`<span class="k">编号年份</span>`, `<label for="cat-y">其他年份</label>`, ">查看</button>", `<span class="nm">全部</span>`,
		`<span class="nm">补丁</span>`, `aria-label="全库当前阶段"`, `例：<a href="/zh-hans/vuln?q=barracuda">barracuda</a> · `,
		`placeholder="CVE-2026-… 产品 厂商"`, `<a href="/zh-hans/vuln" aria-current="page">`} {
		if !strings.Contains(body, want) {
			t.Errorf("zh-Hans missing %s", want)
		}
	}
	for _, l := range e.ui.Locales().Enabled {
		_, body := e.get(t, l.Path("/vuln"))
		for _, old := range []string{"You can search for", "可以搜索", "prose-block", "GHSA ID", "case-insensitive", "不区分大小写"} {
			if strings.Contains(body, old) {
				t.Errorf("%s: old search help %q", l.Tag, old)
			}
		}
		if !strings.Contains(body, `GHSA-gj9m-f8ph-pmhr</a>`) || !strings.Contains(body, `<input id="cat-q" type="search" name="q"`) {
			t.Errorf("%s: search box or examples", l.Tag)
		}
	}
}

// Signed out, the catalogue shows what hot rows show (the researcher
// count), never a post's text, id, URL or author (nonpublic_test.go's
// markers and posts).
func TestCatalogueNoPostData(t *testing.T) {
	e := newCatEnv(t, func(t *testing.T, conn *pgx.Conn) {
		sitetest.SeedTags(t, conn)
		for _, cve := range []string{postCVE, stubA, stubB} {
			sitetest.Seeder{T: t, Conn: conn}.Vuln(cve, nil)
		}
		seedPosts(t, conn)
	})
	seenGPU := false
	for _, l := range e.ui.Locales().Enabled {
		for _, p := range []string{"/vuln", "/vuln?browse=1", "/vuln?stage=kev", "/vuln?year=2026&include_rejected=1", "/vuln?tag=network",
			"/vuln?q=", "/vuln?tag=nope"} {
			resp, body := e.get(t, l.Path(p))
			if resp.StatusCode != 200 {
				t.Errorf("%s: %d", l.Path(p), resp.StatusCode)
			}
			for _, m := range postMarkers {
				if strings.Contains(strings.ToLower(body), strings.ToLower(m)) {
					t.Errorf("%s contains %q", l.Path(p), m)
				}
			}
			if strings.Contains(body, "x.com/") || strings.Contains(body, "t.co/") {
				t.Errorf("%s: a post link", l.Path(p))
			}
			if strings.Contains(body, `data-id="`+sitetest.GPU+`"`) && strings.Contains(body, `<span class="tag rsch-b"`) {
				seenGPU = true
			}
		}
	}
	if !seenGPU {
		t.Error("the researcher count (a public aggregate) is not shown")
	}
}

// With an API host too, the catalogue shows no API command or raw link
// (the API reference is on the account page).
func TestCatalogueTwoHosts(t *testing.T) {
	e := newEnvFull(t, web.Config{PublicURL: "https://www.nday.land", APIURL: "https://api.nday.land"}, webui.Options{})
	_, body := e.get(t, "/vuln?stage=poc&tag=network")
	for _, bad := range []string{"curl ", "data-raw", "api.nday.land"} {
		if strings.Contains(body, bad) {
			t.Errorf("contains %s", bad)
		}
	}
}
