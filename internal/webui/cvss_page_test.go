package webui_test

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// cvssBulk is how many CVEs with score 9.1 cvssSeedPage adds, so a score
// filter has more than one page (50 rows).
const cvssBulk = 55

// cvssSeedPage adds, on top of catSeedPage, vulnerabilities titled
// "cvsstest": CVE-2023-1000..1054 (score 9.1), CVE-2023-0001 (7.5),
// CVE-2023-0002 (5.0, from a GitHub advisory), CVE-2023-0003 (no score).
func cvssSeedPage(t *testing.T, conn *pgx.Conn) {
	catSeedPage(t, conn)
	s := sitetest.Seeder{T: t, Conn: conn}
	add := func(i int, id, typ, src, detail string) {
		s.Vuln(id, sitetest.P("cvsstest "+id))
		at := sitetest.Day(2023, 1, 1).Add(time.Duration(i) * time.Hour)
		s.Event(sitetest.Ev{CVE: id, Type: typ, Source: src, Occurred: &at, Detail: detail, Key: id})
	}
	for i := 0; i < cvssBulk; i++ {
		add(i, "CVE-2023-"+strconv.Itoa(1000+i), "disclosed", "cvelist", `{"cvss": {"base_score": 9.1}}`)
	}
	add(100, "CVE-2023-0001", "disclosed", "cvelist", `{"cvss": {"base_score": 7.5}}`)
	add(101, "CVE-2023-0002", "patch_released", "ghsa", `{"cvss": {"cvss_v3": {"score": 5.0, "vector_string": "CVSS:3.1/AV:N"}}}`)
	add(102, "CVE-2023-0003", "disclosed", "cvelist", `{}`)
	s.Refresh()
}

func TestCatalogueCVSS(t *testing.T) {
	e := newCatEnv(t, cvssSeedPage)
	for _, c := range []struct {
		path string
		p    site.CatalogueParams
		n    int // rows in all
	}{
		{"/vuln?cvss_min=9", site.CatalogueParams{CVSSMin: "9"}, cvssBulk + 2}, // + the fixture's two 9.8
		{"/vuln?cvss_min=9&year=2023", site.CatalogueParams{CVSSMin: "9", Year: 2023}, cvssBulk},
		{"/vuln?cvss_min=7&cvss_max=8.9", site.CatalogueParams{CVSSMin: "7", CVSSMax: "8.9"}, 1},
		{"/vuln?cvss_min=5.0&cvss_max=5.0", site.CatalogueParams{CVSSMin: "5", CVSSMax: "5"}, 1},
		{"/vuln?cvss_max=6.9&stage=patch", site.CatalogueParams{CVSSMax: "6.9", Stage: "patch"}, 1},
		{"/vuln?cvss_min=+9+&cvss_max=", site.CatalogueParams{CVSSMin: "9"}, cvssBulk + 2}, // trimmed; empty = no bound
		{"/vuln?cvss_min=9.9", site.CatalogueParams{CVSSMin: "9.9"}, 0},
	} {
		want := storeIDs(t, e.store, c.p)
		if len(want) != c.n {
			t.Fatalf("%s: the store lists %d rows, want %d", c.path, len(want), c.n)
		}
		got, pages := e.crawl(t, c.path)
		if joinIDs(got) != joinIDs(want) {
			t.Errorf("%s\n got %s\nwant %s", c.path, joinIDs(got), joinIDs(want))
		}
		if wp := (len(want)+49)/50 + map[bool]int{true: 1}[len(want) == 0]; pages != wp {
			t.Errorf("%s: %d pages, want %d", c.path, pages, wp)
		}
		for _, id := range got {
			if id == "CVE-2023-0003" {
				t.Errorf("%s: an unscored vulnerability is listed", c.path)
			}
		}
	}
	// the active band, links that keep the other filters, the summary, and
	// the forms that keep the filter
	_, body := e.get(t, "/vuln?year=2023&cvss_min=9.0&cvss_max=10")
	for _, want := range []string{
		`<span class="k">CVSS score</span>`,
		`<a href="/vuln?year=2023&amp;cvss_min=9&amp;cvss_max=10" aria-current="true">9–10</a>`,
		`<a href="/vuln?year=2023&amp;cvss_min=7&amp;cvss_max=8.9">7–8.9</a>`,
		`<a href="/vuln?year=2023&amp;cvss_min=0.1&amp;cvss_max=3.9">0.1–3.9</a>`,
		`<a href="/vuln?year=2023">all</a>`,                             // the score filter removed
		`<a href="/vuln?cvss_min=9&amp;cvss_max=10">all</a>`,            // the year removed, the score kept
		`<span class="sep" aria-hidden="true">·</span> CVSS score 9–10`, // the summary
		`<details class="flt" open="" data-keep="">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("filtered page missing %s", want)
		}
	}
	// the top bar's and the page's search forms and the year form keep it
	if n := strings.Count(body, `<input type="hidden" name="cvss_min" value="9"/>`); n != 3 {
		t.Errorf("hidden cvss_min: %d", n)
	}
	if n := strings.Count(body, `<input type="hidden" name="cvss_max" value="10"/>`); n != 3 {
		t.Errorf("hidden cvss_max: %d", n)
	}
	// a range that is not a band is shown as its own active entry
	_, body = e.get(t, "/vuln?cvss_min=5")
	if !strings.Contains(body, `<a href="/vuln?cvss_min=5" aria-current="true">≥ 5</a>`) ||
		strings.Count(body, `aria-current="true"`) != 4 { // stage "all", year "all", the score, the language
		t.Errorf("custom range: %d current", strings.Count(body, `aria-current="true"`))
	}
	_, body = e.get(t, "/vuln?cvss_min=9.8&cvss_max=9.8")
	if !strings.Contains(body, `aria-current="true">9.8</a>`) {
		t.Error("exact score entry")
	}
	// the unfiltered list offers the bands; the landing shows no filter
	_, body = e.get(t, "/vuln?browse=1")
	if !strings.Contains(body, `<a href="/vuln?cvss_min=9&amp;cvss_max=10">9–10</a>`) || strings.Contains(body, `name="cvss_min"`) {
		t.Error("unfiltered list")
	}
	_, body = e.get(t, "/vuln")
	if strings.Contains(body, "CVSS score") {
		t.Error("the landing shows the score filter")
	}
	// translated label
	_, body = e.get(t, "/zh-hans/vuln?cvss_min=9")
	if !strings.Contains(body, `<span class="k">CVSS 评分</span>`) {
		t.Error("zh-Hans label")
	}
}

func TestCatalogueCVSSBadParams(t *testing.T) {
	e := newCatEnv(t)
	for _, p := range []string{"/vuln?cvss_min=-1", "/vuln?cvss_min=11", "/vuln?cvss_max=10.5", "/vuln?cvss_min=abc",
		"/vuln?cvss_min=NaN", "/vuln?cvss_min=1e1", "/vuln?cvss_min=9,8", "/vuln?cvss_min=9.85", "/vuln?cvss_min=9&cvss_max=7",
		"/vuln?cvss_min=" + strings.Repeat("9", 500), "/zh-hans/vuln?cvss_max=x", "/vuln?q=cvsstest&cvss_min=x",
		"/vuln?q=cvsstest&cvss_min=8&cvss_max=2"} {
		resp, body := e.get(t, p)
		if resp.StatusCode != 400 || !strings.Contains(body, "<code>") || !strings.Contains(body, "cvss_m") {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

var searchRowRe = regexp.MustCompile(`<div class="tr" data-row="" data-id="([^"]+)"`)

func TestSearchPageCVSS(t *testing.T) {
	e := newCatEnv(t, cvssSeedPage)
	ids := func(body string) string {
		var out []string
		for _, m := range searchRowRe.FindAllStringSubmatch(body, -1) {
			out = append(out, m[1])
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	resp, body := e.get(t, "/vuln?q=cvsstest+CVE-2023-000&cvss_min=0")
	if resp.StatusCode != 200 || ids(body) != "CVE-2023-0001,CVE-2023-0002" {
		t.Errorf("%d %s", resp.StatusCode, ids(body))
	}
	_, body = e.get(t, "/vuln?q=cvsstest+CVE-2023-000")
	if ids(body) != "CVE-2023-0001,CVE-2023-0002,CVE-2023-0003" {
		t.Errorf("unfiltered: %s", ids(body))
	}
	_, body = e.get(t, "/vuln?q=cvsstest+CVE-2023-000&cvss_min=7&cvss_max=8.9")
	if ids(body) != "CVE-2023-0001" {
		t.Errorf("high: %s", ids(body))
	}
	for _, want := range []string{
		`<a href="/vuln?q=cvsstest&#43;CVE-2023-000&amp;cvss_min=7&amp;cvss_max=8.9" aria-current="true">7–8.9</a>`,
		`<a href="/vuln?q=cvsstest&#43;CVE-2023-000">all</a>`,
		`<input type="hidden" name="cvss_min" value="7"/>`, `<input type="hidden" name="cvss_max" value="8.9"/>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("search page missing %s", want)
		}
	}
	// tag links on a filtered search keep the score filter
	_, body = e.get(t, "/vuln?q=CVE-2026&cvss_min=7")
	n := 0
	for _, m := range regexp.MustCompile(`href="(/vuln\?[^"]*tag=[^"]*)"`).FindAllStringSubmatch(body, -1) {
		n++
		if !strings.Contains(m[1], "cvss_min=7") {
			t.Errorf("tag link without the score filter: %s", m[1])
		}
	}
	if n == 0 || ids(body) == "" {
		t.Errorf("no tag link on the filtered search (%d), rows %s", n, ids(body))
	}
}
