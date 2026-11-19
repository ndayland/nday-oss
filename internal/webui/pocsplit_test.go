package webui_test

import (
	"context"
	"encoding/json"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
)

// splitCVE is disclosed only (Ago(0.5): 2026-11-12 13:00 UTC), no PoC.
const splitCVE = "CVE-2026-1004"

// splitRepo is one github_repo row named after splitCVE (full name
// "q/<name>").
type splitRepo struct {
	gh               int
	name, status, by string
	stars            int
	created          string
}

func seedSplitRepos(rows []splitRepo) func(*testing.T, *pgx.Conn) {
	return func(t *testing.T, conn *pgx.Conn) {
		ctx := context.Background()
		for _, r := range rows {
			var by any
			if r.by != "" {
				by = r.by
			}
			if _, err := conn.Exec(ctx, `INSERT INTO github_repo (github_id, queued_name, full_name, owner_login, owner_type, stars, repo_created_at,
                state, first_source, status, status_by, status_at, seen_at)
VALUES ($1, lower($2), $2, 'q', 'User', $3, $4::timestamptz, 'ok', 'search', $5, $6, CASE WHEN $6::text IS NULL THEN NULL ELSE now() END, '2026-11-12')`,
				r.gh, "q/"+r.name, r.stars, r.created, r.status, by); err != nil {
				t.Fatal(err)
			}
		}
		for _, q := range []string{
			`INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo WHERE queued_name LIKE 'q/%'`,
			// each statement commits: the deferred PoC triggers write the github events
			`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, '` + splitCVE + `', 'name' FROM github_repo WHERE queued_name LIKE 'q/%'`,
		} {
			if _, err := conn.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		sitetest.Seeder{T: t, Conn: conn}.Refresh()
	}
}

var (
	splitLiRe  = regexp.MustCompile(`<li><a href="https://github\.com/q/([a-z]+-\d\d)"`)
	splitSumRe = regexp.MustCompile(`<details class="rsrc-u"( open="")?>\n<summary class="rsrc-k">([^<]*)</summary>`)
	splitResRe = regexp.MustCompile(`(?s)<section class="panel rsrc" id="resources".*?</section>`)
)

func splitNames(region string) []string {
	var out []string
	for _, m := range splitLiRe.FindAllStringSubmatch(region, -1) {
		out = append(out, m[1])
	}
	return out
}

func splitStage(t *testing.T, e *tenv) string {
	t.Helper()
	_, body := e.get(t, "/api/vuln/"+splitCVE)
	var v struct {
		Stage string `json:"stage"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return v.Stage
}

// beforeResources is the page up to the resources panel (the chart and its
// popovers included).
func beforeResources(body string) string {
	if i := strings.Index(body, `id="resources"`); i >= 0 {
		return body[:i]
	}
	return body
}

// TestPoCSplitOnlyUnreviewed: a disclosed vulnerability whose repositories
// all do not count (unverified, or rule-trusted but created long before the
// disclosure) shows no "PoC / exploit code" heading, a collapsed group with
// their number, no PoC dot on the chart, and its stage stays disclosed. A
// rejected repository is not shown anywhere. Every locale renders the
// heading; signed out, nothing tells why a repository is (not) trusted.
func TestPoCSplitOnlyUnreviewed(t *testing.T) {
	e := newEnvSeeded(t, seedSplitRepos([]splitRepo{
		{gh: 5001, name: "unrev-01", status: "unverified", stars: 40, created: "2026-11-12 18:00:00+00"},
		{gh: 5002, name: "unrev-02", status: "unverified", stars: 900, created: "2026-11-12 19:00:00+00"},
		{gh: 5003, name: "unrev-03", status: "unverified", stars: 1, created: "2026-11-12 20:00:00+00"},
		{gh: 5004, name: "aged-04", status: "trusted", by: "rule", stars: 70, created: "2026-01-01 00:00:00+00"},
		{gh: 5005, name: "rejected-05", status: "rejected", by: "admin", stars: 999, created: "2026-11-12 18:00:00+00"},
	}))
	if s := splitStage(t, e); s != "disclosed" {
		t.Errorf("stage %q, want disclosed", s)
	}
	_, body := e.get(t, "/vuln/"+splitCVE, "Authorization", "")
	res := splitResRe.FindString(body)
	if strings.Contains(body, `>PoC / exploit code</h3>`) || strings.Contains(body, `id="r-poc"`) {
		t.Errorf("an empty PoC group is rendered:\n%s", res)
	}
	m := splitSumRe.FindStringSubmatch(res)
	if m == nil || m[1] != "" || m[2] != "Unreviewed repositories (4)" {
		t.Errorf("unreviewed group %q:\n%s", m, res)
	}
	got := strings.Join(splitNames(regionOf(body, "r-pocu")), " ")
	if got != "aged-04 unrev-02 unrev-01 unrev-03" { // min(stars, 50) desc, then oldest first
		t.Errorf("unreviewed rows %q", got)
	}
	if strings.Contains(body, "rejected-05") {
		t.Error("a rejected repository is shown")
	}
	if pre := beforeResources(body); strings.Contains(pre, `d-poc`) || strings.Contains(pre, "q/unrev") || strings.Contains(pre, "aged-04") {
		t.Error("the chart draws a repository that does not count")
	}
	for _, w := range []string{"★", "unverified", "trusted", "admin", "rule"} {
		if strings.Contains(res, w) {
			t.Errorf("resources panel shows %q:\n%s", w, res)
		}
	}
	// every locale has the heading
	for loc, want := range map[string]string{"": "Unreviewed repositories (4)", "/zh-Hans": "未审核的仓库（4）", "/zh-Hant": "未審核的儲存庫（4）",
		"/ja": "未審査のリポジトリ（4）", "/ko": "검토되지 않은 저장소 (4)", "/es": "Repositorios sin revisar (4)", "/fr": "Dépôts non examinés (4)"} {
		_, b := e.get(t, loc+"/vuln/"+splitCVE)
		if m := splitSumRe.FindStringSubmatch(b); m == nil || html.UnescapeString(m[2]) != want {
			t.Errorf("%s: heading %q, want %q", loc, m, want)
		}
	}
}

// TestPoCSplitMixed: 12 repositories that count (admin-trusted, and one
// trusted by the post rule created after the disclosure) and 12 that do
// not (unverified, and one rule-trusted but created long before): both
// groups, each paged on its own (10 + 2), the unreviewed one open when its
// page parameter is there; the stage moves to PoC; only the counted ones
// are drawn; counted repositories look alike whoever trusted them.
func TestPoCSplitMixed(t *testing.T) {
	var rows []splitRepo
	for i := 1; i <= 11; i++ {
		rows = append(rows, splitRepo{gh: 6000 + i, name: "counted-" + two(i), status: "trusted", by: "admin", stars: 300 - i*10, created: "2026-11-12 20:00:00+00"})
		rows = append(rows, splitRepo{gh: 7000 + i, name: "unrev-" + two(i), status: "unverified", stars: 50, created: "2026-11-12 " + two(i) + ":00:00+00"})
	}
	rows = append(rows,
		splitRepo{gh: 6012, name: "counted-12", status: "trusted", by: "rule", stars: 5, created: "2026-11-12 21:00:00+00"},
		splitRepo{gh: 7012, name: "unrev-12", status: "trusted", by: "rule", stars: 1, created: "2026-01-01 00:00:00+00"},
		splitRepo{gh: 8000, name: "rejected-00", status: "rejected", by: "admin", stars: 999, created: "2026-11-12 20:00:00+00"})
	e := newEnvSeeded(t, seedSplitRepos(rows))
	if s := splitStage(t, e); s != "poc_published" {
		t.Errorf("stage %q, want poc_published", s)
	}
	path := "/vuln/" + splitCVE
	get := func(q string) string {
		t.Helper()
		resp, b := e.get(t, path+q, "Authorization", "")
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", q, resp.StatusCode)
		}
		return b
	}
	names := func(from, to int, prefix string) string {
		var out []string
		for i := from; i <= to; i++ {
			out = append(out, prefix+two(i))
		}
		return strings.Join(out, " ")
	}
	// unreviewed: min(stars, 50) desc, oldest first: unrev-01..11 (50), then unrev-12 (1)
	for _, c := range []struct {
		q, poc, unrev string
		open          bool
	}{
		{"", names(1, 10, "counted-"), names(1, 10, "unrev-"), false},
		{"?pocp=2", names(11, 12, "counted-"), names(1, 10, "unrev-"), false},
		{"?pocu=2", names(1, 10, "counted-"), names(11, 12, "unrev-"), true},
		{"?pocu=1", names(1, 10, "counted-"), names(1, 10, "unrev-"), true},
		{"?pocp=2&pocu=2", names(11, 12, "counted-"), names(11, 12, "unrev-"), true},
	} {
		b := get(c.q)
		if got := strings.Join(splitNames(regionOf(b, "r-poc")), " "); got != c.poc {
			t.Errorf("%s: PoC group %q, want %q", c.q, got, c.poc)
		}
		if got := strings.Join(splitNames(regionOf(b, "r-pocu")), " "); got != c.unrev {
			t.Errorf("%s: unreviewed group %q, want %q", c.q, got, c.unrev)
		}
		m := splitSumRe.FindStringSubmatch(b)
		if m == nil || (m[1] != "") != c.open || m[2] != "Unreviewed repositories (12)" {
			t.Errorf("%s: details %q", c.q, m)
		}
		if strings.Contains(b, "rejected-00") {
			t.Errorf("%s: a rejected repository is shown", c.q)
		}
		// both regions are paged, each with its own pager
		if n := strings.Count(b, `data-page-region="`); n != 2 || !strings.Contains(regionOf(b, "r-poc"), `class="pager"`) ||
			!strings.Contains(regionOf(b, "r-pocu"), `class="pager"`) {
			t.Errorf("%s: %d regions", c.q, n)
		}
	}
	one := get("")
	// pager links: the PoC list's from page 2, the unreviewed list's on
	// every page (so it opens again without script), each keeping the other
	if m := pocNextRe.FindStringSubmatch(regionOf(one, "r-pocu")); m == nil || html.UnescapeString(m[1]) != path+"?pocu=2#r-pocu" {
		t.Errorf("unreviewed next %v", m)
	}
	if m := pocNextRe.FindStringSubmatch(regionOf(get("?pocu=2"), "r-poc")); m == nil || html.UnescapeString(m[1]) != path+"?pocp=2&pocu=2#r-poc" {
		t.Errorf("PoC next keeps pocu: %v", m)
	}
	p2 := get("?pocu=2")
	if !strings.Contains(regionOf(p2, "r-pocu"), `href="`+path+`?pocu=1#r-pocu"`) {
		t.Errorf("unreviewed page 2 lacks its page 1 link:\n%s", regionOf(p2, "r-pocu"))
	}
	// counted ones show stars, whoever trusted them; the others none
	res := splitResRe.FindString(one)
	if !strings.Contains(regionOf(get("?pocp=2"), "r-poc"), `q/counted-12</a> <span class="rsrc-host">★ 5</span>`) ||
		strings.Contains(regionOf(one, "r-pocu"), "★") || strings.Contains(res, "unverified") || strings.Contains(res, "rule") {
		t.Errorf("rows:\n%s", res)
	}
	// the heading of the first group keeps its look; the PoC region comes first
	if i, j := strings.Index(res, `<h3 class="rsrc-k k-poc">PoC / exploit code</h3>`), strings.Index(res, `<details class="rsrc-u"`); i < 0 || j < i {
		t.Errorf("group order:\n%s", res)
	}
	// the chart: the counted ones only
	pre := beforeResources(one)
	if !strings.Contains(pre, `d-poc`) || !strings.Contains(pre, "q/counted-12") || strings.Contains(pre, "q/unrev-") {
		t.Error("the chart does not draw exactly the counted repositories")
	}
	// outside the two regions, the PoC pages are the same page
	// (the other region's pager links carry pocp: app.js takes them from
	// the loaded page)
	outside := func(b string) string {
		return strings.Replace(outsideRegion(b, "r-poc"), regionOf(b, "r-pocu"), "REGION2", 1)
	}
	if a, b := outside(one), outside(get("?pocp=2")); a != b {
		t.Errorf("pocp pages differ outside r-poc:\n%s", firstDiff(a, b))
	}
	// and the same bytes for every visitor
	_, signedIn := e.get(t, path+"?pocu=2")
	if signedIn != p2 {
		t.Errorf("page differs with a token:\n%s", firstDiff(signedIn, p2))
	}
}

func two(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
