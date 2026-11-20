package webui_test

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
)

// seedPoCRepos lists 23 repositories an admin trusted (stars 230, 220, …,
// 10; counted, site.AddSearchRepos) under the PoC group of GPU, created
// after its disclosure: three pages of the PoC list, every one drawn on the
// chart; and 2 unverified ones in the unreviewed group (no stars, no dot).
func seedPoCRepos(t *testing.T, conn *pgx.Conn) {
	ctx := context.Background()
	q := func(sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	for i := 1; i <= 25; i++ {
		name := fmt.Sprintf("Owner%02d/poc-%02d", i, i)
		created := fmt.Sprintf("2026-11-%02d 12:00:00+00", 5+i%3)
		if i <= 23 {
			q(`INSERT INTO github_repo (github_id, queued_name, full_name, owner_login, owner_type, stars, repo_created_at, state, first_source, status, status_by, status_at, seen_at)
VALUES ($1, lower($2), $2, 'o', 'User', $3, $4, 'ok', 'search', 'trusted', 'admin', now(), now())`, 1000+i, name, (24-i)*10, created)
		} else {
			q(`INSERT INTO github_repo (github_id, queued_name, full_name, owner_login, owner_type, stars, repo_created_at, state, first_source, status, seen_at)
VALUES ($1, lower($2), $2, 'o', 'User', 999, $3, 'ok', 'search', 'unverified', '2026-11-12')`, 1000+i, name, created)
		}
	}
	q(`INSERT INTO github_repo_name (name_key, repo_id) SELECT queued_name, id FROM github_repo`)
	q(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, $1, 'name' FROM github_repo`, sitetest.GPU)
}

var (
	pocLiRe   = regexp.MustCompile(`<li><a href="https://github\.com/(Owner\d\d/poc-\d\d)"`)
	pocPgRe   = regexp.MustCompile(`(?s)<nav class="pager".*?</nav>`)
	pocNextRe = regexp.MustCompile(`<a href="([^"]+)" rel="next"`)
)

// pocRepos are the repositories listed in the PoC region of body.
func pocRepos(t *testing.T, body string) []string {
	t.Helper()
	r := regionOf(body, "r-poc")
	if r == "" {
		t.Fatal("no PoC region")
	}
	var out []string
	for _, m := range pocLiRe.FindAllStringSubmatch(r, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestPoCPages: the PoC list of a vulnerability page shows 10 links per
// page, most stars first, in the
// paging region r-poc inside the resources panel with the pager; ?pocp= out
// of range is clamped; the pager keeps the page's other query parameters;
// outside the region page 2 is the same page as page 1 (the chart draws
// every link on every page), and the page is the same for every visitor.
func TestPoCPages(t *testing.T) {
	e := newEnvSeeded(t, seedPoCRepos)
	gpu := "/vuln/" + sitetest.GPU
	_, one := e.get(t, gpu)
	_, two := e.get(t, gpu+"?pocp=2")
	_, three := e.get(t, gpu+"?pocp=3")
	want := func(from, to int) []string {
		var out []string
		for i := from; i <= to; i++ {
			out = append(out, fmt.Sprintf("Owner%02d/poc-%02d", i, i))
		}
		return out
	}
	for _, c := range []struct {
		name, body string
		repos      []string
		pos        string
	}{
		{"page 1", one, want(1, 10), "page 1 of 3"},
		{"page 2", two, want(11, 20), "page 2 of 3"},
		{"page 3", three, want(21, 23), "page 3 of 3"},
	} {
		if got := pocRepos(t, c.body); strings.Join(got, " ") != strings.Join(c.repos, " ") {
			t.Errorf("%s: %v, want %v", c.name, got, c.repos)
		}
		r := regionOf(c.body, "r-poc")
		pg := pocPgRe.FindString(r)
		if n := strings.Count(c.body, `data-page-region="`); n != 3 || pg == "" || !strings.Contains(pg, c.pos) ||
			!strings.Contains(r, `<h3 class="rsrc-k k-poc">PoC / exploit code</h3>`) {
			t.Errorf("%s: %d regions, pager %q", c.name, n, pg)
		}
		// the region is in the resources panel
		if sec := regexp.MustCompile(`(?s)<section class="panel rsrc" id="resources".*?</section>`).FindString(c.body); !strings.Contains(sec, r) {
			t.Errorf("%s: the region is outside the resources panel", c.name)
		}
	}
	if u := regionOf(three, "r-pocu"); !strings.Contains(u, `poc-25</a> <span class="rsrc-host"><time datetime=`) ||
		strings.Contains(u, "★ 999") || strings.Contains(u, "pager") {
		t.Errorf("the unverified repositories are not in their own group without stars:\n%s", u)
	}
	if m := pocNextRe.FindStringSubmatch(regionOf(one, "r-poc")); m == nil || html.UnescapeString(m[1]) != gpu+"?pocp=2#r-poc" {
		t.Errorf("page 1: next %v", m)
	}
	// clamped: past the end is the last page, nonsense the first
	for _, c := range []struct{ q, same string }{{"?pocp=99", three}, {"?pocp=0", one}, {"?pocp=x", one}, {"?pocp=-2", one}} {
		resp, b := e.get(t, gpu+c.q)
		if resp.StatusCode != 200 || regionOf(b, "r-poc") != regionOf(c.same, "r-poc") {
			t.Errorf("%s: %d, not the clamped page", c.q, resp.StatusCode)
		}
	}
	// outside the region: the same page (chart, popovers, everything)
	// (the event log's pager links carry pocp, as the other region's do)
	rest := func(b string) string {
		return strings.Replace(outsideRegion(b, "r-poc"), regionOf(b, "r-events"), "EVENTS", 1)
	}
	if a, b := rest(one), rest(two); a != b {
		t.Errorf("page 1 vs 2 differ outside r-poc:\n%s", firstDiff(a, b))
	}
	if strings.Count(one, `class="dot d-poc`) == 0 || !strings.Contains(one, `<div class="crow lane">`) ||
		!strings.Contains(one, `class="dp-more" href="#r-poc"`) {
		t.Error("page 1: the chart does not draw the PoC links in a lane, or the popover's more does not lead to the list")
	}
	// the pager keeps the other parameters of the page
	_, kept := e.get(t, gpu+"?c=12&thread=t1&cursor=k&pocp=2")
	pg := pocPgRe.FindString(regionOf(kept, "r-poc"))
	for _, w := range []string{`href="` + gpu + `?c=12&amp;cursor=k&amp;thread=t1#r-poc"`, `href="` + gpu + `?c=12&amp;cursor=k&amp;pocp=3&amp;thread=t1#r-poc"`} {
		if !strings.Contains(pg, w) {
			t.Errorf("pager lacks %s:\n%s", w, pg)
		}
	}
	// the same bytes for every visitor
	if _, out := e.get(t, gpu+"?pocp=2", "Authorization", ""); out != two {
		t.Errorf("page 2 differs without the token:\n%s", firstDiff(out, two))
	}
}
