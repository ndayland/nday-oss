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

// pagedCVE has 25 events (a disclosure and 24 PoCs, one a day, so the
// store's order is the id order) and 25 researcher posts (one allow-listed
// account each, Qz01 the newest); fewCVE has 3 events and no posts.
const (
	pagedCVE = "CVE-2026-2500"
	fewCVE   = "CVE-2026-2501"
)

var pagedEvIDs []int64

func seedPaged(t *testing.T, conn *pgx.Conn) {
	s := sitetest.Seeder{T: t, Conn: conn}
	s.Vuln(pagedCVE, sitetest.P("Paged"))
	s.Vuln(fewCVE, sitetest.P("Few"))
	pagedEvIDs = nil
	pagedEvIDs = append(pagedEvIDs, s.Event(sitetest.Ev{CVE: pagedCVE, Type: "disclosed", Source: "cvelist", Occurred: sitetest.P(sitetest.Day(2026, 9, 1)), Backfill: true, Key: "d0"}))
	for i := 1; i <= 24; i++ {
		pagedEvIDs = append(pagedEvIDs, s.Event(sitetest.Ev{CVE: pagedCVE, Type: "poc_published", Source: fmt.Sprintf("poc%02d", i),
			Occurred: sitetest.P(sitetest.Day(2026, 9, 1).AddDate(0, 0, i)), Backfill: true, Key: fmt.Sprintf("p%d", i)}))
	}
	for i, ty := range []string{"disclosed", "poc_published", "kev_added"} {
		s.Event(sitetest.Ev{CVE: fewCVE, Type: ty, Source: "x" + ty, Occurred: sitetest.P(sitetest.Day(2026, 9, 1+i)), Backfill: true, Key: fmt.Sprintf("f%d", i)})
	}
	for i := 1; i <= 25; i++ {
		uid, handle := fmt.Sprintf("90000%02d", i), fmt.Sprintf("Qz%02d", i)
		if _, err := conn.Exec(context.Background(), `INSERT INTO x_accounts (user_id, handle, enabled) VALUES ($1, $2, true)`, uid, handle); err != nil {
			t.Fatal(err)
		}
		at := sitetest.Ago(1 + float64(i)/100)
		u := "https://x.com/" + handle + "/status/" + uid
		s.Event(sitetest.Ev{CVE: pagedCVE, Type: "social_post", Source: "xposts", Occurred: &at, Observed: at, URL: &u, Key: "x" + uid,
			Detail: `{"post_id": "` + uid + `", "author_id": "` + uid + `", "author_handle": "` + handle + `", "text": "QZPOSTBODY` + handle + `", "lang": "en"}`})
	}
	s.Refresh()
}

var (
	evIDRe   = regexp.MustCompile(`<article class="ev" id="ev-(\d+)"`)
	rpAuthRe = regexp.MustCompile(`<a class="rp-au" href="https://x\.com/(Qz\d\d)"`)
)

func evIDs(body string) []string {
	var out []string
	for _, m := range evIDRe.FindAllStringSubmatch(regionOf(body, "r-events"), -1) {
		out = append(out, m[1])
	}
	return out
}

func rpAuthors(body string) []string {
	var out []string
	for _, m := range rpAuthRe.FindAllStringSubmatch(regionOf(body, "r-research"), -1) {
		out = append(out, m[1])
	}
	return out
}

func TestEventLogPages(t *testing.T) {
	e := newEnvSeeded(t, seedPaged)
	path := "/vuln/" + pagedCVE
	var all []string
	for _, id := range pagedEvIDs {
		all = append(all, fmt.Sprint(id))
	}
	_, one := e.get(t, path)
	_, two := e.get(t, path+"?evp=2")
	_, three := e.get(t, path+"?evp=3")
	for i, c := range []struct {
		body string
		want []string
		pos  string
	}{{one, all[:10], "page 1 of 3"}, {two, all[10:20], "page 2 of 3"}, {three, all[20:], "page 3 of 3"}} {
		if got := evIDs(c.body); strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("page %d: events %v, want %v", i+1, got, c.want)
		}
		if pg := pocPgRe.FindString(regionOf(c.body, "r-events")); !strings.Contains(pg, c.pos) {
			t.Errorf("page %d: pager %q lacks %q", i+1, pg, c.pos)
		}
	}
	// the links
	if m := pocNextRe.FindStringSubmatch(regionOf(one, "r-events")); m == nil || html.UnescapeString(m[1]) != path+"?evp=2#r-events" {
		t.Errorf("page 1 next: %v", m)
	}
	pg2 := pocPgRe.FindString(regionOf(two, "r-events"))
	for _, w := range []string{`href="` + path + `#r-events"`, `href="` + path + `?evp=3#r-events"`} { // first/prev: page 1 has no parameter
		if !strings.Contains(pg2, w) {
			t.Errorf("page 2 pager lacks %s:\n%s", w, pg2)
		}
	}
	// out of range is the last page, nonsense the first
	for _, c := range []struct{ q, same string }{{"?evp=99", three}, {"?evp=0", one}, {"?evp=x", one}, {"?evp=-2", one}, {"?evp=1", one}} {
		resp, b := e.get(t, path+c.q)
		if resp.StatusCode != 200 || regionOf(b, "r-events") != regionOf(c.same, "r-events") {
			t.Errorf("%s: %d, not the clamped page", c.q, resp.StatusCode)
		}
	}
	// derived parts use all events: outside the two regions every page is the same
	strip := func(b string) string { return outsideRegion(outsideRegion(b, "r-events"), "r-research") }
	if a, b := strip(one), strip(two); a != b {
		t.Errorf("page 1 vs 2 differ outside the regions:\n%s", firstDiff(a, b))
	}
	for _, b := range []string{one, two, three} {
		if m := posRe.FindString(b); !strings.Contains(m, "25") {
			t.Errorf("status bar total %q is not all 25 events", m)
		}
		// the lifecycle chart draws the PoC stage of events that are on other pages
		if !strings.Contains(b, "poc") {
			t.Error("no PoC stage on the page")
		}
	}
	// no in-page link to a single event exists; one to an event on page 2
	// lands there with its page parameter and its id
	if strings.Contains(one, `href="#ev-`) {
		t.Error("an in-page link to an event appeared: it needs the page of the event")
	}
	if !strings.Contains(two, `id="ev-`+all[14]+`"`) || strings.Contains(one, `id="ev-`+all[14]+`"`) {
		t.Error("the event of page 2 is not only on page 2")
	}
	// canonical without the parameter, indexable, publicly cached
	resp, _ := e.get(t, path+"?evp=2")
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control %q", cc)
	}
	if !strings.Contains(two, `<link rel="canonical" href="`) || strings.Contains(regexp.MustCompile(`<link rel="canonical"[^>]*>`).FindString(two), "evp") ||
		strings.Contains(two, `name="robots"`) || resp.Header.Get("X-Robots-Tag") != "" {
		t.Error("page 2: canonical keeps the parameter, or the page is noindex")
	}
	// the same bytes for every visitor
	if _, out := e.get(t, path+"?evp=2", "Authorization", ""); out != two {
		t.Errorf("page 2 differs without the token:\n%s", firstDiff(out, two))
	}
	// 10 events or fewer: no pager
	_, few := e.get(t, "/vuln/"+fewCVE)
	if got := evIDs(few); len(got) != 3 || strings.Contains(regionOf(few, "r-events"), `class="pager"`) {
		t.Errorf("small log: %d events, pager %v", len(got), strings.Contains(regionOf(few, "r-events"), `class="pager"`))
	}
	// the JSON API keeps every event
	_, j := e.get(t, "/api/vuln/"+pagedCVE)
	if n := strings.Count(j, `"poc_published"`); n < 24 {
		t.Errorf("the JSON has %d events, want all 25", n)
	}
}

func TestResearchPages(t *testing.T) {
	e := newEnvSeeded(t, seedPaged)
	path := "/vuln/" + pagedCVE
	name := func(from, to int) []string {
		var out []string
		for i := from; i <= to; i++ {
			out = append(out, fmt.Sprintf("Qz%02d", i))
		}
		return out
	}
	_, one := e.get(t, path)
	_, two := e.get(t, path+"?rp=2")
	_, three := e.get(t, path+"?rp=3")
	for i, c := range []struct {
		body string
		want []string
		pos  string
		off  string
	}{{one, name(1, 10), "page 1 of 3", `data-offset="0"`}, {two, name(11, 20), "page 2 of 3", `data-offset="10"`}, {three, name(21, 25), "page 3 of 3", `data-offset="20"`}} {
		r := regionOf(c.body, "r-research")
		if got := rpAuthors(c.body); strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("page %d: %v, want %v", i+1, got, c.want)
		}
		if !strings.Contains(pocPgRe.FindString(r), c.pos) || !strings.Contains(r, c.off) {
			t.Errorf("page %d: pager or offset wrong:\n%s", i+1, r)
		}
		// counts come from all posts, on every page
		if !strings.Contains(r, "Sign in to read 25 posts.") {
			t.Errorf("page %d: counts are not those of all posts", i+1)
		}
		// nothing signed-in-only: no post text, no post links, no counts of the page
		for _, bad := range []string{"QZPOSTBODY", "/status/"} {
			if strings.Contains(c.body, bad) {
				t.Errorf("page %d shows %q", i+1, bad)
			}
		}
	}
	if m := pocNextRe.FindStringSubmatch(regionOf(one, "r-research")); m == nil || html.UnescapeString(m[1]) != path+"?rp=2#r-research" {
		t.Errorf("page 1 next: %v", m)
	}
	for _, c := range []struct{ q, same string }{{"?rp=99", three}, {"?rp=0", one}, {"?rp=x", one}, {"?rp=-1", one}} {
		resp, b := e.get(t, path+c.q)
		if resp.StatusCode != 200 || regionOf(b, "r-research") != regionOf(c.same, "r-research") {
			t.Errorf("%s: %d, not the clamped page", c.q, resp.StatusCode)
		}
	}
	// the chart's dots use every post
	strip := func(b string) string { return outsideRegion(outsideRegion(b, "r-events"), "r-research") }
	if a, b := strip(one), strip(three); a != b {
		t.Errorf("page 1 vs 3 differ outside the regions:\n%s", firstDiff(a, b))
	}
	// both sections on a later page at once: each keeps the other's parameter
	_, both := e.get(t, path+"?evp=2&rp=3")
	if got := rpAuthors(both); strings.Join(got, " ") != strings.Join(name(21, 25), " ") {
		t.Errorf("both: research %v", got)
	}
	var all []string
	for _, id := range pagedEvIDs {
		all = append(all, fmt.Sprint(id))
	}
	if got := evIDs(both); strings.Join(got, " ") != strings.Join(all[10:20], " ") {
		t.Errorf("both: events %v", got)
	}
	evpg := pocPgRe.FindString(regionOf(both, "r-events"))
	rspg := pocPgRe.FindString(regionOf(both, "r-research"))
	if !strings.Contains(evpg, `href="`+path+`?evp=3&amp;rp=3#r-events"`) || !strings.Contains(rspg, `href="`+path+`?evp=2&amp;rp=2#r-research"`) ||
		!strings.Contains(rspg, `href="`+path+`?evp=2#r-research"`) {
		t.Errorf("both: the pagers drop the other parameter:\n%s\n%s", evpg, rspg)
	}
	// the same bytes for every visitor, and one page of the 25 with no outline when the section has none
	if _, out := e.get(t, path+"?evp=2&rp=3", "Authorization", ""); out != both {
		t.Errorf("differs without the token:\n%s", firstDiff(out, both))
	}
	_, few := e.get(t, "/vuln/"+fewCVE)
	if strings.Contains(few, `id="r-research"`) {
		t.Error("a vulnerability without posts has a research region")
	}
}
