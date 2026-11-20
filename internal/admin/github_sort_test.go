package admin_test

import (
	"cmp"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Sorting of the three lists of /admin/github (?us= ?ts= ?rjs=; ghrepo
// ListReviewSorted, webui adminGitHub): every key and direction on every
// list against an order computed here, across pages; unknown stars, rows
// without flags and rows found another way last in both directions; ties
// in the default order; invalid values are the default order; each list's
// order and page are its own; the header links (aria-sort, glyph, target,
// next order, page 1) and the pager links carry every list's state.

// ghSortRow is what the order of a fixture row depends on.
type ghSortRow struct {
	id      int64
	stars   *int
	flags   string // the flags cell's text ("" none)
	found   string // the found-by cell's text ("" another source)
	created time.Time
}

// ghSortList inserts n repositories with status st (one created_at per two
// rows, so ids break ties) and returns them.
func (h *harness) ghSortList(st string, n, base int) []ghSortRow {
	h.t.Helper()
	var by any
	if st != "unverified" {
		by = "admin"
	}
	day := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var out []ghSortRow
	for i := 0; i < n; i++ {
		fork, archived := i%4 == 1 || i%4 == 3, i%3 == 2
		source := []string{"search", "xposts", "manual"}[i%3]
		r := ghSortRow{created: day.Add(time.Duration(i/2) * 24 * time.Hour)}
		stars := 10 + (i*7)%4 // ties; 10 and up so the forks stay in the queue (ghrepo.MinForkStars)
		r.id = h.ghRepo(int64(base+i), fmt.Sprintf("s%s/r%02d", st[:2], i), "", stars, fork, archived, "2024-01-01", source, st, by)
		if i%5 == 4 {
			h.sql(`UPDATE github_repo SET stars = NULL WHERE id = $1`, r.id)
		} else {
			r.stars = &stars
		}
		h.sql(`UPDATE github_repo SET created_at = $2 WHERE id = $1`, r.id, r.created)
		var fl []string
		if fork {
			fl = append(fl, "fork")
		}
		if archived {
			fl = append(fl, "archived")
		}
		r.flags = strings.Join(fl, " · ")
		// an X post links every second row (the 'post' basis); a name
		// basis (every row's own metadata) says nothing about search
		posted := i%2 == 1
		if posted {
			h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'CVE-2024-0001', 'post')`, r.id)
		}
		h.sql(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'CVE-2024-0002', 'name')`, r.id)
		var origins []string
		if l, ok := map[string]string{"search": "search", "xposts": "X post"}[source]; ok {
			origins = append(origins, l)
		}
		if posted && source != "xposts" {
			origins = append(origins, "X post")
		}
		r.found = strings.Join(origins, " · ")
		out = append(out, r)
	}
	return out
}

// ghWant is the ids of rows in the order sort ("" default).
func ghWant(rows []ghSortRow, sort string) []string {
	desc := strings.HasPrefix(sort, "-")
	key := strings.TrimPrefix(sort, "-")
	s := slices.Clone(rows)
	def := func(a, b ghSortRow) int {
		if c := b.created.Compare(a.created); c != 0 {
			return c
		}
		return cmp.Compare(b.id, a.id)
	}
	// nil last in both directions, then the default order
	byText := func(a, b string) int {
		switch {
		case a == b:
			return 0
		case a == "":
			return 1
		case b == "":
			return -1
		case desc:
			return strings.Compare(strings.ToLower(b), strings.ToLower(a))
		}
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	}
	slices.SortStableFunc(s, func(a, b ghSortRow) int {
		var c int
		switch key {
		case "stars":
			switch {
			case a.stars == nil && b.stars == nil:
			case a.stars == nil:
				c = 1
			case b.stars == nil:
				c = -1
			case desc:
				c = cmp.Compare(*b.stars, *a.stars)
			default:
				c = cmp.Compare(*a.stars, *b.stars)
			}
		case "flags":
			c = byText(a.flags, b.flags)
		case "found":
			c = byText(a.found, b.found)
		}
		if c != 0 {
			return c
		}
		return def(a, b)
	})
	var out []string
	for _, r := range s {
		out = append(out, idStr(r.id))
	}
	return out
}

var hrefRe = regexp.MustCompile(`href="(/admin/github[^"]*)"`)

var ghRowRe = regexp.MustCompile(`<tr data-repo="([0-9]+)">`)

// ghIDs reads every page of list (region) in the order of query q (the
// page parameter p added), following the pager's next links.
func ghIDs(t *testing.T, b *browser, regionID, path string) []string {
	t.Helper()
	var out []string
	for i := 0; path != "" && i < 10; i++ {
		r := region(t, page(t, b, path), regionID)
		out = append(out, ids(ghRowRe, r)...)
		path = link(r, "next")
		if j := strings.IndexByte(path, '#'); j >= 0 {
			path = path[:j]
		}
	}
	return out
}

// ghHead is the aria-sort and the unescaped href of the sortable header
// with label in a region, and whether it shows a glyph.
func ghHead(t *testing.T, r, label string) (aria, href, glyph string) {
	t.Helper()
	m := regexp.MustCompile(`<th scope="col" class="adm-sort(?: r)?" aria-sort="([a-z]+)"><a href="([^"]*)">` + regexp.QuoteMeta(label) +
		`(?:<span class="adm-sg" aria-hidden="true">([^<]*)</span>)?</a></th>`).FindStringSubmatch(r)
	if m == nil {
		t.Fatalf("no sortable header %q in\n%s", label, r)
	}
	return m[1], html.UnescapeString(m[2]), m[3]
}

func query(t *testing.T, href string) url.Values {
	t.Helper()
	u, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestGitHubReviewSort(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	lists := []struct {
		status, region, pageP, sortP string
		rows                         []ghSortRow
	}{
		{"unverified", "r-gh-unverified", "up", "us", h.ghSortList("unverified", 23, 2000)},
		{"trusted", "r-gh-trusted", "tp", "ts", h.ghSortList("trusted", 13, 3000)},
		{"rejected", "r-gh-rejected", "rjp", "rjs", h.ghSortList("rejected", 6, 4000)},
	}
	sorts := []string{"", "stars", "-stars", "flags", "-flags", "found", "-found"}

	// every key and direction of every list, across its pages; the other
	// lists stay in their default order
	for _, l := range lists {
		for _, s := range sorts {
			path := "/admin/github"
			if s != "" {
				path += "?" + l.sortP + "=" + url.QueryEscape(s)
			}
			if got, want := ghIDs(t, adm, l.region, path), ghWant(l.rows, s); !slices.Equal(got, want) {
				t.Errorf("%s %q:\n got %v\nwant %v", l.status, s, got, want)
			}
			body := page(t, adm, path)
			for _, o := range lists {
				if o.status != l.status {
					if got := ids(ghRowRe, region(t, body, o.region)); !slices.Equal(got, ghWant(o.rows, "")[:min(10, len(o.rows))]) {
						t.Errorf("%s %q changed the %s list: %v", l.status, s, o.status, got)
					}
				}
			}
		}
	}

	// the found-by cell: the first source, then "X post" when a post links
	// a repository first found otherwise; never "search" from a name basis
	rj := region(t, page(t, adm, "/admin/github"), "r-gh-rejected")
	seen := map[string]bool{}
	for _, row := range lists[2].rows {
		cell := regexp.MustCompile(`(?s)<tr data-repo="` + idStr(row.id) + `">.*?<td class="adm-nw">([^<]*)</td>`).FindStringSubmatch(rj)
		if cell == nil || cell[1] != row.found {
			t.Errorf("rejected %d found by %v, want %q", row.id, cell, row.found)
		}
		seen[row.found] = true
	}
	for _, w := range []string{"search", "search · X post", "X post", ""} {
		if !seen[w] {
			t.Errorf("the fixture has no row found by %q", w)
		}
	}

	// unknown stars last in both directions (rows 4, 9, 14, 19 of unverified)
	u := lists[0]
	for _, s := range []string{"stars", "-stars"} {
		got := ghIDs(t, adm, u.region, "/admin/github?us="+s)
		for _, id := range got[len(got)-4:] {
			for _, r := range u.rows {
				if idStr(r.id) == id && r.stars != nil {
					t.Errorf("%s: %s (stars %d) among the last four", s, id, *r.stars)
				}
			}
		}
	}

	// invalid values are the default order and are not kept in the links
	def := ghWant(u.rows, "")[:10]
	for _, bad := range []string{"bogus", "-", "--stars", "Stars", "stars ", "-found,stars", "id", "1;DROP TABLE x"} {
		body := page(t, adm, "/admin/github?us="+url.QueryEscape(bad)+"&ts="+url.QueryEscape(bad))
		r := region(t, body, u.region)
		if got := ids(ghRowRe, r); !slices.Equal(got, def) {
			t.Errorf("us=%q: %v, want the default %v", bad, got, def)
		}
		// (the language links repeat the request's address as it is, like a bad ?up=)
		in := r + region(t, body, "r-gh-trusted") + region(t, body, "r-gh-rejected")
		for _, m := range hrefRe.FindAllStringSubmatch(in, -1) {
			q := query(t, html.UnescapeString(m[1]))
			for _, k := range []string{"us", "ts"} {
				if v := q.Get(k); q.Has(k) && !slices.Contains(sorts, v) {
					t.Errorf("us=%q: kept in a link: %s", bad, m[1])
				}
			}
		}
		if a, _, g := ghHead(t, r, "stars"); a != "none" || g != "" {
			t.Errorf("us=%q: stars header %s %q", bad, a, g)
		}
	}

	// the header links: aria-sort, glyph, the region, the next order, page 1
	// of this list, every other list's page and order kept
	path := "/admin/github?up=2&us=-stars&tp=2&ts=flags&rjs=-found"
	body := page(t, adm, path)
	for _, c := range []struct {
		region, label, aria, glyph string
		want                       map[string]string // the link's query
	}{
		{u.region, "stars", "descending", "▼", map[string]string{"us": "stars", "tp": "2", "ts": "flags", "rjs": "-found"}},
		{u.region, "flags", "none", "", map[string]string{"us": "flags", "tp": "2", "ts": "flags", "rjs": "-found"}},
		{u.region, "found by", "none", "", map[string]string{"us": "found", "tp": "2", "ts": "flags", "rjs": "-found"}},
		{"r-gh-trusted", "flags", "ascending", "▲", map[string]string{"up": "2", "us": "-stars", "ts": "-flags", "rjs": "-found"}},
		{"r-gh-trusted", "stars", "none", "", map[string]string{"up": "2", "us": "-stars", "ts": "-stars", "rjs": "-found"}},
		{"r-gh-rejected", "found by", "descending", "▼", map[string]string{"up": "2", "us": "-stars", "tp": "2", "ts": "flags"}},
		{"r-gh-rejected", "flags", "none", "", map[string]string{"up": "2", "us": "-stars", "tp": "2", "ts": "flags", "rjs": "flags"}},
	} {
		aria, href, glyph := ghHead(t, region(t, body, c.region), c.label)
		if aria != c.aria || glyph != c.glyph {
			t.Errorf("%s %s: aria-sort %q glyph %q, want %q %q", c.region, c.label, aria, glyph, c.aria, c.glyph)
		}
		if !strings.HasPrefix(href, "/admin/github?") || !strings.HasSuffix(href, "#"+c.region) {
			t.Errorf("%s %s: %s", c.region, c.label, href)
		}
		q := query(t, href)
		got := map[string]string{}
		for k := range q {
			got[k] = q.Get(k)
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s %s: link %s, want %v", c.region, c.label, href, c.want)
		}
	}
	// the cycle: stars most first, then fewest first, then the default (no
	// sort parameter); the text columns A to Z, Z to A, default
	for _, c := range []struct{ from, label, next string }{
		{"", "stars", "-stars"}, {"-stars", "stars", "stars"}, {"stars", "stars", ""},
		{"", "flags", "flags"}, {"flags", "flags", "-flags"}, {"-flags", "flags", ""},
		{"", "found by", "found"}, {"found", "found by", "-found"}, {"-found", "found by", ""},
		{"-found", "stars", "-stars"},
	} {
		_, href, _ := ghHead(t, region(t, page(t, adm, "/admin/github?up=2&us="+c.from), u.region), c.label)
		if got := query(t, href); got.Get("us") != c.next || got.Has("up") {
			t.Errorf("from %q, %s: %s, want us=%q on page 1", c.from, c.label, href, c.next)
		}
	}
	// the default order links back without the parameter at all
	if _, href, _ := ghHead(t, region(t, page(t, adm, "/admin/github?us=stars"), u.region), "stars"); href != "/admin/github#r-gh-unverified" {
		t.Errorf("third click: %s", href)
	}

	// the pager links carry every list's order and page
	r := region(t, body, u.region)
	for _, label := range []string{"page 1", "previous", "next"} {
		q := query(t, link(r, label))
		if q.Get("us") != "-stars" || q.Get("ts") != "flags" || q.Get("tp") != "2" || q.Get("rjs") != "-found" {
			t.Errorf("unverified %s link: %s", label, link(r, label))
		}
	}
	tr := region(t, body, "r-gh-trusted")
	if q := query(t, link(tr, "page 1")); q.Get("us") != "-stars" || q.Get("up") != "2" || q.Get("ts") != "flags" || q.Has("tp") || q.Get("rjs") != "-found" {
		t.Errorf("trusted first link: %s", link(tr, "page 1"))
	}
	// a sorted list's second page is the rest of that order, the trusted
	// list (sorted, page 2) open
	if got, want := ids(ghRowRe, r), ghWant(u.rows, "-stars")[10:20]; !slices.Equal(got, want) {
		t.Errorf("page 2 of -stars: %v, want %v", got, want)
	}
	if got, want := ids(ghRowRe, tr), ghWant(lists[1].rows, "flags")[10:]; !slices.Equal(got, want) {
		t.Errorf("trusted page 2 of flags: %v, want %v", got, want)
	}
	if !strings.Contains(body, `<details class="adm-hist" id="trusted" open="">`) {
		t.Error("the trusted list is not open")
	}
	if b := page(t, adm, "/admin/github?ts=-stars"); !strings.Contains(b, `<details class="adm-hist" id="trusted" open="">`) ||
		strings.Contains(b, `<details class="adm-hist" id="rejected" open="">`) {
		t.Error("a sorted list is not open, or another one is")
	}

	// the Chinese page sorts by the Chinese words, the header link keeps
	// the locale
	zh := page(t, adm, "/zh-hans/admin/github?rjs=found")
	if a, href, _ := ghHead(t, region(t, zh, "r-gh-rejected"), "来源"); a != "ascending" || href != "/zh-hans/admin/github?rjs=-found#r-gh-rejected" {
		t.Errorf("zh-hans found by: %s %s", a, href)
	}
}
