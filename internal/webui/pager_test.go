package webui

import (
	"html/template"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// Every paginated list uses the one pager (parts.tmpl "pager"): no template
// builds a pager of its own.
func TestOnePagerComponent(t *testing.T) {
	uses := 0
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(templateFS, p)
		s := string(b)
		if p != "templates/parts.tmpl" && (strings.Contains(s, `class="pager"`) || strings.Contains(s, `rel="next"`) || strings.Contains(s, `rel="prev"`)) {
			t.Errorf("%s builds its own pager", p)
		}
		for _, k := range []string{"pager.end", "admin.first", "admin.next", "admin.x.prev", "admin.x.page_of"} {
			if strings.Contains(s, `"`+k+`"`) {
				t.Errorf("%s uses the removed key %s", p, k)
			}
		}
		uses += strings.Count(s, `{{template "pager" `)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// hot, catalogue, discussed, a vulnerability page's PoC list, event log,
	// researcher outline and discussion; back
	// office (every list of records, 10 per page): corrections, audit,
	// users, moderation (2), the user page (4), the statistics top lists (1,
	// ranged), system (3), X accounts, candidates (1, both lists), posts and
	// posts per account, drafts pending and history, GitHub (1, all three
	// lists), trusted GitHub accounts, titles
	if uses != 29 {
		t.Errorf("%d lists use the pager, want 29", uses)
	}
}

func TestPagerPosition(t *testing.T) {
	en, zh := loc(t, "en"), loc(t, "zh-Hans")
	if newPager("", "") != nil {
		t.Error("one page has a pager")
	}
	// first, middle and last page, with and without the rows' positions
	for _, c := range []struct {
		page, pages, from, n int
		total                int64
		pg, rng, zhPg, zhRng string
	}{
		{1, 15, 1, 50, 726, "page 1 of 15", "1–50 of 726", "第 1 页，共 15 页", "第 1–50 条，共 726 条"},
		{7, 15, 301, 50, 726, "page 7 of 15", "301–350 of 726", "第 7 页，共 15 页", "第 301–350 条，共 726 条"},
		{15, 15, 701, 26, 726, "page 15 of 15", "701–726 of 726", "第 15 页，共 15 页", "第 701–726 条，共 726 条"},
		{1, 3, 0, 0, -1, "page 1 of 3", "", "第 1 页，共 3 页", ""}, // a back-office list: no positions
		{2, 3, 0, 0, -1, "page 2 of 3", "", "第 2 页，共 3 页", ""},
		{3, 3, 0, 0, -1, "page 3 of 3", "", "第 3 页，共 3 页", ""},
		{3, 0, 101, 50, -1, "page 3", "101–150", "第 3 页", "第 101–150 条"},             // length not known
		{3, 9, 101, 50, 120, "page 3 of 9", "101–150", "第 3 页，共 9 页", "第 101–150 条"}, // a total the rows run past is not shown
		{4, 3, 0, 0, -1, "page 4 of 4", "", "第 4 页，共 4 页", ""},                       // never "page 4 of 3"
		{0, 9, 0, 50, 426342, "", "", "", ""},                                        // page not known: no position
		{2, 2, 51, 0, 50, "page 2 of 2", "", "第 2 页，共 2 页", ""},                      // no rows
	} {
		for _, l := range []struct {
			loc     *i18n.Locale
			pg, rng string
		}{{en, c.pg, c.rng}, {zh, c.zhPg, c.zhRng}} {
			p := newPager("p", "n")
			p.position(l.loc, c.page, c.pages, c.from, c.n, c.total)
			if p.Page != l.pg || p.Range != l.rng {
				t.Errorf("%s %+v: %q %q", l.loc.Tag, c, p.Page, p.Range)
			}
		}
	}
	// the display-only page number never passes the last page; a page
	// after the first is at least page 2; a page with a next one is not the
	// last (a count taken a moment earlier grows to fit)
	for _, c := range []struct {
		cur, pages  int
		first, next bool
		wCur, wPgs  int
	}{
		{1, 5, true, true, 1, 5},
		{3, 5, false, true, 3, 5},
		{5, 5, false, false, 5, 5},
		{9, 5, false, false, 5, 5}, // ?p=9 of 5: the last page
		{9, 5, false, true, 4, 5},  // … but a next page follows
		{3, 2, false, true, 2, 3},  // stale count: more rows than counted
		{1, 1, true, true, 1, 2},   // stale count on the first page
		{2, 1, false, false, 2, 2}, // a later page of a list counted as one page
		{0, 5, false, true, 0, 5},  // page not known stays not known
		{4, 0, false, true, 4, 0},  // length not known: nothing to fit
		{1, 3, true, false, 1, 3},  // first and last page by the rows, count larger: kept
		{7, 9, false, false, 7, 9}, // last page by the rows: the count is kept
	} {
		if cur, pages := clampPage(c.cur, c.pages, c.first, c.next); cur != c.wCur || pages != c.wPgs {
			t.Errorf("clampPage(%+v) = %d, %d", c, cur, pages)
		}
	}
	for total, want := range map[int64]int{-1: 0, 0: 1, 1: 1, 50: 1, 51: 2, 726: 15} {
		if got := pagesOf(total, 50); got != want {
			t.Errorf("pagesOf(%d) = %d", total, got)
		}
	}
	for in, want := range map[string]int{"": 0, "1": 0, "2": 2, " 7 ": 7, "100000": 100000, "100001": 100000, "999999": 100000,
		"-3": 0, "2.5": 0, "x": 0, "0x10": 0, "99999999999999999999999": 0} {
		if got := pageIndex(in); got != want {
			t.Errorf("pageIndex(%q) = %d", in, got)
		}
	}
	if nextIndex(0) != 0 || nextIndex(1) != 2 || prevIndex(2) != 0 || prevIndex(3) != 2 || prevIndex(0) != 0 {
		t.Error("neighbour indexes")
	}
	href := func(p int) string { return "/l?page=" + string(rune('0'+p)) }
	if numberedPager(en, 1, 1, href) != nil {
		t.Error("one numbered page has a pager")
	}
	if g := numberedPager(en, 2, 3, href); g.Prev != "/l?page=1" || g.Next != "/l?page=3" || g.Page != "page 2 of 3" ||
		windowOf(g) != "1 [2] 3" || g.Items[0].Href != "/l?page=1" || g.Items[2].Href != "/l?page=3" {
		t.Errorf("numbered %+v", g)
	}
	if g := numberedPager(en, 3, 3, href); g.Next != "" || g.Prev != "/l?page=2" {
		t.Errorf("numbered last %+v", g)
	}
}

// The catalogue's total comes from the whole-database counts, only where
// they match the filter (no year, no tags; rejected CVEs left out unless
// asked for).
func TestCatTotal(t *testing.T) {
	st := &site.Stats{WithEvents: 1000, Rejected: 10, ByStageLive: [6]int64{500, 100, 50, 200, 80, 60}}
	for i, info := range site.StageInfos {
		st.ByStage = append(st.ByStage, site.StageCount{Stage: info.Type, Code: info.Code, Count: st.ByStageLive[i] + 2})
	}
	for _, c := range []struct {
		f    CatFilters
		want int64
	}{
		{CatFilters{}, 990},
		{CatFilters{IncludeRejected: true}, 1000},
		{CatFilters{Stage: "poc_published"}, 200},
		{CatFilters{Stage: "poc_published", IncludeRejected: true}, 202},
		{CatFilters{Year: 2024}, -1},
		{CatFilters{Tags: []string{"network"}}, -1},
		{CatFilters{Stage: "kev_added", Year: 2024}, -1},
	} {
		if got := catTotal(c.f, st); got != c.want {
			t.Errorf("%+v: %d, want %d", c.f, got, c.want)
		}
	}
	if catTotal(CatFilters{}, nil) != -1 {
		t.Error("no stats")
	}
}

// windowOf writes a pager's numbers as "1 2 … [7] 8 … 19 20" (the
// current page in brackets; narrow-only gaps left out).
func windowOf(p *Pager) string {
	var out []string
	for _, it := range p.Items {
		switch {
		case it.Gap() && it.Class == "pg-n":
		case it.Gap():
			out = append(out, "…")
		case it.Current:
			out = append(out, "["+it.Text+"]")
		default:
			out = append(out, it.Text)
		}
	}
	return strings.Join(out, " ")
}

// narrowOf is what a narrow screen shows of the numbers (.pg-w hidden,
// .pg-n shown).
func narrowOf(p *Pager) string {
	var out []string
	for _, it := range p.Items {
		switch {
		case it.Class == "pg-w":
		case it.Gap():
			out = append(out, "…")
		case it.Current:
			out = append(out, "["+it.Text+"]")
		default:
			out = append(out, it.Text)
		}
	}
	return strings.Join(out, " ")
}

// The numbers: the first two pages, the last two, the current page with
// one neighbour each side, one gap wherever pages are left out; without a
// known length no last pages and a trailing gap while the list goes on.
// Narrow screens keep 1, the current page and the last.
func TestPageWindow(t *testing.T) {
	en := loc(t, "en")
	for _, c := range []struct {
		cur, pages int
		more       bool // a next page exists (what the rows say)
		wide       string
		narrow     string
	}{
		{1, 5, true, "[1] 2 … 4 5", "[1] 2 … 4 5"},
		{3, 5, true, "1 2 [3] 4 5", "1 2 [3] 4 5"},
		{5, 5, false, "1 2 … 4 [5]", "1 2 … 4 [5]"},
		{1, 20, true, "[1] 2 … 19 20", "[1] … 20"},
		{2, 20, true, "1 [2] 3 … 19 20", "1 [2] … 20"},
		{7, 20, true, "1 2 … 6 [7] 8 … 19 20", "1 … [7] … 20"},
		{19, 20, true, "1 2 … 18 [19] 20", "1 … [19] 20"},
		{20, 20, false, "1 2 … 19 [20]", "1 … [20]"},
		{4, 4, false, "1 2 3 [4]", "1 2 3 [4]"},
		{1, 2, true, "[1] 2", "[1] 2"},
		// length not known (a broad tag): head, neighbourhood, arrows
		{1, 0, true, "[1] 2 …", "[1] …"},
		{2, 0, true, "1 [2] 3 …", "1 [2] …"},
		{7, 0, true, "1 2 … 6 [7] 8 …", "1 … [7] …"},
		{7, 0, false, "1 2 … 6 [7]", "1 … [7]"},
		// page number not known (an old cursor link without ?p=)
		{0, 20, true, "1 2 … 19 20", "1 … 20"},
		{0, 0, true, "1 2 …", "1 …"},
	} {
		next := ""
		if c.more {
			next = "/next"
		}
		p := newPager("/prev", next)
		p.numbers(en, c.cur, c.pages, func(n int) string { return "/p" + strconv.Itoa(n) })
		if got := windowOf(p); got != c.wide {
			t.Errorf("%d/%d more=%v: %q, want %q", c.cur, c.pages, c.more, got, c.wide)
		}
		if got := narrowOf(p); got != c.narrow {
			t.Errorf("%d/%d narrow: %q, want %q", c.cur, c.pages, got, c.narrow)
		}
		for _, it := range p.Items {
			n, _ := strconv.Atoi(it.Text)
			switch {
			case it.Gap():
			case it.Current:
				if it.Href != "" {
					t.Errorf("%d/%d: the current page links", c.cur, c.pages)
				}
			case c.cur > 0 && (n == c.cur-1 && it.Href != "/prev" || n == c.cur+1 && it.Href != "/next"):
				t.Errorf("%d/%d: neighbour %d links to %q, not where the arrow does", c.cur, c.pages, n, it.Href)
			case (c.cur == 0 || n != c.cur-1 && n != c.cur+1) && it.Href != "/p"+it.Text:
				t.Errorf("%d/%d: %s links to %q", c.cur, c.pages, it.Text, it.Href)
			}
			if !it.Gap() && it.Name != "page "+it.Text {
				t.Errorf("%d/%d: name %q", c.cur, c.pages, it.Name)
			}
		}
	}
	// one page: no pager at all
	if numberedPager(en, 1, 1, func(int) string { return "/x" }) != nil {
		t.Error("1 of 1 has a pager")
	}
}

// A page number without a position reaches one of the first or last pages
// from the nearest end, never more than two pages of rows away; the
// middle of a long list is out of reach, past the end is the last page.
func TestJumpTo(t *testing.T) {
	const per = 50
	for _, c := range []struct {
		n    int
		rows int64
		want jump
		ok   bool
	}{
		{2, 1000, jump{Page: 2, Offset: 50, Limit: 50}, true},
		{3, 1000, jump{Page: 3, Offset: 100, Limit: 50}, true},
		{4, 1000, jump{}, false}, // page 4 of 20: the middle
		{18, 1000, jump{Page: 18, Offset: 100, Limit: 50, FromEnd: true}, true},
		{19, 1000, jump{Page: 19, Offset: 50, Limit: 50, FromEnd: true}, true},
		{20, 1000, jump{Page: 20, Limit: 50, FromEnd: true}, true},
		{20, 990, jump{Page: 20, Limit: 40, FromEnd: true}, true}, // a short last page
		{19, 990, jump{Page: 19, Offset: 40, Limit: 50, FromEnd: true}, true},
		{999999, 990, jump{Page: 20, Limit: 40, FromEnd: true}, true}, // past the end: the last page
		{100000, 428000, jump{Page: 8560, Limit: 50, FromEnd: true}, true},
		{5000, 428000, jump{}, false},
		{3, 60, jump{Page: 2, Offset: 50, Limit: 50}, true},  // 2 pages: page 2
		{5, 1, jump{Page: 1, Limit: 50}, true},               // one page
		{3, -1, jump{Page: 3, Offset: 100, Limit: 50}, true}, // not counted: the first pages only
		{4, -1, jump{}, false},
	} {
		j, ok := jumpTo(c.n, c.rows, per)
		if j != c.want || ok != c.ok {
			t.Errorf("jumpTo(%d, %d) = %+v %v, want %+v %v", c.n, c.rows, j, ok, c.want, c.ok)
		}
		if ok && j.Offset > 2*per {
			t.Errorf("jumpTo(%d, %d): offset %d", c.n, c.rows, j.Offset)
		}
	}
	// every page a window can link without a position is in reach, for
	// every length and current page
	for rows := int64(1); rows <= 1200; rows += 7 {
		pages := pagesOf(rows, per)
		for cur := 1; cur <= pages; cur++ {
			for _, n := range pageWindow(cur, pages, cur < pages) {
				if n == 0 || n == cur || n == cur-1 || n == cur+1 || n == 1 {
					continue
				}
				if j, ok := jumpTo(n, rows, per); !ok || j.Page != n || j.Offset > 2*per || j.Limit < 1 {
					t.Fatalf("rows %d page %d: link %d → %+v %v", rows, cur, n, j, ok)
				}
			}
		}
	}
}

// The pager's markup in every locale: the arrows are disabled spans at the
// ends (never removed), keep rel and their previous / next names (screen
// readers only); the current page is not a link and carries aria-current;
// every number has an accessible name; no visible "first / previous /
// next" words; the position is said to screen readers only, the row range
// stays visible.
func TestPagerMarkup(t *testing.T) {
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	assets, err := loadAssets("")
	if err != nil {
		t.Fatal(err)
	}
	r, err := newRenderer(assets, set)
	if err != nil {
		t.Fatal(err)
	}
	tags := []string{"en", "zh-Hans", "zh-Hant", "ja", "ko", "es", "fr"}
	if len(set.Enabled) != len(tags) {
		t.Fatalf("%d locales enabled, the test knows %d", len(set.Enabled), len(tags))
	}
	srText := regexp.MustCompile(`<span class="sr">[^<]*</span>`)
	tagRe := regexp.MustCompile(`<[^>]+>`)
	for _, tag := range tags {
		l := loc(t, tag)
		render := func(cur, pages int) string {
			href := func(n int) string { return "/l?p=" + strconv.Itoa(n) + "#r-x" }
			p := numberedPager(l, cur, pages, href)
			p.position(l, cur, pages, (cur-1)*50+1, 50, int64(pages*50))
			var b strings.Builder
			if err := r.pages[l.Tag]["hot"].ExecuteTemplate(&b, "pager", p); err != nil {
				t.Fatal(err)
			}
			return b.String()
		}
		prevName, nextName := template.HTMLEscapeString(l.Text("pager.prev")), template.HTMLEscapeString(l.Text("pager.next"))
		for _, c := range []struct{ cur, pages int }{{1, 20}, {7, 20}, {20, 20}} {
			out := render(c.cur, c.pages)
			what := tag + " " + strconv.Itoa(c.cur) + "/" + strconv.Itoa(c.pages)
			prevOff := `<span class="pg pg-a" aria-disabled="true"><span aria-hidden="true">‹</span><span class="sr">` + prevName + `</span></span>`
			nextOff := `<span class="pg pg-a" aria-disabled="true"><span aria-hidden="true">›</span><span class="sr">` + nextName + `</span></span>`
			if (c.cur == 1) != strings.Contains(out, prevOff) || (c.cur == c.pages) != strings.Contains(out, nextOff) {
				t.Errorf("%s: disabled arrows:\n%s", what, out)
			}
			if c.cur > 1 && !strings.Contains(out, `rel="prev" class="pg pg-a"><span aria-hidden="true">‹</span><span class="sr">`+prevName+`</span></a>`) {
				t.Errorf("%s: previous arrow:\n%s", what, out)
			}
			if c.cur < c.pages && !strings.Contains(out, `rel="next" class="pg pg-a"><span aria-hidden="true">›</span><span class="sr">`+nextName+`</span></a>`) {
				t.Errorf("%s: next arrow:\n%s", what, out)
			}
			name := template.HTMLEscapeString(l.Text("pager.page", "n", c.cur))
			cur := `<span class="pg pg-cur" aria-current="page"><span aria-hidden="true">` + strconv.Itoa(c.cur) + `</span><span class="sr">` + name + `</span></span>`
			if strings.Count(out, `aria-current="page"`) != 1 || !strings.Contains(out, cur) || strings.Contains(out, `p=`+strconv.Itoa(c.cur)+`#`) && c.cur != 1 {
				t.Errorf("%s: current page:\n%s", what, out)
			}
			// every number link: its accessible name, and the admin region suffix
			for _, m := range regexp.MustCompile(`<a href="([^"]+)" class="pg[^"]*"><span aria-hidden="true">([0-9]+)</span><span class="sr">([^<]*)</span></a>`).FindAllStringSubmatch(out, -1) {
				n, _ := strconv.Atoi(m[2])
				if m[3] != template.HTMLEscapeString(l.Text("pager.page", "n", n)) || !strings.HasSuffix(m[1], "#r-x") {
					t.Errorf("%s: number %s: %q %q", what, m[2], m[1], m[3])
				}
			}
			// what shows on screen: no words but the row range
			visible := tagRe.ReplaceAllString(srText.ReplaceAllString(out, ""), " ")
			for _, k := range []string{"pager.prev", "pager.next", "pager.page_of"} {
				w := l.Text(k, "n", c.cur, "pages", c.pages)
				if strings.Contains(visible, template.HTMLEscapeString(w)) {
					t.Errorf("%s: %q visible", what, w)
				}
			}
			if !strings.Contains(out, `<span class="sr">`+template.HTMLEscapeString(l.Text("pager.page_of", "n", c.cur, "pages", c.pages))+`</span>`) {
				t.Errorf("%s: no position for screen readers:\n%s", what, out)
			}
			if rng := template.HTMLEscapeString(l.Text("pager.range_total", "from", (c.cur-1)*50+1, "to", c.cur*50, "total", c.pages*50)); !strings.Contains(out, "<span>"+rng+"</span>") {
				t.Errorf("%s: range %q not visible:\n%s", what, rng, out)
			}
			if strings.Contains(out, "style=") || strings.Contains(out, "<script") || strings.Contains(out, "first") {
				t.Errorf("%s: inline style / script / first:\n%s", what, out)
			}
		}
	}
}
