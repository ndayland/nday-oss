package webui

import (
	"io/fs"
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
	// hot, catalogue, discussed, a vulnerability page's PoC list; back
	// office (every list of records, 10 per page): corrections, audit,
	// users, moderation (2), the user page (4), the statistics top lists (1,
	// ranged), system (3), X accounts, candidates (1, both lists), posts and
	// posts per account, drafts pending and history, GitHub (1, all three
	// lists), trusted GitHub accounts, titles
	if uses != 26 {
		t.Errorf("%d lists use the pager, want 26", uses)
	}
}

func TestPagerPosition(t *testing.T) {
	en, zh := loc(t, "en"), loc(t, "zh-Hans")
	if newPager("", "", "") != nil {
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
			p := newPager("f", "p", "n")
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
	for in, want := range map[string]int{"": 0, "1": 0, "2": 2, " 7 ": 7, "100000": 100000, "100001": 0, "-3": 0, "2.5": 0, "x": 0} {
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
	if g := numberedPager(en, 2, 3, href); g.First != "/l?page=1" || g.Prev != "/l?page=1" || g.Next != "/l?page=3" || g.Page != "page 2 of 3" {
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
