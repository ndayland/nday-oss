package webui

import (
	"sort"
	"strconv"
	"strings"

	"nday.land/nday/internal/webui/i18n"
)

// Pager is the one pager of every paginated list, public and admin
// (parts.tmpl "pager"): `‹ 1 2 … 6 7 8 … 19 20 ›`. The arrows are always
// there (a disabled span when there is no such page), so the row never
// shifts; the numbers are the first two pages, the last two (when the
// length is known) and the current page with one neighbour each side, a
// single gap wherever pages are left out (pageWindow). A list that fits
// on one page has no pager (nil).
//
// Page is the position for screen readers and the in-place announcement
// ("page 3 of 12"); the numbers say it on screen. Range is the visible row
// range ("101–150 of 426,342") where the list's rows have positions.
type Pager struct {
	Page  string // "page 3 of 12"; "page 3" when the length is not known; "" when the page number is not known
	Range string // "101–150 of 426,342" or "101–150"; "" when not known
	Prev  string
	Next  string
	Items []PageItem
}

// PageItem is one number of the pager, or a gap ("…", Text "").
type PageItem struct {
	Text    string // "7"; "" for a gap
	Name    string // the accessible name, "page 7"
	Href    string // "" for the current page and gaps
	Current bool
	// Class: "pg-w" is dropped on narrow screens (the outer neighbours),
	// "pg-n" is a gap shown only there (where the dropped pages were).
	Class string
}

// Gap tells a gap from a number.
func (it PageItem) Gap() bool { return it.Text == "" }

// newPager is the pager with these arrows, nil when neither applies (one
// page). The numbers come from numbers.
func newPager(prev, next string) *Pager {
	if prev == "" && next == "" {
		return nil
	}
	return &Pager{Prev: prev, Next: next}
}

// position sets the position text: page is the 1-based page number (0 =
// not known) and pages the number of pages (0 = not known; see
// clampPage); from the 1-based position of the page's first row (0 = not
// known) and n its rows; total the length of the whole list (< 0 = not
// known; ignored when the rows shown run past it, e.g. counts taken a
// moment earlier).
func (p *Pager) position(l *i18n.Locale, page, pages, from, n int, total int64) {
	if p == nil {
		return
	}
	switch {
	case page > 0 && pages > 0:
		p.Page = l.Text("pager.page_of", "n", page, "pages", max(pages, page))
	case page > 0:
		p.Page = l.Text("pager.page", "n", page)
	}
	if from < 1 || n < 1 {
		return
	}
	to := from + n - 1
	if total >= int64(to) {
		p.Range = l.Text("pager.range_total", "from", from, "to", to, "total", total)
	} else {
		p.Range = l.Text("pager.range", "from", from, "to", to)
	}
}

// numbers sets the page numbers for page cur (0 = not known) of pages (0 =
// not known): the neighbours cur±1 link where the arrows do, every other
// number to href(n). Call it after position, with the same (clamped)
// numbers.
func (p *Pager) numbers(l *i18n.Locale, cur, pages int, href func(int) string) {
	if p == nil {
		return
	}
	if pages > 0 {
		pages = max(pages, cur)
	}
	// five pages or fewer fit a phone as they are: nothing is dropped
	small := pages > 0 && pages <= 5
	anchor := func(n int) bool {
		return small || n == 1 || (cur > 0 && n == cur) || (pages > 0 && n == pages)
	}
	// narrow screens keep 1, the current page and the last; the numbers
	// between two of those are dropped and one gap stands for them
	var out, seg []PageItem
	flush := func() {
		nums, gap := false, false
		for _, it := range seg {
			gap = gap || it.Gap()
			nums = nums || !it.Gap()
		}
		if nums && !gap {
			out = append(out, PageItem{Class: "pg-n"})
		}
		out, seg = append(out, seg...), nil
	}
	for _, n := range pageWindow(cur, pages, p.Next != "") {
		if n == 0 {
			seg = append(seg, PageItem{})
			continue
		}
		it := PageItem{Text: strconv.Itoa(n), Name: l.Text("pager.page", "n", n)}
		switch {
		case n == cur:
			it.Current = true
		case cur > 0 && n == cur-1 && p.Prev != "":
			it.Href = p.Prev
		case cur > 0 && n == cur+1 && p.Next != "":
			it.Href = p.Next
		default:
			it.Href = href(n)
		}
		if anchor(n) {
			flush()
			out = append(out, it)
			continue
		}
		it.Class = "pg-w"
		seg = append(seg, it)
	}
	flush()
	p.Items = out
}

// pageWindow is the page numbers the pager shows for page cur (0 = not
// known) of pages (0 = not known; more: a next page exists), in order, 0
// standing for a gap: the first two pages, the last two, and cur with one
// neighbour each side. Without a known length there are no last pages and
// a list that goes on past cur+1 ends in a gap.
func pageWindow(cur, pages int, more bool) []int {
	hi := pages
	switch {
	case hi > 0:
	case cur > 0 && more:
		hi = cur + 1
	case cur > 0:
		hi = cur
	default:
		hi = 2 // a later page of unknown number: page 2 exists
	}
	set := map[int]bool{}
	add := func(n int) {
		if n >= 1 && n <= hi {
			set[n] = true
		}
	}
	add(1)
	add(2)
	if cur > 0 {
		add(cur - 1)
		add(cur)
		add(cur + 1)
	}
	if pages > 0 {
		add(pages - 1)
		add(pages)
	}
	ns := make([]int, 0, len(set))
	for n := range set {
		ns = append(ns, n)
	}
	sort.Ints(ns)
	var out []int
	for i, n := range ns {
		if i > 0 && n != ns[i-1]+1 {
			out = append(out, 0)
		}
		out = append(out, n)
	}
	if pages == 0 && (more || cur == 0) {
		out = append(out, 0)
	}
	return out
}

// clampPage fits the page number cur (0 = not known) and a counted number
// of pages (0 = not known) to what the page itself shows: a page after the
// first is at least page 2, a page with a next one is not the last. A
// count taken a moment earlier grows to fit; the page number never passes
// the last page.
func clampPage(cur, pages int, first, next bool) (int, int) {
	if pages <= 0 {
		return cur, 0
	}
	least := 1
	if !first {
		least = 2
	}
	if next {
		least++
	}
	pages = max(pages, least)
	last := pages
	if next {
		last--
	}
	return min(cur, last), pages
}

// pagesOf is the number of pages of a list of total rows, per a page (0
// when the length is not known).
func pagesOf(total int64, per int) int {
	if total < 0 || per < 1 {
		return 0
	}
	return max(1, int((total+int64(per)-1)/int64(per)))
}

// maxPageIndex bounds the page number of a link (?p=).
const maxPageIndex = 100000

// pageIndex reads the page number that pager links carry (?p=) for a page
// after the first: 2..maxPageIndex (a larger number is maxPageIndex, which
// the list clamps to its last page), else 0 (not given). Next to a
// position (?cursor=, ?before=) it only labels the page; alone it picks
// the page (jumpTo).
func pageIndex(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	switch {
	case err != nil || n < 2:
		return 0
	case n > maxPageIndex:
		return maxPageIndex
	}
	return n
}

// nextIndex and prevIndex are the page numbers of the neighbours of page
// cur (0 = not known); prevIndex is 0 for the first page, which carries no
// number.
func nextIndex(cur int) int {
	if cur < 1 || cur >= maxPageIndex {
		return 0
	}
	return cur + 1
}

func prevIndex(cur int) int {
	if cur <= 2 {
		return 0
	}
	return cur - 1
}

// Keyset lists (the hot list, the catalogue, the back office's big lists)
// page by position, so a number link can't say "OFFSET (n-1)×per" without
// making a deep page cost the whole list before it. A number that is not a
// neighbour of the current page (those link by position, like the arrows)
// is either one of the first pages or one of the last ones, so it is
// reached from one of the two ends of the list:
//
//   - pages 2..jumpHead: from the start, skipping (n-1)×per rows;
//   - the last jumpTail pages: from the end, walking the index backwards
//     and skipping the rows of the pages after n (at most jumpTail-1 pages
//     and the last page's rows).
//
// Either way a link costs at most 3 pages of rows, whatever the length.
// Any other page number without a position is out of reach (jumpTo: ok
// false); past the last page it is the last page.
const (
	jumpHead = 3
	jumpTail = 3
)

// jump is how a page number without a position is read from a keyset list.
type jump struct {
	Page    int  // the page shown (clamped to the last page)
	Offset  int  // rows skipped from the start (FromEnd false) or from the end
	Limit   int  // rows of the page (the last page may be short)
	FromEnd bool // counted from the end of the list
}

// jumpTo reads page n (≥ 2) of a keyset list of rows rows (< 0 = not
// counted), per a page. ok is false when the page can't be reached cheaply
// (in the middle of the list, or past the first pages of an uncounted
// list).
func jumpTo(n int, rows int64, per int) (j jump, ok bool) {
	pages := pagesOf(rows, per)
	if pages > 0 && n > pages {
		n = pages
	}
	switch {
	case n <= 1:
		return jump{Page: 1, Limit: per}, true
	case n <= jumpHead:
		return jump{Page: n, Offset: (n - 1) * per, Limit: per}, true
	case pages > 0 && n > pages-jumpTail:
		end := min(int64(n)*int64(per), rows)
		return jump{Page: n, Offset: int(rows - end), Limit: int(end) - (n-1)*per, FromEnd: true}, true
	}
	return jump{}, false
}

// numberedPager is the pager of a list addressed by page number (page of
// pages): href gives the URL of a page.
func numberedPager(l *i18n.Locale, page, pages int, href func(int) string) *Pager {
	var prev, next string
	if page > 1 {
		prev = href(page - 1)
	}
	if page < pages {
		next = href(page + 1)
	}
	pg := newPager(prev, next)
	pg.position(l, page, pages, 0, 0, -1)
	pg.numbers(l, page, pages, href)
	return pg
}
