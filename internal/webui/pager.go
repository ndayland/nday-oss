package webui

import (
	"strconv"
	"strings"

	"nday.land/nday/internal/webui/i18n"
)

// Pager is the one pager of every paginated list, public and admin
// (parts.tmpl "pager"): the position on the left, the controls on the
// right in the order first, previous, next. A control whose href is empty
// does not apply on this page and is drawn disabled in its place, so the
// controls never move between pages. A list that fits on one page has no
// pager (nil). The position says the page and how many pages the list has
// ("page 3 of 12"), and where the rows shown are known, their positions
// and the list's length.
type Pager struct {
	Page  string // "page 3 of 12"; "page 3" when the length is not known; "" when the page number is not known
	Range string // "101–150 of 426,342" or "101–150"; "" when not known
	First string
	Prev  string
	Next  string
}

// newPager is the pager with these links, nil when none applies (one page).
func newPager(first, prev, next string) *Pager {
	if first == "" && prev == "" && next == "" {
		return nil
	}
	return &Pager{First: first, Prev: prev, Next: next}
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

// clampPage fits the display-only page number cur (0 = not known) and a
// counted number of pages (0 = not known) to what the page itself shows: a
// page after the first is at least page 2, a page with a next one is not
// the last. A count taken a moment earlier grows to fit; the page number,
// which a link only labels, never passes the last page.
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

// maxPageIndex bounds the display-only page index of a link (?p=).
const maxPageIndex = 100000

// pageIndex reads the display-only page number that pager links carry
// (?p=) for a page after the first: 2..maxPageIndex, else 0 (not known). It
// only labels the page; which rows are shown never depends on it.
func pageIndex(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 2 || n > maxPageIndex {
		return 0
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

// numberedPager is the pager of a numbered back-office list (page of
// pages): href gives the URL of a page.
func numberedPager(l *i18n.Locale, page, pages int, href func(int) string) *Pager {
	var first, prev, next string
	if page > 1 {
		first, prev = href(1), href(page-1)
	}
	if page < pages {
		next = href(page + 1)
	}
	pg := newPager(first, prev, next)
	pg.position(l, page, pages, 0, 0, -1)
	return pg
}
