package admin

import "slices"

// Paging of the back office lists (docs/admin.md): every list of records
// shows at most ListPage rows per page. A list whose total is small and
// cheap to count is numbered (Window: page N of M, LIMIT/OFFSET); a list
// over a big or growing table pages by keyset (keysetPage) both ways, and
// a separate count with the same filters gives its number of pages (a page
// number next to a position only labels the page; alone it picks one of
// the first or last pages, Keyset.Skip).

// ListPage is the page size of every back office list.
const ListPage = 10

// Window is one page of a numbered list.
type Window struct {
	Page  int // 1-based, after clamping to [1, Pages]
	Pages int // ≥ 1
	Total int // rows in the whole list
}

// window clamps page (anything below 1 is 1, past the end is the last
// page) for a list of total rows.
func window(total, page int) Window {
	w := Window{Total: total, Pages: max(1, (total+ListPage-1)/ListPage)}
	w.Page = min(max(page, 1), w.Pages)
	return w
}

// Offset is the number of rows before the page.
func (w Window) Offset() int { return (w.Page - 1) * ListPage }

// Keyset is the position of a newest-first keyset list: Older continues
// after that row (the next page), Newer goes back to the rows just before
// it (the previous page). Neither: the first page, or a page picked by its
// number (the web pager's first and last pages): Skip rows from the
// newest, or with FromEnd from the oldest, then Take rows (0 = a full
// page). Skip is at most MaxKeysetSkip; a larger one is the first page.
type Keyset[C any] struct {
	Older, Newer *C
	Skip, Take   int
	FromEnd      bool
}

// MaxKeysetSkip bounds Keyset.Skip: a page picked by number reads at most
// three pages of rows, however long the list.
const MaxKeysetSkip = 2 * ListPage

// keysetPage runs one page of a newest-first keyset list. fetch reads up
// to n rows strictly after cur in list order (back false: older, newest
// first; cur nil = from the newest) or strictly before it (back true:
// newer, oldest first; cur nil = from the oldest). prev is the position of
// the previous page (nil on the first page), next that of the next one
// (nil on the last page). A previous page that reaches the newest rows is
// the first page itself, so it is always full and never offers a previous
// link; so is a page picked by number that would.
func keysetPage[T, C any](pos Keyset[C], limit int, fetch func(cur *C, back bool, n int) ([]T, error),
	key func(T) C) (rows []T, prev, next *C, err error) {
	if pos.Older == nil && pos.Newer == nil && (pos.Skip > 0 || pos.FromEnd) && pos.Skip <= MaxKeysetSkip {
		take := pos.Take
		if take < 1 || take > limit {
			take = limit
		}
		if pos.FromEnd {
			// the take rows before the last Skip ones, and one more to
			// tell whether anything comes before them
			if rows, err = fetch(nil, true, pos.Skip+take+1); err != nil {
				return nil, nil, nil, err
			}
			if len(rows) > pos.Skip+take {
				rows = rows[pos.Skip : pos.Skip+take]
				slices.Reverse(rows)
				p := key(rows[0])
				if pos.Skip > 0 {
					n := key(rows[len(rows)-1])
					next = &n
				}
				return rows, &p, next, nil
			}
		} else {
			if rows, err = fetch(nil, false, pos.Skip+limit+1); err != nil {
				return nil, nil, nil, err
			}
			if len(rows) > pos.Skip {
				rows = rows[pos.Skip:]
				if len(rows) > limit {
					rows = rows[:limit]
					n := key(rows[len(rows)-1])
					next = &n
				}
				p := key(rows[0])
				return rows, &p, next, nil
			}
		}
	}
	pos.Skip, pos.Take, pos.FromEnd = 0, 0, false
	if pos.Newer != nil {
		rows, err = fetch(pos.Newer, true, limit+1)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			slices.Reverse(rows)
			p, n := key(rows[0]), key(rows[len(rows)-1])
			return rows, &p, &n, nil
		}
		pos = Keyset[C]{}
	}
	rows, err = fetch(pos.Older, false, limit+1)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(rows) > limit {
		rows = rows[:limit]
		n := key(rows[len(rows)-1])
		next = &n
	}
	if pos.Older != nil && len(rows) > 0 {
		p := key(rows[0])
		prev = &p
	}
	return rows, prev, next, nil
}

// PageOf is the window of page (clamped) in a list of total rows, for a
// list the page already holds whole (paged in memory).
func PageOf(total, page int) Window { return window(total, page) }
