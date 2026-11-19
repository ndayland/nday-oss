package webui

import (
	"net/url"
	"strconv"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/webui/i18n"
)

// Paging of the back office lists (docs/admin.md): every list of records
// shows admin.ListPage rows per page with the one pager. Each list of a page
// has its own query parameters; a list's pager links change only those and
// keep the page's filters and every other list's position (adminLinks).
//
// Each paged list and its pager sit in one region: an element with a stable
// id and data-page-region="<id>" (the pager links end in "#<id>"), holding
// nothing that depends on an id outside it, so a script can later replace a
// region with the same region of another page.

// adminLinks builds the links of one admin page.
type adminLinks struct {
	base string
	vs   url.Values
}

// newAdminLinks keeps the request's values of keys (the page's filters and
// lists' positions).
func newAdminLinks(base string, q url.Values, keys ...string) adminLinks {
	a := adminLinks{base: base, vs: url.Values{}}
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			a.vs.Set(k, v)
		}
	}
	return a
}

// set replaces a kept value ("" removes it), e.g. a normalised filter.
func (a adminLinks) set(k, v string) {
	if v == "" {
		a.vs.Del(k)
	} else {
		a.vs.Set(k, v)
	}
}

// get is a kept value.
func (a adminLinks) get(k string) string { return a.vs.Get(k) }

// href is the page with the kept values changed by kv (name, value pairs;
// "" removes) and the fragment frag ("" none, else without '#').
func (a adminLinks) href(frag string, kv ...string) string {
	vs := url.Values{}
	for k, v := range a.vs {
		vs[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			vs.Del(kv[i])
		} else {
			vs.Set(kv[i], kv[i+1])
		}
	}
	h := a.base
	if len(vs) > 0 {
		h += "?" + vs.Encode()
	}
	if frag != "" {
		h += "#" + frag
	}
	return h
}

// hidden is the kept values except names, for the hidden inputs of a
// filter form (the form changes the others).
func (a adminLinks) hidden(names ...string) []KV {
	skip := map[string]bool{}
	for _, n := range names {
		skip[n] = true
	}
	var out []KV
	for k, v := range a.vs {
		if !skip[k] && len(v) > 0 {
			out = append(out, KV{K: k, V: v[0]})
		}
	}
	sortKV(out)
	return out
}

// KV is one hidden input of a filter form.
type KV struct{ K, V string }

func sortKV(s []KV) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].K < s[j-1].K; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// pageStr is a page number as a parameter value ("" for page 1).
func pageStr(p int) string {
	if p <= 1 {
		return ""
	}
	return strconv.Itoa(p)
}

// pageParam reads a numbered list's ?<name>=: anything but a plain number
// from 1 up to 999999 is page 1 (the service clamps it to the last page).
func pageParam(q url.Values, name string) int { return xPageParam(q.Get(name)) }

// numbered is the pager of a numbered list in region (page X of Y).
func (a adminLinks) numbered(l *i18n.Locale, w admin.Window, param, region string) *Pager {
	return numberedPager(l, w.Page, w.Pages, func(p int) string { return a.href(region, param, pageStr(p)) })
}

// keyset is the pager of a newest-first keyset list in region: older and
// newer are its position parameters (the next and the previous page), idx
// the display-only page number; prev and next the encoded positions the
// service returned ("" none); total the length of the list (counted with
// the list's filters; < 0 = not known). A page without a previous one is
// the first.
func (a adminLinks) keyset(l *i18n.Locale, region, older, newer, idx, prev, next string, total int) *Pager {
	cur := 1
	if prev != "" {
		cur = pageIndex(a.get(idx))
	}
	cur, pages := clampPage(cur, pagesOf(int64(total), admin.ListPage), prev == "", next != "")
	if prev != "" {
		a.set(idx, pageStr(cur)) // the links built from here on carry the clamped number
	}
	var first, prevHref, nextHref string
	if prev != "" {
		first = a.href(region, older, "", newer, "", idx, "")
		prevHref = a.href(region, older, "", newer, prev, idx, pageStr(prevIndex(cur)))
		if prevIndex(cur) == 0 && cur == 2 {
			prevHref = first // page 2 goes back to the first page
		}
	}
	if next != "" {
		nextHref = a.href(region, newer, "", older, next, idx, pageStr(nextIndex(cur)))
	}
	pg := newPager(first, prevHref, nextHref)
	pg.position(l, cur, pages, 0, 0, -1)
	return pg
}

// memPage is one page of a list the page holds whole.
func memPage[T any](rows []T, page int) ([]T, admin.Window) {
	w := admin.PageOf(len(rows), page)
	from := min(w.Offset(), len(rows))
	return rows[from:min(from+admin.ListPage, len(rows))], w
}

// BulkBar is the selection bar of a review list (parts.tmpl "bulkbar";
// static/admin.js): Kind names the batch endpoint (xcand, gh, xd), Acts the
// list's decisions in the per-row order, with the per-row words.
type BulkBar struct {
	Kind string
	Acts []BulkAction
}

// BulkAction is one decision of a bulk bar; Danger ones ask to confirm.
type BulkAction struct {
	Act, Label string
	Danger     bool
}

func newBulkBar(kind string, acts []BulkAction) *BulkBar { return &BulkBar{Kind: kind, Acts: acts} }
