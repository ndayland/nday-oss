package webui

import (
	"net/url"

	"nday.land/nday/internal/webui/i18n"
)

// The event log of a vulnerability page is paged like the PoC list
// (resources.go): EventPageSize events per page, the page in the query
// parameter EventPageParam (from page 2), the log in the paging region
// EventRegion. Everything else on the page (the chart, the totals, the
// share text) is built from all events before PageEvents runs.
const (
	EventRegion    = "r-events"
	EventPageParam = "evp"
	EventPageSize  = 10
)

// PageEvents keeps the events of page (clamped to 1..pages; a page number
// is read with pocPage) and gives the log its pager; href is the URL of a
// page. EventCount stays the number of all events.
func (v *VulnView) PageEvents(l *i18n.Locale, page int, href func(int) string) {
	pages := (len(v.Events) + EventPageSize - 1) / EventPageSize
	page = min(max(page, 1), max(pages, 1))
	v.EventPager = numberedPager(l, page, pages, href)
	v.Events = v.Events[(page-1)*EventPageSize : min(page*EventPageSize, len(v.Events))]
}

// eventHref is the URL of page n of the event log of vulnerability id: the
// request's other query parameters, EventPageParam from page 2, and
// #EventRegion.
func eventHref(loc *i18n.Locale, id string, q url.Values) func(int) string {
	return groupHref(loc, id, q, EventPageParam, EventRegion, 2)
}

// The researcher section pages its outline the same way: ResearchPageSize
// posts per page, ?rp= from page 2, the paging region ResearchRegion. The
// count in the heading and the chart dots use all posts; a signed-in
// visitor's script shows the same page of the real posts (Offset).
const (
	ResearchRegion    = "r-research"
	ResearchPageParam = "rp"
	ResearchPageSize  = 10
)

// Page keeps the entries of page (clamped to 1..pages) and gives the
// outline its pager; nil-safe.
func (v *ResearchView) Page(l *i18n.Locale, page int, href func(int) string) {
	if v == nil {
		return
	}
	pages := (len(v.Entries) + ResearchPageSize - 1) / ResearchPageSize
	page = min(max(page, 1), max(pages, 1))
	v.Offset = (page - 1) * ResearchPageSize
	v.Pager = numberedPager(l, page, pages, href)
	v.Entries = v.Entries[v.Offset:min(page*ResearchPageSize, len(v.Entries))]
}

// researchHref is eventHref for the researcher outline.
func researchHref(loc *i18n.Locale, id string, q url.Values) func(int) string {
	return groupHref(loc, id, q, ResearchPageParam, ResearchRegion, 2)
}

// The discussion section pages its comments the same way: DiscPageSize
// top-level comments (with their replies) per page, ?cmp= from page 2, the
// paging region DiscRegion. A permalink (?c=<id>) without ?cmp= shows the
// page that holds the comment; the pager's links name the page instead.
const (
	DiscRegion    = "r-discussion"
	DiscPageParam = "cmp"
	DiscPageSize  = 10
)

// discHref is eventHref for the discussion: without ?c= (it only picks the
// page when ?cmp= is absent), so page 1's link stays on page 1.
func discHref(loc *i18n.Locale, id string, q url.Values) func(int) string {
	rest := url.Values{}
	for k, v := range q {
		if k != discComment1 {
			rest[k] = v
		}
	}
	return groupHref(loc, id, rest, DiscPageParam, DiscRegion, 2)
}
