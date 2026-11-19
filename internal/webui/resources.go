package webui

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
	"nday.land/nday/internal/xlinks"
)

// ResourcesView is the public resources section of a vulnerability page:
// the links of the CVE's researcher posts (site.Store.Resources; what is
// public about them is in site/public.go), grouped by kind. The same HTML
// for everyone: who posted a link is not shown.
type ResourcesView struct {
	Groups []ResourceGroup
}

// ResourceGroup is the links of one kind.
type ResourceGroup struct {
	Kind     string // site.ResourceKinds
	LabelKey string // catalog key of the kind label
	Links    []ResourceLink
	// Region and Pager: the two poc groups are paged (PagePoC,
	// PageUnreviewed): their links and pager sit in the paging region
	// Region (docs/pagination.md); "" and nil for the other groups, and
	// Pager nil when one page holds all.
	Region string
	Pager  *Pager
	// Unreviewed: the second poc group — GitHub repositories that do not
	// count as a PoC source of the vulnerability (unverified, or trusted but
	// not counting here). Collapsed (<details>), dim, its heading says how
	// many (Total, before paging); Open when the page was asked for one of
	// its pages (UnreviewedPageParam), so paging without script keeps it open.
	Unreviewed bool
	Total      int
	Open       bool
}

// The PoC group of a vulnerability page is paged (PagePoC): PoCPageSize
// links per page, the page in the query parameter PoCPageParam, the group in
// the paging region PoCRegion. The unreviewed group is paged the same way on
// its own (PageUnreviewed: UnreviewedPageParam, UnreviewedRegion). The
// lifecycle chart draws every link of the PoC group and none of the
// unreviewed group (ChartItems runs before the paging).
const (
	PoCRegion           = "r-poc"
	PoCPageParam        = "pocp"
	PoCPageSize         = 10
	UnreviewedRegion    = "r-pocu"
	UnreviewedPageParam = "pocu"
)

// pocStarred reports whether l shows a star count: a repository that is not
// unverified (an unverified one's stars are hidden).
func pocStarred(l ResourceLink) bool { return l.Repo != "" && !l.Unverified }

// pocOrder orders PoC links by stars, most first; links without a shown
// star count (plain links, unverified repositories) follow all starred
// ones; ties keep their order.
func pocOrder(ls []ResourceLink) {
	sort.SliceStable(ls, func(i, j int) bool {
		a, b := pocStarred(ls[i]), pocStarred(ls[j])
		if a != b {
			return a
		}
		return a && ls[i].Stars > ls[j].Stars
	})
}

// pocPage reads PoCPageParam: a page number from 1, else 1 (PagePoC clamps
// it to the last page).
func pocPage(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// PagePoC orders the PoC group (pocOrder), keeps the links of page (clamped
// to 1..pages) and gives the group its region and pager; href is the URL of
// a page. Call it after the chart's items were taken from v.
func (v *ResourcesView) PagePoC(l *i18n.Locale, page int, href func(int) string) {
	v.pageGroups(l, false, PoCRegion, page, href)
}

// PageUnreviewed is PagePoC for the unreviewed group (UnreviewedRegion);
// open renders it expanded.
func (v *ResourcesView) PageUnreviewed(l *i18n.Locale, page int, open bool, href func(int) string) {
	v.pageGroups(l, true, UnreviewedRegion, page, href)
	if v == nil {
		return
	}
	for i := range v.Groups {
		if v.Groups[i].Unreviewed {
			v.Groups[i].Open = open
		}
	}
}

func (v *ResourcesView) pageGroups(l *i18n.Locale, unreviewed bool, region string, page int, href func(int) string) {
	if v == nil {
		return
	}
	for i := range v.Groups {
		g := &v.Groups[i]
		if g.Kind != xlinks.KindPoC || g.Unreviewed != unreviewed {
			continue
		}
		pocOrder(g.Links)
		pages := (len(g.Links) + PoCPageSize - 1) / PoCPageSize
		page = min(max(page, 1), max(pages, 1))
		g.Region = region
		g.Pager = numberedPager(l, page, pages, href)
		g.Links = g.Links[(page-1)*PoCPageSize : min(page*PoCPageSize, len(g.Links))]
	}
}

// pocHref is the URL of page n of the PoC list of vulnerability id: the
// page's path in loc with the request's other query parameters (q; not
// the throw-away discFreshParam), PoCPageParam from page 2, and #PoCRegion.
func pocHref(loc *i18n.Locale, id string, q url.Values) func(int) string {
	return groupHref(loc, id, q, PoCPageParam, PoCRegion, 2)
}

// unreviewedHref is pocHref for the unreviewed group: UnreviewedPageParam on
// every page, page 1 too, so the group comes back open after a reload
// without script; #UnreviewedRegion.
func unreviewedHref(loc *i18n.Locale, id string, q url.Values) func(int) string {
	return groupHref(loc, id, q, UnreviewedPageParam, UnreviewedRegion, 1)
}

// groupHref builds the page links of a paged resources group: param from
// page from on, the other query parameters kept, #region.
func groupHref(loc *i18n.Locale, id string, q url.Values, param, region string, from int) func(int) string {
	return func(n int) string {
		v := url.Values{}
		for k, vs := range q {
			if k != param && k != discFreshParam {
				v[k] = vs
			}
		}
		if n >= from {
			v.Set(param, strconv.Itoa(n))
		}
		s := loc.Path("/vuln/" + id)
		if e := v.Encode(); e != "" {
			s += "?" + e
		}
		return s + "#" + region
	}
}

// ResourceLink is one link. URL, Text, Title and Host are untrusted
// (escaped by the template engine); URL is an absolute http/https URL
// (site.ResourceKey). The template shows Title followed by Host (dim) when
// there is a title, else Text; the full URL is the link's title attribute.
type ResourceLink struct {
	URL         string
	Text        string // host + path (+ query), no scheme, cut to resourceTextMax runes
	Title       string // the linked page's title (site.Resource.Title), "" = none
	Host        string // shown after Title: lower case, leading "www." stripped
	Researchers int    // distinct researchers who posted it
	// Repo is the GitHub repository's "Owner/Name" (site.Resource.Repo),
	// shown instead of Title / Text and followed by Stars and Created
	// (YYYY-MM-DD, "" = unknown) in place of Host; "" = not a fetched
	// repository.
	Repo    string
	Stars   int
	Created string
	// Unverified marks a repository nobody vouches for, or one under poc
	// that does not count (site.ResourceRepo): no stars shown. Counted: a
	// PoC source of the vulnerability (site.ResourceRepo.Counted).
	Unverified bool
	Counted    bool
	// When is the link's time on the lifecycle chart (chartdots.go):
	// a repository's creation day (NotAfter when Unverified), else the
	// publication time the page states (site.Resource.Published, Precision
	// exact or day), else the first-mentioned day (site.Resource.FirstMentioned,
	// NotAfter: the page existed by then); zero = no time known.
	When      time.Time
	Precision string // exact | day
	NotAfter  bool
}

// resourceTextMax is the length of a shown link text.
const resourceTextMax = 48

// resourceKindKeys are the catalog keys of the kind labels.
var resourceKindKeys = map[string]string{
	xlinks.KindPoC:      "rsch.res.poc",
	xlinks.KindPatch:    "rsch.res.patch",
	xlinks.KindAdvisory: "rsch.res.advisory",
	xlinks.KindCode:     "rsch.res.code",
	xlinks.KindOther:    "rsch.res.other",
}

// resourceText is the shown text of a resource URL: host and path (and
// query), without the scheme or fragment, cut to resourceTextMax runes;
// "" when u is not a showable URL.
func resourceText(u string) string {
	if _, ok := site.ResourceKey(u); !ok {
		return ""
	}
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	s := strings.ToLower(p.Host)
	if path := p.EscapedPath(); path != "/" {
		s += path
	}
	if p.RawQuery != "" {
		s += "?" + p.RawQuery
	}
	return truncRunes(s, resourceTextMax)
}

// resourceHost is the host shown after a title: r.Host, else the URL's
// host (lower case, without a leading "www.").
func resourceHost(r site.Resource) string {
	if r.Host != "" {
		return r.Host
	}
	p, err := url.Parse(r.URL)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(p.Hostname()), "."), "www.")
}

// resourceWhen is ResourceLink.When, Precision and NotAfter of r.
func resourceWhen(r site.Resource) (time.Time, string, bool) {
	if r.Repo != nil {
		if t, err := time.Parse(time.DateOnly, r.Repo.Created); err == nil {
			return t, site.PrecisionDay, r.Repo.Unverified
		}
	}
	if r.Published != nil && (r.PublishedPrecision == site.PrecisionExact || r.PublishedPrecision == site.PrecisionDay) {
		return r.Published.UTC(), r.PublishedPrecision, false
	}
	if t, err := time.Parse(time.DateOnly, r.FirstMentioned); err == nil {
		return t, site.PrecisionDay, true
	}
	return time.Time{}, "", false
}

// BuildResourcesView groups rs (already in display order) by kind; nil
// when there is nothing to show. The poc links split in two: the PoC group
// (every non-repository link and the counted repositories) and right after
// it the unreviewed group (repositories that do not count); either is left
// out when empty.
func BuildResourcesView(rs []site.Resource) *ResourcesView {
	v := &ResourcesView{}
	for _, kind := range site.ResourceKinds {
		g := ResourceGroup{Kind: kind, LabelKey: resourceKindKeys[kind]}
		u := ResourceGroup{Kind: kind, LabelKey: "rsch.res.unreviewed", Unreviewed: true}
		for _, r := range rs {
			if r.Kind != kind {
				continue
			}
			text := resourceText(r.URL)
			if text == "" {
				continue
			}
			l := ResourceLink{URL: r.URL, Text: text, Researchers: r.Researchers}
			if r.Title != "" {
				l.Title, l.Host = r.Title, resourceHost(r)
			}
			if r.Repo != nil {
				l.Repo, l.Stars, l.Created, l.Unverified, l.Counted = r.Repo.FullName, r.Repo.Stars, r.Repo.Created, r.Repo.Unverified, r.Repo.Counted
			}
			l.When, l.Precision, l.NotAfter = resourceWhen(r)
			if kind == xlinks.KindPoC && r.Repo != nil && !r.Repo.Counted {
				u.Links = append(u.Links, l)
				continue
			}
			g.Links = append(g.Links, l)
		}
		if len(g.Links) > 0 {
			v.Groups = append(v.Groups, g)
		}
		if len(u.Links) > 0 {
			u.Total = len(u.Links)
			v.Groups = append(v.Groups, u)
		}
	}
	if len(v.Groups) == 0 {
		return nil
	}
	return v
}

// resources builds the resources section (nil on failure or when empty:
// the section is left out, the rest of the page stays).
func (u *UI) resources(r *http.Request, cve string) *ResourcesView {
	v, err := u.cached(r.Context(), "rsrc|"+cve, func(ctx context.Context) (any, error) {
		return u.srv.Store.Resources(ctx, cve)
	})
	if err != nil {
		u.srv.Log.Warn("resources unavailable", "cve", cve, "err", err)
		return nil
	}
	return BuildResourcesView(v.([]site.Resource))
}
