package webui

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"nday.land/nday/internal/site"
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

// BuildResourcesView groups rs (already in display order) by kind; nil
// when there is nothing to show.
func BuildResourcesView(rs []site.Resource) *ResourcesView {
	v := &ResourcesView{}
	for _, kind := range site.ResourceKinds {
		g := ResourceGroup{Kind: kind, LabelKey: resourceKindKeys[kind]}
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
			g.Links = append(g.Links, l)
		}
		if len(g.Links) > 0 {
			v.Groups = append(v.Groups, g)
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
