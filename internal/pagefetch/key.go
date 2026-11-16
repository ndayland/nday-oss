package pagefetch

import (
	"net/url"
	"strings"
)

// MaxURL is the longest URL CheckURL and URLKey accept.
const MaxURL = 2048

// URLKey is the de-duplication key of a page URL, shared by the page queue
// (internal/webpages, web_page.url_key) and the site's resources
// (site.ResourceKey) so the two cannot drift: scheme and host lower case,
// the fragment and one trailing slash of the path dropped, the query kept.
// ok is false when u is longer than MaxURL or not an absolute http/https URL
// with a host and without user info.
func URLKey(u string) (key string, ok bool) {
	if len(u) > MaxURL {
		return "", false
	}
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || p.Hostname() == "" || p.User != nil || p.Opaque != "" {
		return "", false
	}
	key = strings.ToLower(p.Scheme) + "://" + strings.ToLower(p.Host) + strings.TrimSuffix(p.EscapedPath(), "/")
	if p.RawQuery != "" || p.ForceQuery {
		key += "?" + p.RawQuery
	}
	return key, true
}
