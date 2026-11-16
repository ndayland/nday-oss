// Package xlinks handles the links in allowlisted X posts (collector xposts,
// table x_post_link, migrations/0019_xposts_links_candidates.sql; see
// docs/xposts.md): Classify sorts a link into a coarse kind from its URL
// alone, and Resolve expands t.co short links that the API did not expand
// (raw records stored before the collector asked for entities).
package xlinks

import (
	"net/url"
	"regexp"
	"strings"
)

// Link kinds (x_post_link.kind).
const (
	KindMedia    = "media"    // the post's own photo / video
	KindQuote    = "quote"    // another post on X
	KindPatch    = "patch"    // a commit, pull request, compare or code review
	KindCode     = "code"     // another repository URL (a PoC or not: a URL cannot tell)
	KindPoC      = "poc"      // an exploit archive
	KindAdvisory = "advisory" // a vendor / CERT advisory host
	KindOther    = "other"
)

// advisoryHosts are vendor / CERT advisory hosts (after the "www." strip),
// plus github.com/advisories/ (in Classify); the only place this list lives,
// kept short on purpose. Exact host match: subdomains do not match.
var advisoryHosts = map[string]bool{
	"msrc.microsoft.com":            true,
	"fortiguard.fortinet.com":       true,
	"support.citrix.com":            true,
	"access.redhat.com":             true,
	"chromereleases.googleblog.com": true,
	"httpd.apache.org":              true,
	"security.paloaltonetworks.com": true,
	"sec.cloudapps.cisco.com":       true,
	"supportportal.juniper.net":     true,
	"nvd.nist.gov":                  true,
	"cve.org":                       true,
	"cisa.gov":                      true,
	"kb.cert.org":                   true,
	"jvn.jp":                        true,
}

// pocHosts are exploit archives.
var pocHosts = map[string]bool{
	"exploit-db.com":          true,
	"packetstormsecurity.com": true,
	"packetstorm.news":        true,
}

var (
	// /<user>/status/<id>[/...] on x.com / twitter.com
	statusPathRe = regexp.MustCompile(`^/(?:[A-Za-z0-9_]{1,15}|i/web|i)/status/([0-9]{1,19})(/.*)?$`)
	mediaTailRe  = regexp.MustCompile(`^/(?:photo|video)/[0-9]+/?$`)
	// github.com/<owner>/<repo>/{commit,pull,compare}/...
	ghPatchRe = regexp.MustCompile(`^/[^/]+/[^/]+/(?:commit|commits|pull|compare)/[^/]`)
	ghRepoRe  = regexp.MustCompile(`^/[^/]+/[^/]+`)
)

var xHosts = map[string]bool{"x.com": true, "twitter.com": true, "mobile.twitter.com": true, "mobile.x.com": true}

// Classify returns the host (lower case, leading "www." stripped; "" when the
// URL is not an absolute http(s) URL) and the kind of finalURL, the link's
// final target. postID is the id of the post that contains the link (its
// own photo / video links are "media"). Pure; never fetches anything.
func Classify(finalURL, postID string) (host, kind string) {
	u, err := url.Parse(strings.TrimSpace(finalURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", KindOther
	}
	host = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	host = strings.TrimPrefix(host, "www.")
	p := u.EscapedPath()
	switch {
	case xHosts[host]:
		if m := statusPathRe.FindStringSubmatch(p); m != nil {
			if m[1] == postID && mediaTailRe.MatchString(m[2]) {
				return host, KindMedia
			}
			return host, KindQuote
		}
	case host == "github.com":
		switch {
		case strings.HasPrefix(p, "/advisories/"):
			return host, KindAdvisory
		case ghPatchRe.MatchString(p):
			return host, KindPatch
		case ghRepoRe.MatchString(p):
			return host, KindCode
		}
	case host == "chromium-review.googlesource.com", host == "crbug.com", host == "issues.chromium.org",
		host == "bugs.chromium.org":
		return host, KindPatch
	case host == "gist.github.com":
		if len(p) > 1 {
			return host, KindCode
		}
	case host == "gitlab.com":
		if strings.Contains(p, "/-/commit/") || strings.Contains(p, "/-/merge_requests/") || strings.Contains(p, "/-/compare/") {
			return host, KindPatch
		}
		if ghRepoRe.MatchString(p) {
			return host, KindCode
		}
	case pocHosts[host]:
		return host, KindPoC
	case advisoryHosts[host]:
		return host, KindAdvisory
	}
	return host, KindOther
}
