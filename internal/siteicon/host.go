// Package siteicon keeps the small icons ("favicons") of the third-party
// sites the vulnerability page links to (table site_icon,
// migrations/0028_site_icon.sql; see docs/siteicons.md). A background job
// (`nday site-icons`, Run) fetches them through internal/pagefetch
// (SSRF-guarded, https only), validates the bytes (Validate) and stores
// them; the site serves the stored bytes from its own origin, so readers
// never contact the third parties. Nothing here is called while a page is
// served except the read-only lookups (Lookup, Load).
package siteicon

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// hostRe is a lower-case ASCII (or punycode) DNS name of at least two
// labels: letters, digits and inner hyphens, 1..63 bytes a label. The same
// rule is the CHECK of site_icon.host.
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// MaxHost is the longest host name accepted.
const MaxHost = 253

// ValidHost reports whether h is already a normalised icon host: lower-case
// ASCII letters, digits, hyphens and dots, at least two labels, no port, no
// trailing dot, not an IP address, at most MaxHost bytes. The serving route
// accepts exactly these (nothing is normalised there).
func ValidHost(h string) bool {
	if len(h) == 0 || len(h) > MaxHost || !hostRe.MatchString(h) {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	// a last label of digits only is not a DNS name (1.2.3.4 is caught
	// above; this also refuses forms like 0x7f.1)
	last := h[strings.LastIndexByte(h, '.')+1:]
	return strings.Trim(last, "0123456789") != ""
}

// HostOf is the icon host of an absolute http/https link: its host name
// lower-cased, without port and trailing dot; ok is false for anything
// else (relative links, other schemes, IP literals, non-ASCII names that
// are not punycode, names ValidHost refuses).
func HostOf(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !ValidHost(h) {
		return "", false
	}
	return h, true
}
