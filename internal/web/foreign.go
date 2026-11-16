package web

import (
	"net"
	"net/netip"
	"strings"
)

// Foreign hosts. Anyone can point a domain of their own at this origin
// (another Cloudflare zone proxying to the same address), which would
// publish a full copy of the site under their name. When NDAY_PUBLIC_URL
// is set, a request whose Host is neither the public host, its bare apex,
// the API host nor a loopback name is therefore not served: GET and HEAD
// answer 308 to the same path and query on the public origin (as the apex
// redirect, apex.go, but never cached: a cached redirect for a spelling of
// the public host that a proxy normalizes, such as a trailing dot, could
// loop), every other method 421 wrong_host.
//
// Loopback names stay served so that checks on the machine itself
// (curl http://127.0.0.1:8080/healthz) work without a Host header. A
// proxy that rewrites the Host header to the public host cannot be told
// apart here; that takes a client certificate on the origin
// (NDAY_TLS_CLIENT_CA with a certificate of this zone only).

// loopbackHost reports whether host (lower case, optional port) is
// localhost, a name under .localhost, or a loopback IP literal.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
