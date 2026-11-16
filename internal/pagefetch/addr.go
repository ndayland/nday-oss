package pagefetch

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// ErrRefused is wrapped by every error that means "this request is not
// allowed": a URL that breaks the URL rules (CheckURL), a redirect to such a
// URL or past MaxRedirects, and a connection to an address that is not a
// public unicast address (GuardControl). No connection is made for any of
// them. Use errors.Is(err, ErrRefused).
var ErrRefused = errors.New("pagefetch: refused")

// refused wraps ErrRefused with a reason.
func refused(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRefused}, args...)...)
}

// v4Blocked are the IPv4 ranges that are never dialled: everything that is
// not a public unicast address.
var v4Blocked = prefixes(
	"0.0.0.0/8",       // "this network", incl. 0.0.0.0
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // shared address space (CGNAT)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, cloud metadata (169.254.169.254)
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, incl. 255.255.255.255 broadcast
)

// v6Blocked are ranges inside 2000::/3 (the only IPv6 block accepted at
// all) that are not public unicast.
var v6Blocked = prefixes(
	"2001::/23",     // IETF protocol assignments: Teredo 2001::/32, benchmarking, ORCHID
	"2001:db8::/32", // documentation
	"3fff::/20",     // documentation (RFC 9637)
)

var (
	v6Global    = netip.MustParsePrefix("2000::/3")
	v6NAT64     = netip.MustParsePrefix("64:ff9b::/96")   // well-known NAT64: last 32 bits are IPv4
	v6NAT64Loc  = netip.MustParsePrefix("64:ff9b:1::/48") // local-use NAT64: refused
	v6To4       = netip.MustParsePrefix("2002::/16")      // 6to4: bits 16..47 are IPv4
	v6Compat    = netip.MustParsePrefix("::/96")          // IPv4-compatible (deprecated), :: and ::1
	v4MappedPfx = netip.MustParsePrefix("::ffff:0:0/96")
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsPublicAddr reports whether a is a public unicast address that the
// fetcher may connect to. False for loopback, RFC 1918, CGNAT, link-local
// (incl. cloud metadata), unique-local, multicast, unspecified, broadcast,
// documentation / benchmarking / reserved ranges, addresses with a zone,
// IPv4-compatible IPv6, local-use NAT64, Teredo; IPv4-mapped IPv6,
// well-known NAT64 and 6to4 addresses are judged by the IPv4 address they
// carry. The single predicate of the connect-time guard (GuardControl).
func IsPublicAddr(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	if a.Is4() {
		return !inAny(a, v4Blocked)
	}
	if v4MappedPfx.Contains(a) {
		return IsPublicAddr(a.Unmap())
	}
	if v6NAT64.Contains(a) {
		b := a.As16()
		return IsPublicAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	if v6NAT64Loc.Contains(a) || v6Compat.Contains(a) {
		return false
	}
	if v6To4.Contains(a) {
		b := a.As16()
		return IsPublicAddr(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
	}
	// everything outside 2000::/3 is not global unicast: ULA fc00::/7,
	// link-local fe80::/10, multicast ff00::/8, discard 100::/64, ...
	if !v6Global.Contains(a) {
		return false
	}
	return !inAny(a, v6Blocked)
}

// GuardControl is a net.Dialer Control hook: it runs after name resolution,
// just before each connect(2), on the address actually dialled, so a name
// that resolves (or re-resolves: DNS rebinding) to a non-public address is
// refused without a connection. Only TCP is allowed.
func GuardControl(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return refused("network %q", network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return refused("address %q", address)
	}
	if !IsPublicAddr(ap.Addr()) {
		return refused("non-public address %s", ap.Addr())
	}
	return nil
}
