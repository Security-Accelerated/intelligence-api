package safenet

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// reservedPrefixes lists blocked ranges not covered by the netip.Addr
// predicate methods (loopback, private, link-local, multicast, unspecified).
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" (RFC 791)
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments (RFC 6890)
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1 (RFC 5737)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2 (RFC 5737)
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3 (RFC 5737)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved (RFC 1112)
	netip.MustParsePrefix("2001:db8::/32"),   // IPv6 documentation (RFC 3849)
}

// BlockedError is returned by DialControl when a connection to a
// private/reserved IP address is rejected.
type BlockedError struct {
	IP netip.Addr
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("safenet: connection to private/reserved address %s blocked", e.IP)
}

// IsPrivateAddr returns true if addr is a loopback, private (RFC 1918),
// link-local, multicast, unspecified, or otherwise reserved address
// (CGNAT, TEST-NET, benchmarking, 240/4, IPv6 documentation). These should
// never be the target of outbound connections initiated from user-supplied
// domains. IPv4-mapped IPv6 addresses are unmapped before checking so
// ::ffff:10.0.0.1 can't bypass the IPv4 rules.
func IsPrivateAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return true
	}
	for _, p := range reservedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsPrivateIP adapts net.IP callers to IsPrivateAddr. Unparseable values are
// treated as blocked.
func IsPrivateIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return IsPrivateAddr(addr)
}

// DialControl is a net.Dialer.Control function that rejects connections to
// private/reserved IP addresses. It fires after DNS resolution but before the
// TCP handshake, eliminating TOCTOU races between resolve and connect.
func DialControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("safenet: invalid address %q: %w", address, err)
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("safenet: could not parse IP %q: %w", host, err)
	}

	if IsPrivateAddr(addr) {
		return &BlockedError{IP: addr}
	}
	return nil
}

// SafeDialer returns a net.Dialer with the given timeout and a Control function
// that blocks connections to private/reserved IP addresses.
func SafeDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: DialControl,
	}
}
