package safenet

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// cgnatBlock is the Carrier-Grade NAT range (100.64.0.0/10), which is not
// covered by Go's net.IP.IsPrivate().
var cgnatBlock = mustParseCIDR("100.64.0.0/10")

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// BlockedError is returned by DialControl when a connection to a
// private/reserved IP address is rejected.
type BlockedError struct {
	IP net.IP
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("safenet: connection to private/reserved address %s blocked", e.IP)
}

// IsPrivateIP returns true if ip is a loopback, private (RFC 1918), link-local,
// multicast, unspecified, or CGNAT address. These should never be the target of
// outbound connections initiated from user-supplied domains.
func IsPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		cgnatBlock.Contains(ip)
}

// DialControl is a net.Dialer.Control function that rejects connections to
// private/reserved IP addresses. It fires after DNS resolution but before the
// TCP handshake, eliminating TOCTOU races between resolve and connect.
func DialControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("safenet: invalid address %q: %w", address, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("safenet: could not parse IP %q", host)
	}

	if IsPrivateIP(ip) {
		return &BlockedError{IP: ip}
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
