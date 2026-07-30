package domain

import (
	"context"
	"net"
	"time"
)

// DefaultDNSServers is the ordered list of external DNS resolvers used for
// all runtime lookups (domain intelligence, IP intelligence, etc.).
var DefaultDNSServers = []string{
	"8.8.8.8:53",        // Google
	"1.1.1.1:53",        // Cloudflare
	"208.67.222.222:53", // OpenDNS
}

// DefaultDNSDialTimeout is the per-server connection timeout.
var DefaultDNSDialTimeout = 30 * time.Second

// NewExternalResolver creates a net.Resolver that uses the given external DNS
// servers in order, falling back to the next if the current one fails.
func NewExternalResolver(servers []string, dialTimeout time.Duration) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	if dialTimeout <= 0 {
		dialTimeout = DefaultDNSDialTimeout
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			var lastErr error
			for _, server := range servers {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				conn, err := d.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// activeDNSServers holds the resolver addresses configured via InitResolver,
// for lookups that need raw DNS access (e.g. DNSSEC/CAA via miekg/dns) rather
// than net.Resolver.
var activeDNSServers = DefaultDNSServers

// ActiveDNSServers returns the resolver addresses configured via InitResolver
// (the defaults when InitResolver hasn't been called).
func ActiveDNSServers() []string {
	return activeDNSServers
}

// InitResolver overrides net.DefaultResolver with an external resolver.
// Call this AFTER database and Redis connections are established so that
// platform-internal hostnames (postgres, redis) resolve via system DNS.
func InitResolver(servers []string, dialTimeout time.Duration) {
	if len(servers) == 0 {
		servers = DefaultDNSServers
	}
	activeDNSServers = servers
	*net.DefaultResolver = *NewExternalResolver(servers, dialTimeout)
}
