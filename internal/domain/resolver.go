package domain

import (
	"context"
	"net"
	"time"
)

// DefaultDNSServers is the ordered list of external DNS resolvers used when
// the system resolver is unavailable or misconfigured (e.g., Fly.io internal DNS).
var DefaultDNSServers = []string{
	"8.8.8.8:53",       // Google
	"1.1.1.1:53",       // Cloudflare
	"208.67.222.222:53", // OpenDNS
}

// NewExternalResolver creates a net.Resolver that uses the given DNS servers
// in order, falling back to the next if the current one fails.
func NewExternalResolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			var lastErr error
			for _, server := range servers {
				conn, err := d.DialContext(ctx, "udp", server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// InitResolver overrides net.DefaultResolver with an external resolver using
// the provided DNS servers. Call this early in application startup.
func InitResolver(servers []string) {
	if len(servers) == 0 {
		servers = DefaultDNSServers
	}
	*net.DefaultResolver = *NewExternalResolver(servers)
}
