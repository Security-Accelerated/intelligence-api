package domain

import (
	"context"
	"net"
	"time"
)

// DefaultDNSServers is the ordered list of external DNS resolvers used when
// the system resolver is unavailable or misconfigured (e.g., Fly.io internal DNS).
var DefaultDNSServers = []string{
	"8.8.8.8:53",        // Google
	"1.1.1.1:53",        // Cloudflare
	"208.67.222.222:53", // OpenDNS
}

// DefaultDNSDialTimeout is the per-server connection timeout. Kept short so
// fallback to the next server happens quickly within the caller's context deadline.
var DefaultDNSDialTimeout = 2 * time.Second

// NewExternalResolver creates a net.Resolver that uses the given DNS servers
// in order, falling back to the next if the current one fails. The caller's
// context controls the total deadline across all attempts.
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
func InitResolver(servers []string, dialTimeout time.Duration) {
	if len(servers) == 0 {
		servers = DefaultDNSServers
	}
	*net.DefaultResolver = *NewExternalResolver(servers, dialTimeout)
}
