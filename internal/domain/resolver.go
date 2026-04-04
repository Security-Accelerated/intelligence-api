package domain

import (
	"context"
	"net"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

// DefaultDNSServers is the ordered list of external DNS resolvers used as
// fallback when the system resolver fails (e.g., Fly.io internal DNS).
var DefaultDNSServers = []string{
	"8.8.8.8:53",        // Google
	"1.1.1.1:53",        // Cloudflare
	"208.67.222.222:53", // OpenDNS
}

// DefaultDNSDialTimeout is the per-server connection timeout. Kept short so
// fallback to the next server happens quickly within the caller's context deadline.
var DefaultDNSDialTimeout = 2 * time.Second

// NewExternalResolver creates a net.Resolver that tries the system resolver
// first, then falls back to the given external DNS servers in order. This
// preserves Docker/platform internal DNS (e.g., resolving "postgres" or
// "redis" container names) while providing external fallback for domains
// that the platform resolver can't handle.
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
			d := net.Dialer{
				Timeout: dialTimeout,
				Control: safenet.DialControl,
			}

			// Try the system/platform resolver first (preserves Docker DNS, etc.)
			conn, err := d.DialContext(ctx, network, address)
			if err == nil {
				return conn, nil
			}

			// Fall back to external resolvers
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

// InitResolver overrides net.DefaultResolver with a resolver that tries the
// system DNS first, then falls back to external servers. Call this early in
// application startup.
func InitResolver(servers []string, dialTimeout time.Duration) {
	if len(servers) == 0 {
		servers = DefaultDNSServers
	}
	*net.DefaultResolver = *NewExternalResolver(servers, dialTimeout)
}
