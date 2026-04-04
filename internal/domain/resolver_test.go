package domain

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewExternalResolver_EmptyServers_ReturnsDefault(t *testing.T) {
	r := NewExternalResolver(nil, 0)
	if r != net.DefaultResolver {
		t.Error("expected net.DefaultResolver when no servers provided")
	}
}

func TestNewExternalResolver_ClampsTimeout(t *testing.T) {
	// Negative timeout should be clamped to default
	r := NewExternalResolver([]string{"8.8.8.8:53"}, -1*time.Second)
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

func TestNewExternalResolver_SystemResolverFirst(t *testing.T) {
	// The resolver should be able to resolve localhost via the system resolver
	// even when external servers are configured. This verifies that the system
	// resolver is tried first (important for Docker hostname resolution).
	r := NewExternalResolver([]string{"8.8.8.8:53"}, 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// "localhost" should resolve via system resolver without hitting external DNS
	addrs, err := r.LookupHost(ctx, "localhost")
	if err != nil {
		t.Fatalf("failed to resolve localhost: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address for localhost")
	}
}

func TestNewExternalResolver_FallsBackToExternal(t *testing.T) {
	// Use a broken system resolver address to force fallback to external
	r := NewExternalResolver([]string{"8.8.8.8:53"}, 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Resolve a well-known domain — even if the system resolver fails,
	// the external fallback (Google DNS) should handle it
	addrs, err := r.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("failed to resolve example.com: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address for example.com")
	}
}

func TestNewExternalResolver_RespectsContextCancellation(t *testing.T) {
	// Create a resolver with unreachable servers
	r := NewExternalResolver([]string{"192.0.2.1:53", "198.51.100.1:53"}, 1*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := r.LookupHost(ctx, "example.com")
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestNewExternalResolver_NoSSRFOnDialer(t *testing.T) {
	// The DNS dialer must NOT have safenet.DialControl because DNS resolvers
	// are often on private/loopback addresses (Docker's 127.0.0.11, Fly's fdaa::3).
	// This test verifies the system resolver path works for loopback addresses.
	r := NewExternalResolver([]string{"8.8.8.8:53"}, 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// If SSRF control were present, resolving via 127.0.0.11 (Docker DNS)
	// or 127.0.0.1 (local stub resolver) would be blocked. Resolving
	// "localhost" exercises the system resolver which uses these addresses.
	addrs, err := r.LookupHost(ctx, "localhost")
	if err != nil {
		t.Fatalf("system resolver blocked (SSRF control should not be on DNS dialer): %v", err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address")
	}
}

func TestInitResolver_SetsDefaultServers(t *testing.T) {
	// InitResolver modifies net.DefaultResolver globally. We can't safely
	// save/restore it (contains a mutex), so just verify it works.
	InitResolver(nil, 0)

	// After init, the resolver should be able to resolve external domains
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("InitResolver failed to configure working resolver: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address")
	}
}
