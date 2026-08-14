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

func TestNewExternalResolver_NegativeTimeout_ReturnsValidResolver(t *testing.T) {
	addr, _ := startDNSServer(t, testZone{A: []string{"203.0.113.7"}})

	r := NewExternalResolver([]string{addr}, -1*time.Second)
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("resolver with clamped timeout should work: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address")
	}
}

func TestNewExternalResolver_ResolvesExternalDomain(t *testing.T) {
	addr, hits := startDNSServer(t, testZone{A: []string{"203.0.113.8"}})

	r := NewExternalResolver([]string{addr}, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("failed to resolve: %v", err)
	}
	if len(addrs) == 0 || addrs[0] != "203.0.113.8" {
		t.Errorf("addrs = %v, want the configured server's answer", addrs)
	}
	if hits.Load() == 0 {
		t.Error("the configured server was never queried — resolv.conf may have been used instead")
	}
}

func TestNewExternalResolver_FallsBackToNextServer(t *testing.T) {
	// A blackholed first server: routable, accepts the packet, never answers.
	// See TestFailover_* for the full matrix.
	prev := DefaultDNSPerServerTimeout
	DefaultDNSPerServerTimeout = 150 * time.Millisecond
	t.Cleanup(func() { DefaultDNSPerServerTimeout = prev })

	dead, _ := startBlackholeDNS(t)
	live, _ := startDNSServer(t, testZone{A: []string{"203.0.113.9"}})

	r := NewExternalResolver([]string{dead, live}, 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("fallback to second server failed: %v", err)
	}
	if len(addrs) == 0 || addrs[0] != "203.0.113.9" {
		t.Errorf("addrs = %v, want the second server's answer", addrs)
	}
}

func TestNewExternalResolver_RespectsContextCancellation(t *testing.T) {
	r := NewExternalResolver([]string{"192.0.2.1:53", "198.51.100.1:53"}, 1*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := r.LookupHost(ctx, "example.com")
	if err == nil {
		t.Error("expected error with canceled context")
	}
}

func TestInitResolver_SetsDefaultServers(t *testing.T) {
	prevResolver := externalResolver.Load()
	prevActive := activeDNSServers
	t.Cleanup(func() {
		externalResolver.Store(prevResolver)
		activeDNSServers = prevActive
	})

	// Empty input falls back to the built-in list and installs a working
	// resolver for lookups. Asserted on the wiring rather than by resolving a
	// real name, so it holds with no network.
	InitResolver(nil, 0)

	if got := ActiveDNSServers(); len(got) != len(DefaultDNSServers) {
		t.Errorf("ActiveDNSServers() = %v, want the defaults", got)
	}
	if Resolver() == net.DefaultResolver {
		t.Error("InitResolver did not install a lookup resolver")
	}
	if Resolver().Dial == nil {
		t.Error("InitResolver did not install a Dial hook")
	}
	if !Resolver().PreferGo {
		t.Error("InitResolver must set PreferGo so the Dial hook is used")
	}

	// InitResolver must not touch the global: infrastructure connections
	// (postgres, redis) keep resolving through the system resolver. This is
	// the regression that broke pooled reconnects — see issue #62.
	if net.DefaultResolver.Dial != nil {
		t.Error("InitResolver installed a Dial hook on net.DefaultResolver; " +
			"internal hostnames would stop resolving once pooled connections recycle")
	}

	// And with explicit servers, a real lookup goes to them.
	addr, hits := startDNSServer(t, testZone{A: []string{"203.0.113.11"}})
	InitResolver([]string{addr}, time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := Resolver().LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("InitResolver failed to configure a working resolver: %v", err)
	}
	if len(addrs) == 0 || addrs[0] != "203.0.113.11" {
		t.Errorf("addrs = %v, want the configured server's answer", addrs)
	}
	if hits.Load() == 0 {
		t.Error("configured server was never queried")
	}
}
