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
	r := NewExternalResolver([]string{"8.8.8.8:53"}, -1*time.Second)
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	r := NewExternalResolver([]string{"8.8.8.8:53"}, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("failed to resolve example.com: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address for example.com")
	}
}

func TestNewExternalResolver_FallsBackToNextServer(t *testing.T) {
	// First server is unreachable (TEST-NET), second is Google DNS
	r := NewExternalResolver([]string{"192.0.2.1:53", "8.8.8.8:53"}, 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("fallback to second server failed: %v", err)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address")
	}
}

func TestNewExternalResolver_RespectsContextCancellation(t *testing.T) {
	r := NewExternalResolver([]string{"192.0.2.1:53", "198.51.100.1:53"}, 1*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := r.LookupHost(ctx, "example.com")
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestInitResolver_SetsDefaultServers(t *testing.T) {
	InitResolver(nil, 0)

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
