package domain

import (
	"context"
	"net"
	"testing"
)

func TestLookupDNS_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	info, err := LookupDNS(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if info != nil {
		t.Errorf("expected nil info for cancelled context, got %+v", info)
	}
}

func TestLookupDNS_NonexistentDomain(t *testing.T) {
	info, err := LookupDNS(context.Background(), "this-domain-does-not-exist-xyz-42.invalid")
	if err == nil {
		t.Fatal("expected error for nonexistent domain, got nil")
	}
	if info != nil {
		t.Errorf("expected nil info for nonexistent domain, got %+v", info)
	}
}

func TestLookupDNS_CNAMEFiltersSelf(t *testing.T) {
	// Most non-CNAME domains return "domain." from LookupCNAME, which the
	// implementation should filter out (cname != domain+".").
	info, err := LookupDNS(context.Background(), "example.com")
	if err != nil {
		t.Skipf("skipping: DNS lookup failed (network unavailable?): %v", err)
	}
	if info == nil {
		t.Skip("skipping: got nil info for example.com")
	}

	// example.com is not a CNAME — the self-referencing "example.com." should
	// be filtered out.
	if info.CNAME != "" {
		t.Errorf("expected empty CNAME for example.com (self-referencing CNAME should be filtered), got %q", info.CNAME)
	}
}

func TestLookupDNS_PartialSuccess(t *testing.T) {
	// example.com should have at least A records. Even if some record types
	// are empty, we should get a non-nil response with whatever resolved.
	info, err := LookupDNS(context.Background(), "example.com")
	if err != nil {
		t.Skipf("skipping: DNS lookup failed (network unavailable?): %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil info for example.com")
	}
	if len(info.A) == 0 && len(info.AAAA) == 0 {
		t.Error("expected at least one A or AAAA record for example.com")
	}
}

func TestLookupDNS_IPv4And6Separation(t *testing.T) {
	// Verify that IPv4 addresses land in A and IPv6 addresses in AAAA.
	info, err := LookupDNS(context.Background(), "example.com")
	if err != nil {
		t.Skipf("skipping: DNS lookup failed (network unavailable?): %v", err)
	}
	if info == nil {
		t.Skip("skipping: got nil info for example.com")
	}

	for _, addr := range info.A {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			t.Errorf("A record contains non-IPv4 address: %q", addr)
		}
	}
	for _, addr := range info.AAAA {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil {
			t.Errorf("AAAA record contains non-IPv6 address: %q", addr)
		}
	}
}

func TestLookupDNS_NXDOMAINReturnsNilAndError(t *testing.T) {
	// .invalid TLD is guaranteed by RFC 6761 to never resolve.
	info, err := LookupDNS(context.Background(), "guaranteed-nxdomain.invalid")
	if info != nil {
		t.Errorf("expected nil info for nxdomain, got %+v", info)
	}
	if err == nil {
		t.Error("expected error for nxdomain, got nil")
	}
}
