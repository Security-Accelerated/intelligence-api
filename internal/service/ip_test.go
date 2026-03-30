package service

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
)

func stubIPService() *IPService {
	svc := &IPService{
		cache:         newMockCache(),
		cacheTTL:      time.Minute,
		lookupTimeout: 30 * time.Second,
		alerter:       &notifications.NoopRecorder{},
	}
	svc.SetLookups(
		func(_ net.IP) (*domain.GeoIPInfo, error) {
			return &domain.GeoIPInfo{Country: "US", City: "Mountain View"}, nil
		},
		func(_ net.IP) (*domain.IPASNInfo, error) {
			return &domain.IPASNInfo{ASN: 15169, Organization: "Google LLC"}, nil
		},
		func(_ context.Context, _ string) (*domain.ReverseDNSInfo, error) {
			return &domain.ReverseDNSInfo{Hostnames: []string{"dns.google"}}, nil
		},
		func(_ context.Context, _ string) (*domain.AbuseContactInfo, error) {
			return &domain.AbuseContactInfo{Email: "abuse@google.com"}, nil
		},
		func(_ context.Context, _ string) (*domain.ThreatIntelInfo, []domain.LookupError) {
			return &domain.ThreatIntelInfo{RiskLevel: "none", Score: 0}, nil
		},
	)
	return svc
}

func TestIPService_Lookup_AllFields(t *testing.T) {
	svc := stubIPService()
	resp, cached := svc.Lookup(context.Background(), "8.8.8.8", domain.IPLookupOptions{ThreatIntel: true})

	if cached {
		t.Error("expected cache miss on first lookup")
	}
	if resp.IP != "8.8.8.8" {
		t.Errorf("IP = %q, want %q", resp.IP, "8.8.8.8")
	}
	if resp.Geo == nil || resp.Geo.Country != "US" {
		t.Error("expected geo info with Country=US")
	}
	if resp.ASN == nil || resp.ASN.ASN != 15169 {
		t.Error("expected ASN info with ASN=15169")
	}
	if resp.ReverseDNS == nil || len(resp.ReverseDNS.Hostnames) == 0 {
		t.Error("expected reverse DNS hostnames")
	}
	if resp.AbuseContact == nil || resp.AbuseContact.Email != "abuse@google.com" {
		t.Error("expected abuse contact email")
	}
	if resp.ThreatIntel == nil {
		t.Error("expected threat intel info")
	}
	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}
}

func TestIPService_Lookup_ThreatIntelOptIn(t *testing.T) {
	tiCalled := false
	svc := stubIPService()
	svc.SetThreatIntelLookup(func(_ context.Context, _ string) (*domain.ThreatIntelInfo, []domain.LookupError) {
		tiCalled = true
		return &domain.ThreatIntelInfo{RiskLevel: "none"}, nil
	})

	// Without threat_intel
	svc.Lookup(context.Background(), "8.8.8.8", domain.IPLookupOptions{ThreatIntel: false})
	if tiCalled {
		t.Error("threat intel should not be called when not requested")
	}

	// With threat_intel
	svc.Lookup(context.Background(), "8.8.8.8", domain.IPLookupOptions{ThreatIntel: true})
	if !tiCalled {
		t.Error("threat intel should be called when requested")
	}
}

func TestIPService_Lookup_PartialFailure(t *testing.T) {
	svc := stubIPService()
	svc.lookupReverseDNS = func(_ context.Context, _ string) (*domain.ReverseDNSInfo, error) {
		return nil, net.UnknownNetworkError("test error")
	}

	resp, _ := svc.Lookup(context.Background(), "8.8.8.8", domain.IPLookupOptions{})

	if resp.Geo == nil {
		t.Error("geo should still succeed on partial failure")
	}
	if resp.ReverseDNS != nil {
		t.Error("reverse DNS should be nil on failure")
	}
	if len(resp.Errors) == 0 {
		t.Error("expected at least one error")
	}
	found := false
	for _, e := range resp.Errors {
		if e.Lookup == "reverse_dns" {
			found = true
		}
	}
	if !found {
		t.Error("expected error with lookup=reverse_dns")
	}
}

func TestIPService_Lookup_NilGeo(t *testing.T) {
	svc := stubIPService()
	svc.lookupGeo = nil
	svc.lookupASN = nil

	resp, _ := svc.Lookup(context.Background(), "8.8.8.8", domain.IPLookupOptions{})

	if resp.Geo != nil {
		t.Error("expected nil geo when reader not configured")
	}
	if resp.ASN != nil {
		t.Error("expected nil ASN when reader not configured")
	}
	// Other lookups should still work
	if resp.ReverseDNS == nil {
		t.Error("reverse DNS should still work without geo reader")
	}
}

func TestBuildIPCacheKey(t *testing.T) {
	tests := []struct {
		ip   string
		opts domain.IPLookupOptions
		want string
	}{
		{"8.8.8.8", domain.IPLookupOptions{}, "ip:8.8.8.8"},
		{"8.8.8.8", domain.IPLookupOptions{ThreatIntel: true}, "ip:8.8.8.8:threat_intel"},
		{"2001:4860:4860::8888", domain.IPLookupOptions{}, "ip:2001:4860:4860::8888"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := buildIPCacheKey(tt.ip, tt.opts)
			if got != tt.want {
				t.Errorf("buildIPCacheKey(%q, %+v) = %q, want %q", tt.ip, tt.opts, got, tt.want)
			}
		})
	}
}
