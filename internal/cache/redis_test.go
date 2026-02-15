package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func setup(t *testing.T) (*RedisCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := NewRedisCache(mr.Addr(), "", 0)
	return rc, mr
}

func TestCacheKey(t *testing.T) {
	got := cacheKey("example.com")
	want := "domain:example.com"
	if got != want {
		t.Errorf("cacheKey() = %q, want %q", got, want)
	}
}

func TestGet_Miss(t *testing.T) {
	rc, _ := setup(t)
	resp, err := rc.Get(context.Background(), "nonexistent.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on cache miss, got %+v", resp)
	}
}

func TestGet_Hit(t *testing.T) {
	rc, mr := setup(t)
	mr.Set("domain:example.com", `{"domain":"example.com","whois":{"domain_name":"example.com"}}`)

	resp, err := rc.Get(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Whois == nil || resp.Whois.DomainName != "example.com" {
		t.Errorf("Whois.DomainName = %v, want %q", resp.Whois, "example.com")
	}
}

func TestGet_CorruptJSON(t *testing.T) {
	rc, mr := setup(t)
	mr.Set("domain:bad.com", `{not valid json`)

	resp, err := rc.Get(context.Background(), "bad.com")
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
	if resp != nil {
		t.Fatalf("expected nil response on corrupt JSON, got %+v", resp)
	}
}

func TestSetThenGet_RoundTrip(t *testing.T) {
	rc, _ := setup(t)
	ctx := context.Background()

	original := &domain.DomainResponse{
		Domain: "roundtrip.com",
		Whois:  &domain.WhoisInfo{DomainName: "roundtrip.com", Registrar: "TestRegistrar"},
		DNS:    &domain.DNSInfo{A: []string{"1.2.3.4"}},
	}

	rc.Set(ctx, "roundtrip.com", original, 5*time.Minute)

	got, err := rc.Get(ctx, "roundtrip.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil response after Set")
	}
	if got.Domain != original.Domain {
		t.Errorf("Domain = %q, want %q", got.Domain, original.Domain)
	}
	if got.Whois == nil || got.Whois.Registrar != "TestRegistrar" {
		t.Errorf("Whois.Registrar = %v, want %q", got.Whois, "TestRegistrar")
	}
	if got.DNS == nil || len(got.DNS.A) != 1 || got.DNS.A[0] != "1.2.3.4" {
		t.Errorf("DNS.A = %v, want [1.2.3.4]", got.DNS)
	}
}
