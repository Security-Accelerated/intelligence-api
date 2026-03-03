package service

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func okSubdomain(_ context.Context, d string, _ domain.SubdomainOptions) (*domain.SubdomainResponse, error) {
	return &domain.SubdomainResponse{
		Domain: d,
		Count:  2,
		Subdomains: []domain.SubdomainEntry{
			{Domain: "www." + d, Source: "crt.sh"},
			{Domain: "mail." + d, Source: "crt.sh"},
		},
	}, nil
}

func failSubdomain(_ context.Context, _ string, _ domain.SubdomainOptions) (*domain.SubdomainResponse, error) {
	return nil, errors.New("subdomain failed")
}

func newTestSubdomainService(mc *mockCache) *SubdomainService {
	svc := NewSubdomainService(mc, 5*time.Minute, 30*time.Second, 500, 20)
	svc.SetLookup(okSubdomain)
	return svc
}

func TestSubdomain_CacheMiss_Success(t *testing.T) {
	mc := newMockCache()
	svc := newTestSubdomainService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", false)
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Count != 2 {
		t.Errorf("Count = %d, want 2", resp.Count)
	}
	if len(resp.Subdomains) != 2 {
		t.Errorf("len(Subdomains) = %d, want 2", len(resp.Subdomains))
	}

	mc.mu.Lock()
	if mc.setCalls != 1 {
		t.Errorf("expected 1 cache Set call, got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestSubdomain_CacheHit(t *testing.T) {
	mc := newMockCache()
	cached := &domain.SubdomainResponse{Domain: "cached.com", Count: 1}
	data, _ := json.Marshal(cached)
	mc.store["subdomain:cached.com"] = data

	svc := newTestSubdomainService(mc)
	svc.SetLookup(func(_ context.Context, _ string, _ domain.SubdomainOptions) (*domain.SubdomainResponse, error) {
		t.Fatal("lookup should not be called on cache hit")
		return nil, nil
	})

	resp, hit := svc.Lookup(context.Background(), "cached.com", false)
	if !hit {
		t.Error("expected cache hit")
	}
	if resp.Domain != "cached.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "cached.com")
	}
}

func TestSubdomain_SeparateCacheKeys(t *testing.T) {
	mc := newMockCache()
	svc := newTestSubdomainService(mc)

	svc.Lookup(context.Background(), "example.com", false)
	svc.Lookup(context.Background(), "example.com", true)

	mc.mu.Lock()
	defer mc.mu.Unlock()

	expected := []string{
		"subdomain:example.com",
		"subdomain+check_live:example.com",
	}
	for _, key := range expected {
		if _, ok := mc.store[key]; !ok {
			t.Errorf("expected cache entry for key %q", key)
		}
	}
	if mc.setCalls != 2 {
		t.Errorf("expected 2 cache Set calls, got %d", mc.setCalls)
	}
}

func TestSubdomain_Failure_ReturnsError(t *testing.T) {
	mc := newMockCache()
	svc := newTestSubdomainService(mc)
	svc.SetLookup(failSubdomain)

	resp, hit := svc.Lookup(context.Background(), "fail.com", false)
	if hit {
		t.Error("expected cache miss")
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(resp.Errors))
	}
	if resp.Errors[0].Lookup != "subdomain" {
		t.Errorf("error lookup = %q, want %q", resp.Errors[0].Lookup, "subdomain")
	}

	mc.mu.Lock()
	if mc.setCalls != 0 {
		t.Errorf("expected 0 cache Set calls on failure, got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestSubdomain_CacheGetError_StillWorks(t *testing.T) {
	mc := newMockCache()
	mc.getErr = errors.New("redis down")
	svc := newTestSubdomainService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", false)
	if hit {
		t.Error("expected cache miss when Get errors")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Count != 2 {
		t.Errorf("Count = %d, want 2", resp.Count)
	}
}

func TestSubdomain_CacheUnmarshalError_FallsBackToLookup(t *testing.T) {
	mc := newMockCache()
	mc.store["subdomain:example.com:"] = []byte("{invalid json")
	svc := newTestSubdomainService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", false)
	if hit {
		t.Error("expected cache miss when unmarshal fails")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Count != 2 {
		t.Errorf("Count = %d, want 2 (from live lookup)", resp.Count)
	}
}

func TestSubdomain_ConstructorDefaults(t *testing.T) {
	mc := newMockCache()
	svc := NewSubdomainService(mc, 5*time.Minute, 30*time.Second, 0, 0)
	svc.SetLookup(func(_ context.Context, _ string, opts domain.SubdomainOptions) (*domain.SubdomainResponse, error) {
		if opts.MaxResults != 500 {
			t.Errorf("MaxResults = %d, want 500 (default)", opts.MaxResults)
		}
		if opts.Concurrency != 20 {
			t.Errorf("Concurrency = %d, want 20 (default)", opts.Concurrency)
		}
		return &domain.SubdomainResponse{Domain: "test.com"}, nil
	})

	svc.Lookup(context.Background(), "test.com", false)
}

func TestSubdomain_ConstructorRespectsCustomValues(t *testing.T) {
	mc := newMockCache()
	svc := NewSubdomainService(mc, 5*time.Minute, 30*time.Second, 100, 5)
	svc.SetLookup(func(_ context.Context, _ string, opts domain.SubdomainOptions) (*domain.SubdomainResponse, error) {
		if opts.MaxResults != 100 {
			t.Errorf("MaxResults = %d, want 100", opts.MaxResults)
		}
		if opts.Concurrency != 5 {
			t.Errorf("Concurrency = %d, want 5", opts.Concurrency)
		}
		return &domain.SubdomainResponse{Domain: "test.com"}, nil
	})

	svc.Lookup(context.Background(), "test.com", false)
}

func TestSubdomain_DomainNameReachesLookup(t *testing.T) {
	mc := newMockCache()
	svc := newTestSubdomainService(mc)

	var captured string
	svc.SetLookup(func(_ context.Context, d string, _ domain.SubdomainOptions) (*domain.SubdomainResponse, error) {
		captured = d
		return &domain.SubdomainResponse{Domain: d}, nil
	})

	svc.Lookup(context.Background(), "forwarded.com", false)
	if captured != "forwarded.com" {
		t.Errorf("lookup received domain = %q, want %q", captured, "forwarded.com")
	}
}

func TestSubdomain_ConcurrentSafety(t *testing.T) {
	mc := newMockCache()
	svc := newTestSubdomainService(mc)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := svc.Lookup(context.Background(), "concurrent.com", false)
			if resp == nil {
				t.Error("expected non-nil response")
			}
		}()
	}
	wg.Wait()
}
