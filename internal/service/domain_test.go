package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

// mockCache is a hand-written mock for DomainCache.
type mockCache struct {
	mu      sync.Mutex
	store   map[string]*domain.DomainResponse
	getErr  error
	setCalls int
}

func newMockCache() *mockCache {
	return &mockCache{store: make(map[string]*domain.DomainResponse)}
}

func (m *mockCache) Get(_ context.Context, key string) (*domain.DomainResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.store[key], nil
}

func (m *mockCache) Set(_ context.Context, key string, resp *domain.DomainResponse, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[key] = resp
	m.setCalls++
}

// helpers to build a testable DomainService with stub lookups.

func okWhois(_ context.Context, _ string) (*domain.WhoisInfo, error) {
	return &domain.WhoisInfo{DomainName: "example.com"}, nil
}
func okDNS(_ context.Context, _ string) (*domain.DNSInfo, error) {
	return &domain.DNSInfo{A: []string{"1.2.3.4"}}, nil
}
func okSSL(_ context.Context, _ string) (*domain.SSLInfo, error) {
	return &domain.SSLInfo{Subject: "example.com"}, nil
}
func okHeaders(_ context.Context, _ string) (*domain.HeadersInfo, error) {
	return &domain.HeadersInfo{StatusCode: 200}, nil
}

func failWhois(_ context.Context, _ string) (*domain.WhoisInfo, error) {
	return nil, errors.New("whois failed")
}
func failDNS(_ context.Context, _ string) (*domain.DNSInfo, error) {
	return nil, errors.New("dns failed")
}
func failSSL(_ context.Context, _ string) (*domain.SSLInfo, error) {
	return nil, errors.New("ssl failed")
}
func failHeaders(_ context.Context, _ string) (*domain.HeadersInfo, error) {
	return nil, errors.New("headers failed")
}

func newTestService(mc *mockCache) *DomainService {
	return &DomainService{
		cache:         mc,
		cacheTTL:      5 * time.Minute,
		lookupWhois:   okWhois,
		lookupDNS:     okDNS,
		lookupSSL:     okSSL,
		lookupHeaders: okHeaders,
	}
}

func TestLookup_CacheHit(t *testing.T) {
	mc := newMockCache()
	cached := &domain.DomainResponse{Domain: "cached.com"}
	mc.store["cached.com"] = cached

	svc := newTestService(mc)
	// replace lookups with ones that panic to prove they aren't called
	svc.lookupWhois = func(context.Context, string) (*domain.WhoisInfo, error) {
		t.Fatal("whois lookup should not be called on cache hit")
		return nil, nil
	}

	resp, hit := svc.Lookup(context.Background(), "cached.com")
	if !hit {
		t.Error("expected cache hit")
	}
	if resp.Domain != "cached.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "cached.com")
	}
}

func TestLookup_CacheMiss_AllSucceed(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com")
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Whois == nil {
		t.Error("expected Whois to be populated")
	}
	if resp.DNS == nil {
		t.Error("expected DNS to be populated")
	}
	if resp.SSL == nil {
		t.Error("expected SSL to be populated")
	}
	if resp.Headers == nil {
		t.Error("expected Headers to be populated")
	}
	if len(resp.Errors) != 0 {
		t.Errorf("expected no errors, got %v", resp.Errors)
	}
	mc.mu.Lock()
	if mc.setCalls != 1 {
		t.Errorf("expected 1 cache Set call, got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestLookup_CacheMiss_AllFail(t *testing.T) {
	mc := newMockCache()
	svc := &DomainService{
		cache:         mc,
		cacheTTL:      5 * time.Minute,
		lookupWhois:   failWhois,
		lookupDNS:     failDNS,
		lookupSSL:     failSSL,
		lookupHeaders: failHeaders,
	}

	resp, hit := svc.Lookup(context.Background(), "fail.com")
	if hit {
		t.Error("expected cache miss")
	}
	if len(resp.Errors) != 4 {
		t.Errorf("expected 4 errors, got %d: %v", len(resp.Errors), resp.Errors)
	}
	mc.mu.Lock()
	if mc.setCalls != 0 {
		t.Errorf("expected 0 cache Set calls when all lookups fail, got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestLookup_CacheMiss_PartialSuccess(t *testing.T) {
	mc := newMockCache()
	svc := &DomainService{
		cache:         mc,
		cacheTTL:      5 * time.Minute,
		lookupWhois:   okWhois,
		lookupDNS:     failDNS,
		lookupSSL:     okSSL,
		lookupHeaders: failHeaders,
	}

	resp, hit := svc.Lookup(context.Background(), "partial.com")
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Whois == nil {
		t.Error("expected Whois to be populated")
	}
	if resp.SSL == nil {
		t.Error("expected SSL to be populated")
	}
	if len(resp.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d: %v", len(resp.Errors), resp.Errors)
	}
	mc.mu.Lock()
	if mc.setCalls != 1 {
		t.Errorf("expected 1 cache Set call (has data), got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestLookup_CacheGetError(t *testing.T) {
	mc := newMockCache()
	mc.getErr = errors.New("redis down")
	svc := newTestService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com")
	if hit {
		t.Error("expected cache miss when Get errors")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	// lookups should still proceed and succeed
	if resp.Whois == nil {
		t.Error("expected Whois to be populated after cache error")
	}
}

func TestLookup_ConcurrentSafety(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := svc.Lookup(context.Background(), "concurrent.com")
			if resp == nil {
				t.Error("expected non-nil response")
			}
		}()
	}
	wg.Wait()
}
