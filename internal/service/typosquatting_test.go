package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func okTyposquatting(_ context.Context, d string, _ domain.TyposquattingOptions) (*domain.TyposquattingResponse, error) {
	return &domain.TyposquattingResponse{
		Domain: d,
		Depth:  "shallow",
		Count:  2,
		Permutations: []domain.Permutation{
			{Domain: "exarnple.com", Technique: "homoglyph"},
			{Domain: "examlpe.com", Technique: "character_swap"},
		},
	}, nil
}

func failTyposquatting(_ context.Context, _ string, _ domain.TyposquattingOptions) (*domain.TyposquattingResponse, error) {
	return nil, errors.New("typosquatting failed")
}

func newTestTyposquattingService(mc *mockCache) *TyposquattingService {
	svc := NewTyposquattingService(mc, 5*time.Minute, 30*time.Second, 500, 20)
	svc.SetLookup(okTyposquatting)
	return svc
}

func TestTyposquatting_CacheMiss_Success(t *testing.T) {
	mc := newMockCache()
	svc := newTestTyposquattingService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", false, "shallow")
	if hit {
		t.Error("expected cache miss")
	}
	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Count != 2 {
		t.Errorf("Count = %d, want 2", resp.Count)
	}
	if len(resp.Permutations) != 2 {
		t.Errorf("len(Permutations) = %d, want 2", len(resp.Permutations))
	}

	// Should have cached the result
	mc.mu.Lock()
	if mc.setCalls != 1 {
		t.Errorf("expected 1 cache Set call, got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestTyposquatting_CacheHit(t *testing.T) {
	mc := newMockCache()
	cached := &domain.TyposquattingResponse{Domain: "cached.com", Depth: "shallow", Count: 1}
	data, _ := json.Marshal(cached)
	mc.store["typosquatting:cached.com:shallow"] = data

	svc := newTestTyposquattingService(mc)
	// Replace lookup with one that panics to prove it's not called.
	svc.SetLookup(func(_ context.Context, _ string, _ domain.TyposquattingOptions) (*domain.TyposquattingResponse, error) {
		t.Fatal("lookup should not be called on cache hit")
		return nil, nil
	})

	resp, hit := svc.Lookup(context.Background(), "cached.com", false, "shallow")
	if !hit {
		t.Error("expected cache hit")
	}
	if resp.Domain != "cached.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "cached.com")
	}
}

func TestTyposquatting_SeparateCacheKeys(t *testing.T) {
	mc := newMockCache()
	svc := newTestTyposquattingService(mc)

	// Shallow, no active
	svc.Lookup(context.Background(), "example.com", false, "shallow")
	// Deep, no active
	svc.Lookup(context.Background(), "example.com", false, "deep")
	// Shallow, active
	svc.Lookup(context.Background(), "example.com", true, "shallow")
	// Deep, active
	svc.Lookup(context.Background(), "example.com", true, "deep")

	mc.mu.Lock()
	defer mc.mu.Unlock()

	expected := []string{
		"typosquatting:example.com:shallow",
		"typosquatting:example.com:deep",
		"typosquatting+active:example.com:shallow",
		"typosquatting+active:example.com:deep",
	}
	for _, key := range expected {
		if _, ok := mc.store[key]; !ok {
			t.Errorf("expected cache entry for key %q", key)
		}
	}
	if mc.setCalls != 4 {
		t.Errorf("expected 4 cache Set calls, got %d", mc.setCalls)
	}
}

func TestTyposquatting_Failure_ReturnsError(t *testing.T) {
	mc := newMockCache()
	svc := newTestTyposquattingService(mc)
	svc.SetLookup(failTyposquatting)

	resp, hit := svc.Lookup(context.Background(), "fail.com", false, "shallow")
	if hit {
		t.Error("expected cache miss")
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(resp.Errors))
	}
	if resp.Errors[0].Lookup != "typosquatting" {
		t.Errorf("error lookup = %q, want %q", resp.Errors[0].Lookup, "typosquatting")
	}

	// Should not cache failures
	mc.mu.Lock()
	if mc.setCalls != 0 {
		t.Errorf("expected 0 cache Set calls on failure, got %d", mc.setCalls)
	}
	mc.mu.Unlock()
}

func TestTyposquatting_CacheGetError_StillWorks(t *testing.T) {
	mc := newMockCache()
	mc.getErr = errors.New("redis down")
	svc := newTestTyposquattingService(mc)

	resp, hit := svc.Lookup(context.Background(), "example.com", false, "shallow")
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
