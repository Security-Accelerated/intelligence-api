package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// mockRepository implements Repository with a configurable response and a call counter.
type mockRepository struct {
	customer *Customer
	err      error
	calls    atomic.Int64
}

func (m *mockRepository) GetByKey(_ context.Context, _ string) (*Customer, error) {
	m.calls.Add(1)
	return m.customer, m.err
}

func TestCachedRepository_CacheHit(t *testing.T) {
	inner := &mockRepository{customer: &Customer{ID: 1, Name: "acme"}}
	repo := NewCachedRepository(inner, 5*time.Minute)

	ctx := context.Background()
	c1, err := repo.GetByKey(ctx, "key-1")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	c2, err := repo.GetByKey(ctx, "key-1")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if c1 != c2 {
		t.Error("expected same pointer from cache")
	}
	if got := inner.calls.Load(); got != 1 {
		t.Errorf("inner calls = %d, want 1", got)
	}
}

func TestCachedRepository_CacheMiss_DifferentKeys(t *testing.T) {
	inner := &mockRepository{customer: &Customer{ID: 1}}
	repo := NewCachedRepository(inner, 5*time.Minute)

	ctx := context.Background()
	if _, err := repo.GetByKey(ctx, "key-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByKey(ctx, "key-b"); err != nil {
		t.Fatal(err)
	}

	if got := inner.calls.Load(); got != 2 {
		t.Errorf("inner calls = %d, want 2", got)
	}
}

func TestCachedRepository_Expiry(t *testing.T) {
	inner := &mockRepository{customer: &Customer{ID: 1}}
	repo := NewCachedRepository(inner, 1*time.Millisecond)

	ctx := context.Background()
	if _, err := repo.GetByKey(ctx, "key-1"); err != nil {
		t.Fatal(err)
	}

	time.Sleep(5 * time.Millisecond)

	if _, err := repo.GetByKey(ctx, "key-1"); err != nil {
		t.Fatal(err)
	}

	if got := inner.calls.Load(); got != 2 {
		t.Errorf("inner calls = %d, want 2 (entry should have expired)", got)
	}
}

func TestCachedRepository_InnerError_NotCached(t *testing.T) {
	dbErr := errors.New("connection refused")
	inner := &mockRepository{err: dbErr}
	repo := NewCachedRepository(inner, 5*time.Minute)

	ctx := context.Background()
	_, err := repo.GetByKey(ctx, "key-1")
	if !errors.Is(err, dbErr) {
		t.Fatalf("err = %v, want %v", err, dbErr)
	}

	if got := repo.Size(); got != 0 {
		t.Errorf("cache size = %d, want 0 (errors should not be cached)", got)
	}
}

func TestCachedRepository_InvalidateAll(t *testing.T) {
	inner := &mockRepository{customer: &Customer{ID: 1}}
	repo := NewCachedRepository(inner, 5*time.Minute)

	ctx := context.Background()
	if _, err := repo.GetByKey(ctx, "key-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByKey(ctx, "key-2"); err != nil {
		t.Fatal(err)
	}
	if got := repo.Size(); got != 2 {
		t.Fatalf("size before invalidate = %d, want 2", got)
	}

	repo.InvalidateAll()

	if got := repo.Size(); got != 0 {
		t.Errorf("size after invalidate = %d, want 0", got)
	}

	// Next lookup should hit inner again
	if _, err := repo.GetByKey(ctx, "key-1"); err != nil {
		t.Fatal(err)
	}
	if got := inner.calls.Load(); got != 3 {
		t.Errorf("inner calls = %d, want 3", got)
	}
}

func TestCachedRepository_Size(t *testing.T) {
	inner := &mockRepository{customer: &Customer{ID: 1}}
	repo := NewCachedRepository(inner, 5*time.Minute)

	if got := repo.Size(); got != 0 {
		t.Errorf("empty cache size = %d, want 0", got)
	}

	ctx := context.Background()
	repo.GetByKey(ctx, "a")
	repo.GetByKey(ctx, "b")
	repo.GetByKey(ctx, "c")

	if got := repo.Size(); got != 3 {
		t.Errorf("cache size = %d, want 3", got)
	}
}

func TestCachedRepository_HashesKey(t *testing.T) {
	inner := &mockRepository{customer: &Customer{ID: 1}}
	repo := NewCachedRepository(inner, 5*time.Minute)

	ctx := context.Background()
	repo.GetByKey(ctx, "raw-api-key")

	// Internal map should be keyed by SHA-256 hash, not the raw key
	repo.mu.RLock()
	defer repo.mu.RUnlock()

	hashed := HashKey("raw-api-key")
	if _, ok := repo.entries[hashed]; !ok {
		t.Error("cache entry not stored under hashed key")
	}
	if _, ok := repo.entries["raw-api-key"]; ok {
		t.Error("cache entry stored under raw key — should be hashed")
	}
}
