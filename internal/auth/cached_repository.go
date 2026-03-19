package auth

import (
	"context"
	"sync"
	"time"
)

type cacheEntry struct {
	customer  *Customer
	expiresAt time.Time
}

// CachedRepository wraps any Repository with an in-memory cache keyed by API
// key hash. Entries expire after the configured TTL. InvalidateAll clears the
// entire cache (e.g. after plan changes).
//
// A generation counter prevents a TOCTOU race where a concurrent DB lookup
// started before InvalidateAll could re-populate the cache with stale data.
type CachedRepository struct {
	inner      Repository
	mu         sync.RWMutex
	entries    map[string]*cacheEntry
	ttl        time.Duration
	generation uint64
}

func NewCachedRepository(inner Repository, ttl time.Duration) *CachedRepository {
	return &CachedRepository{
		inner:   inner,
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

func (r *CachedRepository) GetByKey(ctx context.Context, key string) (*Customer, error) {
	cacheKey := HashKey(key)

	r.mu.RLock()
	if e, ok := r.entries[cacheKey]; ok && time.Now().Before(e.expiresAt) {
		r.mu.RUnlock()
		return e.customer, nil
	}
	gen := r.generation
	r.mu.RUnlock()

	customer, err := r.inner.GetByKey(ctx, key)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	// Only write if the cache hasn't been invalidated since we started the lookup.
	if r.generation == gen {
		r.entries[cacheKey] = &cacheEntry{customer: customer, expiresAt: time.Now().Add(r.ttl)}
	}
	r.mu.Unlock()

	return customer, nil
}

// Size returns the number of entries currently in the cache.
func (r *CachedRepository) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// InvalidateAll clears all cached entries and increments the generation counter
// so that in-flight lookups don't re-populate stale data.
func (r *CachedRepository) InvalidateAll() {
	r.mu.Lock()
	r.entries = make(map[string]*cacheEntry)
	r.generation++
	r.mu.Unlock()
}
