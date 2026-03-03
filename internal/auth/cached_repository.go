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
// key. Entries expire after the configured TTL. InvalidateAll clears the entire
// cache (e.g. after role changes).
type CachedRepository struct {
	inner   Repository
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
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
	r.mu.RUnlock()

	customer, err := r.inner.GetByKey(ctx, key)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.entries[cacheKey] = &cacheEntry{customer: customer, expiresAt: time.Now().Add(r.ttl)}
	r.mu.Unlock()

	return customer, nil
}

// Size returns the number of entries currently in the cache.
func (r *CachedRepository) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// InvalidateAll clears all cached entries.
func (r *CachedRepository) InvalidateAll() {
	r.mu.Lock()
	r.entries = make(map[string]*cacheEntry)
	r.mu.Unlock()
}
