package cache

import (
	"context"
	"time"
)

// LookupKeyPrefix namespaces per-lookup cache entries. Keys have the shape
// "lookup:<domain>:<lookup_name>".
const LookupKeyPrefix = "lookup:"

// LookupKey builds the cache key for a single lookup result on a single domain.
// Both inputs must already be normalized (trimmed, lowercased, scheme-stripped)
// — normalization is the handler's responsibility and this builder never
// re-normalizes, so callers cannot accidentally paper over a missed step.
func LookupKey(domainName, lookupName string) string {
	return LookupKeyPrefix + domainName + ":" + lookupName
}

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	// MGet fetches several keys in one round trip. The returned slice always has
	// the same length and ordering as keys; a nil element means "not present".
	MGet(ctx context.Context, keys []string) ([][]byte, error)
	Set(ctx context.Context, key string, data []byte, ttl time.Duration) error
}
