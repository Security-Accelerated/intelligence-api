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

// IPLookupKeyPrefix namespaces per-lookup IP cache entries, keeping them
// distinct from domain entries. Keys have the shape "ip:<ip>:<lookup_name>".
const IPLookupKeyPrefix = "ip:"

// IPLookupKey builds the cache key for a single lookup on a single IP. The IP
// must already be canonicalized (netip.Addr.String()); like LookupKey this
// never re-normalizes its inputs.
func IPLookupKey(ip, lookupName string) string {
	return IPLookupKeyPrefix + ip + ":" + lookupName
}

// EncryptionLookupKeyPrefix namespaces per-lookup encryption cache entries.
// Keys have the shape "encryption:<host>:<lookup_name>". A host is a domain
// name, so without its own prefix an encryption lookup would share a keyspace
// with the domain endpoint and a future name reused across the two would
// collide.
const EncryptionLookupKeyPrefix = "encryption:"

// EncryptionLookupKey builds the cache key for a single encryption lookup on a
// single host. The host must already be normalized; like LookupKey this never
// re-normalizes its inputs.
func EncryptionLookupKey(host, lookupName string) string {
	return EncryptionLookupKeyPrefix + host + ":" + lookupName
}
