package config

import (
	"time"

	"github.com/spf13/viper"
)

// DefaultCacheTTLKey is the config key for the fallback TTL applied to any
// lookup without its own entry under cache.ttl.
const DefaultCacheTTLKey = "cache.default_ttl"

// CacheTTLKey returns the config key holding the TTL for a single lookup.
func CacheTTLKey(lookupName string) string {
	return "cache.ttl." + lookupName
}

// CacheTTLs resolves the per-lookup TTL table for the given lookup names.
//
// Each name is read with its own Get call rather than pulling the cache.ttl
// subtree as a map, because Viper's AutomaticEnv only consults the environment
// for explicitly requested keys — reading the subtree would silently ignore
// CACHE_TTL_WHOIS and friends. Names with no configured (or non-positive) TTL
// are omitted so callers fall back to the default.
func CacheTTLs(cfg *viper.Viper, lookupNames []string) map[string]time.Duration {
	ttls := make(map[string]time.Duration, len(lookupNames))
	if cfg == nil {
		return ttls
	}
	for _, name := range lookupNames {
		if d := cfg.GetDuration(CacheTTLKey(name)); d > 0 {
			ttls[name] = d
		}
	}
	return ttls
}

// DefaultCacheTTL returns the fallback TTL for lookups without their own entry.
func DefaultCacheTTL(cfg *viper.Viper) time.Duration {
	if cfg == nil {
		return 0
	}
	return cfg.GetDuration(DefaultCacheTTLKey)
}
