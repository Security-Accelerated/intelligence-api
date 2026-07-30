package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestCacheTTLKey(t *testing.T) {
	if got := CacheTTLKey("whois"); got != "cache.ttl.whois" {
		t.Errorf("CacheTTLKey(whois) = %q, want cache.ttl.whois", got)
	}
	if DefaultCacheTTLKey != "cache.default_ttl" {
		t.Errorf("DefaultCacheTTLKey = %q", DefaultCacheTTLKey)
	}
}

func TestCacheTTLs_ReadsPerLookupValues(t *testing.T) {
	cfg := viper.New()
	cfg.Set("cache.ttl.whois", "24h")
	cfg.Set("cache.ttl.dns", "30m")

	ttls := CacheTTLs(cfg, []string{"whois", "dns", "ssl"})

	if ttls["whois"] != 24*time.Hour {
		t.Errorf("whois = %v, want 24h", ttls["whois"])
	}
	if ttls["dns"] != 30*time.Minute {
		t.Errorf("dns = %v, want 30m", ttls["dns"])
	}
	// Unlisted names are omitted so callers fall back to the default.
	if _, ok := ttls["ssl"]; ok {
		t.Errorf("ssl should be absent, got %v", ttls["ssl"])
	}
}

func TestCacheTTLs_EnvVarOverride(t *testing.T) {
	// Viper's AutomaticEnv only consults the environment for explicitly
	// requested keys, which is exactly how CacheTTLs reads them.
	t.Setenv("CACHE_TTL_WHOIS", "48h")
	t.Setenv("CACHE_DEFAULT_TTL", "90m")

	cfg := viper.New()
	cfg.SetEnvKeyReplacer(envKeyReplacer())
	cfg.AutomaticEnv()
	cfg.SetDefault("cache.ttl.whois", "24h")
	cfg.SetDefault("cache.default_ttl", "60m")

	ttls := CacheTTLs(cfg, []string{"whois"})
	if ttls["whois"] != 48*time.Hour {
		t.Errorf("CACHE_TTL_WHOIS override = %v, want 48h", ttls["whois"])
	}
	if got := DefaultCacheTTL(cfg); got != 90*time.Minute {
		t.Errorf("CACHE_DEFAULT_TTL override = %v, want 90m", got)
	}
}

func TestCacheTTLs_NilConfigIsSafe(t *testing.T) {
	if got := CacheTTLs(nil, []string{"whois"}); len(got) != 0 {
		t.Errorf("CacheTTLs(nil) = %v, want empty", got)
	}
	if got := DefaultCacheTTL(nil); got != 0 {
		t.Errorf("DefaultCacheTTL(nil) = %v, want 0", got)
	}
}

func TestDefaultCacheTTL_FromPackageConfig(t *testing.T) {
	if got := DefaultCacheTTL(Config()); got != 60*time.Minute {
		t.Errorf("package default TTL = %v, want 60m", got)
	}
}
