package config

import (
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

var config *viper.Viper

const appName = "intelligence-api"

func init() {
	config = viper.New()

	// setup config sources
	config.SetConfigType("yaml")
	config.SetConfigName(appName)
	config.AddConfigPath("../../config/")
	config.AddConfigPath("../config/")
	config.AddConfigPath("config/")
	config.AddConfigPath("/etc/security-accelerated/")

	// application
	config.Set("application.start.time", time.Now().UTC())
	config.Set("application.name", appName)
	config.Set("application.session.id", uuid.New().String())

	// environment information
	host, err := os.Hostname()
	if err != nil {
		log.Fatalf("error generating hostname, %s", err)
	}
	config.Set("environment.host", host)
	config.Set("environment.golang.version", runtime.Version())
	config.Set("environment.architecture", runtime.GOARCH)
	config.Set("environment.os", runtime.GOOS)

	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		config.Set("environment.kernel", charsToString(uname.Release[:]))
	}

	// defaults (overridden by config file, then env vars)
	setDefaults(config)

	// allow env vars to override config: POSTGRES_HOST → postgres.host
	config.SetEnvKeyReplacer(envKeyReplacer())
	config.AutomaticEnv()

	// read in config
	if err := config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("no config file found")
		} else {
			log.Fatalf("error reading config file %s.yaml: %s", appName, err)
		}
	}
}

// setDefaults populates v with every built-in default.
//
// Separate from init so the defaults can be asserted against a fresh Viper.
// Testing them through Config() tested whatever configuration the machine
// happened to have instead: this host carries
// /etc/security-accelerated/intelligence-api.yaml, so a changed default read
// back as its old value locally and only failed in CI, where no file exists.
func setDefaults(v *viper.Viper) {
	v.SetDefault("application.port", 8080)
	// Cache TTLs: one entry per lookup, with default_ttl covering anything
	// unlisted. Each key is read individually so env overrides (CACHE_TTL_WHOIS)
	// work per Viper convention.
	v.SetDefault("cache.default_ttl", "60m")
	v.SetDefault("cache.ttl.whois", "24h")
	v.SetDefault("cache.ttl.ct_logs", "24h")
	v.SetDefault("cache.ttl.subdomains", "24h")
	v.SetDefault("cache.ttl.bgp", "24h")
	v.SetDefault("cache.ttl.ssl", "4h")
	v.SetDefault("cache.ttl.email_security", "4h")
	v.SetDefault("cache.ttl.dns", "30m")
	v.SetDefault("cache.ttl.headers", "30m")
	v.SetDefault("cache.ttl.reputation", "30m")
	v.SetDefault("cache.ttl.threat_intel", "30m")
	// IP lookups. geo is absent deliberately: it reads a local mmap and is
	// never cached, so a TTL would be meaningless.
	v.SetDefault("cache.ttl.asn", "24h")
	v.SetDefault("cache.ttl.reverse_dns", "6h")
	v.SetDefault("cache.ttl.abuse_contact", "24h")
	v.SetDefault("auth.cache_ttl", "5m")
	v.SetDefault("auth.rotation_grace", "24h")
	v.SetDefault("subdomain.http_timeout", "15s")
	v.SetDefault("ct_logs.http_timeout", "15s")
	v.SetDefault("billing.cleanup_interval", "10m")
	v.SetDefault("auth.last_used_buffer_size", 256)
	v.SetDefault("auth.last_used_flush_interval", "10s")
	v.SetDefault("domain.max_domains.free", 1)
	v.SetDefault("domain.max_domains.pro", 20)
	v.SetDefault("subdomain.max_results", 500)
	v.SetDefault("ct_logs.max_entries", 100)
	v.SetDefault("subdomain.max_domains.free", 1)
	v.SetDefault("subdomain.max_domains.pro", 5)
	v.SetDefault("rate_limit.free", 5)
	v.SetDefault("rate_limit.pro", 120)
	v.SetDefault("postgres.sslmode", "require")
	v.SetDefault("postgres.max_open_conns", 25)
	v.SetDefault("postgres.max_idle_conns", 5)
	v.SetDefault("postgres.conn_max_lifetime", "5m")
	v.SetDefault("postgres.conn_max_idle_time", "2m")
	v.SetDefault("pushover.api_token", "")
	v.SetDefault("pushover.user_key", "")
	v.SetDefault("alerts.throttle_threshold", 5)
	v.SetDefault("alerts.throttle_window", "5m")
	v.SetDefault("alerts.spike_threshold", 15)
	v.SetDefault("alerts.spike_window", "5m")
	v.SetDefault("alerts.cooldown", "15m")
	v.SetDefault("stripe.secret_key", "")
	v.SetDefault("stripe.webhook_secret", "")
	v.SetDefault("stripe.prices.pro_monthly", "")
	v.SetDefault("stripe.payment_link.pro", "")
	v.SetDefault("stripe.portal_link", "")
	v.SetDefault("billing.stale_key_days", 365)
	v.SetDefault("usage.buffer_size", 256)
	v.SetDefault("usage.flush_interval", "5s")
	v.SetDefault("threat_intel.virustotal_api_key", "")
	v.SetDefault("threat_intel.alienvault_api_key", "")
	v.SetDefault("server.read_timeout", "10s")
	v.SetDefault("server.write_timeout", "45s")
	v.SetDefault("server.idle_timeout", "60s")
	v.SetDefault("server.shutdown_timeout", "15s")
	v.SetDefault("server.body_limit", 1048576) // 1 MB
	v.SetDefault("domain.lookup_timeout", "30s")
	v.SetDefault("subdomain.max_response_bytes", 10485760) // 10 MB
	v.SetDefault("alerts.max_concurrent_sends", 5)
	v.SetDefault("alerts.max_window_size", 1000)
	v.SetDefault("geoip.db_path", "/data/geoip")
	v.SetDefault("geoip.city_db", "dbip-city-lite.mmdb")
	// DB-IP publishes Lite releases monthly. Refresh anything older than this
	// at startup; 0 disables the check and pins whatever is on disk.
	v.SetDefault("geoip.max_age", "720h")
	v.SetDefault("ip.lookup_timeout", "30s")
	v.SetDefault("ip.max_ips.free", 1)
	v.SetDefault("ip.max_ips.pro", 20)
	v.SetDefault("dns.servers", []string{})
	v.SetDefault("dns.timeout", "30s")
}

// Config returns the process-wide Viper instance, populated at init with
// defaults, any config file found on the search path, and environment
// overrides.
func Config() *viper.Viper {
	return config
}

// envKeyReplacer maps config keys onto environment variable names
// (postgres.host → POSTGRES_HOST, cache.ttl.whois → CACHE_TTL_WHOIS).
func envKeyReplacer() *strings.Replacer {
	return strings.NewReplacer(".", "_")
}

// charsToString renders a NUL-terminated C character array from uname(2) as a
// Go string. The source is ASCII kernel/release metadata, so every element is
// in 0-127 and the int8 -> byte conversion cannot change a value; a negative
// element would mean uname returned non-ASCII, which it does not.
func charsToString(ca []int8) string {
	b := make([]byte, 0, len(ca))
	for _, c := range ca {
		if c == 0 {
			break
		}
		//nolint:gosec // G115: uname fields are ASCII, so c is always 0-127.
		b = append(b, byte(c))
	}
	return string(b)
}
