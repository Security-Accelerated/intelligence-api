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
	config.SetDefault("application.port", 8080)
	config.SetDefault("redis.cache_ttl", "60m")
	config.SetDefault("auth.cache_ttl", "5m")
	config.SetDefault("auth.last_used_buffer_size", 256)
	config.SetDefault("auth.last_used_flush_interval", "10s")
	config.SetDefault("screenshot.timeout", "15s")
	config.SetDefault("domain.max_domains.free", 1)
	config.SetDefault("domain.max_domains.basic", 5)
	config.SetDefault("domain.max_domains.pro", 20)
	config.SetDefault("subdomain.max_results", 500)
	config.SetDefault("ct_logs.max_entries", 100)
	config.SetDefault("subdomain.max_domains.free", 1)
	config.SetDefault("subdomain.max_domains.basic", 3)
	config.SetDefault("subdomain.max_domains.pro", 5)
	config.SetDefault("rate_limit.free", 5)
	config.SetDefault("rate_limit.basic", 30)
	config.SetDefault("rate_limit.pro", 120)
	config.SetDefault("postgres.sslmode", "require")
	config.SetDefault("postgres.max_open_conns", 25)
	config.SetDefault("postgres.max_idle_conns", 5)
	config.SetDefault("postgres.conn_max_lifetime", "5m")
	config.SetDefault("postgres.conn_max_idle_time", "2m")
	config.SetDefault("pushover.api_token", "")
	config.SetDefault("pushover.user_key", "")
	config.SetDefault("alerts.throttle_threshold", 5)
	config.SetDefault("alerts.throttle_window", "5m")
	config.SetDefault("alerts.spike_threshold", 15)
	config.SetDefault("alerts.spike_window", "5m")
	config.SetDefault("alerts.cooldown", "15m")
	config.SetDefault("stripe.secret_key", "")
	config.SetDefault("stripe.webhook_secret", "")
	config.SetDefault("stripe.prices.basic_monthly", "")
	config.SetDefault("stripe.prices.pro_monthly", "")
	config.SetDefault("stripe.payment_link.basic", "")
	config.SetDefault("stripe.payment_link.pro", "")
	config.SetDefault("stripe.portal_link", "")
	config.SetDefault("billing.stale_key_days", 365)
	config.SetDefault("usage.buffer_size", 256)
	config.SetDefault("usage.flush_interval", "5s")
	config.SetDefault("threat_intel.virustotal_api_key", "")
	config.SetDefault("threat_intel.alienvault_api_key", "")
	config.SetDefault("server.read_timeout", "10s")
	config.SetDefault("server.write_timeout", "45s")
	config.SetDefault("server.idle_timeout", "60s")
	config.SetDefault("server.shutdown_timeout", "15s")
	config.SetDefault("server.body_limit", 1048576) // 1 MB
	config.SetDefault("domain.lookup_timeout", "30s")
	config.SetDefault("screenshot.max_png_bytes", 5242880) // 5 MB
	config.SetDefault("subdomain.max_response_bytes", 10485760) // 10 MB
	config.SetDefault("alerts.max_concurrent_sends", 5)
	config.SetDefault("alerts.max_window_size", 1000)

	// allow env vars to override config: POSTGRES_HOST → postgres.host
	config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
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

func Config() *viper.Viper {
	return config
}

func charsToString(ca []int8) string {
	b := make([]byte, 0, len(ca))
	for _, c := range ca {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
