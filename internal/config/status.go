package config

import (
	"sync"
	"time"
)

// StatusSnapshot holds all static application status, built once at startup.
// Used for structured startup logging and the /v1/info admin endpoint.
// Adding a field to any sub-struct automatically surfaces it in both places.
// The mu field protects fields that may be updated at runtime (e.g. GeoIP status
// after an admin refresh).
type StatusSnapshot struct {
	mu       sync.RWMutex   `json:"-"`
	System   SystemStatus   `json:"system"`
	Database DatabaseConfig `json:"database"`
	Cache    CacheConfig    `json:"cache"`
	Lookups  LookupConfig   `json:"lookups"`
	Services ServicesStatus `json:"services"`
}

// SetGeoIPStatus updates the GeoIP status safely for concurrent access.
func (s *StatusSnapshot) SetGeoIPStatus(status GeoIPStatus) {
	s.mu.Lock()
	s.Services.GeoIP = status
	s.mu.Unlock()
}

// GetServices returns a snapshot of ServicesStatus safely for concurrent access.
func (s *StatusSnapshot) GetServices() ServicesStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Services
}

type SystemStatus struct {
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	Mode            string    `json:"mode"`
	SessionID       string    `json:"session_id"`
	StartTime       time.Time `json:"start_time"`
	Host            string    `json:"host"`
	OS              string    `json:"os"`
	Kernel          string    `json:"kernel"`
	Architecture    string    `json:"architecture"`
	GoVersion       string    `json:"golang_version"`
	GinMode         string    `json:"gin_mode"`
	Port            int       `json:"port"`
	ReadTimeout     string    `json:"read_timeout"`
	WriteTimeout    string    `json:"write_timeout"`
	IdleTimeout     string    `json:"idle_timeout"`
	ShutdownTimeout string    `json:"shutdown_timeout"`
	BodyLimit       int       `json:"body_limit"`
}

type DatabaseConfig struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	DBName          string `json:"dbname"`
	SSLMode         string `json:"sslmode"`
	MaxOpenConns    int    `json:"max_open_conns"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	ConnMaxLifetime string `json:"conn_max_lifetime"`
	ConnMaxIdleTime string `json:"conn_max_idle_time"`
}

type CacheConfig struct {
	Addr             string `json:"addr"`
	DB               int    `json:"db"`
	CacheTTL         string `json:"cache_ttl"`
	NegativeCacheTTL string `json:"negative_cache_ttl"`
	AuthCacheTTL     string `json:"auth_cache_ttl"`
}

type LookupConfig struct {
	Timeout              string `json:"timeout"`
	ScreenshotTimeout    string `json:"screenshot_timeout"`
	ScreenshotMaxPNG     int    `json:"screenshot_max_png_bytes"`
	SubdomainMaxResults  int    `json:"subdomain_max_results"`
	SubdomainMaxResponse int    `json:"subdomain_max_response_bytes"`
	CTLogsMaxEntries     int    `json:"ct_logs_max_entries"`
	RateLimitFree        int    `json:"rate_limit_free"`
	RateLimitBasic       int    `json:"rate_limit_basic"`
	RateLimitPro         int    `json:"rate_limit_pro"`
	MaxDomainsFree       int    `json:"max_domains_free"`
	MaxDomainsBasic      int    `json:"max_domains_basic"`
	MaxDomainsPro        int    `json:"max_domains_pro"`
	IPTimeout            string `json:"ip_timeout"`
	MaxIPsFree           int    `json:"max_ips_free"`
	MaxIPsBasic          int    `json:"max_ips_basic"`
	MaxIPsPro            int    `json:"max_ips_pro"`
}

type ServicesStatus struct {
	Notifications NotificationsStatus `json:"notifications"`
	Billing       BillingStatus       `json:"billing"`
	ThreatIntel   ThreatIntelStatus   `json:"threat_intel"`
	Fingerprint   FingerprintStatus   `json:"fingerprint"`
	Usage         UsageStatus         `json:"usage"`
	GeoIP         GeoIPStatus         `json:"geoip"`
}

type NotificationsStatus struct {
	Enabled            bool   `json:"enabled"`
	ThrottleThreshold  int    `json:"throttle_threshold"`
	ThrottleWindow     string `json:"throttle_window"`
	SpikeThreshold     int    `json:"spike_threshold"`
	SpikeWindow        string `json:"spike_window"`
	Cooldown           string `json:"cooldown"`
	MaxConcurrentSends int    `json:"max_concurrent_sends"`
	MaxWindowSize      int    `json:"max_window_size"`
}

type BillingStatus struct {
	Enabled              bool `json:"enabled"`
	PortalLinkConfigured bool `json:"portal_link_configured"`
	StaleKeyDays         int  `json:"stale_key_days"`
}

type ThreatIntelStatus struct {
	ProviderCount int      `json:"provider_count"`
	Providers     []string `json:"providers"`
}

type FingerprintStatus struct {
	Source    string `json:"source"`
	RuleCount int    `json:"rule_count"`
}

type UsageStatus struct {
	BufferSize    int    `json:"buffer_size"`
	FlushInterval string `json:"flush_interval"`
}

type GeoIPStatus struct {
	Enabled bool   `json:"enabled"`
	CityDB  string `json:"city_db"`
	ASNDB   string `json:"asn_db"`
	DBPath  string `json:"db_path"`
}

// NewStatusSnapshot builds a StatusSnapshot from the current config values.
// Service-level fields (Services.*) are left at zero values — the caller
// populates them as each service is initialized.
func NewStatusSnapshot(version string) *StatusSnapshot {
	cfg := Config()
	return &StatusSnapshot{
		System: SystemStatus{
			Name:            cfg.GetString("application.name"),
			Version:         version,
			Mode:            cfg.GetString("application.mode"),
			SessionID:       cfg.GetString("application.session.id"),
			StartTime:       cfg.GetTime("application.start.time"),
			Host:            cfg.GetString("environment.host"),
			OS:              cfg.GetString("environment.os"),
			Kernel:          cfg.GetString("environment.kernel"),
			Architecture:    cfg.GetString("environment.architecture"),
			GoVersion:       cfg.GetString("environment.golang.version"),
			GinMode:         cfg.GetString("gin.mode"),
			Port:            cfg.GetInt("application.port"),
			ReadTimeout:     cfg.GetDuration("server.read_timeout").String(),
			WriteTimeout:    cfg.GetDuration("server.write_timeout").String(),
			IdleTimeout:     cfg.GetDuration("server.idle_timeout").String(),
			ShutdownTimeout: cfg.GetDuration("server.shutdown_timeout").String(),
			BodyLimit:       cfg.GetInt("server.body_limit"),
		},
		Database: DatabaseConfig{
			Host:            cfg.GetString("postgres.host"),
			Port:            cfg.GetInt("postgres.port"),
			DBName:          cfg.GetString("postgres.dbname"),
			SSLMode:         cfg.GetString("postgres.sslmode"),
			MaxOpenConns:    cfg.GetInt("postgres.max_open_conns"),
			MaxIdleConns:    cfg.GetInt("postgres.max_idle_conns"),
			ConnMaxLifetime: cfg.GetDuration("postgres.conn_max_lifetime").String(),
			ConnMaxIdleTime: cfg.GetDuration("postgres.conn_max_idle_time").String(),
		},
		Cache: CacheConfig{
			Addr:         cfg.GetString("redis.addr"),
			DB:           cfg.GetInt("redis.db"),
			CacheTTL:         cfg.GetDuration("redis.cache_ttl").String(),
			NegativeCacheTTL: cfg.GetDuration("redis.negative_cache_ttl").String(),
			AuthCacheTTL:     cfg.GetDuration("auth.cache_ttl").String(),
		},
		Lookups: LookupConfig{
			Timeout:              cfg.GetDuration("domain.lookup_timeout").String(),
			ScreenshotTimeout:    cfg.GetDuration("screenshot.timeout").String(),
			ScreenshotMaxPNG:     cfg.GetInt("screenshot.max_png_bytes"),
			SubdomainMaxResults:  cfg.GetInt("subdomain.max_results"),
			SubdomainMaxResponse: cfg.GetInt("subdomain.max_response_bytes"),
			CTLogsMaxEntries:     cfg.GetInt("ct_logs.max_entries"),
			RateLimitFree:        cfg.GetInt("rate_limit.free"),
			RateLimitBasic:       cfg.GetInt("rate_limit.basic"),
			RateLimitPro:         cfg.GetInt("rate_limit.pro"),
			MaxDomainsFree:       cfg.GetInt("domain.max_domains.free"),
			MaxDomainsBasic:      cfg.GetInt("domain.max_domains.basic"),
			MaxDomainsPro:        cfg.GetInt("domain.max_domains.pro"),
			IPTimeout:            cfg.GetDuration("ip.lookup_timeout").String(),
			MaxIPsFree:           cfg.GetInt("ip.max_ips.free"),
			MaxIPsBasic:          cfg.GetInt("ip.max_ips.basic"),
			MaxIPsPro:            cfg.GetInt("ip.max_ips.pro"),
		},
	}
}
