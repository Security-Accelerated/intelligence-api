package handler

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/billing"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/usage"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

//go:embed changelog.yaml
var changelogYAML []byte

// ChangelogVersion represents a single version entry in the changelog.
type ChangelogVersion struct {
	Version string            `json:"version" yaml:"version"`
	Date    string            `json:"date" yaml:"date"`
	Changes []ChangelogChange `json:"changes" yaml:"changes"`
}

// ChangelogChange is a single change entry with audience tagging.
type ChangelogChange struct {
	Text     string `json:"text" yaml:"text"`
	Audience string `json:"audience" yaml:"audience"`
}

func parseChangelog() []ChangelogVersion {
	var entries []ChangelogVersion
	yaml.Unmarshal(changelogYAML, &entries)
	return entries
}

// FingerprintAdminService provides admin access to fingerprint rules.
type FingerprintAdminService interface {
	GetRules() []domain.TechRule
	UpdateRules(ctx context.Context, rules []domain.TechRule, apiKeyID int) error
}

type DomainLookupService interface {
	Lookup(ctx context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, bool)
}

type IPLookupService interface {
	Lookup(ctx context.Context, ip string, opts domain.IPLookupOptions) (*domain.IPResponse, bool)
}

// GeoIPRefresher downloads and hot-reloads MaxMind databases.
type GeoIPRefresher interface {
	DownloadAndReload(licenseKey, dbPath string) (*domain.RefreshResult, error)
}

// AuthCacheStats provides read-only access to auth cache metrics for the info endpoint.
type AuthCacheStats interface {
	Size() int
}

type Handler struct {
	domainService      DomainLookupService
	ipService          IPLookupService
	fingerprintService FingerprintAdminService
	billingService     billing.Service
	usageService       usage.Queryer
	geoRefresher       GeoIPRefresher
	cfg                *viper.Viper
	redisCache         *cache.RedisCache
	authCacheStats     AuthCacheStats
	db                 *sql.DB
	status             *config.StatusSnapshot
	changelog          []ChangelogVersion
}

func New(domainService DomainLookupService, ipService IPLookupService, fingerprintService FingerprintAdminService, billingService billing.Service, usageService usage.Queryer, geoRefresher GeoIPRefresher, cfg *viper.Viper, redisCache *cache.RedisCache, authCacheStats AuthCacheStats, db *sql.DB, status *config.StatusSnapshot) *Handler {
	return &Handler{
		domainService:      domainService,
		ipService:          ipService,
		fingerprintService: fingerprintService,
		billingService:     billingService,
		usageService:       usageService,
		geoRefresher:       geoRefresher,
		cfg:                cfg,
		redisCache:         redisCache,
		authCacheStats:     authCacheStats,
		db:                 db,
		status:             status,
		changelog:          parseChangelog(),
	}
}

// maxDomains returns the configured maximum number of domains for the given
// config prefix and plan. Returns 0 (no limit) if config is nil.
func (h *Handler) maxDomains(prefix, plan string) int {
	if h.cfg == nil {
		return 0
	}
	return h.cfg.GetInt(fmt.Sprintf("%s.max_domains.%s", prefix, plan))
}

// maxIPs returns the configured maximum number of IPs per request for the given
// plan. Returns 0 (no limit) if config is nil.
func (h *Handler) maxIPs(plan string) int {
	if h.cfg == nil {
		return 0
	}
	return h.cfg.GetInt(fmt.Sprintf("ip.max_ips.%s", plan))
}

// RegisterRoutes registers unauthenticated routes only (health check, docs, billing).
func (h *Handler) RegisterRoutes(router *gin.Engine) {
	router.GET("/", h.Docs)
	v1 := router.Group("/v1")
	v1.GET("/hello", h.Hello)

	billingGroup := router.Group("/billing")
	billingGroup.POST("/webhook", h.StripeWebhook)
	billingGroup.GET("/success", h.CheckoutSuccess)
}

// RegisterProtectedRoutes registers routes that require API key authentication.
// Middleware are applied in order: typically auth first, then rate limiting.
func (h *Handler) RegisterProtectedRoutes(router *gin.Engine, middlewares ...gin.HandlerFunc) {
	v1 := router.Group("/v1")
	v1.Use(middlewares...)
	v1.GET("/info", middleware.RequireAdmin(), h.Info)
	v1.GET("/admin/changelog", middleware.RequireAdmin(), h.Changelog)
	v1.POST("/admin/geoip/refresh", middleware.RequireAdmin(), h.RefreshGeoIP)
	v1.POST("/domain/lookup", h.DomainLookup)
	v1.POST("/ip/lookup", h.IPLookup)
}
