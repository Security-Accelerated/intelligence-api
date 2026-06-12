package handler

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/billing"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/usage"
	"github.com/spf13/viper"
	"go.uber.org/zap"
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

func parseChangelog() ([]ChangelogVersion, error) {
	var entries []ChangelogVersion
	if err := yaml.Unmarshal(changelogYAML, &entries); err != nil {
		return nil, fmt.Errorf("parse changelog yaml: %w", err)
	}
	return entries, nil
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
	DownloadAndReload(licenseKey, dbPath, cityFile, asnFile string) (*domain.RefreshResult, error)
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
	changelog, err := parseChangelog()
	if err != nil {
		logging.Logger().Error("failed to parse changelog", zap.Error(err))
	}

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
		changelog:          changelog,
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
	router.GET("/", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/docs") })
	router.GET("/docs", h.Docs)
	router.GET("/docs/domain", h.DocsDomain)
	router.GET("/docs/ip", h.DocsIP)
	router.GET("/docs/styles.css", h.DocsCSS)
	router.GET("/docs/theme.js", h.DocsThemeJS)
	router.GET("/docs/docs.js", h.DocsJS)
	router.GET("/docs/checkout_success.js", h.CheckoutSuccessJS)
	v1 := router.Group("/v1")
	v1.GET("/hello", h.Hello)
	v1.GET("/health", h.Health)

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
	v1.GET("/usage", h.MyUsage)
}
