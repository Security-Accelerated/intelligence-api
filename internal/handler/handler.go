package handler

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/billing"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/usage"
	"github.com/spf13/viper"
)

// FingerprintAdminService provides admin access to fingerprint rules.
type FingerprintAdminService interface {
	GetRules() []domain.TechRule
	UpdateRules(ctx context.Context, rules []domain.TechRule, apiKeyID int) error
}

type DomainLookupService interface {
	Lookup(ctx context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, bool)
}

// AuthCacheStats provides read-only access to auth cache metrics for the info endpoint.
type AuthCacheStats interface {
	Size() int
}

type Handler struct {
	domainService      DomainLookupService
	fingerprintService FingerprintAdminService
	billingService     billing.Service
	usageService       usage.Queryer
	cfg                *viper.Viper
	redisCache         *cache.RedisCache
	authCacheStats     AuthCacheStats
	db                 *sql.DB
	status             *config.StatusSnapshot
}

func New(domainService DomainLookupService, fingerprintService FingerprintAdminService, billingService billing.Service, usageService usage.Queryer, cfg *viper.Viper, redisCache *cache.RedisCache, authCacheStats AuthCacheStats, db *sql.DB, status *config.StatusSnapshot) *Handler {
	return &Handler{
		domainService:      domainService,
		fingerprintService: fingerprintService,
		billingService:     billingService,
		usageService:       usageService,
		cfg:                cfg,
		redisCache:         redisCache,
		authCacheStats:     authCacheStats,
		db:                 db,
		status:             status,
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
	v1.POST("/domain/lookup", h.DomainLookup)
}
