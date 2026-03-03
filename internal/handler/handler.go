package handler

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/spf13/viper"
)

type DomainLookupService interface {
	Lookup(ctx context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, bool)
}

type TyposquattingLookupService interface {
	Lookup(ctx context.Context, domainName string, checkLive bool, depth string) (*domain.TyposquattingResponse, bool)
}

type Handler struct {
	domainService        DomainLookupService
	typosquattingService TyposquattingLookupService
	version              string
	cfg                  *viper.Viper
	redisCache           *cache.RedisCache
	cachedRepo           *auth.CachedRepository
}

func New(domainService DomainLookupService, typosquattingService TyposquattingLookupService, version string, cfg *viper.Viper, redisCache *cache.RedisCache, cachedRepo *auth.CachedRepository) *Handler {
	return &Handler{
		domainService:        domainService,
		typosquattingService: typosquattingService,
		version:              version,
		cfg:                  cfg,
		redisCache:           redisCache,
		cachedRepo:           cachedRepo,
	}
}

// maxDomains returns the configured maximum number of domains for the given
// config prefix and tier. Returns 0 (no limit) if config is nil.
func (h *Handler) maxDomains(prefix, tier string) int {
	if h.cfg == nil {
		return 0
	}
	return h.cfg.GetInt(fmt.Sprintf("%s.max_domains.%s", prefix, tier))
}

// RegisterRoutes registers unauthenticated routes only (health check).
func (h *Handler) RegisterRoutes(router *gin.Engine) {
	v1 := router.Group("/api/v1")
	v1.GET("/hello", h.Hello)
}

// RegisterProtectedRoutes registers routes that require API key authentication.
// Middleware are applied in order: typically auth first, then rate limiting.
func (h *Handler) RegisterProtectedRoutes(router *gin.Engine, middlewares ...gin.HandlerFunc) {
	v1 := router.Group("/api/v1")
	v1.Use(middlewares...)
	v1.GET("/info", middleware.RequireRoles("admin"), h.Info)
	v1.POST("/domain", middleware.RequireRoles("admin", "domain"), h.DomainLookup)
	v1.POST("/domain/typosquatting", middleware.RequireRoles("admin", "domain"), h.TyposquattingLookup)
}
