package handler

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
)

type DomainLookupService interface {
	Lookup(ctx context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, bool)
}

type Handler struct {
	domainService DomainLookupService
	version       string
}

func New(domainService DomainLookupService, version string) *Handler {
	return &Handler{
		domainService: domainService,
		version:       version,
	}
}

// RegisterRoutes registers unauthenticated routes only (health check).
func (h *Handler) RegisterRoutes(router *gin.Engine) {
	v1 := router.Group("/api/v1")
	v1.GET("/hello", h.Hello)
}

// RegisterProtectedRoutes registers routes that require API key authentication.
// The authMiddleware validates the key; per-route role middleware controls access.
func (h *Handler) RegisterProtectedRoutes(router *gin.Engine, authMiddleware gin.HandlerFunc) {
	v1 := router.Group("/api/v1")
	v1.Use(authMiddleware)
	v1.GET("/info", middleware.RequireRoles("admin"), h.Info)
	v1.POST("/domain", middleware.RequireRoles("admin", "domain"), h.DomainLookup)
}
