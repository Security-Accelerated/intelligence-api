package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/handler"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
)

// NewRouter builds the gin engine with all middleware and routes registered.
func NewRouter(h *handler.Handler, cachedRepo *auth.CachedRepository, mode string) *gin.Engine {
	if mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.RequestLogger())

	h.RegisterRoutes(router)
	h.RegisterProtectedRoutes(router, middleware.APIKeyAuth(cachedRepo))

	admin := router.Group("/api/v1/admin")
	admin.Use(middleware.APIKeyAuth(cachedRepo), middleware.RequireRoles("admin"))
	admin.POST("/auth/cache/invalidate", func(c *gin.Context) {
		cachedRepo.InvalidateAll()
		c.JSON(http.StatusOK, gin.H{"message": "auth cache invalidated"})
	})

	return router
}
