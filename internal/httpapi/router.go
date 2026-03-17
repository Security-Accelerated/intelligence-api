package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/handler"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/usage"
	"go.uber.org/zap"
)

// NewRouter builds the gin engine with all middleware and routes registered.
func NewRouter(h *handler.Handler, cachedRepo *auth.CachedRepository, redisClient *redis.Client, rlCfg middleware.RateLimitConfig, recorder usage.Recorder, mode string) *gin.Engine {
	if mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.BodyLimit(1 << 20)) // 1 MB
	router.Use(middleware.ClientRequestID())
	router.Use(middleware.RequestLogger())

	authMW := middleware.APIKeyAuth(cachedRepo)
	rateLimitMW := middleware.RateLimit(redisClient, rlCfg)
	usageMW := middleware.UsageLog(recorder)

	h.RegisterRoutes(router)
	h.RegisterProtectedRoutes(router, authMW, rateLimitMW, usageMW)

	admin := router.Group("/v1/admin")
	admin.Use(authMW, rateLimitMW, usageMW, middleware.RequireAdmin())
	admin.POST("/auth/cache/invalidate", func(c *gin.Context) {
		cachedRepo.InvalidateAll()
		if v, ok := c.Get("api_key_id"); ok {
			if id, ok := v.(int); ok {
				logging.Logger().Info("auth cache invalidated",
					zap.Int("api_key_id", id),
					zap.String("client_ip", c.ClientIP()),
				)
			}
		}
		c.JSON(http.StatusOK, gin.H{"message": "auth cache invalidated"})
	})

	admin.GET("/fingerprints", h.GetFingerprints)
	admin.POST("/fingerprints", h.UpdateFingerprints)
	admin.GET("/usage", h.GetUsage)

	return router
}
