package httpapi

import (
	"errors"
	"fmt"
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

// FlyClientIPHeader is the header Fly.io sets from its immediate peer. It is
// the default and the only client-IP source that is trustworthy without the
// origin-secret check: once another proxy sits in front of Fly, this carries
// that proxy's address instead of the caller's.
const FlyClientIPHeader = "Fly-Client-IP"

// RouterDeps carries everything NewRouter needs. It is a struct rather than
// positional parameters for the same reason handler.Deps is: adding a
// dependency stays additive instead of churning every call site.
type RouterDeps struct {
	Handler   *handler.Handler
	Auth      *auth.CachedRepository
	Redis     *redis.Client
	Usage     usage.Recorder
	RateLimit middleware.RateLimitConfig
	Origin    middleware.OriginConfig

	Mode           string
	BodyLimit      int64
	ClientIPHeader string
}

// Validate rejects edge configurations that would be unsafe or unserviceable.
// It is called by NewRouter, so a bad combination is a startup error rather
// than something discovered from production traffic.
func (d RouterDeps) Validate() error {
	if d.Origin.Require {
		if d.Origin.Secret == "" {
			return errors.New("edge.require_origin_secret is true but edge.origin_secret is empty: every request would be rejected")
		}
		if d.Origin.Header == "" {
			return errors.New("edge.require_origin_secret is true but edge.origin_secret_header is empty: every request would be rejected")
		}
	}

	// Trusting a header the edge sets only means anything while the edge is the
	// only way in. Without the origin check, a caller reaching the origin
	// directly forges the header and picks the client IP that lands in our logs.
	if d.ClientIPHeader != FlyClientIPHeader && !d.Origin.Require {
		return fmt.Errorf("edge.client_ip_header is %q but edge.require_origin_secret is false: a caller reaching the origin directly could forge its own client IP", d.ClientIPHeader)
	}

	return nil
}

// NewRouter builds the gin engine with all middleware and routes registered.
func NewRouter(d RouterDeps) (*gin.Engine, error) {
	if err := d.Validate(); err != nil {
		return nil, fmt.Errorf("router config: %w", err)
	}

	if d.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Trust no proxy's X-Forwarded-For. Gin's default trusts every one of them,
	// which lets any caller choose the client IP that reaches our logs.
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("set trusted proxies: %w", err)
	}

	// In production the client IP comes from a header the edge sets and a
	// caller cannot spoof, so c.ClientIP() reports the real client in logs.
	// Outside production nothing in front of us is trustworthy, so the IP stays
	// whatever the connection says it is.
	if d.Mode == "production" {
		router.TrustedPlatform = d.ClientIPHeader
	}

	router.Use(gin.Recovery())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.BodyLimit(d.BodyLimit))
	router.Use(middleware.ClientRequestID())
	router.Use(middleware.RequestLogger())
	// After RequestLogger so a rejection is still logged with its request ID,
	// and before APIKeyAuth so it costs no database round trip.
	router.Use(middleware.OriginSecret(d.Origin))

	authMW := middleware.APIKeyAuth(d.Auth)
	rateLimitMW := middleware.RateLimit(d.Redis, d.RateLimit)
	usageMW := middleware.UsageLog(d.Usage)

	d.Handler.RegisterRoutes(router)
	d.Handler.RegisterProtectedRoutes(router, authMW, rateLimitMW, usageMW)

	admin := router.Group("/v1/admin")
	admin.Use(authMW, rateLimitMW, usageMW, middleware.RequireAdmin())
	admin.POST("/auth/cache/invalidate", func(c *gin.Context) {
		d.Auth.InvalidateAll()
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

	admin.GET("/fingerprints", d.Handler.GetFingerprints)
	admin.POST("/fingerprints", d.Handler.UpdateFingerprints)
	admin.GET("/usage", d.Handler.GetUsage)

	return router, nil
}
