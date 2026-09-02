package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// OriginConfig configures the shared-secret check that locks the origin to
// traffic arriving through the CDN.
//
// The application also answers on its platform hostname
// (security-accelerated-intelligence-api.fly.dev). Anyone who finds that
// hostname reaches the origin directly, skipping the edge WAF and its rate
// limit, and can forge whatever client-IP header the origin trusts. The CDN
// adds Header with Secret to every request it proxies; this middleware rejects
// anything that arrives without it.
type OriginConfig struct {
	Header  string
	Secret  string
	Require bool
}

// OriginSecret returns middleware that rejects requests missing the shared
// secret the CDN injects. When Require is false it returns a pass-through, so
// the check ships inert and is switched on at cutover without a redeploy.
func OriginSecret(cfg OriginConfig) gin.HandlerFunc {
	return OriginSecretWithLogger(cfg, logging.Logger())
}

// OriginSecretWithLogger is like OriginSecret but accepts a logger for testing.
func OriginSecretWithLogger(cfg OriginConfig, logger *zap.Logger) gin.HandlerFunc {
	if !cfg.Require {
		return func(c *gin.Context) { c.Next() }
	}

	want := []byte(cfg.Secret)
	return func(c *gin.Context) {
		got := []byte(c.GetHeader(cfg.Header))
		if subtle.ConstantTimeCompare(got, want) == 1 {
			c.Next()
			return
		}

		// client_ip here is whatever the request claims: a caller reaching the
		// origin directly controls every header the platform would normally
		// overwrite. It is a hint for triage, not an identity.
		logger.Warn("origin secret rejected",
			zap.String("client_ip", c.ClientIP()),
			zap.String("path", c.Request.URL.Path),
		)
		// Deliberately generic. A distinct message would confirm to a prober
		// that they had found the unproxied origin.
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	}
}
