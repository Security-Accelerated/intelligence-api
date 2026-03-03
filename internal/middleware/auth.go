package middleware

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// APIKeyAuth validates the X-API-Key header and sets "api_key_features" on the context.
func APIKeyAuth(repo auth.Repository) gin.HandlerFunc {
	return APIKeyAuthWithLogger(repo, logging.Logger())
}

// APIKeyAuthWithLogger is like APIKeyAuth but accepts a logger for testing.
func APIKeyAuthWithLogger(repo auth.Repository, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			logger.Warn("auth failed: missing API key",
				zap.String("client_ip", c.ClientIP()),
				zap.String("path", c.Request.URL.Path),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing API key"})
			return
		}

		customer, err := repo.GetByKey(c.Request.Context(), key)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				logger.Warn("auth failed: invalid API key",
					zap.String("client_ip", c.ClientIP()),
					zap.String("path", c.Request.URL.Path),
				)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			} else {
				logger.Error("auth failed: database error",
					zap.String("client_ip", c.ClientIP()),
					zap.String("path", c.Request.URL.Path),
					zap.Error(err),
				)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			}
			return
		}

		c.Set("api_key_id", customer.APIKeyID)
		c.Set("api_key_features", customer.Features)
		c.Set("api_key_tier", customer.Tier)
		c.Next()
	}
}

// RequireFeatures returns middleware that checks the authenticated features (set by
// APIKeyAuth) against a set of allowed features. Returns 403 if none of the
// customer's features are in the allowed set.
func RequireFeatures(allowed ...string) gin.HandlerFunc {
	set := make(map[string]struct{}, len(allowed))
	for _, f := range allowed {
		set[f] = struct{}{}
	}
	return func(c *gin.Context) {
		val, _ := c.Get("api_key_features")
		features, _ := val.([]string)
		for _, f := range features {
			if _, ok := set[f]; ok {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	}
}
