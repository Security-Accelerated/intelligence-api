package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
)

// APIKeyAuth validates the X-API-Key header and sets "api_key_roles" on the context.
func APIKeyAuth(repo auth.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing API key"})
			return
		}

		customer, err := repo.GetByKey(c.Request.Context(), key)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			return
		}

		c.Set("api_key_roles", customer.Roles)
		c.Next()
	}
}

// RequireRoles returns middleware that checks the authenticated roles (set by
// APIKeyAuth) against a set of allowed roles. Returns 403 if none of the
// customer's roles are in the allowed set.
func RequireRoles(allowed ...string) gin.HandlerFunc {
	set := make(map[string]struct{}, len(allowed))
	for _, r := range allowed {
		set[r] = struct{}{}
	}
	return func(c *gin.Context) {
		val, _ := c.Get("api_key_roles")
		roles, _ := val.([]string)
		for _, r := range roles {
			if _, ok := set[r]; ok {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	}
}
