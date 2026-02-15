package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
)

// APIKeyAuth validates the X-API-Key header and sets "api_key_role" on the context.
func APIKeyAuth(repo auth.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing API key"})
			return
		}

		apiKey, err := repo.GetByKey(c.Request.Context(), key)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			return
		}

		c.Set("api_key_role", apiKey.Role)
		c.Next()
	}
}

// RequireRoles returns middleware that checks the authenticated role (set by
// APIKeyAuth) against a set of allowed roles. Returns 403 if the role is not
// in the allowed set.
func RequireRoles(allowed ...string) gin.HandlerFunc {
	set := make(map[string]struct{}, len(allowed))
	for _, r := range allowed {
		set[r] = struct{}{}
	}
	return func(c *gin.Context) {
		role, _ := c.Get("api_key_role")
		if _, ok := set[role.(string)]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
		c.Next()
	}
}
