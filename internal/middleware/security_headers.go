package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders sets defensive HTTP headers on every response.
// The Content-Security-Policy here is a strict default suitable for the JSON
// API; HTML-serving handlers override it with a page-specific policy.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Cache-Control", "no-store")
		c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		c.Next()
	}
}
