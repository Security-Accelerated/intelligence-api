package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodyLimit rejects request bodies larger than maxBytes with 413 Content Too Large.
// It checks Content-Length upfront for an early reject, and wraps the body with
// MaxBytesReader as a safety net for chunked or missing Content-Length.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large",
			})
			return
		}
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
