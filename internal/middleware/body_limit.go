package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodyLimit rejects request bodies larger than maxBytes with 413 Payload Too Large.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
