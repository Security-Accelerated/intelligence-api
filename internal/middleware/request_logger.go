package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// ContextKeys lists every gin context key that the request logger reads.
// Handlers must set these keys so the logger can include them. Tests use this
// slice as the single source of truth for drift detection.
var ContextKeys = []string{
	"cache_hit",
	"screenshot_requested",
	"typosquatting_requested",
	"reputation_requested",
	"check_live_requested",
}

// RequestLogger returns middleware that logs each request using the global logger.
func RequestLogger() gin.HandlerFunc {
	return RequestLoggerWithLogger(logging.Logger())
}

// RequestLoggerWithLogger returns request-logging middleware that writes to the
// supplied logger. This allows tests to inject an observable logger.
func RequestLoggerWithLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		}

		for _, key := range ContextKeys {
			if val, exists := c.Get(key); exists {
				fields = append(fields, zap.Bool(key, val.(bool)))
			}
		}

		logger.Info("request", fields...)
	}
}
