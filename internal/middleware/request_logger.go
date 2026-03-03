package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
		requestID := uuid.New().String()
		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)

		start := time.Now()

		c.Next()

		fields := []zap.Field{
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
			zap.Int("response_bytes", c.Writer.Size()),
		}

		if apiKeyID, exists := c.Get("api_key_id"); exists {
			if v, ok := apiKeyID.(int); ok {
				fields = append(fields, zap.Int("api_key_id", v))
			}
		}
		if tier, exists := c.Get("api_key_tier"); exists {
			if v, ok := tier.(string); ok {
				fields = append(fields, zap.String("api_key_tier", v))
			}
		}
		if roles, exists := c.Get("api_key_roles"); exists {
			if v, ok := roles.([]string); ok {
				fields = append(fields, zap.Strings("api_key_roles", v))
			}
		}

		for _, key := range ContextKeys {
			if val, exists := c.Get(key); exists {
				if v, ok := val.(bool); ok {
					fields = append(fields, zap.Bool(key, v))
				}
			}
		}

		status := c.Writer.Status()
		if status >= 500 {
			logger.Error("request", fields...)
		} else {
			logger.Info("request", fields...)
		}
	}
}
