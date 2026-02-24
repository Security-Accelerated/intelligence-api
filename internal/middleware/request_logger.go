package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

func RequestLogger() gin.HandlerFunc {
	logger := logging.Logger()

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

		if cacheHit, exists := c.Get("cache_hit"); exists {
			fields = append(fields, zap.Bool("cache_hit", cacheHit.(bool)))
		}

		if screenshot, exists := c.Get("screenshot_requested"); exists {
			fields = append(fields, zap.Bool("screenshot_requested", screenshot.(bool)))
		}

		if typosquatting, exists := c.Get("typosquatting_requested"); exists {
			fields = append(fields, zap.Bool("typosquatting_requested", typosquatting.(bool)))
		}

		if reputation, exists := c.Get("reputation_requested"); exists {
			fields = append(fields, zap.Bool("reputation_requested", reputation.(bool)))
		}

		logger.Info("request", fields...)
	}
}
