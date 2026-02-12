package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

func RequestLogger() gin.HandlerFunc {
	logger := logging.Logger()

	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		logger.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		)
	}
}
