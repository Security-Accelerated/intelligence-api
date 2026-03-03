package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// RateLimitConfig holds per-tier request limits (requests per minute).
type RateLimitConfig struct {
	Basic   int
	Premium int
}

// RateLimit returns middleware that enforces per-API-key, tier-aware rate
// limiting using a Redis sliding-window counter. It must run after APIKeyAuth
// so that api_key_id and api_key_tier are available in the context.
//
// If Redis is unavailable the request is allowed (fail-open) to avoid blocking
// the API during a Redis outage.
func RateLimit(client *redis.Client, cfg RateLimitConfig) gin.HandlerFunc {
	return RateLimitWithLogger(client, cfg, logging.Logger())
}

// RateLimitWithLogger is like RateLimit but accepts a logger for testing.
func RateLimitWithLogger(client *redis.Client, cfg RateLimitConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID, exists := c.Get("api_key_id")
		if !exists {
			c.Next()
			return
		}

		tier, _ := c.Get("api_key_tier")
		tierStr, _ := tier.(string)

		if roles, ok := c.Get("api_key_roles"); ok {
			if rs, ok := roles.([]string); ok {
				for _, r := range rs {
					if r == "admin" {
						c.Next()
						return
					}
				}
			}
		}

		limit := cfg.Basic
		if tierStr == "premium" {
			limit = cfg.Premium
		}

		bucket := time.Now().Unix() / 60
		redisKey := fmt.Sprintf("ratelimit:%d:%d", keyID, bucket)

		ctx := c.Request.Context()
		count, err := client.Incr(ctx, redisKey).Result()
		if err != nil {
			logger.Warn("rate limiter redis error, allowing request", zap.Error(err))
			c.Next()
			return
		}

		if count == 1 {
			client.Expire(ctx, redisKey, 2*time.Minute)
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
		remaining := limit - int(count)
		if remaining < 0 {
			remaining = 0
		}
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		c.Set("rate_limit", limit)
		c.Set("rate_limit_remaining", remaining)

		if int(count) > limit {
			retryAfter := 60 - (time.Now().Unix() % 60)
			c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
			logger.Warn("rate limit exceeded",
				zap.Int("api_key_id", keyID.(int)),
				zap.String("tier", tierStr),
				zap.Int64("count", count),
				zap.Int("limit", limit),
			)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}

		c.Next()
	}
}
