package middleware

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// RateLimitConfig holds per-plan request limits (requests per minute).
type RateLimitConfig struct {
	Free int
	Pro  int
}

// RateLimit returns middleware that enforces per-API-key, plan-aware rate
// limiting using a weighted sliding window over two adjacent one-minute
// buckets in Redis. It must run after APIKeyAuth so that api_key_id and
// api_key_plan are available in the context.
//
// The weighted approach prevents the boundary-straddling issue where a
// fixed bucket allows up to 2× the limit across adjacent minutes.
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

		plan, _ := c.Get("api_key_plan")
		planStr, _ := plan.(string)

		if planStr == "admin" {
			c.Next()
			return
		}

		// Free is both its own plan and the fallback: an unrecognized plan
		// gets the least privileged limit, matching how lookup gating
		// treats a plan it does not know.
		limit := cfg.Free
		if planStr == "pro" {
			limit = cfg.Pro
		}

		now := time.Now()
		currentBucket := now.Unix() / 60
		previousBucket := currentBucket - 1
		elapsedFraction := float64(now.Unix()%60) / 60.0

		currentKey := fmt.Sprintf("ratelimit:%d:%d", keyID, currentBucket)
		previousKey := fmt.Sprintf("ratelimit:%d:%d", keyID, previousBucket)

		ctx := c.Request.Context()

		// Increment current bucket and read previous bucket in a pipeline.
		pipe := client.Pipeline()
		currentCmd := pipe.Incr(ctx, currentKey)
		previousCmd := pipe.Get(ctx, previousKey)
		pipe.Expire(ctx, currentKey, 2*time.Minute)
		_, execErr := pipe.Exec(ctx)

		// If the INCR on the current bucket failed, Redis is likely down — fail open.
		// We check currentCmd specifically because previousCmd returns redis.Nil for
		// missing keys which is expected and not a real error.
		currentCount := currentCmd.Val()
		if currentCount == 0 && execErr != nil {
			logger.Warn("rate limiter redis error, allowing request", zap.Error(execErr))
			c.Next()
			return
		}

		previousCount, _ := previousCmd.Int64() // 0 if key expired/missing

		// Weighted sliding window: weight previous bucket by how much of it
		// still falls within the trailing 60-second window.
		weighted := float64(currentCount) + float64(previousCount)*(1.0-elapsedFraction)
		count := int64(math.Ceil(weighted))

		c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
		remaining := max(limit-int(count), 0)
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		c.Set("rate_limit", limit)
		c.Set("rate_limit_remaining", remaining)

		if int(count) > limit {
			retryAfter := 60 - (now.Unix() % 60)
			c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
			logger.Warn("rate limit exceeded",
				zap.Int("api_key_id", keyID.(int)),
				zap.String("plan", planStr),
				zap.Int64("count", count),
				zap.Int("limit", limit),
			)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}

		c.Next()
	}
}
