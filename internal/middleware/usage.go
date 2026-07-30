package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/usage"
)

// UsageLog returns middleware that records request metadata to a usage.Recorder
// after the request completes. It reads context keys set by auth middleware and
// handlers (api_key_id, api_key_plan, customer_id, domain_count, ip_count,
// lookups_requested, and the per-lookup cache hit/miss counts).
func UsageLog(recorder usage.Recorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		entry := usage.UsageEntry{
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			StatusCode: c.Writer.Status(),
			LatencyMs:  int(time.Since(start).Milliseconds()),
		}

		if v, ok := c.Get("customer_id"); ok {
			if id, ok := v.(int); ok {
				entry.CustomerID = id
			}
		}
		if v, ok := c.Get("api_key_id"); ok {
			if id, ok := v.(int); ok {
				entry.APIKeyID = id
			}
		}
		if v, ok := c.Get("api_key_plan"); ok {
			if s, ok := v.(string); ok {
				entry.Plan = s
			}
		}
		if v, ok := c.Get("domain_count"); ok {
			if n, ok := v.(int); ok {
				entry.DomainCount = n
			}
		}
		if v, ok := c.Get("ip_count"); ok {
			if n, ok := v.(int); ok {
				entry.IPCount = n
			}
		}
		if v, ok := c.Get("cache_hits"); ok {
			if n, ok := v.(int); ok {
				entry.CacheHits = n
			}
		}
		if v, ok := c.Get("cache_misses"); ok {
			if n, ok := v.(int); ok {
				entry.CacheMisses = n
			}
		}
		// Requested lookups, regardless of how they were served. Both the domain
		// and IP handlers publish this key.
		if v, ok := c.Get("lookups_requested"); ok {
			if names, ok := v.([]string); ok {
				entry.Lookups = names
			}
		}

		recorder.Record(entry)
	}
}
