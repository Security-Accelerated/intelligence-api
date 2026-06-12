package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/usage"
)

// UsageLog returns middleware that records request metadata to a usage.Recorder
// after the request completes. It reads context keys set by auth middleware and
// handlers (api_key_id, api_key_plan, customer_id, domain_count, cache_hit, and
// the feature-request booleans).
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
		if v, ok := c.Get("cache_hit"); ok {
			if b, ok := v.(bool); ok {
				entry.CacheHit = b
			}
		}
		if v, ok := c.Get("screenshot_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.Screenshot = b
			}
		}
		if v, ok := c.Get("reputation_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.Reputation = b
			}
		}
		if v, ok := c.Get("email_security_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.EmailSecurity = b
			}
		}
		if v, ok := c.Get("subdomain_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.Subdomains = b
			}
		}
		if v, ok := c.Get("ct_logs_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.CTLogs = b
			}
		}
		if v, ok := c.Get("bgp_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.BGP = b
			}
		}
		if v, ok := c.Get("fingerprint_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.Fingerprint = b
			}
		}
		if v, ok := c.Get("threat_intel_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.ThreatIntel = b
			}
		}
		if v, ok := c.Get("dns_security_requested"); ok {
			if b, ok := v.(bool); ok {
				entry.DNSSecurity = b
			}
		}
		if v, ok := c.Get("ip_threat_intel_requested"); ok {
			if b, ok := v.(bool); ok && b {
				entry.ThreatIntel = true
			}
		}

		recorder.Record(entry)
	}
}
