package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const healthCheckTimeout = 2 * time.Second

// Health reports dependency health for load balancers and uptime monitoring.
// Unauthenticated by design — it returns only component states, never
// addresses, versions, or other internals. Postgres or Redis being down makes
// the endpoint return 503; the GeoIP database is optional (absent until its
// download lands on a fresh volume) so its state is reported but does not
// degrade overall health.
func (h *Handler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), healthCheckTimeout)
	defer cancel()

	components := gin.H{}
	healthy := true

	if h.db != nil {
		if err := h.db.PingContext(ctx); err != nil {
			components["postgres"] = "down"
			healthy = false
		} else {
			components["postgres"] = "ok"
		}
	} else {
		components["postgres"] = "not_configured"
	}

	if h.redisCache != nil {
		if err := h.redisCache.Ping(ctx); err != nil {
			components["redis"] = "down"
			healthy = false
		} else {
			components["redis"] = "ok"
		}
	} else {
		components["redis"] = "not_configured"
	}

	if g, ok := h.geoRefresher.(interface{ Loaded() bool }); ok {
		if g.Loaded() {
			components["geoip"] = "ok"
		} else {
			components["geoip"] = "not_loaded"
		}
	} else {
		components["geoip"] = "not_configured"
	}

	status := "ok"
	code := http.StatusOK
	if !healthy {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	c.JSON(code, gin.H{"status": status, "components": components})
}
