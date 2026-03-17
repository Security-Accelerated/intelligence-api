package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handler) Info(c *gin.Context) {
	resp := gin.H{
		"application": gin.H{
			"name":       h.cfg.GetString("application.name"),
			"version":    h.version,
			"mode":       h.cfg.GetString("application.mode"),
			"start_time": h.cfg.GetTime("application.start.time"),
			"uptime":     time.Since(h.cfg.GetTime("application.start.time")).Truncate(time.Second).String(),
			"session_id": h.cfg.GetString("application.session.id"),
		},
		"environment": gin.H{
			"host":           h.cfg.GetString("environment.host"),
			"os":             h.cfg.GetString("environment.os"),
			"kernel":         h.cfg.GetString("environment.kernel"),
			"architecture":   h.cfg.GetString("environment.architecture"),
			"golang_version": h.cfg.GetString("environment.golang.version"),
		},
		"config": gin.H{
			"cache_ttl":          h.cfg.GetDuration("redis.cache_ttl").String(),
			"auth_cache_ttl":     h.cfg.GetDuration("auth.cache_ttl").String(),
			"screenshot_timeout": h.cfg.GetDuration("screenshot.timeout").String(),
			"rate_limit_free":    h.cfg.GetInt("rate_limit.free"),
			"rate_limit_basic":   h.cfg.GetInt("rate_limit.basic"),
			"rate_limit_pro":     h.cfg.GetInt("rate_limit.pro"),
			"max_domains_free":   h.cfg.GetInt("domain.max_domains.free"),
			"max_domains_basic":  h.cfg.GetInt("domain.max_domains.basic"),
			"max_domains_pro":    h.cfg.GetInt("domain.max_domains.pro"),
			"subdomain_max_results": h.cfg.GetInt("subdomain.max_results"),
			"ct_logs_max_entries":   h.cfg.GetInt("ct_logs.max_entries"),
			"postgres_host":     h.cfg.GetString("postgres.host"),
			"postgres_port":     h.cfg.GetInt("postgres.port"),
			"postgres_dbname":   h.cfg.GetString("postgres.dbname"),
			"postgres_sslmode":  h.cfg.GetString("postgres.sslmode"),
		},
		"notifications": gin.H{
			"pushover_enabled":    h.cfg.GetString("pushover.api_token") != "",
			"throttle_threshold":  h.cfg.GetInt("alerts.throttle_threshold"),
			"throttle_window":     h.cfg.GetDuration("alerts.throttle_window").String(),
			"spike_threshold":     h.cfg.GetInt("alerts.spike_threshold"),
			"spike_window":        h.cfg.GetDuration("alerts.spike_window").String(),
			"cooldown":            h.cfg.GetDuration("alerts.cooldown").String(),
		},
		"billing": gin.H{
			"stripe_enabled":         h.cfg.GetString("stripe.secret_key") != "",
			"portal_link_configured": h.cfg.GetString("stripe.portal_link") != "",
			"stale_key_days":         h.cfg.GetInt("billing.stale_key_days"),
		},
	}

	if h.fingerprintService != nil {
		resp["fingerprint"] = gin.H{
			"rule_count": len(h.fingerprintService.GetRules()),
		}
	}

	if h.redisCache != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		client := h.redisCache.Client()
		redisInfo := gin.H{
			"addr": h.cfg.GetString("redis.addr"),
			"db":   h.cfg.GetInt("redis.db"),
		}

		if keyCount, err := client.DBSize(ctx).Result(); err == nil {
			redisInfo["key_count"] = keyCount
		}

		if info, err := client.Info(ctx, "memory").Result(); err == nil {
			for _, line := range strings.Split(info, "\r\n") {
				if strings.HasPrefix(line, "used_memory_human:") {
					redisInfo["memory_used"] = strings.TrimPrefix(line, "used_memory_human:")
					break
				}
			}
		}

		resp["redis"] = redisInfo
	}

	if h.authCacheStats != nil {
		resp["auth_cache"] = gin.H{
			"ttl":  h.cfg.GetDuration("auth.cache_ttl").String(),
			"size": h.authCacheStats.Size(),
		}
	}

	c.JSON(http.StatusOK, resp)
}
