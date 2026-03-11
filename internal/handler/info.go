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
			"start_time": h.cfg.GetString("application.start.time"),
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
			"cache_ttl":        h.cfg.GetDuration("redis.cache_ttl").String(),
			"auth_cache_ttl":   h.cfg.GetDuration("auth.cache_ttl").String(),
			"screenshot_timeout": h.cfg.GetDuration("screenshot.timeout").String(),
			"rate_limit_basic": h.cfg.GetInt("rate_limit.basic"),
			"rate_limit_pro":   h.cfg.GetInt("rate_limit.pro"),
			"postgres_host":    h.cfg.GetString("postgres.host"),
			"postgres_port":    h.cfg.GetInt("postgres.port"),
			"postgres_dbname":  h.cfg.GetString("postgres.dbname"),
			"postgres_sslmode": h.cfg.GetString("postgres.sslmode"),
		},
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

	if h.cachedRepo != nil {
		resp["auth_cache"] = gin.H{
			"ttl":  h.cfg.GetDuration("auth.cache_ttl").String(),
			"size": h.cachedRepo.Size(),
		}
	}

	c.JSON(http.StatusOK, resp)
}
