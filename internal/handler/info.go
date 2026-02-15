package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/config"
)

func (h *Handler) Info(c *gin.Context) {
	cfg := config.Config()

	c.JSON(http.StatusOK, gin.H{
		"application": gin.H{
			"name":       cfg.GetString("application.name"),
			"version":    h.version,
			"mode":       cfg.GetString("application.mode"),
			"start_time": cfg.GetString("application.start.time"),
			"session_id": cfg.GetString("application.session.id"),
		},
		"environment": gin.H{
			"host":           cfg.GetString("environment.host"),
			"os":             cfg.GetString("environment.os"),
			"os_version":     cfg.GetString("environment.os.version"),
			"architecture":   cfg.GetString("environment.architecture"),
			"golang_version": cfg.GetString("environment.golang.version"),
		},
	})
}
