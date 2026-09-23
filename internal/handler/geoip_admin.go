package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// RefreshGeoIP triggers a download and hot-reload of the GeoIP City database.
// Admin-only, bodyless endpoint.
func (h *Handler) RefreshGeoIP(c *gin.Context) {
	if h.geoRefresher == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "geoip not configured"})
		return
	}

	dbPath := "/data/geoip"
	cityFile := "dbip-city-lite.mmdb"
	if h.cfg != nil {
		dbPath = h.cfg.GetString("geoip.db_path")
		cityFile = h.cfg.GetString("geoip.city_db")
	}

	result, err := h.geoRefresher.DownloadAndReload(c.Request.Context(), dbPath, cityFile)
	if err != nil {
		logging.Logger().Error("geoip refresh failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "geoip refresh failed"})
		return
	}

	if h.status != nil {
		h.status.SetGeoIPStatus(config.GeoIPStatus{
			Enabled: true,
			CityDB:  cityFile,
			DBPath:  dbPath,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "geoip database refreshed",
		"details": result,
	})
}
