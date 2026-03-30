package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RefreshGeoIP triggers a download and hot-reload of the MaxMind GeoIP databases.
// Admin-only, bodyless endpoint.
func (h *Handler) RefreshGeoIP(c *gin.Context) {
	if h.geoRefresher == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "geoip not configured"})
		return
	}

	licenseKey := ""
	dbPath := "/data/maxmind"
	if h.cfg != nil {
		licenseKey = h.cfg.GetString("maxmind.license_key")
		dbPath = h.cfg.GetString("maxmind.db_path")
	}

	if licenseKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maxmind license key not configured"})
		return
	}

	result, err := h.geoRefresher.DownloadAndReload(licenseKey, dbPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MaxMind databases refreshed",
		"details": result,
	})
}
