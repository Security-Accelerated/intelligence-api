package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
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
	cityFile := "GeoLite2-City.mmdb"
	asnFile := "GeoLite2-ASN.mmdb"
	if h.cfg != nil {
		licenseKey = h.cfg.GetString("maxmind.license_key")
		dbPath = h.cfg.GetString("maxmind.db_path")
		cityFile = h.cfg.GetString("maxmind.city_db")
		asnFile = h.cfg.GetString("maxmind.asn_db")
	}

	if licenseKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maxmind license key not configured"})
		return
	}

	result, err := h.geoRefresher.DownloadAndReload(c.Request.Context(), licenseKey, dbPath, cityFile, asnFile)
	if err != nil {
		logging.Logger().Error("geoip refresh failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "geoip refresh failed"})
		return
	}

	if h.status != nil {
		h.status.SetGeoIPStatus(config.GeoIPStatus{
			Enabled: true,
			CityDB:  cityFile,
			ASNDB:   asnFile,
			DBPath:  dbPath,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MaxMind databases refreshed",
		"details": result,
	})
}
