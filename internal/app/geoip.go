package app

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// geoipPlan is what initGeoIP intends to do with the databases on disk.
type geoipPlan struct {
	load     bool   // open what is already there
	download bool   // fetch a fresh copy
	reason   string // logged, so the choice is visible in startup logs
}

// planGeoIP decides whether the databases on disk are usable, refreshable, or
// absent. Split out from initGeoIP because it is the part with the interesting
// behaviour and it can be tested without touching the network.
//
// A stale database is still loaded before the refresh is started: serving
// slightly out-of-date geolocation immediately beats serving none for the
// minute or so a download takes.
//
// maxAge <= 0 disables the staleness check, pinning whatever is on disk.
func planGeoIP(cityPath string, maxAge time.Duration, now time.Time) geoipPlan {
	info, err := os.Stat(cityPath)
	if err != nil {
		return geoipPlan{download: true, reason: "no database on disk"}
	}
	if maxAge > 0 && now.Sub(info.ModTime()) > maxAge {
		return geoipPlan{load: true, download: true, reason: "database on disk is older than maxmind.max_age"}
	}
	return geoipPlan{load: true, reason: "database on disk is current"}
}

// initGeoIP returns a GeoIPReader for the configured MaxMind databases, opening
// whatever is already on disk and downloading in the background when what is
// there is missing, unreadable, or stale.
//
// The download is backgrounded rather than awaited because it is around 80 MB.
// Blocking startup would hold the listener down past Fly's health checks on
// every cold start, and with auto_stop_machines those are frequent. Lookups
// already degrade gracefully — geo and asn report "geoip database not loaded"
// rather than failing the whole request — so serving immediately and filling
// the databases in a few seconds later is strictly better than not serving.
//
// Without this, an ephemeral /data/maxmind came up empty after every restart
// and only an admin calling POST /v1/admin/geoip/refresh by hand restored geo
// and asn. That endpoint remains, for forcing a refresh between restarts.
func initGeoIP(ctx context.Context, cfg *viper.Viper, logger *zap.Logger, status *config.StatusSnapshot) *domain.GeoIPReader {
	dbPath := cfg.GetString("maxmind.db_path")
	cityFile := cfg.GetString("maxmind.city_db")
	asnFile := cfg.GetString("maxmind.asn_db")
	cityPath := filepath.Join(dbPath, cityFile)
	asnPath := filepath.Join(dbPath, asnFile)

	geoStatus := config.GeoIPStatus{
		Enabled: true,
		CityDB:  cityFile,
		ASNDB:   asnFile,
		DBPath:  dbPath,
	}

	plan := planGeoIP(cityPath, cfg.GetDuration("maxmind.max_age"), time.Now())

	reader := domain.NewEmptyGeoIPReader()
	if plan.load {
		loaded, err := domain.NewGeoIPReader(cityPath, asnPath)
		if err != nil {
			// Unreadable is worse than absent: a truncated download from a
			// killed machine looks like a database until it is opened.
			logger.Warn("failed to open MaxMind databases, will download a fresh copy", zap.Error(err))
			plan.download = true
		} else {
			reader = loaded
			status.SetGeoIPStatus(geoStatus)
			logger.Info("geoip databases loaded", zap.String("reason", plan.reason), zap.Any("config", geoStatus))
		}
	}

	if !plan.download {
		return reader
	}

	licenseKey := cfg.GetString("maxmind.license_key")
	if licenseKey == "" {
		logger.Warn("geoip databases need downloading but no license key is configured; geo and asn will be unavailable",
			zap.String("reason", plan.reason), zap.String("path", cityPath))
		return reader
	}

	go func() {
		logger.Info("downloading geoip databases", zap.String("reason", plan.reason), zap.String("path", dbPath))
		result, err := reader.DownloadAndReload(ctx, licenseKey, dbPath, cityFile, asnFile)
		if err != nil {
			// Not fatal: the process serves everything else, and geo/asn keep
			// reporting that they are unavailable. POST /v1/admin/geoip/refresh
			// retries without a redeploy.
			logger.Error("geoip bootstrap download failed", zap.Error(err))
			return
		}
		status.SetGeoIPStatus(geoStatus)
		logger.Info("geoip databases downloaded", zap.Any("result", result), zap.Any("config", geoStatus))
	}()

	return reader
}
