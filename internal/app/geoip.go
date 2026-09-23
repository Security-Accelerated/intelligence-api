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

// geoipPlan is what initGeoIP intends to do with the database on disk.
type geoipPlan struct {
	load     bool   // open what is already there
	download bool   // fetch a fresh copy
	reason   string // logged, so the choice is visible in startup logs
}

// planGeoIP decides whether the database on disk is usable, refreshable, or
// absent. Split out from initGeoIP because it is the part with the interesting
// behavior and it can be tested without touching the network.
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
		return geoipPlan{load: true, download: true, reason: "database on disk is older than geoip.max_age"}
	}
	return geoipPlan{load: true, reason: "database on disk is current"}
}

// initGeoIP returns a GeoIPReader for the configured DB-IP City database,
// opening whatever is already on disk and downloading in the background when
// what is there is missing, unreadable, or stale.
//
// The download is backgrounded rather than awaited because it is around 60 MB
// compressed. Blocking startup would hold the listener down past Fly's health
// checks. geo already degrades gracefully — it reports "geoip database not
// loaded" rather than failing the whole request — so serving immediately and
// filling the database in a few seconds later is strictly better than not
// serving. POST /v1/admin/geoip/refresh forces a refresh between restarts.
func initGeoIP(ctx context.Context, cfg *viper.Viper, logger *zap.Logger, status *config.StatusSnapshot) *domain.GeoIPReader {
	dbPath := cfg.GetString("geoip.db_path")
	cityFile := cfg.GetString("geoip.city_db")
	cityPath := filepath.Join(dbPath, cityFile)

	geoStatus := config.GeoIPStatus{
		Enabled: true,
		CityDB:  cityFile,
		DBPath:  dbPath,
	}

	plan := planGeoIP(cityPath, cfg.GetDuration("geoip.max_age"), time.Now())

	reader := domain.NewEmptyGeoIPReader()
	if plan.load {
		loaded, err := domain.NewGeoIPReader(cityPath)
		if err != nil {
			// Unreadable is worse than absent: a truncated download from a
			// killed machine looks like a database until it is opened.
			logger.Warn("failed to open geoip database, will download a fresh copy", zap.Error(err))
			plan.download = true
		} else {
			reader = loaded
			status.SetGeoIPStatus(geoStatus)
			logger.Info("geoip database loaded", zap.String("reason", plan.reason), zap.Any("config", geoStatus))
		}
	}

	if !plan.download {
		return reader
	}

	go func() {
		logger.Info("downloading geoip database", zap.String("reason", plan.reason), zap.String("path", dbPath))
		result, err := reader.DownloadAndReload(ctx, dbPath, cityFile)
		if err != nil {
			// Not fatal: the process serves everything else, and geo keeps
			// reporting that it is unavailable. POST /v1/admin/geoip/refresh
			// retries without a redeploy.
			logger.Error("geoip bootstrap download failed", zap.Error(err))
			return
		}
		status.SetGeoIPStatus(geoStatus)
		logger.Info("geoip database downloaded", zap.Any("result", result), zap.Any("config", geoStatus))
	}()

	return reader
}
