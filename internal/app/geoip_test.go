package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeDB creates a stand-in database file with the given modification time.
func writeDB(t *testing.T, dir string, modTime time.Time) string {
	t.Helper()
	path := filepath.Join(dir, "GeoLite2-City.mmdb")
	if err := os.WriteFile(path, []byte("not really a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanGeoIP_MissingDatabaseDownloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")

	plan := planGeoIP(path, 168*time.Hour, time.Now())
	if plan.load {
		t.Error("nothing on disk to load")
	}
	if !plan.download {
		t.Error("a missing database must be downloaded — this is the ephemeral-volume case that left geo broken after every restart")
	}
}

func TestPlanGeoIP_CurrentDatabaseLoadsWithoutDownload(t *testing.T) {
	now := time.Now()
	path := writeDB(t, t.TempDir(), now.Add(-24*time.Hour))

	plan := planGeoIP(path, 168*time.Hour, now)
	if !plan.load {
		t.Error("a current database must be loaded")
	}
	if plan.download {
		t.Error("a current database must not trigger a download on every restart")
	}
}

func TestPlanGeoIP_StaleDatabaseLoadsAndRefreshes(t *testing.T) {
	now := time.Now()
	path := writeDB(t, t.TempDir(), now.Add(-8*24*time.Hour))

	plan := planGeoIP(path, 168*time.Hour, now)
	if !plan.load {
		t.Error("a stale database must still be loaded — stale geolocation now beats none for the length of a download")
	}
	if !plan.download {
		t.Error("a stale database must be refreshed")
	}
}

func TestPlanGeoIP_BoundaryIsNotStale(t *testing.T) {
	now := time.Now()
	path := writeDB(t, t.TempDir(), now.Add(-168*time.Hour))

	if plan := planGeoIP(path, 168*time.Hour, now); plan.download {
		t.Error("a database exactly at max_age is not yet stale")
	}
}

func TestPlanGeoIP_ZeroMaxAgeDisablesStalenessCheck(t *testing.T) {
	now := time.Now()
	path := writeDB(t, t.TempDir(), now.Add(-365*24*time.Hour))

	for _, maxAge := range []time.Duration{0, -1} {
		plan := planGeoIP(path, maxAge, now)
		if !plan.load {
			t.Errorf("maxAge=%v: database must still be loaded", maxAge)
		}
		if plan.download {
			t.Errorf("maxAge=%v: staleness check must be disabled", maxAge)
		}
	}
}

// TestPlanGeoIP_ReasonIsPopulated keeps the startup log useful: the reason is
// the only signal an operator has for why a download did or did not happen.
func TestPlanGeoIP_ReasonIsPopulated(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()

	cases := map[string]string{
		"missing": filepath.Join(dir, "absent.mmdb"),
		"current": writeDB(t, t.TempDir(), now),
		"stale":   writeDB(t, t.TempDir(), now.Add(-365*24*time.Hour)),
	}
	for name, path := range cases {
		if plan := planGeoIP(path, 168*time.Hour, now); plan.reason == "" {
			t.Errorf("%s: plan has no reason to log", name)
		}
	}
}
