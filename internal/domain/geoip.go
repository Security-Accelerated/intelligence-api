package domain

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// dbipDownloadURL is the DB-IP Lite City release for a given month (YYYY-MM).
// The Lite databases are CC BY 4.0 — commercial use is allowed with a link back
// to db-ip.com, which /docs/ip carries. var (not const) so tests can point it
// at a stub server.
var dbipDownloadURL = "https://download.db-ip.com/free/dbip-city-lite-%s.mmdb.gz"

// maxMMDBBytes caps the decompressed database so a malformed or hostile
// response cannot fill the volume. The City Lite file is about 127 MB. var so
// tests can lower it.
var maxMMDBBytes int64 = 256 << 20

// ErrDBNotLoaded is returned when a GeoIP lookup is attempted before the
// database is loaded (e.g., a fresh volume before the first download lands).
var ErrDBNotLoaded = fmt.Errorf("geoip database not loaded")

// errReleaseNotPublished marks a month DB-IP has not published yet, so the
// download falls back to the previous month instead of failing.
var errReleaseNotPublished = errors.New("release not published")

// GeoIPReader provides concurrent-safe access to the DB-IP City database, which
// uses the GeoIP2 City layout. Multiple goroutines can read simultaneously;
// Reload() acquires a write lock to swap the underlying reader atomically.
type GeoIPReader struct {
	mu       sync.RWMutex
	cityDB   *geoip2.Reader
	cityPath string
}

// NewEmptyGeoIPReader creates a reader with no database loaded. Lookups will
// return ErrDBNotLoaded until DownloadAndReload or Reload succeeds.
func NewEmptyGeoIPReader() *GeoIPReader {
	return &GeoIPReader{}
}

// NewGeoIPReader opens the City database at cityPath.
func NewGeoIPReader(cityPath string) (*GeoIPReader, error) {
	cityDB, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("open city db: %w", err)
	}
	return &GeoIPReader{cityDB: cityDB, cityPath: cityPath}, nil
}

// Loaded reports whether the database is loaded and lookups can serve data.
func (r *GeoIPReader) Loaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cityDB != nil
}

// LookupGeo returns geographic information for the given IP. DB-IP Lite carries
// no postal code, timezone, accuracy radius, or subdivision code, so GeoIPInfo
// has no fields for them.
func (r *GeoIPReader) LookupGeo(ip net.IP) (*GeoIPInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cityDB == nil {
		return nil, ErrDBNotLoaded
	}

	record, err := r.cityDB.City(ip)
	if err != nil {
		return nil, err
	}

	info := &GeoIPInfo{
		Latitude:  record.Location.Latitude,
		Longitude: record.Location.Longitude,
	}
	if record.Continent.Names != nil {
		info.Continent = record.Continent.Names["en"]
		info.ContinentCode = record.Continent.Code
	}
	if record.Country.Names != nil {
		info.Country = record.Country.Names["en"]
		info.CountryCode = record.Country.IsoCode
	}
	if record.City.Names != nil {
		info.City = record.City.Names["en"]
	}
	if len(record.Subdivisions) > 0 {
		info.Region = record.Subdivisions[0].Names["en"]
	}

	return info, nil
}

// Reload opens a new database file and atomically swaps the reader. If the
// file fails to open, the existing database remains in use.
func (r *GeoIPReader) Reload(cityPath string) error {
	newCity, err := geoip2.Open(cityPath)
	if err != nil {
		return fmt.Errorf("open new city db: %w", err)
	}

	r.mu.Lock()
	oldCity := r.cityDB
	r.cityDB = newCity
	r.cityPath = cityPath
	r.mu.Unlock()

	if oldCity != nil {
		oldCity.Close()
	}
	return nil
}

// Close releases the underlying database reader.
func (r *GeoIPReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cityDB == nil {
		return nil
	}
	err := r.cityDB.Close()
	r.cityDB = nil
	return err
}

// RefreshResult contains metadata about a successful database refresh.
type RefreshResult struct {
	Release string `json:"release"` // DB-IP release month, YYYY-MM
	Size    int64  `json:"size_bytes"`
	SHA256  string `json:"sha256"`
}

// DownloadAndReload fetches the current DB-IP Lite City release, writes it to a
// temp file in dbPath, validates it, moves it to dbPath/cityFile, and swaps it
// into the reader. DB-IP publishes monthly and the new month appears a few days
// in, so a month that is not published yet falls back to the previous one.
// ctx cancels the in-flight download; the 5-minute client timeout is the
// absolute ceiling.
func (r *GeoIPReader) DownloadAndReload(ctx context.Context, dbPath, cityFile string) (*RefreshResult, error) {
	client := &http.Client{Timeout: 5 * time.Minute, Transport: trustedTransport}

	var (
		tmpPath string
		result  RefreshResult
		err     error
	)
	for _, release := range dbipReleases(time.Now()) {
		tmpPath, result.SHA256, result.Size, err = downloadMMDB(ctx, client, release, dbPath)
		if err == nil {
			result.Release = release
			break
		}
		if !errors.Is(err, errReleaseNotPublished) {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}

	// Validate with a throwaway reader before touching the live one.
	testCity, err := geoip2.Open(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("validate city db: %w", err)
	}
	testCity.Close()

	final := filepath.Join(dbPath, cityFile)
	if err := os.Rename(tmpPath, final); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("move city db: %w", err)
	}
	if err := r.Reload(final); err != nil {
		return nil, fmt.Errorf("reload from final path: %w", err)
	}
	return &result, nil
}

// dbipReleases lists the release months to try, newest first.
func dbipReleases(now time.Time) []string {
	now = now.UTC()
	firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return []string{
		firstOfMonth.Format("2006-01"),
		firstOfMonth.AddDate(0, -1, 0).Format("2006-01"),
	}
}

// downloadMMDB streams one gzipped release into a temp file in dbPath and
// returns its path, SHA-256, and size. Streaming rather than buffering keeps a
// 127 MB database out of memory on a small machine. A 404 is reported as
// errReleaseNotPublished.
func downloadMMDB(ctx context.Context, client *http.Client, release, dbPath string) (tmpPath, sha256Hex string, size int64, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(dbipDownloadURL, release), http.NoBody)
	if err != nil {
		return "", "", 0, fmt.Errorf("build %s request: %w", release, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, fmt.Errorf("fetch %s: %w", release, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", "", 0, fmt.Errorf("fetch %s: %w", release, errReleaseNotPublished)
	case resp.StatusCode != http.StatusOK:
		return "", "", 0, fmt.Errorf("fetch %s: HTTP %d", release, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", "", 0, fmt.Errorf("decompress %s: %w", release, err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dbPath, 0o755); err != nil {
		return "", "", 0, fmt.Errorf("create db directory: %w", err)
	}
	tmp, err := os.CreateTemp(dbPath, "dbip-city-*.mmdb")
	if err != nil {
		return "", "", 0, fmt.Errorf("create temp file: %w", err)
	}
	fail := func(err error) (string, string, int64, error) {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", "", 0, err
	}

	hasher := sha256.New()
	// Read one byte past the cap so an oversized file is detected rather than
	// silently truncated into a corrupt database.
	n, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(gz, maxMMDBBytes+1))
	if err != nil {
		return fail(fmt.Errorf("write %s: %w", release, err))
	}
	if n > maxMMDBBytes {
		return fail(fmt.Errorf("%s exceeds %d byte limit", release, maxMMDBBytes))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", "", 0, fmt.Errorf("close %s: %w", release, err)
	}

	return tmp.Name(), fmt.Sprintf("%x", hasher.Sum(nil)), n, nil
}
