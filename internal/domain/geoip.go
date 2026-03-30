package domain

import (
	"compress/gzip"
	"crypto/sha256"
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

// MaxMind download URL template. The license key and edition are substituted at runtime.
const maxmindDownloadURL = "https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz"

// GeoIPReader provides concurrent-safe access to MaxMind GeoLite2 City and ASN
// databases. Multiple goroutines can read simultaneously; Reload() acquires a
// write lock to swap the underlying readers atomically.
type GeoIPReader struct {
	mu       sync.RWMutex
	cityDB   *geoip2.Reader
	asnDB    *geoip2.Reader
	cityPath string
	asnPath  string
}

// NewEmptyGeoIPReader creates a reader with no databases loaded. Lookups will
// return errors, but DownloadAndReload can be called to bootstrap the databases.
func NewEmptyGeoIPReader() *GeoIPReader {
	return &GeoIPReader{}
}

// NewGeoIPReader opens the City and ASN databases from the given file paths.
func NewGeoIPReader(cityPath, asnPath string) (*GeoIPReader, error) {
	cityDB, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("open city db: %w", err)
	}

	asnDB, err := geoip2.Open(asnPath)
	if err != nil {
		cityDB.Close()
		return nil, fmt.Errorf("open asn db: %w", err)
	}

	return &GeoIPReader{
		cityDB:   cityDB,
		asnDB:    asnDB,
		cityPath: cityPath,
		asnPath:  asnPath,
	}, nil
}

// LookupGeo returns geographic information for the given IP.
func (r *GeoIPReader) LookupGeo(ip net.IP) (*GeoIPInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cityDB == nil {
		return nil, fmt.Errorf("city database not loaded")
	}

	record, err := r.cityDB.City(ip)
	if err != nil {
		return nil, err
	}

	info := &GeoIPInfo{
		Latitude:       record.Location.Latitude,
		Longitude:      record.Location.Longitude,
		Timezone:       record.Location.TimeZone,
		AccuracyRadius: record.Location.AccuracyRadius,
		PostalCode:     record.Postal.Code,
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
		info.RegionCode = record.Subdivisions[0].IsoCode
	}

	return info, nil
}

// LookupASN returns ASN information for the given IP.
func (r *GeoIPReader) LookupASN(ip net.IP) (*IPASNInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.asnDB == nil {
		return nil, fmt.Errorf("asn database not loaded")
	}

	record, err := r.asnDB.ASN(ip)
	if err != nil {
		return nil, err
	}

	return &IPASNInfo{
		ASN:          int(record.AutonomousSystemNumber),
		Organization: record.AutonomousSystemOrganization,
	}, nil
}

// Reload opens new database files, validates them, and atomically swaps the
// readers. If either file fails to open, the existing databases remain in use.
func (r *GeoIPReader) Reload(cityPath, asnPath string) error {
	newCity, err := geoip2.Open(cityPath)
	if err != nil {
		return fmt.Errorf("open new city db: %w", err)
	}

	newASN, err := geoip2.Open(asnPath)
	if err != nil {
		newCity.Close()
		return fmt.Errorf("open new asn db: %w", err)
	}

	r.mu.Lock()
	oldCity := r.cityDB
	oldASN := r.asnDB
	r.cityDB = newCity
	r.asnDB = newASN
	r.cityPath = cityPath
	r.asnPath = asnPath
	r.mu.Unlock()

	if oldCity != nil {
		oldCity.Close()
	}
	if oldASN != nil {
		oldASN.Close()
	}

	return nil
}

// Close releases the underlying database readers.
func (r *GeoIPReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	if r.cityDB != nil {
		if err := r.cityDB.Close(); err != nil {
			errs = append(errs, err)
		}
		r.cityDB = nil
	}
	if r.asnDB != nil {
		if err := r.asnDB.Close(); err != nil {
			errs = append(errs, err)
		}
		r.asnDB = nil
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

// RefreshResult contains metadata about a successful database refresh.
type RefreshResult struct {
	CitySize int64  `json:"city_size_bytes"`
	ASNSize  int64  `json:"asn_size_bytes"`
	CityHash string `json:"city_sha256"`
	ASNHash  string `json:"asn_sha256"`
}

// DownloadAndReload fetches the latest MaxMind databases using the provided
// license key, writes them to temp files, validates them, and atomically swaps
// them into the reader. cityFile and asnFile are the filenames (not paths) to
// write inside dbPath, matching the configured maxmind.city_db / maxmind.asn_db.
func (r *GeoIPReader) DownloadAndReload(licenseKey, dbPath, cityFile, asnFile string) (*RefreshResult, error) {
	if licenseKey == "" {
		return nil, fmt.Errorf("maxmind license key not configured")
	}

	client := &http.Client{Timeout: 5 * time.Minute}

	cityTmp, cityHash, citySize, err := downloadMMDB(client, "GeoLite2-City", licenseKey, dbPath)
	if err != nil {
		return nil, fmt.Errorf("download city db: %w", err)
	}

	asnTmp, asnHash, asnSize, err := downloadMMDB(client, "GeoLite2-ASN", licenseKey, dbPath)
	if err != nil {
		os.Remove(cityTmp)
		return nil, fmt.Errorf("download asn db: %w", err)
	}

	// Validate by opening the temp files as MaxMind databases
	if err := r.Reload(cityTmp, asnTmp); err != nil {
		os.Remove(cityTmp)
		os.Remove(asnTmp)
		return nil, fmt.Errorf("validate downloaded databases: %w", err)
	}

	// Move temp files to final location using configured filenames
	cityFinal := filepath.Join(dbPath, cityFile)
	asnFinal := filepath.Join(dbPath, asnFile)

	if err := os.Rename(cityTmp, cityFinal); err != nil {
		os.Remove(asnTmp)
		return nil, fmt.Errorf("move city db: %w", err)
	}
	if err := os.Rename(asnTmp, asnFinal); err != nil {
		// City already moved to final; ASN temp orphaned — clean up
		os.Remove(asnTmp)
		return nil, fmt.Errorf("move asn db: %w", err)
	}

	// Re-reload from the final paths so the reader tracks the correct filenames
	if err := r.Reload(cityFinal, asnFinal); err != nil {
		return nil, fmt.Errorf("reload from final paths: %w", err)
	}

	return &RefreshResult{
		CitySize: citySize,
		ASNSize:  asnSize,
		CityHash: cityHash,
		ASNHash:  asnHash,
	}, nil
}

// downloadMMDB downloads a MaxMind database edition, decompresses it, and writes
// the .mmdb file to a temp file in dbPath. Returns the temp file path, SHA-256
// hash, and file size.
func downloadMMDB(client *http.Client, edition, licenseKey, dbPath string) (string, string, int64, error) {
	url := fmt.Sprintf(maxmindDownloadURL, edition, licenseKey)

	resp, err := client.Get(url)
	if err != nil {
		return "", "", 0, fmt.Errorf("fetch %s: %w", edition, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("fetch %s: HTTP %d", edition, resp.StatusCode)
	}

	// MaxMind returns a gzipped tarball. The .mmdb file is inside the tar.
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", "", 0, fmt.Errorf("decompress %s: %w", edition, err)
	}
	defer gz.Close()

	// Extract the .mmdb file from the tar archive
	mmdbData, err := extractMMDBFromTar(gz, edition)
	if err != nil {
		return "", "", 0, err
	}

	// Write to temp file
	if err := os.MkdirAll(dbPath, 0o755); err != nil {
		return "", "", 0, fmt.Errorf("create db directory: %w", err)
	}

	tmp, err := os.CreateTemp(dbPath, edition+"-*.mmdb")
	if err != nil {
		return "", "", 0, fmt.Errorf("create temp file: %w", err)
	}

	hasher := sha256.New()
	w := io.MultiWriter(tmp, hasher)

	n, err := w.Write(mmdbData)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", "", 0, fmt.Errorf("write %s: %w", edition, err)
	}
	tmp.Close()

	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	return tmp.Name(), hash, int64(n), nil
}
