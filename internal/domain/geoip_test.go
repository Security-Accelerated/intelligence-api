package domain

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// stubDBIP serves the given body for one release month and 404s every other,
// and points dbipDownloadURL at it for the duration of the test. The stub is on
// loopback, which safenet rightly blocks, so trustedTransport is swapped for a
// plain one.
func stubDBIP(t *testing.T, release string, body []byte) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, release) {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	orig := dbipDownloadURL
	dbipDownloadURL = srv.URL + "/dbip-city-lite-%s.mmdb.gz"
	t.Cleanup(func() { dbipDownloadURL = orig })

	origTransport := trustedTransport
	trustedTransport = &http.Transport{}
	t.Cleanup(func() { trustedTransport = origTransport })
}

func TestDBIPReleases(t *testing.T) {
	tests := []struct {
		now  time.Time
		want []string
	}{
		{time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC), []string{"2026-09", "2026-08"}},
		{time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), []string{"2026-01", "2025-12"}},
		// The 31st must not skip a month the way AddDate on the day would.
		{time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC), []string{"2026-03", "2026-02"}},
	}
	for _, tt := range tests {
		got := dbipReleases(tt.now)
		if len(got) != 2 || got[0] != tt.want[0] || got[1] != tt.want[1] {
			t.Errorf("dbipReleases(%s) = %v, want %v", tt.now.Format(time.DateOnly), got, tt.want)
		}
	}
}

func TestDownloadMMDB(t *testing.T) {
	payload := []byte("not really an mmdb, but the downloader does not care")
	stubDBIP(t, "2026-09", gzipped(t, payload))
	client := &http.Client{}

	t.Run("streams and decompresses", func(t *testing.T) {
		dir := t.TempDir()
		path, sum, size, err := downloadMMDB(context.Background(), client, "2026-09", dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) || size != int64(len(payload)) || len(sum) != 64 {
			t.Errorf("got %d bytes (size %d, sha %q), want the %d-byte payload", len(got), size, sum, len(payload))
		}
	})

	t.Run("unpublished month is distinguishable", func(t *testing.T) {
		_, _, _, err := downloadMMDB(context.Background(), client, "2026-10", t.TempDir())
		if !errors.Is(err, errReleaseNotPublished) {
			t.Errorf("err = %v, want errReleaseNotPublished", err)
		}
	})

	t.Run("oversized file is rejected, not truncated", func(t *testing.T) {
		orig := maxMMDBBytes
		maxMMDBBytes = 10
		t.Cleanup(func() { maxMMDBBytes = orig })

		dir := t.TempDir()
		_, _, _, err := downloadMMDB(context.Background(), client, "2026-09", dir)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v, want a size-limit error", err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("left %d files behind, want the temp file removed", len(entries))
		}
	})
}

// The current month 404s early in the month, before DB-IP publishes it; the
// refresh must fall back to last month rather than fail. The stub body is not
// a valid database, so reaching validation proves the fallback fetched it.
func TestDownloadAndReload_FallsBackToPreviousMonth(t *testing.T) {
	previous := dbipReleases(time.Now())[1]
	stubDBIP(t, previous, gzipped(t, []byte("garbage")))

	dir := t.TempDir()
	r := NewEmptyGeoIPReader()
	_, err := r.DownloadAndReload(context.Background(), dir, "city.mmdb")
	if err == nil || !strings.Contains(err.Error(), "validate city db") {
		t.Fatalf("err = %v, want a validation error after falling back to %s", err, previous)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("left %d files behind, want the invalid download removed", len(entries))
	}
	if r.Loaded() {
		t.Error("reader reports loaded after a failed refresh")
	}
}

func TestDownloadAndReload_NoReleasePublished(t *testing.T) {
	stubDBIP(t, "1999-01", nil)

	_, err := NewEmptyGeoIPReader().DownloadAndReload(context.Background(), t.TempDir(), "city.mmdb")
	if !errors.Is(err, errReleaseNotPublished) {
		t.Errorf("err = %v, want errReleaseNotPublished when neither month exists", err)
	}
}
