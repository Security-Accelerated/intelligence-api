package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/spf13/viper"
)

type mockGeoRefresher struct {
	err    error
	result *domain.RefreshResult
}

func (m *mockGeoRefresher) DownloadAndReload(_ context.Context, _, _, _, _ string) (*domain.RefreshResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.result != nil {
		return m.result, nil
	}
	return &domain.RefreshResult{CitySize: 1000, ASNSize: 500, CityHash: "abc", ASNHash: "def"}, nil
}

func newGeoIPAdminRouter(refresher GeoIPRefresher, cfg *viper.Viper) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(Deps{GeoRefresher: refresher, Config: cfg})
	admin := r.Group("/v1/admin")
	admin.POST("/geoip/refresh", h.RefreshGeoIP)
	return r
}

func TestRefreshGeoIP_Success(t *testing.T) {
	cfg := viper.New()
	cfg.Set("maxmind.license_key", "test-key")
	cfg.Set("maxmind.db_path", "/tmp/test")

	r := newGeoIPAdminRouter(&mockGeoRefresher{}, cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRefreshGeoIP_NoRefresher(t *testing.T) {
	r := newGeoIPAdminRouter(nil, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestRefreshGeoIP_NoLicenseKey(t *testing.T) {
	cfg := viper.New()
	cfg.Set("maxmind.license_key", "")

	r := newGeoIPAdminRouter(&mockGeoRefresher{}, cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRefreshGeoIP_RefreshError(t *testing.T) {
	cfg := viper.New()
	cfg.Set("maxmind.license_key", "test-key")
	cfg.Set("maxmind.db_path", "/tmp/test")

	r := newGeoIPAdminRouter(&mockGeoRefresher{err: errors.New("download failed")}, cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}
