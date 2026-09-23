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
	err     error
	gotPath string
	gotCity string
}

func (m *mockGeoRefresher) DownloadAndReload(_ context.Context, dbPath, cityFile string) (*domain.RefreshResult, error) {
	m.gotPath, m.gotCity = dbPath, cityFile
	if m.err != nil {
		return nil, m.err
	}
	return &domain.RefreshResult{Release: "2026-09", Size: 1000, SHA256: "abc"}, nil
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
	cfg.Set("geoip.db_path", "/tmp/test")
	cfg.Set("geoip.city_db", "city.mmdb")

	m := &mockGeoRefresher{}
	r := newGeoIPAdminRouter(m, cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if m.gotPath != "/tmp/test" || m.gotCity != "city.mmdb" {
		t.Errorf("refresh got path %q file %q, want the configured /tmp/test and city.mmdb", m.gotPath, m.gotCity)
	}
}

func TestRefreshGeoIP_NoRefresher(t *testing.T) {
	r := newGeoIPAdminRouter(nil, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestRefreshGeoIP_RefreshError(t *testing.T) {
	r := newGeoIPAdminRouter(&mockGeoRefresher{err: errors.New("download failed")}, viper.New())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}
