package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func newHealthRouter(h *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/v1/health", h.Health)
	return r
}

func doHealthRequest(r *gin.Engine) (rec *httptest.ResponseRecorder, body map[string]any) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", http.NoBody)
	r.ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

func TestHealth_NothingConfigured(t *testing.T) {
	h := New(Deps{})
	w, body := doHealthRequest(newHealthRouter(h))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	components := body["components"].(map[string]any)
	for _, name := range []string{"postgres", "redis", "geoip"} {
		if components[name] != "not_configured" {
			t.Errorf("%s = %v, want not_configured", name, components[name])
		}
	}
}

func TestHealth_RedisUp(t *testing.T) {
	mr := miniredis.RunT(t)
	rc := cache.NewRedisCache(mr.Addr(), "", 0)
	h := New(Deps{RedisCache: rc})

	w, body := doHealthRequest(newHealthRouter(h))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	components := body["components"].(map[string]any)
	if components["redis"] != "ok" {
		t.Errorf("redis = %v, want ok", components["redis"])
	}
}

func TestHealth_RedisDown(t *testing.T) {
	mr := miniredis.RunT(t)
	rc := cache.NewRedisCache(mr.Addr(), "", 0)
	mr.Close()
	h := New(Deps{RedisCache: rc})

	w, body := doHealthRequest(newHealthRouter(h))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if body["status"] != "degraded" {
		t.Errorf("status = %v, want degraded", body["status"])
	}
	components := body["components"].(map[string]any)
	if components["redis"] != "down" {
		t.Errorf("redis = %v, want down", components["redis"])
	}
}

func TestHealth_GeoIPNotLoadedDoesNotDegrade(t *testing.T) {
	geo := domain.NewEmptyGeoIPReader()
	h := New(Deps{GeoRefresher: geo})

	w, body := doHealthRequest(newHealthRouter(h))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (missing geoip must not degrade health)", w.Code)
	}
	components := body["components"].(map[string]any)
	if components["geoip"] != "not_loaded" {
		t.Errorf("geoip = %v, want not_loaded", components["geoip"])
	}
}
