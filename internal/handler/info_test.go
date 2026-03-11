package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/spf13/viper"
)

// stubRepo implements auth.Repository for seeding the CachedRepository.
type stubRepo struct {
	customer *auth.Customer
}

func (s *stubRepo) GetByKey(_ context.Context, _ string) (*auth.Customer, error) {
	return s.customer, nil
}

func newInfoRouter(version string, cfg *viper.Viper, rc *cache.RedisCache, cr *auth.CachedRepository) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, version, cfg, rc, cr)
	// Simulate admin auth so RequireAdmin passes
	r.GET("/api/v1/info", func(c *gin.Context) {
		c.Set("api_key_plan", "admin")
		c.Next()
	}, h.Info)
	return r
}

func doInfoRequest(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/info", nil)
	r.ServeHTTP(w, req)
	return w
}

func parseInfoResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal info response: %v", err)
	}
	return resp
}

func TestInfo_NilRedisAndNilCachedRepo(t *testing.T) {
	cfg := viper.New()
	cfg.Set("application.name", "test-api")
	cfg.Set("application.mode", "test")

	r := newInfoRouter("1.0.0", cfg, nil, nil)
	w := doInfoRequest(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseInfoResponse(t, w)

	if _, ok := resp["application"]; !ok {
		t.Error("missing 'application' key")
	}
	if _, ok := resp["environment"]; !ok {
		t.Error("missing 'environment' key")
	}
	if _, ok := resp["config"]; !ok {
		t.Error("missing 'config' key")
	}
	if _, ok := resp["redis"]; ok {
		t.Error("'redis' key should be absent when redisCache is nil")
	}
	if _, ok := resp["auth_cache"]; ok {
		t.Error("'auth_cache' key should be absent when cachedRepo is nil")
	}
}

func TestInfo_WithRedisCache(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.Set("intel:example.com", "data")
	mr.Set("intel:other.com", "data2")

	cfg := viper.New()
	cfg.Set("redis.addr", mr.Addr())
	cfg.Set("redis.db", 0)

	rc := cache.NewRedisCache(mr.Addr(), "", 0)

	r := newInfoRouter("1.0.0", cfg, rc, nil)
	w := doInfoRequest(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseInfoResponse(t, w)
	redisSection, ok := resp["redis"].(map[string]any)
	if !ok {
		t.Fatal("missing or malformed 'redis' section")
	}

	if redisSection["addr"] != mr.Addr() {
		t.Errorf("redis.addr = %v, want %v", redisSection["addr"], mr.Addr())
	}

	keyCount, ok := redisSection["key_count"].(float64)
	if !ok {
		t.Fatal("missing redis.key_count")
	}
	if int(keyCount) != 2 {
		t.Errorf("redis.key_count = %v, want 2", keyCount)
	}

	// memory_used may be absent with miniredis (no INFO memory support).
	// Just verify the field is either present with a string value or absent.
	if v, ok := redisSection["memory_used"]; ok {
		if _, isStr := v.(string); !isStr {
			t.Errorf("redis.memory_used = %T, want string", v)
		}
	}
}

func TestInfo_WithCachedRepo(t *testing.T) {
	inner := &stubRepo{customer: &auth.Customer{ID: 1, Name: "test"}}
	cr := auth.NewCachedRepository(inner, 5*time.Minute)

	// Seed the cache with two entries
	cr.GetByKey(context.Background(), "key-a")
	cr.GetByKey(context.Background(), "key-b")

	cfg := viper.New()
	cfg.Set("auth.cache_ttl", 5*time.Minute)

	r := newInfoRouter("1.0.0", cfg, nil, cr)
	w := doInfoRequest(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseInfoResponse(t, w)
	authCache, ok := resp["auth_cache"].(map[string]any)
	if !ok {
		t.Fatal("missing or malformed 'auth_cache' section")
	}

	size, ok := authCache["size"].(float64)
	if !ok {
		t.Fatal("missing auth_cache.size")
	}
	if int(size) != 2 {
		t.Errorf("auth_cache.size = %v, want 2", size)
	}
}

func TestInfo_VersionField(t *testing.T) {
	cfg := viper.New()
	r := newInfoRouter("2.5.3", cfg, nil, nil)
	w := doInfoRequest(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseInfoResponse(t, w)
	app, ok := resp["application"].(map[string]any)
	if !ok {
		t.Fatal("missing or malformed 'application' section")
	}
	if app["version"] != "2.5.3" {
		t.Errorf("application.version = %v, want %q", app["version"], "2.5.3")
	}
}
