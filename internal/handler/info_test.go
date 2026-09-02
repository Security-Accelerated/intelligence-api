package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
)

// stubRepo implements auth.Repository for seeding the CachedRepository.
type stubRepo struct {
	customer *auth.Customer
}

func (s *stubRepo) GetByKey(_ context.Context, _ string) (*auth.Customer, error) {
	return s.customer, nil
}

func testStatus(version string) *config.StatusSnapshot {
	return &config.StatusSnapshot{
		System: config.SystemStatus{
			Name:    "test-api",
			Version: version,
			Mode:    "test",
		},
		Cache: config.CacheConfig{
			AuthCacheTTL: "5m",
		},
	}
}

func newInfoRouter(version string, rc *cache.RedisCache, cr AuthCacheStats) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	status := testStatus(version)
	if rc != nil {
		status.Cache.Addr = rc.Client().Options().Addr
	}
	h := New(Deps{RedisCache: rc, AuthCacheStats: cr, Status: status})
	// Simulate admin auth so RequireAdmin passes
	r.GET("/v1/info", func(c *gin.Context) {
		c.Set("api_key_plan", "admin")
		c.Next()
	}, h.Info)
	return r
}

func doInfoRequest(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/info", http.NoBody)
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
	r := newInfoRouter("1.0.0", nil, nil)
	w := doInfoRequest(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseInfoResponse(t, w)

	if _, ok := resp["system"]; !ok {
		t.Error("missing 'system' key")
	}
	if _, ok := resp["database"]; !ok {
		t.Error("missing 'database' key")
	}
	if _, ok := resp["lookups"]; !ok {
		t.Error("missing 'lookups' key")
	}
	if _, ok := resp["services"]; !ok {
		t.Error("missing 'services' key")
	}
	if _, ok := resp["runtime"]; !ok {
		t.Error("missing 'runtime' key")
	}

	// cache section should still be present (with static config) even without redis
	cacheSection, ok := resp["cache"].(map[string]any)
	if !ok {
		t.Fatal("missing or malformed 'cache' section")
	}
	// ping_ms should be absent when redisCache is nil
	if _, ok := cacheSection["ping_ms"]; ok {
		t.Error("'cache.ping_ms' should be absent when redisCache is nil")
	}
	// auth_cache_size should be absent when authCacheStats is nil
	if _, ok := cacheSection["auth_cache_size"]; ok {
		t.Error("'cache.auth_cache_size' should be absent when authCacheStats is nil")
	}
}

func TestInfo_WithRedisCache(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.Set("intel:example.com", "data")
	mr.Set("intel:other.com", "data2")

	rc := cache.NewRedisCache(mr.Addr(), "", 0)

	r := newInfoRouter("1.0.0", rc, nil)
	w := doInfoRequest(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseInfoResponse(t, w)
	cacheSection, ok := resp["cache"].(map[string]any)
	if !ok {
		t.Fatal("missing or malformed 'cache' section")
	}

	if cacheSection["addr"] != mr.Addr() {
		t.Errorf("cache.addr = %v, want %v", cacheSection["addr"], mr.Addr())
	}

	keyCount, ok := cacheSection["key_count"].(float64)
	if !ok {
		t.Fatal("missing cache.key_count")
	}
	if int(keyCount) != 2 {
		t.Errorf("cache.key_count = %v, want 2", keyCount)
	}

	// memory_used may be absent with miniredis (no INFO memory support).
	if v, ok := cacheSection["memory_used"]; ok {
		if _, isStr := v.(string); !isStr {
			t.Errorf("cache.memory_used = %T, want string", v)
		}
	}
}

func TestInfo_WithCachedRepo(t *testing.T) {
	inner := &stubRepo{customer: &auth.Customer{ID: 1, Name: "test"}}
	cr := auth.NewCachedRepository(inner, 5*time.Minute)

	// Seed the cache with two entries
	cr.GetByKey(context.Background(), "key-a")
	cr.GetByKey(context.Background(), "key-b")

	r := newInfoRouter("1.0.0", nil, cr)
	w := doInfoRequest(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseInfoResponse(t, w)
	cacheSection, ok := resp["cache"].(map[string]any)
	if !ok {
		t.Fatal("missing or malformed 'cache' section")
	}

	size, ok := cacheSection["auth_cache_size"].(float64)
	if !ok {
		t.Fatal("missing cache.auth_cache_size")
	}
	if int(size) != 2 {
		t.Errorf("cache.auth_cache_size = %v, want 2", size)
	}
}

func TestInfo_VersionField(t *testing.T) {
	r := newInfoRouter("2.5.3", nil, nil)
	w := doInfoRequest(r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := parseInfoResponse(t, w)
	sys, ok := resp["system"].(map[string]any)
	if !ok {
		t.Fatal("missing or malformed 'system' section")
	}
	if sys["version"] != "2.5.3" {
		t.Errorf("system.version = %v, want %q", sys["version"], "2.5.3")
	}
}

// The system block is an embed of config.SystemStatus, not a hand-written copy
// of its fields. This asserts every JSON key SystemStatus declares survives the
// round trip: the copy this replaced dropped anything added to the snapshot,
// silently, and the edge posture below is what the CDN cutover is verified with.
func TestInfo_SystemCarriesEveryStatusField(t *testing.T) {
	status := testStatus("1.0.0")
	status.System.RequireOriginSecret = true
	status.System.ClientIPHeader = "CF-Connecting-IP"

	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(Deps{Status: status})
	r.GET("/v1/info", h.Info)

	w := doInfoRequest(r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	sys, ok := parseInfoResponse(t, w)["system"].(map[string]any)
	if !ok {
		t.Fatal("missing or malformed 'system' section")
	}

	for _, f := range reflect.VisibleFields(reflect.TypeFor[config.SystemStatus]()) {
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if key == "" || key == "-" {
			continue
		}
		if _, present := sys[key]; !present {
			t.Errorf("system.%s is missing from /v1/info", key)
		}
	}

	if sys["require_origin_secret"] != true {
		t.Errorf("system.require_origin_secret = %v, want true", sys["require_origin_secret"])
	}
	if sys["client_ip_header"] != "CF-Connecting-IP" {
		t.Errorf("system.client_ip_header = %v, want %q", sys["client_ip_header"], "CF-Connecting-IP")
	}
	if _, leaked := sys["origin_secret"]; leaked {
		t.Error("/v1/info must never report the origin secret")
	}
	if sys["uptime"] == nil {
		t.Error("system.uptime is missing")
	}
}

func TestInfo_NoStatusConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(Deps{})
	r.GET("/v1/info", h.Info)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/info", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}
