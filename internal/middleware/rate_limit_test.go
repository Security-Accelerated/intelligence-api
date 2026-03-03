package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func setupRateLimit(t *testing.T, cfg RateLimitConfig) (*gin.Engine, *miniredis.Miniredis, *observer.ObservedLogs) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("api_key_id", 1)
		c.Set("api_key_tier", "basic")
		c.Next()
	})
	r.Use(RateLimitWithLogger(client, cfg, logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	return r, mr, logs
}

func doRequest(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
	return w
}

func TestRateLimit_UnderLimit(t *testing.T) {
	r, _, _ := setupRateLimit(t, RateLimitConfig{Basic: 5, Premium: 10})

	w := doRequest(r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("X-RateLimit-Limit"); got != "5" {
		t.Errorf("X-RateLimit-Limit = %q, want %q", got, "5")
	}
	if got := w.Header().Get("X-RateLimit-Remaining"); got != "4" {
		t.Errorf("X-RateLimit-Remaining = %q, want %q", got, "4")
	}
}

func TestRateLimit_AtLimit(t *testing.T) {
	r, _, _ := setupRateLimit(t, RateLimitConfig{Basic: 3, Premium: 10})

	// Use up the limit
	for i := 0; i < 3; i++ {
		w := doRequest(r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}

	// Next request should be rejected
	w := doRequest(r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Error("missing Retry-After header")
	}
	if got := w.Header().Get("X-RateLimit-Remaining"); got != "0" {
		t.Errorf("X-RateLimit-Remaining = %q, want %q", got, "0")
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "rate limit exceeded" {
		t.Errorf("error = %q, want %q", body["error"], "rate limit exceeded")
	}
}

func TestRateLimit_PremiumGetsHigherLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	core, _ := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	cfg := RateLimitConfig{Basic: 2, Premium: 5}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("api_key_id", 1)
		c.Set("api_key_tier", "premium")
		c.Next()
	})
	r.Use(RateLimitWithLogger(client, cfg, logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Basic limit is 2, but premium gets 5 — so 3 requests should succeed
	for i := 0; i < 5; i++ {
		w := doRequest(r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}

	// 6th should be rejected
	w := doRequest(r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}
	if got := w.Header().Get("X-RateLimit-Limit"); got != strconv.Itoa(cfg.Premium) {
		t.Errorf("X-RateLimit-Limit = %q, want %q", got, strconv.Itoa(cfg.Premium))
	}
}

func TestRateLimit_RedisDown_FailOpen(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	cfg := RateLimitConfig{Basic: 1, Premium: 1}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("api_key_id", 1)
		c.Set("api_key_tier", "basic")
		c.Next()
	})
	r.Use(RateLimitWithLogger(client, cfg, logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Stop Redis
	mr.Close()

	w := doRequest(r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (should fail-open)", w.Code, http.StatusOK)
	}

	if logs.Len() == 0 {
		t.Error("expected a warning log about redis error")
	}
}

func TestRateLimit_NoAuthContext_Passthrough(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	core, _ := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	// No auth middleware — api_key_id not set
	r.Use(RateLimitWithLogger(client, RateLimitConfig{Basic: 1, Premium: 1}, logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := doRequest(r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
