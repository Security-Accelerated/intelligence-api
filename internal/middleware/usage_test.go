package middleware

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/usage"
)

type mockRecorder struct {
	mu      sync.Mutex
	entries []usage.UsageEntry
}

func (m *mockRecorder) Record(e usage.UsageEntry) {
	m.mu.Lock()
	m.entries = append(m.entries, e)
	m.mu.Unlock()
}

func TestUsageLog_CapturesContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := &mockRecorder{}
	r := gin.New()
	r.Use(UsageLog(rec))
	r.POST("/v1/domain/lookup", func(c *gin.Context) {
		c.Set("customer_id", 42)
		c.Set("api_key_id", 100)
		c.Set("api_key_plan", "pro")
		c.Set("domain_count", 3)
		c.Set("ip_count", 2)
		c.Set("cache_hits", 5)
		c.Set("cache_misses", 4)
		c.Set("lookups_requested", []string{"screenshot", "email_security", "fingerprint", "threat_intel"})
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", http.NoBody)
	r.ServeHTTP(w, req)

	if len(rec.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rec.entries))
	}
	e := rec.entries[0]

	if e.CustomerID != 42 {
		t.Errorf("CustomerID = %d, want 42", e.CustomerID)
	}
	if e.APIKeyID != 100 {
		t.Errorf("APIKeyID = %d, want 100", e.APIKeyID)
	}
	if e.Plan != "pro" {
		t.Errorf("Plan = %q, want %q", e.Plan, "pro")
	}
	if e.DomainCount != 3 {
		t.Errorf("DomainCount = %d, want 3", e.DomainCount)
	}
	if e.IPCount != 2 {
		t.Errorf("IPCount = %d, want 2", e.IPCount)
	}
	if e.CacheHits != 5 {
		t.Errorf("CacheHits = %d, want 5", e.CacheHits)
	}
	if e.CacheMisses != 4 {
		t.Errorf("CacheMisses = %d, want 4", e.CacheMisses)
	}
	want := []string{"screenshot", "email_security", "fingerprint", "threat_intel"}
	if len(e.Lookups) != len(want) {
		t.Fatalf("Lookups = %v, want %v", e.Lookups, want)
	}
	for _, name := range want {
		if !slices.Contains(e.Lookups, name) {
			t.Errorf("Lookups = %v, missing %q", e.Lookups, name)
		}
	}
	if e.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", e.StatusCode)
	}
	if e.Method != "POST" {
		t.Errorf("Method = %q, want POST", e.Method)
	}
	if e.Path != "/v1/domain/lookup" {
		t.Errorf("Path = %q, want /v1/domain/lookup", e.Path)
	}
	if e.LatencyMs < 0 {
		t.Errorf("LatencyMs = %d, want >= 0", e.LatencyMs)
	}
}

func TestUsageLog_NoContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := &mockRecorder{}
	r := gin.New()
	r.Use(UsageLog(rec))
	r.GET("/v1/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "hello"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/hello", http.NoBody)
	r.ServeHTTP(w, req)

	if len(rec.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rec.entries))
	}
	e := rec.entries[0]
	if e.CustomerID != 0 {
		t.Errorf("CustomerID = %d, want 0", e.CustomerID)
	}
	if e.Plan != "" {
		t.Errorf("Plan = %q, want empty", e.Plan)
	}
}
