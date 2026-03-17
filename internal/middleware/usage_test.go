package middleware

import (
	"net/http"
	"net/http/httptest"
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
		c.Set("cache_hit", true)
		c.Set("screenshot_requested", true)
		c.Set("reputation_requested", false)
		c.Set("email_security_requested", true)
		c.Set("subdomain_requested", false)
		c.Set("ct_logs_requested", false)
		c.Set("bgp_requested", false)
		c.Set("fingerprint_requested", true)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", nil)
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
	if !e.CacheHit {
		t.Error("CacheHit = false, want true")
	}
	if !e.Screenshot {
		t.Error("Screenshot = false, want true")
	}
	if e.Reputation {
		t.Error("Reputation = true, want false")
	}
	if !e.EmailSecurity {
		t.Error("EmailSecurity = false, want true")
	}
	if !e.Fingerprint {
		t.Error("Fingerprint = false, want true")
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
	req := httptest.NewRequest(http.MethodGet, "/v1/hello", nil)
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
