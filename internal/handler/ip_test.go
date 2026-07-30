package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/spf13/viper"
)

type mockIPService struct {
	mu       sync.Mutex
	resp     *domain.IPResponse
	cached   bool
	lastOpts domain.IPLookupOptions
}

func (m *mockIPService) Lookup(_ context.Context, ip string, opts domain.IPLookupOptions) (*domain.IPResponse, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastOpts = opts
	if m.resp != nil {
		return m.resp, m.cached
	}
	return &domain.IPResponse{IP: ip}, m.cached
}

func newIPTestRouter(svc IPLookupService) *gin.Engine {
	return newIPTestRouterWithPlan(svc, "pro")
}

func newIPTestRouterWithPlan(svc IPLookupService, plan string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, svc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

func newIPTestRouterWithCfg(svc IPLookupService, plan string, cfg *viper.Viper) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, svc, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

// --- Basic functionality ---

func TestIPLookup_ValidIP(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIPLookup_MultipleIPs(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","1.1.1.1"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var results []*domain.IPResponse
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
}

func TestIPLookup_IPv6(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["2001:4860:4860::8888"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

// --- Validation ---

func TestIPLookup_InvalidIP(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["not-an-ip"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIPLookup_PrivateIP_Rejected(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	tests := []struct {
		name string
		ip   string
	}{
		{"loopback", "127.0.0.1"},
		{"private", "10.0.0.1"},
		{"link-local", "169.254.169.254"},
		{"private v6", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			body := `{"ips":["` + tt.ip + `"]}`
			req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d for %s", w.Code, http.StatusBadRequest, tt.ip)
			}
		})
	}
}

func TestIPLookup_MixedValidInvalid(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","127.0.0.1"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var results []*domain.IPResponse
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	// First should be valid, second should have validation error
	if len(results[0].Errors) > 0 {
		t.Error("first IP should not have errors")
	}
	if len(results[1].Errors) == 0 {
		t.Error("second IP (private) should have validation error")
	}
}

func TestIPLookup_EmptyArray(t *testing.T) {
	r := newIPTestRouter(&mockIPService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":[]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// --- Plan gating ---

func TestIPLookup_ThreatIntel_ProAllowed(t *testing.T) {
	r := newIPTestRouterWithPlan(&mockIPService{}, "pro")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIPLookup_ThreatIntel_AdminAllowed(t *testing.T) {
	r := newIPTestRouterWithPlan(&mockIPService{}, "admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIPLookup_ThreatIntel_FreeForbidden(t *testing.T) {
	r := newIPTestRouterWithPlan(&mockIPService{}, "free")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIPLookup_ThreatIntel_BasicForbidden(t *testing.T) {
	r := newIPTestRouterWithPlan(&mockIPService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- Max IPs per plan ---

func TestIPLookup_MaxIPs_ExceedsLimit(t *testing.T) {
	cfg := testCfg(map[string]any{
		"ip.max_ips.basic": 2,
	})

	r := newIPTestRouterWithCfg(&mockIPService{}, "basic", cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","1.1.1.1","9.9.9.9"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestIPLookup_MaxIPs_AtLimit(t *testing.T) {
	cfg := testCfg(map[string]any{
		"ip.max_ips.basic": 2,
	})

	r := newIPTestRouterWithCfg(&mockIPService{}, "basic", cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","1.1.1.1"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- Options passthrough ---

func TestIPLookup_OptsPassedToService(t *testing.T) {
	svc := &mockIPService{}
	r := newIPTestRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if !svc.lastOpts.ThreatIntel {
		t.Error("expected ThreatIntel=true to be passed to service")
	}
}

// --- Body limit ---

func TestIPLookup_OversizedBody_Returns413(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.BodyLimit(128))
	h := New(nil, &mockIPService{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", "pro")
		c.Next()
	})

	w := httptest.NewRecorder()
	oversized := `{"ips":["` + strings.Repeat("8.8.8.8,", 50) + `8.8.8.8"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
}
