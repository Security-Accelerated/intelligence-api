package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

type mockService struct {
	resp   *domain.DomainResponse
	cached bool
}

func (m *mockService) Lookup(_ context.Context, domainName string, _ domain.LookupOptions) (*domain.DomainResponse, bool) {
	if m.resp != nil {
		return m.resp, m.cached
	}
	return &domain.DomainResponse{Domain: domainName}, m.cached
}

func newTestRouter(svc DomainLookupService) *gin.Engine {
	return newTestRouterWithTier(svc, "premium")
}

func newTestRouterWithTier(svc DomainLookupService, tier string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(svc, nil, "test")
	h.RegisterRoutes(r)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_roles", []string{"admin"})
		c.Set("api_key_tier", tier)
		c.Next()
	})
	return r
}

func TestDomainLookup_ValidDomain(t *testing.T) {
	r := newTestRouter(&mockService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp[0].Domain, "example.com")
	}
}

func TestDomainLookup_MultipleDomains(t *testing.T) {
	r := newTestRouter(&mockService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["example.com","example.org"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("len(resp) = %d, want 2", len(resp))
	}
	if resp[0].Domain != "example.com" {
		t.Errorf("resp[0].Domain = %q, want %q", resp[0].Domain, "example.com")
	}
	if resp[1].Domain != "example.org" {
		t.Errorf("resp[1].Domain = %q, want %q", resp[1].Domain, "example.org")
	}
}

func TestDomainLookup_MixedValidInvalid(t *testing.T) {
	r := newTestRouter(&mockService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["example.com","notadomain","example.org"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp) != 3 {
		t.Fatalf("len(resp) = %d, want 3", len(resp))
	}

	// First domain: valid
	if resp[0].Domain != "example.com" {
		t.Errorf("resp[0].Domain = %q, want %q", resp[0].Domain, "example.com")
	}
	if len(resp[0].Errors) != 0 {
		t.Errorf("resp[0].Errors = %v, want none", resp[0].Errors)
	}

	// Second domain: invalid, should have validation error
	if resp[1].Domain != "notadomain" {
		t.Errorf("resp[1].Domain = %q, want %q", resp[1].Domain, "notadomain")
	}
	if len(resp[1].Errors) != 1 || resp[1].Errors[0].Lookup != "validation" {
		t.Errorf("resp[1].Errors = %v, want validation error", resp[1].Errors)
	}

	// Third domain: valid
	if resp[2].Domain != "example.org" {
		t.Errorf("resp[2].Domain = %q, want %q", resp[2].Domain, "example.org")
	}
}

func TestDomainLookup_CachedResponse(t *testing.T) {
	svc := &mockService{
		resp:   &domain.DomainResponse{Domain: "cached.com"},
		cached: true,
	}
	r := newTestRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["cached.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if !resp[0].CacheHit {
		t.Errorf("CacheHit = false, want true")
	}
}

func TestDomainLookup_MissingBody(t *testing.T) {
	r := newTestRouter(&mockService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", nil)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDomainLookup_EmptyArray(t *testing.T) {
	r := newTestRouter(&mockService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":[]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDomainLookup_SingleInvalidDomain(t *testing.T) {
	r := newTestRouter(&mockService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["localhost"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDomainLookup_StripsProtocolAndSlash(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"https prefix", `{"domains":["https://example.com/"]}`, "example.com"},
		{"http prefix", `{"domains":["http://example.com/"]}`, "example.com"},
		{"trailing slash", `{"domains":["example.com/"]}`, "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockService{}
			r := newTestRouter(svc)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(tt.input))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}

			var resp []*domain.DomainResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(resp) != 1 {
				t.Fatalf("len(resp) = %d, want 1", len(resp))
			}
			if resp[0].Domain != tt.expect {
				t.Errorf("Domain = %q, want %q", resp[0].Domain, tt.expect)
			}
		})
	}
}

func TestDomainLookup_WhitespaceTrimming(t *testing.T) {
	svc := &mockService{}
	r := newTestRouter(svc)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["  example.com  "]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp[0].Domain, "example.com")
	}
}

func TestDomainLookup_Reputation_PremiumAllowed(t *testing.T) {
	r := newTestRouterWithTier(&mockService{}, "premium")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_Reputation_BasicForbidden(t *testing.T) {
	r := newTestRouterWithTier(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestDomainLookup_Reputation_AbsentWhenNotRequested(t *testing.T) {
	svc := &mockService{
		resp: &domain.DomainResponse{Domain: "example.com"},
	}
	r := newTestRouter(svc)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.DomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Reputation != nil {
		t.Error("expected reputation to be nil when not requested")
	}
}
