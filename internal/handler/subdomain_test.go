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
	"github.com/spf13/viper"
)

type mockSubdomainService struct {
	mu            sync.Mutex
	resp          *domain.SubdomainResponse
	cached        bool
	lastCheckLive bool
}

func (m *mockSubdomainService) Lookup(_ context.Context, domainName string, checkLive bool) (*domain.SubdomainResponse, bool) {
	m.mu.Lock()
	m.lastCheckLive = checkLive
	m.mu.Unlock()
	if m.resp != nil {
		return m.resp, m.cached
	}
	return &domain.SubdomainResponse{
		Domain: domainName,
		Count:  2,
		Subdomains: []domain.SubdomainEntry{
			{Domain: "www." + domainName, Source: "crt.sh"},
			{Domain: "mail." + domainName, Source: "crt.sh"},
		},
	}, m.cached
}

func newSubdomainRouter(tier string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, &mockSubdomainService{}, "test", nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_features", []string{"admin"})
		if tier != "" {
			c.Set("api_key_tier", tier)
		}
		c.Next()
	})
	return r
}

func newSubdomainRouterWithService(svc SubdomainLookupService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, svc, "test", nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_features", []string{"admin"})
		c.Set("api_key_tier", "premium")
		c.Next()
	})
	return r
}

func postSubdomain(r *gin.Engine, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/subdomains", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestSubdomainLookup_FeatureAllowed(t *testing.T) {
	r := newSubdomainRouter("premium")
	w := postSubdomain(r, `{"domains":["example.com"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.SubdomainResponse
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

func TestSubdomainLookup_WrongFeatureForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, &mockSubdomainService{}, "test", nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_features", []string{"lookup"})
		c.Set("api_key_tier", "premium")
		c.Next()
	})

	w := postSubdomain(r, `{"domains":["example.com"]}`)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestSubdomainLookup_MissingBody(t *testing.T) {
	r := newSubdomainRouter("premium")
	w := postSubdomain(r, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestSubdomainLookup_EmptyDomainsArray(t *testing.T) {
	r := newSubdomainRouter("premium")
	w := postSubdomain(r, `{"domains":[]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestSubdomainLookup_SingleInvalidDomain(t *testing.T) {
	r := newSubdomainRouter("premium")
	w := postSubdomain(r, `{"domains":["notadomain"]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestSubdomainLookup_MultipleDomains(t *testing.T) {
	r := newSubdomainRouter("premium")
	w := postSubdomain(r, `{"domains":["example.com","example.org"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.SubdomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 2 {
		t.Fatalf("len(resp) = %d, want 2", len(resp))
	}
}

func TestSubdomainLookup_MixedValidInvalid(t *testing.T) {
	r := newSubdomainRouter("premium")
	w := postSubdomain(r, `{"domains":["example.com","notadomain"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.SubdomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 2 {
		t.Fatalf("len(resp) = %d, want 2", len(resp))
	}
	if len(resp[1].Errors) == 0 {
		t.Error("expected errors for invalid domain at index 1")
	}
}

func TestSubdomainLookup_CheckLiveForwarded(t *testing.T) {
	svc := &mockSubdomainService{}
	r := newSubdomainRouterWithService(svc)
	postSubdomain(r, `{"domains":["example.com"],"check_live":true}`)

	svc.mu.Lock()
	defer svc.mu.Unlock()
	if !svc.lastCheckLive {
		t.Error("expected check_live=true to be forwarded to service")
	}
}

func TestSubdomainLookup_CheckLiveDefaultFalse(t *testing.T) {
	svc := &mockSubdomainService{}
	r := newSubdomainRouterWithService(svc)
	postSubdomain(r, `{"domains":["example.com"]}`)

	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.lastCheckLive {
		t.Error("expected check_live to default to false")
	}
}

func TestSubdomainLookup_CacheHitPopulated(t *testing.T) {
	svc := &mockSubdomainService{cached: true}
	r := newSubdomainRouterWithService(svc)
	w := postSubdomain(r, `{"domains":["example.com"]}`)

	var resp []*domain.SubdomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp[0].CacheHit {
		t.Error("expected CacheHit to be true")
	}
}

func TestSubdomainLookup_MaxDomains_ExceedsLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	cfg := viper.New()
	cfg.Set("subdomain.max_domains.premium", 1)
	h := New(nil, nil, &mockSubdomainService{}, "test", cfg, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_features", []string{"admin"})
		c.Set("api_key_tier", "premium")
		c.Next()
	})

	w := postSubdomain(r, `{"domains":["example.com","example.org"]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestSubdomainLookup_StripsProtocolAndSlash(t *testing.T) {
	svc := &mockSubdomainService{}
	r := newSubdomainRouterWithService(svc)
	w := postSubdomain(r, `{"domains":["https://example.com/"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.SubdomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp[0].Domain != "example.com" {
		t.Errorf("Domain = %q, want %q (stripped)", resp[0].Domain, "example.com")
	}
}
