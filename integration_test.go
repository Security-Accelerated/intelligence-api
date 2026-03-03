//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/handler"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/service"
)

// stubRepo is an in-memory auth.Repository for integration tests.
type stubRepo struct {
	keys map[string]*auth.Customer
}

func newStubRepo() *stubRepo {
	return &stubRepo{keys: map[string]*auth.Customer{
		"test-admin-key":  {ID: 1, APIKeyID: 100, Name: "Test Admin", Active: true, Tier: "premium", Roles: []string{"admin", "domain"}},
		"test-domain-key": {ID: 2, APIKeyID: 200, Name: "Test Domain User", Active: true, Tier: "basic", Roles: []string{"domain"}},
	}}
}

func (r *stubRepo) GetByKey(_ context.Context, key string) (*auth.Customer, error) {
	if c, ok := r.keys[key]; ok {
		return c, nil
	}
	return nil, context.DeadlineExceeded // any non-nil error triggers 401
}

func setupRouter(t *testing.T) (*gin.Engine, *miniredis.Miniredis) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rc := cache.NewRedisCache(mr.Addr(), "", 0)

	svc := service.NewDomainService(rc, 5*time.Minute, 15*time.Second)
	// Replace real lookups with stubs so we don't hit the network.
	svc.SetLookups(
		func(_ context.Context, _ string) (*domain.WhoisInfo, error) {
			return &domain.WhoisInfo{DomainName: "example.com", Registrar: "Test Registrar"}, nil
		},
		func(_ context.Context, _ string) (*domain.DNSInfo, error) {
			return &domain.DNSInfo{A: []string{"93.184.216.34"}}, nil
		},
		func(_ context.Context, _ string) (*domain.SSLInfo, error) {
			return &domain.SSLInfo{Subject: "example.com", Issuer: "Test CA"}, nil
		},
		func(_ context.Context, _ string) (*domain.HeadersInfo, error) {
			return &domain.HeadersInfo{StatusCode: 200, Headers: map[string]string{"Server": "test"}}, nil
		},
		func(_ context.Context, _ string, _ time.Duration) (*domain.ScreenshotInfo, error) {
			return &domain.ScreenshotInfo{StatusCode: 200, PNG: "c3R1Yg=="}, nil
		},
		func(_ context.Context, _ string) (*domain.ReputationResult, []domain.LookupError) {
			return &domain.ReputationResult{
				Score: 35,
				Risk:  "medium",
				Providers: []*domain.ProviderResult{
					{Listed: true, Category: "phishing", Provider: "spamhaus_dbl", ReturnCode: "127.0.1.4"},
					{Listed: false, Provider: "surbl"},
					{Listed: false, Provider: "uribl"},
					{Listed: false, Provider: "spamhaus_zen"},
				},
			}, nil
		},
	)

	typosquattingSvc := service.NewTyposquattingService(rc, 5*time.Minute, 30*time.Second, 500, 20)
	typosquattingSvc.SetLookup(func(_ context.Context, d string, opts domain.TyposquattingOptions) (*domain.TyposquattingResponse, error) {
		return &domain.TyposquattingResponse{
			Domain: d,
			Depth:  opts.Depth,
			Count:  2,
			Permutations: []domain.Permutation{
				{Domain: "exarnple.com", Technique: "homoglyph"},
				{Domain: "examlpe.com", Technique: "character_swap"},
			},
		}, nil
	})

	repo := newStubRepo()
	cachedRepo := auth.NewCachedRepository(repo, 5*time.Minute)

	r := gin.New()
	r.Use(middleware.RequestLogger())
	h := handler.New(svc, typosquattingSvc, "test", nil, rc, cachedRepo)
	h.RegisterRoutes(r)
	h.RegisterProtectedRoutes(r, middleware.APIKeyAuth(cachedRepo))

	admin := r.Group("/api/v1/admin")
	admin.Use(middleware.APIKeyAuth(cachedRepo), middleware.RequireRoles("admin"))
	admin.POST("/auth/cache/invalidate", func(c *gin.Context) {
		cachedRepo.InvalidateAll()
		c.JSON(http.StatusOK, gin.H{"message": "auth cache invalidated"})
	})

	return r, mr
}

func TestIntegration_DomainLookup_FullFlow(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	r0 := resp[0]
	if r0.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", r0.Domain, "example.com")
	}
	if r0.Whois == nil || r0.Whois.Registrar != "Test Registrar" {
		t.Errorf("Whois = %+v, want Registrar=Test Registrar", r0.Whois)
	}
	if r0.DNS == nil || len(r0.DNS.A) == 0 {
		t.Errorf("DNS.A = %v, want non-empty", r0.DNS)
	}
	if r0.SSL == nil || r0.SSL.Subject != "example.com" {
		t.Errorf("SSL = %+v, want Subject=example.com", r0.SSL)
	}
	if r0.Headers == nil || r0.Headers.StatusCode != 200 {
		t.Errorf("Headers = %+v, want StatusCode=200", r0.Headers)
	}
	if len(r0.Errors) != 0 {
		t.Errorf("Errors = %v, want none", r0.Errors)
	}
}

func TestIntegration_DomainLookup_CacheRoundTrip(t *testing.T) {
	r, _ := setupRouter(t)

	body := `{"domains":["example.com"]}`

	// First request — cache miss, populates cache.
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want %d", w1.Code, http.StatusOK)
	}

	// Second request — should be served from cache with identical data.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("second request: status = %d, want %d", w2.Code, http.StatusOK)
	}

	var resp1, resp2 []*domain.DomainResponse
	json.Unmarshal(w1.Body.Bytes(), &resp1)
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	if len(resp1) != 1 || len(resp2) != 1 {
		t.Fatalf("expected 1 result each, got %d and %d", len(resp1), len(resp2))
	}
	if resp1[0].CacheHit {
		t.Error("first request should be a cache miss")
	}
	if !resp2[0].CacheHit {
		t.Error("second request should be a cache hit")
	}
	if resp1[0].Domain != resp2[0].Domain {
		t.Errorf("Domain mismatch: %q vs %q", resp1[0].Domain, resp2[0].Domain)
	}
	if resp2[0].Whois == nil || resp2[0].Whois.Registrar != "Test Registrar" {
		t.Errorf("cached response Whois = %+v, want Registrar=Test Registrar", resp2[0].Whois)
	}
	if resp2[0].DNS == nil || len(resp2[0].DNS.A) == 0 {
		t.Errorf("cached DNS.A = %v, want non-empty", resp2[0].DNS)
	}
	if resp2[0].SSL == nil || resp2[0].SSL.Subject != "example.com" {
		t.Errorf("cached SSL = %+v, want Subject=example.com", resp2[0].SSL)
	}
	if resp2[0].Headers == nil || resp2[0].Headers.StatusCode != 200 {
		t.Errorf("cached Headers = %+v, want StatusCode=200", resp2[0].Headers)
	}
}

func TestIntegration_DomainLookup_InvalidDomain(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["notadomain"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIntegration_Hello(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hello", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["message"] != "hello world" {
		t.Errorf("message = %q, want %q", body["message"], "hello world")
	}
}

func TestIntegration_Auth_MissingKey(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_Auth_InvalidKey(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "bad-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_Auth_DomainKeyCanAccessDomain(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-domain-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIntegration_Auth_DomainKeyCannotAccessInfo(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/info", nil)
	req.Header.Set("X-API-Key", "test-domain-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIntegration_Screenshot_PremiumCanScreenshot(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Screenshot == nil {
		t.Fatal("expected screenshot to be populated for premium customer")
	}
	if resp[0].Screenshot.StatusCode != 200 {
		t.Errorf("Screenshot.StatusCode = %d, want 200", resp[0].Screenshot.StatusCode)
	}
	if resp[0].Screenshot.PNG == "" {
		t.Error("expected Screenshot.PNG to be non-empty")
	}
}

func TestIntegration_Screenshot_BasicGets403(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-domain-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_Screenshot_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.DomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Screenshot != nil {
		t.Error("expected screenshot to be nil when not requested")
	}
}

func TestIntegration_Typosquat_PremiumCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.TyposquattingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp[0].Domain, "example.com")
	}
	if resp[0].Count != 2 {
		t.Errorf("Count = %d, want 2", resp[0].Count)
	}
	if len(resp[0].Permutations) != 2 {
		t.Errorf("len(Permutations) = %d, want 2", len(resp[0].Permutations))
	}
}

func TestIntegration_Typosquat_BasicGets403(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-domain-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_Typosquat_DeepDepth(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com"],"depth":"deep"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.TyposquattingResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Depth != "deep" {
		t.Errorf("Depth = %q, want %q", resp[0].Depth, "deep")
	}
}

func TestIntegration_Typosquat_InvalidDepth(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com"],"depth":"invalid"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestIntegration_Typosquat_DefaultDepthShallow(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.TyposquattingResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Depth != "shallow" {
		t.Errorf("Depth = %q, want %q (default)", resp[0].Depth, "shallow")
	}
}

func TestIntegration_Typosquat_MultipleDomains(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com","example.org"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.TyposquattingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
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

func TestIntegration_Typosquat_SingleInvalidDomain(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["notadomain"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestIntegration_Typosquat_CacheRoundTrip(t *testing.T) {
	r, _ := setupRouter(t)
	body := `{"domains":["example.com"]}`

	// First request — cache miss
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want %d", w1.Code, http.StatusOK)
	}

	var resp1 []*domain.TyposquattingResponse
	json.Unmarshal(w1.Body.Bytes(), &resp1)
	if resp1[0].CacheHit {
		t.Error("first request should be a cache miss")
	}

	// Second request — should be served from cache
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("second: status = %d, want %d", w2.Code, http.StatusOK)
	}

	var resp2 []*domain.TyposquattingResponse
	json.Unmarshal(w2.Body.Bytes(), &resp2)
	if !resp2[0].CacheHit {
		t.Error("second request should be a cache hit")
	}
	if resp2[0].Domain != resp1[0].Domain {
		t.Errorf("cached Domain = %q, want %q", resp2[0].Domain, resp1[0].Domain)
	}
	if resp2[0].Count != resp1[0].Count {
		t.Errorf("cached Count = %d, want %d", resp2[0].Count, resp1[0].Count)
	}
}

func TestIntegration_Typosquat_CheckLiveParameter(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com"],"check_live":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.TyposquattingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Count != 2 {
		t.Errorf("Count = %d, want 2", resp[0].Count)
	}
}

func TestIntegration_Reputation_PremiumCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Reputation == nil {
		t.Fatal("expected reputation to be populated for premium customer")
	}
	if resp[0].Reputation.Score != 35 {
		t.Errorf("Reputation.Score = %d, want 35", resp[0].Reputation.Score)
	}
	if resp[0].Reputation.Risk != "medium" {
		t.Errorf("Reputation.Risk = %q, want %q", resp[0].Reputation.Risk, "medium")
	}
	if len(resp[0].Reputation.Providers) != 4 {
		t.Fatalf("len(Reputation.Providers) = %d, want 4", len(resp[0].Reputation.Providers))
	}
	dbl := resp[0].Reputation.Providers[0]
	if !dbl.Listed || dbl.Category != "phishing" || dbl.Provider != "spamhaus_dbl" {
		t.Errorf("first provider = %+v, want listed phishing from spamhaus_dbl", dbl)
	}
}

func TestIntegration_Reputation_BasicGets403(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-domain-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_Reputation_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
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

func TestIntegration_Reputation_CombinedWithScreenshot(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"reputation":true,"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Reputation == nil {
		t.Fatal("expected reputation to be populated")
	}
	if resp[0].Reputation.Score != 35 {
		t.Errorf("Reputation.Score = %d, want 35", resp[0].Reputation.Score)
	}
	if len(resp[0].Reputation.Providers) != 4 {
		t.Errorf("len(Reputation.Providers) = %d, want 4", len(resp[0].Reputation.Providers))
	}
	if resp[0].Screenshot == nil {
		t.Fatal("expected screenshot to be populated")
	}
	if resp[0].Screenshot.StatusCode != 200 {
		t.Errorf("Screenshot.StatusCode = %d, want 200", resp[0].Screenshot.StatusCode)
	}
	if resp[0].Screenshot.PNG == "" {
		t.Error("expected Screenshot.PNG to be non-empty")
	}
}

// --- Admin cache invalidate ---

func TestIntegration_AdminCacheInvalidate_AdminAllowed(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth/cache/invalidate", nil)
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["message"] != "auth cache invalidated" {
		t.Errorf("message = %q, want %q", body["message"], "auth cache invalidated")
	}
}

func TestIntegration_AdminCacheInvalidate_NonAdminForbidden(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth/cache/invalidate", nil)
	req.Header.Set("X-API-Key", "test-domain-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_AdminCacheInvalidate_NoKeyUnauthorized(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth/cache/invalidate", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}
