//go:build integration

package main

import (
	"context"
	"database/sql"
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
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// stubRepo is an in-memory auth.Repository for integration tests.
type stubRepo struct {
	keys map[string]*auth.Customer
}

func newStubRepo() *stubRepo {
	return &stubRepo{keys: map[string]*auth.Customer{
		"test-admin-key":          {ID: 1, APIKeyID: 100, Name: "Test Admin", Active: true, Tier: "premium", Features: []string{"admin"}},
		"test-lookup-key":         {ID: 2, APIKeyID: 200, Name: "Test Lookup User", Active: true, Tier: "basic", Features: []string{"lookup"}},
		"test-typosquatting-key":  {ID: 3, APIKeyID: 300, Name: "Test Typosquatting User", Active: true, Tier: "premium", Features: []string{"typosquatting"}},
		"test-enterprise-key":    {ID: 4, APIKeyID: 400, Name: "Test Enterprise User", Active: true, Tier: "premium", Features: []string{"lookup", "typosquatting"}},
	}}
}

func (r *stubRepo) GetByKey(_ context.Context, key string) (*auth.Customer, error) {
	if c, ok := r.keys[key]; ok {
		return c, nil
	}
	return nil, sql.ErrNoRows
}

// stubFingerprintService is an in-memory FingerprintAdminService for integration tests.
type stubFingerprintService struct {
	rules []domain.TechRule
}

func newStubFingerprintService() *stubFingerprintService {
	return &stubFingerprintService{
		rules: []domain.TechRule{
			{Name: "TestServer", Category: "web-server", Headers: map[string]string{"Server": "test"}},
		},
	}
}

func (s *stubFingerprintService) GetRules() []domain.TechRule {
	return s.rules
}

func (s *stubFingerprintService) UpdateRules(_ context.Context, rules []domain.TechRule, _ int) error {
	s.rules = rules
	return nil
}

func testConfig() *viper.Viper {
	cfg := viper.New()
	cfg.Set("application.name", "intelligence-api")
	cfg.Set("application.mode", "test")
	cfg.Set("application.start.time", "2026-01-01T00:00:00Z")
	cfg.Set("application.session.id", "test-session")
	cfg.Set("environment.host", "test-host")
	cfg.Set("environment.os", "linux")
	cfg.Set("environment.kernel", "6.0.0")
	cfg.Set("environment.architecture", "amd64")
	cfg.Set("environment.golang.version", "go1.26")
	cfg.Set("redis.addr", "localhost:6379")
	cfg.Set("redis.db", 0)
	cfg.Set("redis.cache_ttl", "5m")
	cfg.Set("auth.cache_ttl", "5m")
	cfg.Set("screenshot.timeout", "15s")
	cfg.Set("typosquatting.timeout", "30s")
	cfg.Set("typosquatting.max_permutations", 500)
	cfg.Set("typosquatting.concurrency", 20)
	cfg.Set("rate_limit.basic", 30)
	cfg.Set("rate_limit.premium", 120)
	cfg.Set("postgres.host", "localhost")
	cfg.Set("postgres.port", 5432)
	cfg.Set("postgres.dbname", "test_db")
	cfg.Set("postgres.sslmode", "disable")
	cfg.Set("domain.max_domains.basic", 5)
	cfg.Set("domain.max_domains.premium", 20)
	cfg.Set("typosquatting.max_domains.basic", 3)
	cfg.Set("typosquatting.max_domains.premium", 5)
	return cfg
}

func setupRouter(t *testing.T) (*gin.Engine, *miniredis.Miniredis) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rc := cache.NewRedisCache(mr.Addr(), "", 0)

	fpEngine := domain.NewFingerprintEngine()
	fpEngine.LoadRules([]domain.TechRule{
		{Name: "TestServer", Category: "web-server", Headers: map[string]string{"Server": "test"}},
	})

	svc := service.NewDomainService(rc, 5*time.Minute, 15*time.Second, 500, 100, fpEngine)
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
			return &domain.HeadersInfo{StatusCode: 200, Headers: map[string]string{"Server": "test/1.0"}}, nil
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

	svc.SetEmailSecurityLookup(func(_ context.Context, _ string) (*domain.EmailSecurityInfo, error) {
		return &domain.EmailSecurityInfo{
			SPF:   &domain.SPFRecord{Raw: "v=spf1 include:_spf.google.com -all", Version: "spf1", All: "-all"},
			DMARC: &domain.DMARCRecord{Raw: "v=DMARC1; p=reject", Version: "DMARC1", Policy: "reject"},
			DKIM: []domain.DKIMRecord{
				{Selector: "google", Found: true, Raw: "v=DKIM1; k=rsa; p=MIGf..."},
				{Selector: "default", Found: false},
			},
		}, nil
	})

	svc.SetSubdomainLookup(func(_ context.Context, d string, _ domain.SubdomainOptions) (*domain.SubdomainInfo, error) {
		return &domain.SubdomainInfo{
			Count: 2,
			Subdomains: []domain.SubdomainEntry{
				{Domain: "www." + d, Source: "crt.sh"},
				{Domain: "mail." + d, Source: "crt.sh"},
			},
		}, nil
	})

	svc.SetCTLogsLookup(func(_ context.Context, d string, _ int) (*domain.CTLogsInfo, error) {
		return &domain.CTLogsInfo{
			Count: 2,
			Entries: []domain.CTLogEntry{
				{LoggedAt: "2024-01-15T00:00:00", Issuer: "Let's Encrypt", CommonName: d, Serial: "abc123"},
				{LoggedAt: "2023-06-01T00:00:00", Issuer: "DigiCert", CommonName: "*." + d, Serial: "def456"},
			},
		}, nil
	})

	svc.SetBGPLookup(func(_ context.Context, _ string) (*domain.BGPInfo, error) {
		return &domain.BGPInfo{
			Records: []domain.ASNRecord{
				{IP: "93.184.216.34", ASN: 15133, Prefix: "93.184.216.0/24", Country: "US", Registry: "arin", Description: "EDGECAST, US"},
			},
		}, nil
	})

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

	fpSvc := newStubFingerprintService()

	repo := newStubRepo()
	cachedRepo := auth.NewCachedRepository(repo, 5*time.Minute)

	cfg := testConfig()
	nop := zap.NewNop()

	rlCfg := middleware.RateLimitConfig{Basic: 30, Premium: 120}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.BodyLimit(1 << 20))
	r.Use(middleware.ClientRequestID())
	r.Use(middleware.RequestLoggerWithLogger(nop))

	authMW := middleware.APIKeyAuthWithLogger(cachedRepo, nop)
	rateLimitMW := middleware.RateLimitWithLogger(rc.Client(), rlCfg, nop)

	h := handler.New(svc, typosquattingSvc, fpSvc, "test", cfg, rc, cachedRepo)
	h.RegisterRoutes(r)
	h.RegisterProtectedRoutes(r, authMW, rateLimitMW)

	admin := r.Group("/api/v1/admin")
	admin.Use(authMW, rateLimitMW, middleware.RequireFeatures("admin"))
	admin.POST("/auth/cache/invalidate", func(c *gin.Context) {
		cachedRepo.InvalidateAll()
		c.JSON(http.StatusOK, gin.H{"message": "auth cache invalidated"})
	})
	admin.GET("/fingerprints", h.GetFingerprints)
	admin.POST("/fingerprints", h.UpdateFingerprints)

	return r, mr
}

func TestIntegration_DomainLookup_FullFlow(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
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
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want %d", w1.Code, http.StatusOK)
	}

	// Second request — should be served from cache with identical data.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(body))
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(`{"domains":["notadomain"]}`))
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_Auth_InvalidKey(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "bad-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_Auth_LookupKeyCanAccessLookup(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIntegration_Auth_LookupKeyCannotAccessInfo(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/info", nil)
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIntegration_Screenshot_PremiumCanScreenshot(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_Screenshot_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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

func TestIntegration_Typosquat_LookupKeyGets403(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_Reputation_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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
	req.Header.Set("X-API-Key", "test-lookup-key")
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

// --- Email Security ---

func TestIntegration_EmailSecurity_AllTiersCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	// Basic tier can request email_security (no premium gate)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"email_security":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
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
	if resp[0].EmailSecurity == nil {
		t.Fatal("expected email_security to be populated")
	}
	if resp[0].EmailSecurity.SPF == nil {
		t.Fatal("expected SPF to be populated")
	}
	if resp[0].EmailSecurity.SPF.Version != "spf1" {
		t.Errorf("SPF.Version = %q, want %q", resp[0].EmailSecurity.SPF.Version, "spf1")
	}
	if resp[0].EmailSecurity.DMARC == nil {
		t.Fatal("expected DMARC to be populated")
	}
	if resp[0].EmailSecurity.DMARC.Policy != "reject" {
		t.Errorf("DMARC.Policy = %q, want %q", resp[0].EmailSecurity.DMARC.Policy, "reject")
	}
}

func TestIntegration_EmailSecurity_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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
	if resp[0].EmailSecurity != nil {
		t.Error("expected email_security to be nil when not requested")
	}
}

// --- Subdomain Enumeration (via domain lookup) ---

func TestIntegration_Subdomain_IncludedWhenRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"subdomains":true}`))
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
	if resp[0].Subdomains == nil {
		t.Fatal("expected subdomains to be populated")
	}
	if resp[0].Subdomains.Count != 2 {
		t.Errorf("Subdomains.Count = %d, want 2", resp[0].Subdomains.Count)
	}
	if len(resp[0].Subdomains.Subdomains) != 2 {
		t.Errorf("len(Subdomains.Subdomains) = %d, want 2", len(resp[0].Subdomains.Subdomains))
	}
}

func TestIntegration_Subdomain_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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
	if resp[0].Subdomains != nil {
		t.Error("expected subdomains to be nil when not requested")
	}
}

func TestIntegration_Subdomain_BasicTierCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"subdomains":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.DomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Subdomains == nil {
		t.Fatal("expected subdomains to be populated for basic tier")
	}
}

// --- CT Logs ---

func TestIntegration_CTLogs_IncludedWhenRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"ct_logs":true}`))
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
	if resp[0].CTLogs == nil {
		t.Fatal("expected ct_logs to be populated")
	}
	if resp[0].CTLogs.Count != 2 {
		t.Errorf("CTLogs.Count = %d, want 2", resp[0].CTLogs.Count)
	}
	if len(resp[0].CTLogs.Entries) != 2 {
		t.Errorf("len(CTLogs.Entries) = %d, want 2", len(resp[0].CTLogs.Entries))
	}
}

func TestIntegration_CTLogs_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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
	if resp[0].CTLogs != nil {
		t.Error("expected ct_logs to be nil when not requested")
	}
}

func TestIntegration_CTLogs_BasicTierCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"ct_logs":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.DomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].CTLogs == nil {
		t.Fatal("expected ct_logs to be populated for basic tier")
	}
}

// --- BGP/ASN ---

func TestIntegration_BGP_IncludedWhenRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"bgp":true}`))
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
	if resp[0].BGP == nil {
		t.Fatal("expected bgp to be populated")
	}
	if len(resp[0].BGP.Records) != 1 {
		t.Errorf("len(BGP.Records) = %d, want 1", len(resp[0].BGP.Records))
	}
	if resp[0].BGP.Records[0].ASN != 15133 {
		t.Errorf("BGP.Records[0].ASN = %d, want 15133", resp[0].BGP.Records[0].ASN)
	}
	if resp[0].BGP.Records[0].Description != "EDGECAST, US" {
		t.Errorf("BGP.Records[0].Description = %q, want %q", resp[0].BGP.Records[0].Description, "EDGECAST, US")
	}
}

func TestIntegration_BGP_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
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
	if resp[0].BGP != nil {
		t.Error("expected bgp to be nil when not requested")
	}
}

func TestIntegration_BGP_BasicTierCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"bgp":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []*domain.DomainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].BGP == nil {
		t.Fatal("expected bgp to be populated for basic tier")
	}
}

// --- Middleware: Security Headers ---

func TestIntegration_SecurityHeaders_Present(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hello", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", w.Header().Get("X-Content-Type-Options"), "nosniff")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want %q", w.Header().Get("X-Frame-Options"), "DENY")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", w.Header().Get("Cache-Control"), "no-store")
	}
}

// --- Middleware: Body Limit ---

func TestIntegration_BodyLimit_Exceeded(t *testing.T) {
	r, _ := setupRouter(t)

	// Create a body larger than 1MB. MaxBytesReader causes a read error that
	// surfaces as 400 from Gin's JSON binding layer.
	bigBody := strings.Repeat("x", 1<<20+1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (oversized body rejected via MaxBytesReader)", w.Code, http.StatusBadRequest)
	}
}

// --- Middleware: Client Request ID ---

func TestIntegration_ClientRequestID_EchoedBack(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hello", nil)
	req.Header.Set("X-Client-Request-ID", "integration-test-id-123")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get("X-Client-Request-ID") != "integration-test-id-123" {
		t.Errorf("X-Client-Request-ID = %q, want %q", w.Header().Get("X-Client-Request-ID"), "integration-test-id-123")
	}
}

// --- Middleware: Rate Limiting ---

func TestIntegration_RateLimit_BasicExceeded(t *testing.T) {
	r, _ := setupRouter(t)

	body := `{"domains":["example.com"]}`

	// Send 31 requests — basic limit is 30
	for i := 0; i < 30; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-lookup-key")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}

	// Request 31 should be rate limited
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request 31: status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

func TestIntegration_RateLimit_AdminBypasses(t *testing.T) {
	r, _ := setupRouter(t)

	body := `{"domains":["example.com"]}`

	// Admin should bypass rate limiting entirely — send 35 requests
	for i := 0; i < 35; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-admin-key")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("admin request %d: status = %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}
}

// --- Admin Fingerprints ---

func TestIntegration_AdminFingerprints_GetRules(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/fingerprints", nil)
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := body["count"]; !ok {
		t.Error("expected 'count' field in response")
	}
	if _, ok := body["rules"]; !ok {
		t.Error("expected 'rules' field in response")
	}
}

func TestIntegration_AdminFingerprints_GetForbiddenForNonAdmin(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/fingerprints", nil)
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIntegration_AdminFingerprints_GetUnauthorizedNoKey(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/fingerprints", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_AdminFingerprints_UpdateRules(t *testing.T) {
	r, _ := setupRouter(t)

	rules := `[{"name":"NewTech","category":"cdn","headers":{"X-CDN":"test"}}]`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/fingerprints", strings.NewReader(rules))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["message"] != "fingerprint rules updated" {
		t.Errorf("message = %q, want %q", body["message"], "fingerprint rules updated")
	}
}

func TestIntegration_AdminFingerprints_UpdateForbiddenForNonAdmin(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/fingerprints",
		strings.NewReader(`[{"name":"X","category":"other","headers":{"X":"y"}}]`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- Info endpoint success path ---

func TestIntegration_Info_AdminCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/info", nil)
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := body["application"]; !ok {
		t.Error("expected 'application' field in response")
	}
	if _, ok := body["environment"]; !ok {
		t.Error("expected 'environment' field in response")
	}
	if _, ok := body["config"]; !ok {
		t.Error("expected 'config' field in response")
	}
}

// --- Multi-domain domain lookup ---

func TestIntegration_DomainLookup_MultipleDomains(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com","example.org"]}`))
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

// --- Cache key isolation by feature combo ---

func TestIntegration_CacheKeyIsolation_FeatureCombo(t *testing.T) {
	r, _ := setupRouter(t)

	// First: base lookup (no options)
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"]}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("base lookup: status = %d, want %d", w1.Code, http.StatusOK)
	}

	var base []*domain.DomainResponse
	json.Unmarshal(w1.Body.Bytes(), &base)
	if base[0].CacheHit {
		t.Error("base lookup should be a cache miss")
	}
	if base[0].Reputation != nil {
		t.Error("base lookup should not include reputation")
	}

	// Second: reputation lookup — should NOT be a cache hit from the base lookup
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("reputation lookup: status = %d, want %d", w2.Code, http.StatusOK)
	}

	var rep []*domain.DomainResponse
	json.Unmarshal(w2.Body.Bytes(), &rep)
	if rep[0].CacheHit {
		t.Error("reputation lookup should be a cache miss (different cache key than base)")
	}
	if rep[0].Reputation == nil {
		t.Fatal("reputation lookup should include reputation data")
	}

	// Third: repeat reputation lookup — should be a cache hit now
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w3, req3)

	var rep2 []*domain.DomainResponse
	json.Unmarshal(w3.Body.Bytes(), &rep2)
	if !rep2[0].CacheHit {
		t.Error("repeated reputation lookup should be a cache hit")
	}
	if rep2[0].Reputation == nil {
		t.Error("cached reputation lookup should include reputation data")
	}
}

// --- Fingerprint via domain lookup ---

func TestIntegration_Fingerprint_IncludedWhenRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"fingerprint":true}`))
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
	if resp[0].Fingerprint == nil {
		t.Fatal("expected fingerprint to be populated")
	}
	if resp[0].Fingerprint.Count < 1 {
		t.Errorf("Fingerprint.Count = %d, want >= 1", resp[0].Fingerprint.Count)
	}
}
