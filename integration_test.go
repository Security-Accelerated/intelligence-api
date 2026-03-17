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
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"github.com/security-accelerated/intelligence-api/internal/service"
	"github.com/security-accelerated/intelligence-api/internal/usage"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// stubRepo is an in-memory auth.Repository for integration tests.
type stubRepo struct {
	keys map[string]*auth.Customer
}

func newStubRepo() *stubRepo {
	return &stubRepo{keys: map[string]*auth.Customer{
		"test-admin-key":  {ID: 1, APIKeyID: 100, Name: "Test Admin", Active: true, Plan: "admin"},
		"test-lookup-key": {ID: 2, APIKeyID: 200, Name: "Test Lookup User", Active: true, Plan: "basic"},
		"test-pro-key":    {ID: 3, APIKeyID: 300, Name: "Test Pro User", Active: true, Plan: "pro"},
		"test-free-key":   {ID: 4, APIKeyID: 400, Name: "Test Free User", Active: true, Plan: "free"},
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

// stubUsageQueryer returns a fixed summary for integration tests.
type stubUsageQueryer struct{}

func (stubUsageQueryer) QueryUsage(_, _ int, since, until time.Time) (*usage.UsageSummary, error) {
	return &usage.UsageSummary{
		TotalRequests:  42,
		CacheHits:      10,
		CacheHitRate:   23.81,
		AvgLatencyMs:   500,
		TotalDomains:   50,
		StatusCodes:    map[string]int{"200": 40, "400": 2},
		FeatureUsage:   map[string]int{"screenshot": 5, "reputation": 3},
		RequestsByPath: map[string]int{"/v1/domain/lookup": 40},
		PeriodStart:    since,
		PeriodEnd:      until,
	}, nil
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
	cfg.Set("rate_limit.free", 5)
	cfg.Set("rate_limit.basic", 30)
	cfg.Set("rate_limit.pro", 120)
	cfg.Set("postgres.host", "localhost")
	cfg.Set("postgres.port", 5432)
	cfg.Set("postgres.dbname", "test_db")
	cfg.Set("postgres.sslmode", "disable")
	cfg.Set("domain.max_domains.free", 1)
	cfg.Set("domain.max_domains.basic", 5)
	cfg.Set("domain.max_domains.pro", 20)
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

	svc := service.NewDomainService(rc, 5*time.Minute, 15*time.Second, 500, 100, fpEngine, &notifications.NoopRecorder{})
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

	fpSvc := newStubFingerprintService()

	repo := newStubRepo()
	cachedRepo := auth.NewCachedRepository(repo, 5*time.Minute)

	cfg := testConfig()
	nop := zap.NewNop()

	rlCfg := middleware.RateLimitConfig{Free: 5, Basic: 30, Pro: 120}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.BodyLimit(1 << 20))
	r.Use(middleware.ClientRequestID())
	r.Use(middleware.RequestLoggerWithLogger(nop))

	authMW := middleware.APIKeyAuthWithLogger(cachedRepo, nop)
	rateLimitMW := middleware.RateLimitWithLogger(rc.Client(), rlCfg, nop)

	usageQ := &stubUsageQueryer{}
	usageRec := usage.NoopRecorder{}

	h := handler.New(svc, fpSvc, nil, usageQ, "test", cfg, rc, cachedRepo)
	h.RegisterRoutes(r)
	h.RegisterProtectedRoutes(r, authMW, rateLimitMW, middleware.UsageLog(usageRec))

	admin := r.Group("/v1/admin")
	admin.Use(authMW, rateLimitMW, middleware.UsageLog(usageRec), middleware.RequireAdmin())
	admin.POST("/auth/cache/invalidate", func(c *gin.Context) {
		cachedRepo.InvalidateAll()
		c.JSON(http.StatusOK, gin.H{"message": "auth cache invalidated"})
	})
	admin.GET("/fingerprints", h.GetFingerprints)
	admin.POST("/fingerprints", h.UpdateFingerprints)
	admin.GET("/usage", h.GetUsage)

	return r, mr
}

func TestIntegration_DomainLookup_FullFlow(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
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
	req1 := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want %d", w1.Code, http.StatusOK)
	}

	// Second request — should be served from cache with identical data.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["notadomain"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIntegration_Docs_RootServesHTML(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestIntegration_Hello(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/hello", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_Auth_InvalidKey(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
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
	req := httptest.NewRequest(http.MethodGet, "/v1/info", nil)
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIntegration_Auth_ProKeyCanAccessLookup(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-pro-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIntegration_Auth_ProKeyCannotAccessInfo(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/info", nil)
	req.Header.Set("X-API-Key", "test-pro-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIntegration_Auth_FreeKeyCanAccessLookup(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-free-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIntegration_Screenshot_FreeGets403(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-free-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_Reputation_FreeGets403(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-free-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_FreePlan_MaxDomains(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["a.com","b.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-free-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "too many domains: maximum 1 allowed for free plan" {
		t.Errorf("error = %q", body["error"])
	}
}

func TestIntegration_Screenshot_ProCanScreenshot(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-pro-key")
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
		t.Fatal("expected screenshot to be populated for pro customer")
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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

func TestIntegration_Reputation_ProCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-pro-key")
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
		t.Fatal("expected reputation to be populated for pro customer")
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/cache/invalidate", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/cache/invalidate", nil)
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_AdminCacheInvalidate_NoKeyUnauthorized(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/cache/invalidate", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}

// --- Email Security ---

func TestIntegration_EmailSecurity_AllPlansCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	// Basic plan can request email_security (no premium gate)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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

func TestIntegration_Subdomain_BasicPlanCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
		t.Fatal("expected subdomains to be populated for basic plan")
	}
}

// --- CT Logs ---

func TestIntegration_CTLogs_IncludedWhenRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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

func TestIntegration_CTLogs_BasicPlanCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
		t.Fatal("expected ct_logs to be populated for basic plan")
	}
}

// --- BGP/ASN ---

func TestIntegration_BGP_IncludedWhenRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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

func TestIntegration_BGP_BasicPlanCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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
		t.Fatal("expected bgp to be populated for basic plan")
	}
}

// --- Middleware: Security Headers ---

func TestIntegration_SecurityHeaders_Present(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/hello", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(bigBody))
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
	req := httptest.NewRequest(http.MethodGet, "/v1/hello", nil)
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
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-lookup-key")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}

	// Request 31 should be rate limited
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
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
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
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
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/fingerprints", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/fingerprints", nil)
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIntegration_AdminFingerprints_GetUnauthorizedNoKey(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/fingerprints", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_AdminFingerprints_UpdateRules(t *testing.T) {
	r, _ := setupRouter(t)

	rules := `[{"name":"NewTech","category":"cdn","headers":{"X-CDN":"test"}}]`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/fingerprints", strings.NewReader(rules))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/fingerprints",
		strings.NewReader(`[{"name":"X","category":"other","headers":{"X":"y"}}]`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- Cache Expiry ---

func TestIntegration_CacheExpiry(t *testing.T) {
	r, mr := setupRouter(t)

	body := `{"domains":["example.com"]}`

	// 1. First request — cache miss, populates cache.
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want %d", w1.Code, http.StatusOK)
	}

	var resp1 []*domain.DomainResponse
	json.Unmarshal(w1.Body.Bytes(), &resp1)
	if len(resp1) != 1 {
		t.Fatalf("first request: len(resp) = %d, want 1", len(resp1))
	}
	if resp1[0].CacheHit {
		t.Error("first request should be a cache miss")
	}

	// 2. Second request — cache hit.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("second request: status = %d, want %d", w2.Code, http.StatusOK)
	}

	var resp2 []*domain.DomainResponse
	json.Unmarshal(w2.Body.Bytes(), &resp2)
	if len(resp2) != 1 {
		t.Fatalf("second request: len(resp) = %d, want 1", len(resp2))
	}
	if !resp2[0].CacheHit {
		t.Error("second request should be a cache hit")
	}

	// 3. Fast-forward past the 5m cache TTL.
	mr.FastForward(6 * time.Minute)

	// 4. Third request — cache expired, should be a miss again.
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("third request: status = %d, want %d", w3.Code, http.StatusOK)
	}

	var resp3 []*domain.DomainResponse
	json.Unmarshal(w3.Body.Bytes(), &resp3)
	if len(resp3) != 1 {
		t.Fatalf("third request: len(resp) = %d, want 1", len(resp3))
	}
	if resp3[0].CacheHit {
		t.Error("third request should be a cache miss after TTL expiry")
	}
}

// --- Validation Edge Cases ---

func TestIntegration_DomainLookup_EmptyDomainsArray(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestIntegration_AdminUsage_AdminAllowed(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage", nil)
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp usage.UsageSummary
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TotalRequests != 42 {
		t.Errorf("TotalRequests = %d, want 42", resp.TotalRequests)
	}
}

func TestIntegration_AdminUsage_CustomDays(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage?days=7", nil)
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIntegration_AdminUsage_NonAdminForbidden(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage", nil)
	req.Header.Set("X-API-Key", "test-lookup-key") // basic plan
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIntegration_AdminUsage_NoKeyUnauthorized(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
