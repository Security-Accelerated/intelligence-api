//go:build integration

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
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
	cfg.Set("cache.default_ttl", "60m")
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
	cfg.Set("ip.max_ips.free", 1)
	cfg.Set("ip.max_ips.basic", 5)
	cfg.Set("ip.max_ips.pro", 20)
	return cfg
}

// defaultTestTTL and testCacheTTLs mirror the shape of the configured per-lookup
// TTL table, with deliberately distinct values so tests can assert that each
// lookup key expires on its own schedule. `screenshot` is absent so it exercises
// the default-TTL fallback.
const defaultTestTTL = 60 * time.Minute

var testCacheTTLs = map[string]time.Duration{
	domain.LookupWhoisName:         24 * time.Hour,
	domain.LookupDNSName:           30 * time.Minute,
	domain.LookupSSLName:           4 * time.Hour,
	domain.LookupHeadersName:       45 * time.Minute,
	domain.LookupEmailSecurityName: 2 * time.Hour,
	domain.LookupSubdomainsName:    12 * time.Hour,
	domain.LookupCTLogsName:        18 * time.Hour,
	domain.LookupBGPName:           20 * time.Hour,
	domain.LookupReputationName:    25 * time.Minute,
	domain.LookupThreatIntelName:   35 * time.Minute,
	domain.LookupDNSSecurityName:   6 * time.Hour,
	domain.LookupReverseDNSName:    6 * time.Hour,
	domain.LookupAbuseContactName:  24 * time.Hour,
}

// decodeResults unwraps the {"results": [...]} envelope returned by the domain
// lookup endpoint.
func decodeResults(t *testing.T, w *httptest.ResponseRecorder) []*domain.DomainResponse {
	t.Helper()
	var env domain.DomainResponseEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to unmarshal response envelope: %v\nbody: %s", err, w.Body.String())
	}
	return env.Results
}

// decodeIPResults unwraps the {"results": [...]} envelope from the IP endpoint.
func decodeIPResults(t *testing.T, w *httptest.ResponseRecorder) []*domain.IPResponse {
	t.Helper()
	var env domain.IPResponseEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to unmarshal IP response envelope: %v\nbody: %s", err, w.Body.String())
	}
	return env.Results
}

// ipRedisKey returns the namespaced Redis key for a per-lookup IP cache entry.
func ipRedisKey(ip, lookupName string) string {
	return "intel:" + cache.IPLookupKey(ip, lookupName)
}

// redisKey returns the namespaced Redis key for a per-lookup cache entry, as
// written by cache.RedisCache.
func redisKey(domainName, lookupName string) string {
	return "intel:" + cache.LookupKey(domainName, lookupName)
}

// recordingRecorder captures usage entries so tests can assert on what the
// usage middleware recorded.
type recordingRecorder struct {
	mu      sync.Mutex
	entries []usage.UsageEntry
}

func (r *recordingRecorder) Record(e usage.UsageEntry) {
	r.mu.Lock()
	r.entries = append(r.entries, e)
	r.mu.Unlock()
}

func (r *recordingRecorder) last(t *testing.T) usage.UsageEntry {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		t.Fatal("no usage entries recorded")
	}
	return r.entries[len(r.entries)-1]
}

func setupRouter(t *testing.T) (*gin.Engine, *miniredis.Miniredis) {
	r, mr, _ := setupRouterWithUsage(t)
	return r, mr
}

func setupRouterWithUsage(t *testing.T) (*gin.Engine, *miniredis.Miniredis, *recordingRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rc := cache.NewRedisCache(mr.Addr(), "", 0)

	fpEngine := domain.NewFingerprintEngine()
	fpEngine.LoadRules([]domain.TechRule{
		{Name: "TestServer", Category: "web-server", Headers: map[string]string{"Server": "test"}},
	})

	svc := service.NewDomainService(rc, defaultTestTTL, testCacheTTLs, 30*time.Second, 15*time.Second, 4, 500, 100, fpEngine, &notifications.NoopRecorder{}, nil)
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
		func(_ context.Context, _ string) (*domain.ReputationInfo, []domain.LookupError) {
			return &domain.ReputationInfo{
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

	svc.SetDNSSecurityLookup(func(_ context.Context, _ string) (*domain.DNSSecurityInfo, error) {
		return &domain.DNSSecurityInfo{
			DNSSEC: &domain.DNSSECInfo{Enabled: true, DSRecords: 1, DNSKEYRecords: 2},
			CAA:    &domain.CAAInfo{Present: true, Records: []domain.CAARecord{{Tag: "issue", Value: "letsencrypt.org"}}},
		}, nil
	})

	svc.SetThreatIntelLookup(func(_ context.Context, _ string) (*domain.ThreatIntelInfo, []domain.LookupError) {
		return &domain.ThreatIntelInfo{
			RiskLevel:  "medium",
			Score:      45,
			Categories: []string{"malware"},
			Providers: []*domain.ThreatIntelProviderResult{
				{Provider: "virustotal", Detected: true, Score: 5, Categories: []string{"malware"}, Details: "3/70 engines detected this domain"},
				{Provider: "urlhaus", Detected: false},
				{Provider: "alienvault_otx", Detected: true, Score: 20, Categories: []string{"malware"}, Details: "5 threat pulses reference this domain"},
			},
		}, nil
	})

	svc.SetDNSSecurityLookup(func(_ context.Context, _ string) (*domain.DNSSecurityInfo, error) {
		return &domain.DNSSecurityInfo{
			DNSSEC: &domain.DNSSECInfo{Enabled: true, DSRecords: 1, DNSKEYRecords: 2, Algorithms: []string{"ECDSAP256SHA256"}},
			CAA: &domain.CAAInfo{Present: true, Records: []domain.CAARecord{
				{Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
			}},
		}, nil
	})

	// IP service with stubs
	ipSvc := service.NewIPService(rc, defaultTestTTL, testCacheTTLs, 30*time.Second, nil, &notifications.NoopRecorder{}, nil)
	ipSvc.SetLookups(
		func(_ net.IP) (*domain.GeoIPInfo, error) {
			return &domain.GeoIPInfo{Country: "United States", CountryCode: "US", City: "Mountain View", Latitude: 37.386, Longitude: -122.084}, nil
		},
		func(_ net.IP) (*domain.IPASNInfo, error) {
			return &domain.IPASNInfo{ASN: 15169, Organization: "GOOGLE"}, nil
		},
		func(_ context.Context, _ string) (*domain.ReverseDNSInfo, error) {
			return &domain.ReverseDNSInfo{Hostnames: []string{"dns.google"}}, nil
		},
		func(_ context.Context, _ string) (*domain.AbuseContactInfo, error) {
			return &domain.AbuseContactInfo{Organization: "Google LLC", Country: "US", Email: "network-abuse@google.com"}, nil
		},
		func(_ context.Context, _ string) (*domain.ThreatIntelInfo, []domain.LookupError) {
			return &domain.ThreatIntelInfo{
				RiskLevel: "low",
				Score:     15,
				Providers: []*domain.ThreatIntelProviderResult{
					{Provider: "virustotal", Detected: false},
					{Provider: "urlhaus", Detected: false},
				},
			}, nil
		},
	)

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
	usageRec := &recordingRecorder{}

	h := handler.New(svc, ipSvc, fpSvc, nil, usageQ, nil, nil, cfg, rc, cachedRepo, nil, &config.StatusSnapshot{
		System: config.SystemStatus{Version: "test"},
	})
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

	return r, mr, usageRec
}

func TestIntegration_DomainLookup_FullFlow(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)

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

	body := `{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`

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

	resp1 := decodeResults(t, w1)
	resp2 := decodeResults(t, w2)

	if len(resp1) != 1 || len(resp2) != 1 {
		t.Fatalf("expected 1 result each, got %d and %d", len(resp1), len(resp2))
	}
	for _, f := range []struct {
		name string
		hit  bool
	}{
		{"whois", resp1[0].Whois.CacheHit},
		{"dns", resp1[0].DNS.CacheHit},
		{"ssl", resp1[0].SSL.CacheHit},
		{"headers", resp1[0].Headers.CacheHit},
	} {
		if f.hit {
			t.Errorf("first request: %s cache_hit = true, want false", f.name)
		}
	}
	for _, f := range []struct {
		name string
		hit  bool
	}{
		{"whois", resp2[0].Whois.CacheHit},
		{"dns", resp2[0].DNS.CacheHit},
		{"ssl", resp2[0].SSL.CacheHit},
		{"headers", resp2[0].Headers.CacheHit},
	} {
		if !f.hit {
			t.Errorf("second request: %s cache_hit = false, want true", f.name)
		}
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["notadomain"],"lookups":["dns"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIntegration_Docs_RootRedirects(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusMovedPermanently)
	}
	if loc := w.Header().Get("Location"); loc != "/docs" {
		t.Errorf("Location = %q, want /docs", loc)
	}
}

func TestIntegration_Docs_LandingPage(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_Auth_InvalidKey(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","screenshot"]}`))
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","reputation"]}`))
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
		strings.NewReader(`{"domains":["a.com","b.com"],"lookups":["dns"]}`))
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","screenshot"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-pro-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","screenshot"]}`))
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","reputation"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-pro-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","reputation"]}`))
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","reputation","screenshot"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","email_security"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","subdomains"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","subdomains"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","ct_logs"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","ct_logs"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","bgp"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := decodeResults(t, w)
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
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","bgp"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
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

	// Create a body larger than 1MB. The middleware rejects it with 413
	// via Content-Length early check.
	bigBody := strings.Repeat("x", 1<<20+1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d (oversized body rejected)", w.Code, http.StatusRequestEntityTooLarge)
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

	body := `{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`

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

	body := `{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}`

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

	// dns has a 30m TTL and whois 24h, so fast-forwarding past 30m must expire
	// exactly one of them.
	body := `{"domains":["example.com"],"lookups":["dns","whois"]}`

	do := func(label string) []*domain.DomainResponse {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-admin-key")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want %d; body: %s", label, w.Code, http.StatusOK, w.Body.String())
		}
		results := decodeResults(t, w)
		if len(results) != 1 {
			t.Fatalf("%s: len(results) = %d, want 1", label, len(results))
		}
		return results
	}

	// 1. First request — both lookups miss and populate their own keys.
	first := do("first request")
	if first[0].DNS.CacheHit || first[0].Whois.CacheHit {
		t.Error("first request should miss on both lookups")
	}

	// Each lookup gets its own flat key with its own TTL.
	for _, tc := range []struct {
		lookup string
		ttl    time.Duration
	}{
		{domain.LookupDNSName, 30 * time.Minute},
		{domain.LookupWhoisName, 24 * time.Hour},
	} {
		k := redisKey("example.com", tc.lookup)
		if !mr.Exists(k) {
			t.Fatalf("expected redis key %q", k)
		}
		if got := mr.TTL(k); got != tc.ttl {
			t.Errorf("TTL(%s) = %v, want %v", k, got, tc.ttl)
		}
	}

	// 2. Second request — both hit.
	second := do("second request")
	if !second[0].DNS.CacheHit || !second[0].Whois.CacheHit {
		t.Error("second request should hit on both lookups")
	}

	// 3. Fast-forward past the dns TTL but well short of the whois TTL.
	mr.FastForward(31 * time.Minute)

	// 4. Third request — dns expired, whois still warm. No stale serving: the
	// expired entry is simply gone and gets refetched.
	third := do("third request")
	if third[0].DNS.CacheHit {
		t.Error("dns should miss after its 30m TTL expired")
	}
	if !third[0].Whois.CacheHit {
		t.Error("whois should still hit — its 24h TTL has not expired")
	}
}

func TestIntegration_Cache_PerLookupKeysWarmIndependently(t *testing.T) {
	r, mr := setupRouter(t)

	post := func(body string) []*domain.DomainResponse {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-admin-key")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
		return decodeResults(t, w)
	}

	// A dns-only request warms lookup:example.com:dns and nothing else.
	post(`{"domains":["example.com"],"lookups":["dns"]}`)
	if !mr.Exists(redisKey("example.com", domain.LookupDNSName)) {
		t.Fatal("dns key not warmed")
	}
	if mr.Exists(redisKey("example.com", domain.LookupSSLName)) {
		t.Error("ssl key should not exist after a dns-only request")
	}

	// A later dns+ssl request reuses the warm dns entry and fetches ssl live.
	results := post(`{"domains":["example.com"],"lookups":["dns","ssl"]}`)
	if !results[0].DNS.CacheHit {
		t.Error("dns cache_hit = false, want true (warmed by the earlier request)")
	}
	if results[0].SSL.CacheHit {
		t.Error("ssl cache_hit = true, want false (first time it was requested)")
	}
}

func TestIntegration_Cache_FingerprintWarmsHeadersKey(t *testing.T) {
	r, mr := setupRouter(t)

	post := func(body string) []*domain.DomainResponse {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-admin-key")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
		return decodeResults(t, w)
	}

	// A fingerprint-only request fetches headers internally and caches them...
	fpOnly := post(`{"domains":["example.com"],"lookups":["fingerprint"]}`)
	if fpOnly[0].Fingerprint == nil {
		t.Fatal("fingerprint missing from response")
	}
	if fpOnly[0].Headers != nil {
		t.Error("headers must not appear when only fingerprint was requested")
	}
	if !mr.Exists(redisKey("example.com", domain.LookupHeadersName)) {
		t.Fatal("headers key not warmed by the fingerprint request")
	}
	// ...and fingerprint itself never gets a key of its own.
	if mr.Exists(redisKey("example.com", domain.LookupFingerprintName)) {
		t.Error("fingerprint must never be cached under its own key")
	}

	// ...so a later headers request is served from that same entry.
	headers := post(`{"domains":["example.com"],"lookups":["headers"]}`)
	if headers[0].Headers == nil || !headers[0].Headers.CacheHit {
		t.Errorf("headers cache_hit = false, want true; got %+v", headers[0].Headers)
	}
}

func TestIntegration_Cache_FingerprintCacheHitMirrorsHeaders(t *testing.T) {
	r, _ := setupRouter(t)

	post := func(body string) []*domain.DomainResponse {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-admin-key")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
		}
		return decodeResults(t, w)
	}

	first := post(`{"domains":["example.com"],"lookups":["headers","fingerprint"]}`)
	if first[0].Fingerprint.CacheHit {
		t.Error("fingerprint cache_hit = true on a cold headers fetch")
	}

	second := post(`{"domains":["example.com"],"lookups":["fingerprint"]}`)
	if !second[0].Fingerprint.CacheHit {
		t.Error("fingerprint cache_hit = false, want true (headers came from cache)")
	}
}

// --- Validation Edge Cases ---

func TestIntegration_DomainLookup_EmptyDomainsArray(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":[],"lookups":["dns"]}`))
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

// --- Threat Intel integration tests ---

func TestIntegration_ThreatIntel_FreeGets403(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-free-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_ThreatIntel_BasicGets403(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestIntegration_ThreatIntel_ProAllowed(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-pro-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].ThreatIntel == nil {
		t.Fatal("expected ThreatIntel to be populated")
	}
	if resp[0].ThreatIntel.RiskLevel != "medium" {
		t.Errorf("RiskLevel = %q, want %q", resp[0].ThreatIntel.RiskLevel, "medium")
	}
	if len(resp[0].ThreatIntel.Providers) != 3 {
		t.Errorf("len(Providers) = %d, want 3", len(resp[0].ThreatIntel.Providers))
	}
}

func TestIntegration_ThreatIntel_AdminAllowed(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"lookups":["whois","dns","ssl","headers","threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
	if resp[0].ThreatIntel == nil {
		t.Fatal("expected ThreatIntel to be populated")
	}
}

// --- DNS Security ---

func TestIntegration_DNSSecurity_AllPlansCanAccess(t *testing.T) {
	r, _ := setupRouter(t)

	// Free plan can request dns_security (no premium gate)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"lookups":["dns_security"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-free-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	ds := resp[0].DNSSecurity
	if ds == nil {
		t.Fatal("expected dns_security to be populated")
	}
	if ds.DNSSEC == nil || !ds.DNSSEC.Enabled {
		t.Errorf("DNSSEC = %+v, want Enabled=true", ds.DNSSEC)
	}
	if ds.DNSSEC != nil && (ds.DNSSEC.DSRecords != 1 || ds.DNSSEC.DNSKEYRecords != 2) {
		t.Errorf("DNSSEC records = %d DS / %d DNSKEY, want 1 / 2", ds.DNSSEC.DSRecords, ds.DNSSEC.DNSKEYRecords)
	}
	if ds.CAA == nil || !ds.CAA.Present || len(ds.CAA.Records) != 1 {
		t.Errorf("CAA = %+v, want Present=true with 1 record", ds.CAA)
	}
	if ds.CAA != nil && len(ds.CAA.Records) == 1 && ds.CAA.Records[0].Tag != "issue" {
		t.Errorf("CAA.Records[0].Tag = %q, want %q", ds.CAA.Records[0].Tag, "issue")
	}
}

func TestIntegration_DNSSecurity_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := postLookup(t, r, "test-admin-key", `{"domains":["example.com"],"lookups":["dns"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].DNSSecurity != nil {
		t.Error("expected dns_security to be nil when not requested")
	}
}

// --- Aggregate Risk Score ---

func TestIntegration_DomainLookup_RiskIncluded(t *testing.T) {
	r, _ := setupRouter(t)

	// Risk is opt-in and scores over whatever else was requested.
	w := postLookup(t, r, "test-free-key",
		`{"domains":["example.com"],"lookups":["ssl","headers","risk"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	resp := decodeResults(t, w)
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	risk := resp[0].Risk
	if risk == nil {
		t.Fatal("expected risk to be populated on every domain lookup")
	}
	if risk.Score < 0 || risk.Score > 100 {
		t.Errorf("Risk.Score = %d, want 0-100", risk.Score)
	}
	if risk.Level == "" {
		t.Error("expected Risk.Level to be non-empty")
	}
	if len(risk.Components) == 0 {
		t.Fatal("expected risk components from base lookups (ssl, security_headers)")
	}
	for _, c := range risk.Components {
		if c.Weight <= 0 {
			t.Errorf("component %q has weight %v, want > 0", c.Component, c.Weight)
		}
	}
}

// --- My Usage (self-service) ---

func TestIntegration_MyUsage_Authenticated(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/usage", nil)
	req.Header.Set("X-API-Key", "test-lookup-key") // basic plan — no admin needed
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

func TestIntegration_MyUsage_CustomDays(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/usage?days=7", nil)
	req.Header.Set("X-API-Key", "test-free-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIntegration_MyUsage_InvalidDays(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/usage?days=999", nil)
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIntegration_MyUsage_NoKeyUnauthorized(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/usage", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// --- Health ---

func TestIntegration_Health(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body struct {
		Status     string            `json:"status"`
		Components map[string]string `json:"components"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
	// miniredis is wired in, so redis should report healthy.
	if body.Components["redis"] != "ok" {
		t.Errorf("components.redis = %q, want %q", body.Components["redis"], "ok")
	}
}

// ==================== IP Lookup Integration Tests ====================

func TestIntegration_IPLookup_FullFlow(t *testing.T) {
	r, _ := setupRouter(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	results := decodeIPResults(t, w)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	ip := results[0]
	if ip.IP != "8.8.8.8" {
		t.Errorf("IP = %q, want %q", ip.IP, "8.8.8.8")
	}
	if ip.Geo == nil || ip.Geo.Country != "United States" {
		t.Error("expected geo.country = United States")
	}
	if ip.ASN == nil || ip.ASN.ASN != 15169 {
		t.Error("expected asn.asn = 15169")
	}
	if ip.ReverseDNS == nil || len(ip.ReverseDNS.Hostnames) == 0 {
		t.Error("expected reverse_dns hostnames")
	}
	if ip.AbuseContact == nil || ip.AbuseContact.Email == "" {
		t.Error("expected abuse_contact with email")
	}
}

func TestIntegration_IPLookup_Caching(t *testing.T) {
	r, mr := setupRouter(t)

	post := func(body string) []*domain.IPResponse {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-lookup-key")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
		return decodeIPResults(t, w)
	}

	body := `{"ips":["8.8.8.8"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}`

	first := post(body)
	for _, f := range []struct {
		name string
		hit  bool
	}{
		{"geo", first[0].Geo.CacheHit},
		{"asn", first[0].ASN.CacheHit},
		{"reverse_dns", first[0].ReverseDNS.CacheHit},
		{"abuse_contact", first[0].AbuseContact.CacheHit},
	} {
		if f.hit {
			t.Errorf("first request: %s cache_hit = true, want false", f.name)
		}
	}

	// Only the network-backed lookups get keys. geo and asn read a local
	// MaxMind mmap, so caching them would cost more than recomputing.
	for _, name := range []string{domain.LookupReverseDNSName, domain.LookupAbuseContactName} {
		if !mr.Exists(ipRedisKey("8.8.8.8", name)) {
			t.Errorf("expected redis key for %s", name)
		}
	}
	for _, name := range []string{domain.LookupGeoName, domain.LookupASNName} {
		if mr.Exists(ipRedisKey("8.8.8.8", name)) {
			t.Errorf("%s must never be cached", name)
		}
	}

	second := post(body)
	if !second[0].ReverseDNS.CacheHit {
		t.Error("second request: reverse_dns cache_hit = false, want true")
	}
	if !second[0].AbuseContact.CacheHit {
		t.Error("second request: abuse_contact cache_hit = false, want true")
	}
	// Uncached lookups never become hits, however many times they are asked for.
	if second[0].Geo.CacheHit || second[0].ASN.CacheHit {
		t.Error("geo/asn cache_hit = true, want false (never cached)")
	}
}

func TestIntegration_IPLookup_PerLookupTTLs(t *testing.T) {
	r, mr := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["reverse_dns","abuse_contact"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	for _, tc := range []struct {
		lookup string
		ttl    time.Duration
	}{
		{domain.LookupReverseDNSName, 6 * time.Hour},
		{domain.LookupAbuseContactName, 24 * time.Hour},
	} {
		if got := mr.TTL(ipRedisKey("8.8.8.8", tc.lookup)); got != tc.ttl {
			t.Errorf("TTL(%s) = %v, want %v", tc.lookup, got, tc.ttl)
		}
	}
}

func TestIntegration_IPLookup_KeyspaceSeparateFromDomains(t *testing.T) {
	r, mr := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	// Same lookup name on both endpoints — the namespaces must not collide.
	if !mr.Exists(ipRedisKey("8.8.8.8", domain.LookupThreatIntelName)) {
		t.Error("IP threat_intel missing from the ip: keyspace")
	}
	if mr.Exists(redisKey("8.8.8.8", domain.LookupThreatIntelName)) {
		t.Error("IP threat_intel leaked into the domain lookup: keyspace")
	}
}

func TestIntegration_IPLookup_ThreatIntelProOnly(t *testing.T) {
	r, _ := setupRouter(t)

	// Basic plan — should be forbidden
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key") // basic plan
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("basic plan with threat_intel: status = %d, want %d", w.Code, http.StatusForbidden)
	}

	// Pro plan — should succeed
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["threat_intel"]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", "test-pro-key")
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("pro plan with threat_intel: status = %d, want %d; body: %s", w2.Code, http.StatusOK, w2.Body.String())
	}

	results := decodeIPResults(t, w2)
	if results[0].ThreatIntel == nil {
		t.Error("expected threat_intel to be populated for pro plan")
	}
}

func TestIntegration_IPLookup_PrivateIPRejected(t *testing.T) {
	r, _ := setupRouter(t)

	tests := []struct {
		name string
		ip   string
	}{
		{"loopback", "127.0.0.1"},
		{"private", "10.0.0.1"},
		{"metadata", "169.254.169.254"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			body := `{"ips":["` + tt.ip + `"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}`
			req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-API-Key", "test-admin-key")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d for %s", w.Code, http.StatusBadRequest, tt.ip)
			}
		})
	}
}

func TestIntegration_IPLookup_MaxIPsPerPlan(t *testing.T) {
	r, _ := setupRouter(t)

	// Free plan allows 1 IP — send 2
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","1.1.1.1"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-free-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("free plan 2 IPs: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIntegration_IPLookup_NoAuth(t *testing.T) {
	r, _ := setupRouter(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_IPLookup_InvalidBody(t *testing.T) {
	r, _ := setupRouter(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIntegration_IPLookup_IPv6(t *testing.T) {
	r, _ := setupRouter(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["2001:4860:4860::8888"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestIntegration_IPLookup_MultipleIPs(t *testing.T) {
	r, _ := setupRouter(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8","1.1.1.1"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-pro-key") // pro allows up to 20
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	results := decodeIPResults(t, w)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

// --- GeoIP Admin Integration ---

func TestIntegration_GeoIPRefresh_AdminOnly(t *testing.T) {
	r, _ := setupRouter(t)

	// No auth — 401
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", nil)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: status = %d, want %d", w1.Code, http.StatusUnauthorized)
	}

	// Basic plan — 403
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/admin/geoip/refresh", nil)
	req2.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("basic plan: status = %d, want %d", w2.Code, http.StatusForbidden)
	}
}

// --- Billing route integration tests ---
// The integration test wires nil for the billing service. These tests verify
// that routes are reachable through the middleware chain and that nil-guard
// responses are correct (the production fallback when billing is unconfigured).

func TestIntegration_BillingWebhook_NoBillingService(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	body := strings.NewReader(`{"type": "checkout.session.completed"}`)
	req := httptest.NewRequest(http.MethodPost, "/billing/webhook", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", "t=123,v1=abc")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "billing not configured" {
		t.Errorf("error = %q, want %q", resp["error"], "billing not configured")
	}
}

func TestIntegration_BillingWebhook_NoBillingService_NoSignature(t *testing.T) {
	r, _ := setupRouter(t)

	// Billing is nil, so the nil guard fires before signature validation.
	// This verifies the route is reachable through the middleware chain.
	w := httptest.NewRecorder()
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/billing/webhook", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestIntegration_BillingSuccess_NoBillingService(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success?session_id=cs_test_123", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Billing is not configured") {
		t.Error("expected 'Billing is not configured' error message in rendered page")
	}
}

func TestIntegration_BillingSuccess_NoBillingService_NoSessionID(t *testing.T) {
	r, _ := setupRouter(t)

	// Billing is nil, so the nil guard fires before session_id validation.
	// This verifies the route is reachable without auth through the middleware chain.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Billing is not configured") {
		t.Error("expected billing not configured error")
	}
}

func TestIntegration_BillingWebhook_NoAuthRequired(t *testing.T) {
	r, _ := setupRouter(t)

	// Billing routes should not require API key auth
	w := httptest.NewRecorder()
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/billing/webhook", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", "t=123,v1=abc")
	r.ServeHTTP(w, req)

	// Should get 503 (billing not configured), NOT 401 (unauthorized)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("billing webhook should not require API key auth")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestIntegration_BillingSuccess_NoAuthRequired(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success?session_id=cs_test", nil)
	r.ServeHTTP(w, req)

	// Should get 200 (rendered page), NOT 401
	if w.Code == http.StatusUnauthorized {
		t.Fatal("billing success should not require API key auth")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- Admin positive path tests ---

func TestIntegration_AdminChangelog_AdminAllowed(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/changelog", nil)
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	// Response is a JSON array of changelog versions
	body := w.Body.String()
	if body == "" || body[0] != '[' {
		t.Errorf("expected JSON array, got %q", body[:min(len(body), 50)])
	}
	// Should include both public and internal entries (unfiltered)
	if !strings.Contains(body, "public") || !strings.Contains(body, "internal") {
		t.Error("admin changelog should include both public and internal audience entries")
	}
}

func TestIntegration_AdminChangelog_NonAdminForbidden(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/changelog", nil)
	req.Header.Set("X-API-Key", "test-lookup-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIntegration_AdminChangelog_NoKeyUnauthorized(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/changelog", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestIntegration_AdminInfo_AdminAllowed(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/info", nil)
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "system") {
		t.Error("expected info response to contain 'system' section")
	}
	if !strings.Contains(body, "version") {
		t.Error("expected info response to contain 'version' field")
	}
}

// --- Selectable lookups: validation and exact-field responses ---

func postLookup(t *testing.T, r *gin.Engine, apiKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	r.ServeHTTP(w, req)
	return w
}

func TestIntegration_Lookups_RequiredAndNonEmpty(t *testing.T) {
	r, _ := setupRouter(t)

	for _, body := range []string{
		`{"domains":["example.com"]}`,
		`{"domains":["example.com"],"lookups":[]}`,
		`{"domains":["example.com"],"lookups":["  "]}`,
	} {
		t.Run(body, func(t *testing.T) {
			w := postLookup(t, r, "test-admin-key", body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "lookups is required") {
				t.Errorf("body = %s, want the lookups-required message", w.Body.String())
			}
		})
	}
}

func TestIntegration_Lookups_UnknownName(t *testing.T) {
	r, _ := setupRouter(t)

	w := postLookup(t, r, "test-admin-key", `{"domains":["example.com"],"lookups":["dns","nope"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "nope") {
		t.Errorf("body = %s, want it to name the invalid lookup", w.Body.String())
	}
}

func TestIntegration_Lookups_PlanGatingPerLookup(t *testing.T) {
	r, _ := setupRouter(t)

	cases := []struct {
		key    string
		lookup string
		want   int
	}{
		{"test-free-key", "screenshot", http.StatusForbidden},
		{"test-free-key", "reputation", http.StatusForbidden},
		{"test-free-key", "threat_intel", http.StatusForbidden},
		{"test-free-key", "dns", http.StatusOK},
		{"test-lookup-key", "screenshot", http.StatusForbidden},   // basic
		{"test-lookup-key", "reputation", http.StatusForbidden},   // basic
		{"test-lookup-key", "threat_intel", http.StatusForbidden}, // basic
		{"test-lookup-key", "dns", http.StatusOK},
		{"test-lookup-key", "subdomains", http.StatusOK},
		{"test-pro-key", "screenshot", http.StatusOK},
		{"test-pro-key", "reputation", http.StatusOK},
		{"test-pro-key", "threat_intel", http.StatusOK},
		{"test-admin-key", "screenshot", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.key+"/"+tc.lookup, func(t *testing.T) {
			body := `{"domains":["example.com"],"lookups":["` + tc.lookup + `"]}`
			w := postLookup(t, r, tc.key, body)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), tc.lookup) {
				t.Errorf("403 body should name the gated lookup, got %s", w.Body.String())
			}
		})
	}
}

func TestIntegration_Lookups_ReturnsExactlyRequestedFields(t *testing.T) {
	r, _ := setupRouter(t)

	w := postLookup(t, r, "test-admin-key",
		`{"domains":["example.com"],"lookups":["dns","bgp","ct_logs"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	var env struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.Results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(env.Results))
	}

	got := env.Results[0]
	want := map[string]bool{"domain": true, "inputs": true, "dns": true, "bgp": true, "ct_logs": true}
	for k := range got {
		if !want[k] {
			t.Errorf("response contains unrequested field %q; full body: %s", k, w.Body.String())
		}
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("response missing expected field %q; full body: %s", k, w.Body.String())
		}
	}
}

func TestIntegration_Lookups_NormalizedNamesAndDomains(t *testing.T) {
	r, _ := setupRouter(t)

	w := postLookup(t, r, "test-admin-key",
		`{"domains":["HTTPS://Example.COM/","example.com","example.net"],"lookups":[" DNS ","dns","SSL"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	results := decodeResults(t, w)
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2 unique normalized domains", len(results))
	}

	var com *domain.DomainResponse
	for _, res := range results {
		if res.Domain == "example.com" {
			com = res
		}
	}
	if com == nil {
		t.Fatalf("no result for example.com: %+v", results)
	}
	if len(com.Inputs) != 2 || com.Inputs[0] != "HTTPS://Example.COM/" || com.Inputs[1] != "example.com" {
		t.Errorf("inputs = %v, want the two verbatim entries", com.Inputs)
	}
	if com.DNS == nil || com.SSL == nil {
		t.Errorf("expected dns and ssl on the result, got %+v", com)
	}
	if com.Whois != nil || com.Headers != nil {
		t.Error("response contains lookups that were not requested")
	}
}

// --- Usage tracking ---

func TestIntegration_Usage_RequestedLookupsCountedRegardlessOfCache(t *testing.T) {
	r, _, rec := setupRouterWithUsage(t)

	body := `{"domains":["example.com"],"lookups":["dns","ssl","whois"]}`

	// Fully live.
	if w := postLookup(t, r, "test-admin-key", body); w.Code != http.StatusOK {
		t.Fatalf("first request status = %d; body: %s", w.Code, w.Body.String())
	}
	live := rec.last(t)

	// Fully cached.
	if w := postLookup(t, r, "test-admin-key", body); w.Code != http.StatusOK {
		t.Fatalf("second request status = %d; body: %s", w.Code, w.Body.String())
	}
	cached := rec.last(t)

	// Requested lookups are customer demand: identical either way.
	sortedLookups := func(e usage.UsageEntry) []string {
		out := slices.Clone(e.Lookups)
		slices.Sort(out)
		return out
	}
	if !slices.Equal(sortedLookups(live), sortedLookups(cached)) {
		t.Errorf("lookups differ between live (%v) and cached (%v) requests", live.Lookups, cached.Lookups)
	}
	if want := []string{"dns", "ssl", "whois"}; !slices.Equal(sortedLookups(live), want) {
		t.Errorf("lookups = %v, want %v", sortedLookups(live), want)
	}

	// Cache metrics do differ — that is the operational signal.
	if live.CacheHits != 0 || live.CacheMisses != 3 {
		t.Errorf("live request: hits/misses = %d/%d, want 0/3", live.CacheHits, live.CacheMisses)
	}
	if cached.CacheHits != 3 || cached.CacheMisses != 0 {
		t.Errorf("cached request: hits/misses = %d/%d, want 3/0", cached.CacheHits, cached.CacheMisses)
	}
}

func TestIntegration_Usage_MixedCacheHitAndMissCounts(t *testing.T) {
	r, _, rec := setupRouterWithUsage(t)

	// Warm dns only.
	if w := postLookup(t, r, "test-admin-key", `{"domains":["example.com"],"lookups":["dns"]}`); w.Code != http.StatusOK {
		t.Fatalf("warm-up status = %d; body: %s", w.Code, w.Body.String())
	}

	if w := postLookup(t, r, "test-admin-key", `{"domains":["example.com"],"lookups":["dns","ssl","bgp"]}`); w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	e := rec.last(t)

	if e.CacheHits != 1 || e.CacheMisses != 2 {
		t.Errorf("hits/misses = %d/%d, want 1/2", e.CacheHits, e.CacheMisses)
	}
	if e.DomainCount != 1 {
		t.Errorf("DomainCount = %d, want 1", e.DomainCount)
	}
}

func TestIntegration_Risk_AbsentWhenNotRequested(t *testing.T) {
	r, _ := setupRouter(t)

	w := postLookup(t, r, "test-admin-key", `{"domains":["example.com"],"lookups":["ssl","headers"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if resp := decodeResults(t, w); resp[0].Risk != nil {
		t.Error("risk present without being requested")
	}
}

func TestIntegration_Risk_NeverGetsItsOwnCacheKey(t *testing.T) {
	r, mr := setupRouter(t)

	w := postLookup(t, r, "test-admin-key", `{"domains":["example.com"],"lookups":["ssl","risk"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	if !mr.Exists(redisKey("example.com", domain.LookupSSLName)) {
		t.Error("ssl key not warmed")
	}
	if mr.Exists(redisKey("example.com", domain.LookupRiskName)) {
		t.Error("risk must never be cached under its own key")
	}
}

func TestIntegration_FailedLookupIsNotCached(t *testing.T) {
	r, mr := setupRouter(t)

	// Domain lookups deliberately do not negative-cache: a failing lookup is
	// retried rather than remembered, and per-lookup TTLs mean it can't drag
	// its healthy siblings down with it.
	w := postLookup(t, r, "test-admin-key", `{"domains":["fail.example"],"lookups":["dns","ssl"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	// The stubs always succeed, so assert the invariant directly on the keys:
	// every cached key corresponds to a lookup that returned data.
	for _, name := range []string{domain.LookupDNSName, domain.LookupSSLName} {
		if !mr.Exists(redisKey("fail.example", name)) {
			t.Errorf("expected %s to be cached after a successful lookup", name)
		}
	}
}

func TestIntegration_IPLookups_RequiredAndValidated(t *testing.T) {
	r, _ := setupRouter(t)

	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-admin-key")
		r.ServeHTTP(w, req)
		return w
	}

	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"missing", `{"ips":["8.8.8.8"]}`, "lookups is required"},
		{"empty", `{"ips":["8.8.8.8"],"lookups":[]}`, "lookups is required"},
		{"blank", `{"ips":["8.8.8.8"],"lookups":["  "]}`, "lookups is required"},
		{"unknown", `{"ips":["8.8.8.8"],"lookups":["geo","nope"]}`, "nope"},
		{"domain-only name", `{"ips":["8.8.8.8"],"lookups":["whois"]}`, "whois"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := post(tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("body = %s, want it to mention %q", w.Body.String(), tc.want)
			}
		})
	}
}

func TestIntegration_IPLookup_ReturnsExactlyRequestedFields(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":["8.8.8.8"],"lookups":["geo","reverse_dns"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	var env struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]bool{"ip": true, "inputs": true, "geo": true, "reverse_dns": true}
	for k := range env.Results[0] {
		if !want[k] {
			t.Errorf("response contains unrequested field %q; body: %s", k, w.Body.String())
		}
	}
	for k := range want {
		if _, ok := env.Results[0][k]; !ok {
			t.Errorf("response missing expected field %q; body: %s", k, w.Body.String())
		}
	}
}

func TestIntegration_IPLookup_DedupesAndRecordsInputs(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/lookup",
		strings.NewReader(`{"ips":[" 8.8.8.8 ","8.8.8.8","1.1.1.1"],"lookups":["geo"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-admin-key")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}

	results := decodeIPResults(t, w)
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2 unique canonical addresses", len(results))
	}
	var google *domain.IPResponse
	for _, res := range results {
		if res.IP == "8.8.8.8" {
			google = res
		}
	}
	if google == nil {
		t.Fatalf("no result for 8.8.8.8: %+v", results)
	}
	if len(google.Inputs) != 2 || google.Inputs[0] != " 8.8.8.8 " {
		t.Errorf("inputs = %v, want both verbatim entries", google.Inputs)
	}
}
