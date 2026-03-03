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

type mockService struct {
	mu       sync.Mutex
	resp     *domain.DomainResponse
	cached   bool
	lastOpts domain.LookupOptions
}

func (m *mockService) Lookup(_ context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, bool) {
	m.mu.Lock()
	m.lastOpts = opts
	m.mu.Unlock()
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
	h := New(svc, nil, "test", nil, nil, nil)
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
	assertErrorBody(t, w)
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
	assertErrorBody(t, w)
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
	assertErrorBody(t, w)
}

func TestDomainLookup_RawIPRejectedWithMessage(t *testing.T) {
	r := newTestRouter(&mockService{})

	t.Run("single IP returns 400 with specific message", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["169.254.169.254"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		want := "raw IP addresses are not accepted; provide a domain name"
		if body["error"] != want {
			t.Errorf("error = %q, want %q", body["error"], want)
		}
	})

	t.Run("IP in multi-domain returns validation error with specific message", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domains":["example.com","10.0.0.1"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
		}
		var resp []*domain.DomainResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		if len(resp) != 2 {
			t.Fatalf("len(resp) = %d, want 2", len(resp))
		}
		if len(resp[1].Errors) != 1 {
			t.Fatalf("len(resp[1].Errors) = %d, want 1", len(resp[1].Errors))
		}
		want := "raw IP addresses are not accepted; provide a domain name"
		if resp[1].Errors[0].Message != want {
			t.Errorf("error message = %q, want %q", resp[1].Errors[0].Message, want)
		}
	})
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

// --- normalizeDomain unit tests ---

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantOK  bool
	}{
		{"plain domain", "example.com", "example.com", true},
		{"https prefix", "https://example.com", "example.com", true},
		{"http prefix", "http://example.com", "example.com", true},
		{"trailing slash", "example.com/", "example.com", true},
		{"path segments", "https://example.com/foo/bar", "example.com/foo/bar", true},
		{"double prefix", "https://https://example.com", "https://example.com", true},
		{"ftp prefix preserved", "ftp://example.com", "ftp://example.com", true},
		{"whitespace", "  example.com  ", "example.com", true},
		{"empty", "", "", false},
		{"no dot", "localhost", "localhost", false},
		{"protocol only", "https://", "", false},
		{"ipv4 address", "192.168.1.1", "192.168.1.1", false},
		{"cloud metadata ip", "169.254.169.254", "169.254.169.254", false},
		{"public ip", "8.8.8.8", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeDomain(tt.input)
			if ok != tt.wantOK {
				t.Errorf("normalizeDomain(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Tier gating ---

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
	assertErrorBody(t, w)
}

func TestDomainLookup_Screenshot_PremiumAllowed(t *testing.T) {
	r := newTestRouterWithTier(&mockService{}, "premium")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_Screenshot_BasicForbidden(t *testing.T) {
	r := newTestRouterWithTier(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
	assertErrorBody(t, w)
}

func TestDomainLookup_OptsPassedToService(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantScreenshot bool
		wantReputation bool
	}{
		{"no opts", `{"domains":["example.com"]}`, false, false},
		{"screenshot only", `{"domains":["example.com"],"screenshot":true}`, true, false},
		{"reputation only", `{"domains":["example.com"],"reputation":true}`, false, true},
		{"both", `{"domains":["example.com"],"screenshot":true,"reputation":true}`, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockService{}
			r := newTestRouter(svc)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
			}
			if svc.lastOpts.Screenshot != tt.wantScreenshot {
				t.Errorf("opts.Screenshot = %v, want %v", svc.lastOpts.Screenshot, tt.wantScreenshot)
			}
			if svc.lastOpts.Reputation != tt.wantReputation {
				t.Errorf("opts.Reputation = %v, want %v", svc.lastOpts.Reputation, tt.wantReputation)
			}
		})
	}
}

// domainLoggerKeys derived from middleware.ContextKeys.
var domainLoggerKeys = filterKeys("screenshot", "reputation", "cache_hit")

func TestDomainLookup_SetsLoggerContextKeys(t *testing.T) {
	tests := []struct {
		name string
		body string
		want map[string]bool
	}{
		{
			"no optional features",
			`{"domains":["example.com"]}`,
			map[string]bool{"screenshot_requested": false, "reputation_requested": false, "cache_hit": false},
		},
		{
			"all optional features",
			`{"domains":["example.com"],"screenshot":true,"reputation":true}`,
			map[string]bool{"screenshot_requested": true, "reputation_requested": true, "cache_hit": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockService{}
			gin.SetMode(gin.TestMode)
			r := gin.New()
			h := New(svc, nil, "test", nil, nil, nil)

			captured := make(map[string]any)
			auth := func(c *gin.Context) {
				c.Set("api_key_roles", []string{"admin"})
				c.Set("api_key_tier", "premium")
				c.Next()
				for _, key := range domainLoggerKeys {
					if v, exists := c.Get(key); exists {
						captured[key] = v
					}
				}
			}

			h.RegisterRoutes(r)
			h.RegisterProtectedRoutes(r, auth)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
			}

			for _, key := range domainLoggerKeys {
				val, exists := captured[key]
				if !exists {
					t.Errorf("context key %q not set by handler (logger will silently skip it)", key)
					continue
				}
				if want, ok := tt.want[key]; ok {
					if val.(bool) != want {
						t.Errorf("context key %q = %v, want %v", key, val, want)
					}
				}
			}
		})
	}
}

// --- Max domains per request ---

func testCfg(overrides map[string]any) *viper.Viper {
	v := viper.New()
	for k, val := range overrides {
		v.Set(k, val)
	}
	return v
}

func newTestRouterWithCfg(svc DomainLookupService, tier string, cfg *viper.Viper) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(svc, nil, "test", cfg, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_roles", []string{"admin"})
		c.Set("api_key_tier", tier)
		c.Next()
	})
	return r
}

func TestDomainLookup_MaxDomains_ExceedsLimit(t *testing.T) {
	cfg := testCfg(map[string]any{
		"domain.max_domains.basic":   2,
		"domain.max_domains.premium": 3,
	})

	t.Run("basic tier over limit", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "basic", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
			strings.NewReader(`{"domains":["a.com","b.com","c.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
		}
		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["error"] != "too many domains: maximum 2 allowed for basic tier" {
			t.Errorf("error = %q", body["error"])
		}
	})

	t.Run("premium tier over limit", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "premium", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
			strings.NewReader(`{"domains":["a.com","b.com","c.com","d.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
		}
		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["error"] != "too many domains: maximum 3 allowed for premium tier" {
			t.Errorf("error = %q", body["error"])
		}
	})

	t.Run("premium tier at limit succeeds", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "premium", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
			strings.NewReader(`{"domains":["a.com","b.com","c.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
	})

	t.Run("nil config means no limit", func(t *testing.T) {
		r := newTestRouterWithTier(&mockService{}, "basic")
		w := httptest.NewRecorder()
		// 10 domains, but nil config → no limit enforced
		req := httptest.NewRequest(http.MethodPost, "/api/v1/domain",
			strings.NewReader(`{"domains":["a.com","b.com","c.com","d.com","e.com","f.com","g.com","h.com","i.com","j.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
	})
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
