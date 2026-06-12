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

// assertErrorBody checks that the response body contains a JSON "error" key.
func assertErrorBody(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error field in response body")
	}
}

// filterKeys returns the subset of middleware.ContextKeys whose base name
// (before "_requested") appears in the keep list. cache_hit is always kept.
func filterKeys(keep ...string) []string {
	set := make(map[string]struct{}, len(keep))
	for _, k := range keep {
		set[k] = struct{}{}
	}
	var out []string
	for _, key := range middleware.ContextKeys {
		base := strings.TrimSuffix(key, "_requested")
		if _, ok := set[base]; ok {
			out = append(out, key)
		}
	}
	return out
}

func newTestRouter(svc DomainLookupService) *gin.Engine {
	return newTestRouterWithPlan(svc, "pro")
}

func newTestRouterWithPlan(svc DomainLookupService, plan string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(svc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterRoutes(r)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

func TestDomainLookup_ValidDomain(t *testing.T) {
	r := newTestRouter(&mockService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
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

func TestDomainLookup_NoService(t *testing.T) {
	r := newTestRouter(nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestDomainLookup_MultipleDomains(t *testing.T) {
	r := newTestRouter(&mockService{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com","example.org"]}`))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com","notadomain","example.org"]}`))
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

	if resp[0].Domain != "example.com" {
		t.Errorf("resp[0].Domain = %q, want %q", resp[0].Domain, "example.com")
	}
	if len(resp[0].Errors) != 0 {
		t.Errorf("resp[0].Errors = %v, want none", resp[0].Errors)
	}

	if resp[1].Domain != "notadomain" {
		t.Errorf("resp[1].Domain = %q, want %q", resp[1].Domain, "notadomain")
	}
	if len(resp[1].Errors) != 1 || resp[1].Errors[0].Lookup != "validation" {
		t.Errorf("resp[1].Errors = %v, want validation error", resp[1].Errors)
	}

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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["cached.com"]}`))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":[]}`))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["localhost"]}`))
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
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["169.254.169.254"]}`))
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
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["example.com","10.0.0.1"]}`))
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
			req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(tt.input))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(`{"domains":["  example.com  "]}`))
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
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{"plain domain", "example.com", "example.com", true},
		{"https prefix", "https://example.com", "example.com", true},
		{"http prefix", "http://example.com", "example.com", true},
		{"trailing slash", "example.com/", "example.com", true},
		{"mixed case", "Example.COM", "example.com", true},
		{"whitespace", "  example.com  ", "example.com", true},
		{"path extracted", "https://example.com/foo/bar", "example.com", true},
		{"port extracted", "example.com:8080", "example.com", true},
		{"query string extracted", "example.com?q=1", "example.com", true},
		{"fragment extracted", "example.com#section", "example.com", true},
		{"userinfo extracted", "user@example.com", "example.com", true},
		{"full url extracted", "https://user:pass@example.com:443/path?q=1#frag", "example.com", true},
		{"ftp scheme stripped", "ftp://example.com", "example.com", true},
		{"ssh scheme stripped", "ssh://example.com", "example.com", true},
		{"double scheme stripped", "https://https://example.com", "example.com", true},
		{"path at-sign not userinfo", "https://example.com/path@evil.com", "example.com", true},
		{"full compound", "https://user:pass@example.com:443/path@evil.com?q=1#frag", "example.com", true},
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

// --- Plan gating ---

func TestDomainLookup_Reputation_ProAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "pro")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_Reputation_AdminAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_Reputation_FreeForbidden(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "free")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "reputation requires a pro plan" {
		t.Errorf("error = %q, want %q", body["error"], "reputation requires a pro plan")
	}
}

func TestDomainLookup_Reputation_BasicForbidden(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"reputation":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "reputation requires a pro plan" {
		t.Errorf("error = %q, want %q", body["error"], "reputation requires a pro plan")
	}
}

func TestDomainLookup_Screenshot_AdminAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_Screenshot_ProAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "pro")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_Screenshot_FreeForbidden(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "free")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "screenshot requires a pro plan" {
		t.Errorf("error = %q, want %q", body["error"], "screenshot requires a pro plan")
	}
}

func TestDomainLookup_Screenshot_BasicForbidden(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"screenshot":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "screenshot requires a pro plan" {
		t.Errorf("error = %q, want %q", body["error"], "screenshot requires a pro plan")
	}
}

func TestDomainLookup_OptsPassedToService(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		wantScreenshot    bool
		wantReputation    bool
		wantEmailSecurity bool
		wantSubdomains    bool
		wantCTLogs        bool
		wantBGP           bool
		wantFingerprint   bool
		wantThreatIntel   bool
	}{
		{"no opts", `{"domains":["example.com"]}`, false, false, false, false, false, false, false, false},
		{"screenshot only", `{"domains":["example.com"],"screenshot":true}`, true, false, false, false, false, false, false, false},
		{"reputation only", `{"domains":["example.com"],"reputation":true}`, false, true, false, false, false, false, false, false},
		{"email_security only", `{"domains":["example.com"],"email_security":true}`, false, false, true, false, false, false, false, false},
		{"subdomains only", `{"domains":["example.com"],"subdomains":true}`, false, false, false, true, false, false, false, false},
		{"ct_logs only", `{"domains":["example.com"],"ct_logs":true}`, false, false, false, false, true, false, false, false},
		{"bgp only", `{"domains":["example.com"],"bgp":true}`, false, false, false, false, false, true, false, false},
		{"fingerprint only", `{"domains":["example.com"],"fingerprint":true}`, false, false, false, false, false, false, true, false},
		{"threat_intel only", `{"domains":["example.com"],"threat_intel":true}`, false, false, false, false, false, false, false, true},
		{"all", `{"domains":["example.com"],"screenshot":true,"reputation":true,"email_security":true,"subdomains":true,"ct_logs":true,"bgp":true,"fingerprint":true,"threat_intel":true}`, true, true, true, true, true, true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockService{}
			r := newTestRouter(svc)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(tt.body))
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
			if svc.lastOpts.EmailSecurity != tt.wantEmailSecurity {
				t.Errorf("opts.EmailSecurity = %v, want %v", svc.lastOpts.EmailSecurity, tt.wantEmailSecurity)
			}
			if svc.lastOpts.Subdomains != tt.wantSubdomains {
				t.Errorf("opts.Subdomains = %v, want %v", svc.lastOpts.Subdomains, tt.wantSubdomains)
			}
			if svc.lastOpts.CTLogs != tt.wantCTLogs {
				t.Errorf("opts.CTLogs = %v, want %v", svc.lastOpts.CTLogs, tt.wantCTLogs)
			}
			if svc.lastOpts.BGP != tt.wantBGP {
				t.Errorf("opts.BGP = %v, want %v", svc.lastOpts.BGP, tt.wantBGP)
			}
			if svc.lastOpts.Fingerprint != tt.wantFingerprint {
				t.Errorf("opts.Fingerprint = %v, want %v", svc.lastOpts.Fingerprint, tt.wantFingerprint)
			}
			if svc.lastOpts.ThreatIntel != tt.wantThreatIntel {
				t.Errorf("opts.ThreatIntel = %v, want %v", svc.lastOpts.ThreatIntel, tt.wantThreatIntel)
			}
		})
	}
}

// domainLoggerKeys derived from middleware.ContextKeys.
var domainLoggerKeys = filterKeys("screenshot", "reputation", "email_security", "subdomain", "cache_hit", "ct_logs", "bgp", "fingerprint", "threat_intel")

func TestDomainLookup_SetsLoggerContextKeys(t *testing.T) {
	tests := []struct {
		name string
		body string
		want map[string]bool
	}{
		{
			"no optional features",
			`{"domains":["example.com"]}`,
			map[string]bool{"screenshot_requested": false, "reputation_requested": false, "email_security_requested": false, "subdomain_requested": false, "ct_logs_requested": false, "bgp_requested": false, "fingerprint_requested": false, "threat_intel_requested": false, "cache_hit": false},
		},
		{
			"all optional features",
			`{"domains":["example.com"],"screenshot":true,"reputation":true,"email_security":true,"subdomains":true,"ct_logs":true,"bgp":true,"fingerprint":true,"threat_intel":true}`,
			map[string]bool{"screenshot_requested": true, "reputation_requested": true, "email_security_requested": true, "subdomain_requested": true, "ct_logs_requested": true, "bgp_requested": true, "fingerprint_requested": true, "threat_intel_requested": true, "cache_hit": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockService{}
			gin.SetMode(gin.TestMode)
			r := gin.New()
			h := New(svc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

			captured := make(map[string]any)
			auth := func(c *gin.Context) {
				c.Set("api_key_plan", "admin")
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
			req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(tt.body))
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

func newTestRouterWithCfg(svc DomainLookupService, plan string, cfg *viper.Viper) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(svc, nil, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", plan)
		c.Next()
	})
	return r
}

func TestDomainLookup_MaxDomains_ExceedsLimit(t *testing.T) {
	cfg := testCfg(map[string]any{
		"domain.max_domains.basic": 2,
		"domain.max_domains.pro":   3,
	})

	t.Run("basic plan over limit", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "basic", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
			strings.NewReader(`{"domains":["a.com","b.com","c.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
		}
		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["error"] != "too many domains: maximum 2 allowed for basic plan" {
			t.Errorf("error = %q", body["error"])
		}
	})

	t.Run("pro plan over limit", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "pro", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
			strings.NewReader(`{"domains":["a.com","b.com","c.com","d.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
		}
		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["error"] != "too many domains: maximum 3 allowed for pro plan" {
			t.Errorf("error = %q", body["error"])
		}
	})

	t.Run("pro plan at limit succeeds", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "pro", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
			strings.NewReader(`{"domains":["a.com","b.com","c.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
	})

	t.Run("admin plan has no limit", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "admin", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
			strings.NewReader(`{"domains":["a.com","b.com","c.com","d.com","e.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
	})

	t.Run("nil config means no limit", func(t *testing.T) {
		r := newTestRouterWithPlan(&mockService{}, "basic")
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
			strings.NewReader(`{"domains":["a.com","b.com","c.com","d.com","e.com","f.com","g.com","h.com","i.com","j.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
	})
}

func TestDomainLookup_MaxDomains_FreePlanLimit(t *testing.T) {
	cfg := testCfg(map[string]any{
		"domain.max_domains.free":  1,
		"domain.max_domains.basic": 5,
	})

	t.Run("free plan over limit", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "free", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
			strings.NewReader(`{"domains":["a.com","b.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
		}
		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["error"] != "too many domains: maximum 1 allowed for free plan" {
			t.Errorf("error = %q", body["error"])
		}
	})

	t.Run("free plan at limit succeeds", func(t *testing.T) {
		r := newTestRouterWithCfg(&mockService{}, "free", cfg)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
			strings.NewReader(`{"domains":["a.com"]}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
	})
}

func TestDomainLookup_EmailSecurity_AllPlansAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"email_security":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_Reputation_AbsentWhenNotRequested(t *testing.T) {
	svc := &mockService{
		resp: &domain.DomainResponse{Domain: "example.com"},
	}
	r := newTestRouter(svc)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
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

func TestDomainLookup_CTLogs_AllPlansAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"ct_logs":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_BGP_AllPlansAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"bgp":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_Fingerprint_AllPlansAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"fingerprint":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_ThreatIntel_ProAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "pro")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_ThreatIntel_AdminAllowed(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestDomainLookup_ThreatIntel_FreeForbidden(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "free")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "threat_intel requires a pro plan" {
		t.Errorf("error = %q, want %q", body["error"], "threat_intel requires a pro plan")
	}
}

func TestDomainLookup_ThreatIntel_BasicForbidden(t *testing.T) {
	r := newTestRouterWithPlan(&mockService{}, "basic")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup",
		strings.NewReader(`{"domains":["example.com"],"threat_intel":true}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "threat_intel requires a pro plan" {
		t.Errorf("error = %q, want %q", body["error"], "threat_intel requires a pro plan")
	}
}

// --- Body limit 413 ---

func TestDomainLookup_OversizedBody_Returns413(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.BodyLimit(128)) // small limit for testing
	h := New(&mockService{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_plan", "pro")
		c.Next()
	})

	w := httptest.NewRecorder()
	oversized := `{"domains":["` + strings.Repeat("example.com,", 50) + `example.com"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/domain/lookup", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	// Remove Content-Length to force the MaxBytesReader path (not the early reject)
	req.ContentLength = -1
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "request body too large" {
		t.Errorf("error = %q, want %q", body["error"], "request body too large")
	}
}
