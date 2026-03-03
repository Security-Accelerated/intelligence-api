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

type mockTyposquattingService struct {
	resp   *domain.TyposquattingResponse
	cached bool
}

func (m *mockTyposquattingService) Lookup(_ context.Context, domainName string, _ bool, depth string) (*domain.TyposquattingResponse, bool) {
	if m.resp != nil {
		return m.resp, m.cached
	}
	return &domain.TyposquattingResponse{
		Domain: domainName,
		Depth:  depth,
	}, m.cached
}

func newTyposquattingRouter(tier string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, &mockTyposquattingService{}, "test")
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_roles", []string{"admin"})
		if tier != "" {
			c.Set("api_key_tier", tier)
		}
		c.Next()
	})
	return r
}

func newTyposquattingRouterWithService(svc TyposquattingLookupService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, svc, "test")
	h.RegisterProtectedRoutes(r, func(c *gin.Context) {
		c.Set("api_key_roles", []string{"admin"})
		c.Set("api_key_tier", "premium")
		c.Next()
	})
	return r
}

func postTyposquatting(r *gin.Engine, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

// --- Tier gating ---

func TestTyposquattingLookup_PremiumTierAllowed(t *testing.T) {
	r := newTyposquattingRouter("premium")
	w := postTyposquatting(r, `{"domains":["example.com"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestTyposquattingLookup_BasicTierForbidden(t *testing.T) {
	r := newTyposquattingRouter("basic")
	w := postTyposquatting(r, `{"domains":["example.com"]}`)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestTyposquattingLookup_NoTierForbidden(t *testing.T) {
	r := newTyposquattingRouter("")
	w := postTyposquatting(r, `{"domains":["example.com"]}`)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- Input validation ---

func TestTyposquattingLookup_MissingBody(t *testing.T) {
	r := newTyposquattingRouter("premium")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting", nil)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestTyposquattingLookup_MalformedJSON(t *testing.T) {
	r := newTyposquattingRouter("premium")
	w := postTyposquatting(r, `{not json}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestTyposquattingLookup_EmptyDomainsArray(t *testing.T) {
	r := newTyposquattingRouter("premium")
	w := postTyposquatting(r, `{"domains":[]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestTyposquattingLookup_MissingDomainsField(t *testing.T) {
	r := newTyposquattingRouter("premium")
	w := postTyposquatting(r, `{"check_live":true}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// --- Depth validation ---

func TestTyposquattingLookup_InvalidDepth(t *testing.T) {
	r := newTyposquattingRouter("premium")
	w := postTyposquatting(r, `{"domains":["example.com"],"depth":"medium"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestTyposquattingLookup_EmptyDepthDefaultsShallow(t *testing.T) {
	r := newTyposquattingRouterWithService(&mockTyposquattingService{})
	w := postTyposquatting(r, `{"domains":["example.com"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.TyposquattingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("len(resp) = %d, want 1", len(resp))
	}
	if resp[0].Depth != "shallow" {
		t.Errorf("Depth = %q, want %q", resp[0].Depth, "shallow")
	}
}

func TestTyposquattingLookup_DeepDepthAccepted(t *testing.T) {
	r := newTyposquattingRouterWithService(&mockTyposquattingService{})
	w := postTyposquatting(r, `{"domains":["example.com"],"depth":"deep"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.TyposquattingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp[0].Depth != "deep" {
		t.Errorf("Depth = %q, want %q", resp[0].Depth, "deep")
	}
}

// --- Domain normalization ---

func TestTyposquattingLookup_StripsProtocolAndSlash(t *testing.T) {
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
			r := newTyposquattingRouterWithService(&mockTyposquattingService{})
			w := postTyposquatting(r, tt.input)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}

			var resp []*domain.TyposquattingResponse
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

// --- Single invalid domain ---

func TestTyposquattingLookup_SingleInvalidDomain(t *testing.T) {
	r := newTyposquattingRouter("premium")
	w := postTyposquatting(r, `{"domains":["localhost"]}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// --- Multi-domain ---

func TestTyposquattingLookup_MultipleDomains(t *testing.T) {
	r := newTyposquattingRouterWithService(&mockTyposquattingService{})
	w := postTyposquatting(r, `{"domains":["example.com","example.org"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
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

func TestTyposquattingLookup_MixedValidInvalid(t *testing.T) {
	r := newTyposquattingRouterWithService(&mockTyposquattingService{})
	w := postTyposquatting(r, `{"domains":["example.com","notadomain","example.org"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.TyposquattingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp) != 3 {
		t.Fatalf("len(resp) = %d, want 3", len(resp))
	}

	// First: valid
	if resp[0].Domain != "example.com" {
		t.Errorf("resp[0].Domain = %q, want %q", resp[0].Domain, "example.com")
	}
	if len(resp[0].Errors) != 0 {
		t.Errorf("resp[0].Errors = %v, want none", resp[0].Errors)
	}

	// Second: invalid, validation error
	if resp[1].Domain != "notadomain" {
		t.Errorf("resp[1].Domain = %q, want %q", resp[1].Domain, "notadomain")
	}
	if len(resp[1].Errors) != 1 || resp[1].Errors[0].Lookup != "validation" {
		t.Errorf("resp[1].Errors = %v, want validation error", resp[1].Errors)
	}

	// Third: valid
	if resp[2].Domain != "example.org" {
		t.Errorf("resp[2].Domain = %q, want %q", resp[2].Domain, "example.org")
	}
}

// --- Cache hit propagation ---

func TestTyposquattingLookup_CacheHitPopulated(t *testing.T) {
	svc := &mockTyposquattingService{
		resp: &domain.TyposquattingResponse{
			Domain: "cached.com",
			Depth:  "shallow",
		},
		cached: true,
	}
	r := newTyposquattingRouterWithService(svc)
	w := postTyposquatting(r, `{"domains":["cached.com"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.TyposquattingResponse
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

var typosquattingLoggerKeys = []string{"typosquatting_requested", "cache_hit"}

func TestTyposquattingLookup_SetsLoggerContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, &mockTyposquattingService{}, "test")

	captured := make(map[string]any)
	auth := func(c *gin.Context) {
		c.Set("api_key_roles", []string{"admin"})
		c.Set("api_key_tier", "premium")
		c.Next()
		for _, key := range typosquattingLoggerKeys {
			if v, exists := c.Get(key); exists {
				captured[key] = v
			}
		}
	}

	h.RegisterProtectedRoutes(r, auth)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain/typosquatting",
		strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	for _, key := range typosquattingLoggerKeys {
		if _, exists := captured[key]; !exists {
			t.Errorf("context key %q not set by handler (logger will silently skip it)", key)
		}
	}
}

func TestTyposquattingLookup_CacheMissFlagFalse(t *testing.T) {
	svc := &mockTyposquattingService{cached: false}
	r := newTyposquattingRouterWithService(svc)
	w := postTyposquatting(r, `{"domains":["fresh.com"]}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []*domain.TyposquattingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp[0].CacheHit {
		t.Errorf("CacheHit = true, want false")
	}
}
