package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/usage"
)

type mockUsageQueryer struct {
	summary        *usage.UsageSummary
	err            error
	lastCustomerID int
	lastAPIKeyID   int
}

func (m *mockUsageQueryer) QueryUsage(customerID, apiKeyID int, since, until time.Time) (*usage.UsageSummary, error) {
	m.lastCustomerID = customerID
	m.lastAPIKeyID = apiKeyID
	return m.summary, m.err
}

func newUsageRouter(uq usage.Queryer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, nil, nil, uq, nil, nil, nil, nil, nil, nil, nil)
	admin := r.Group("/v1/admin")
	admin.Use(func(c *gin.Context) {
		c.Set("api_key_plan", "admin")
		c.Next()
	})
	admin.GET("/usage", h.GetUsage)
	return r
}

func TestGetUsage_DefaultDays(t *testing.T) {
	summary := &usage.UsageSummary{
		TotalRequests:  100,
		CacheHits:      25,
		CacheHitRate:   25.0,
		AvgLatencyMs:   500.0,
		TotalDomains:   150,
		StatusCodes:    map[string]int{"200": 90, "400": 10},
		FeatureUsage:   map[string]int{"screenshot": 5},
		RequestsByPath: map[string]int{"/v1/domain/lookup": 95},
		PeriodStart:    time.Now().AddDate(0, 0, -30),
		PeriodEnd:      time.Now(),
	}
	r := newUsageRouter(&mockUsageQueryer{summary: summary})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp usage.UsageSummary
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TotalRequests != 100 {
		t.Errorf("TotalRequests = %d, want 100", resp.TotalRequests)
	}
	if resp.CacheHits != 25 {
		t.Errorf("CacheHits = %d, want 25", resp.CacheHits)
	}
}

func TestGetUsage_CustomDays(t *testing.T) {
	r := newUsageRouter(&mockUsageQueryer{summary: &usage.UsageSummary{
		StatusCodes:    map[string]int{},
		FeatureUsage:   map[string]int{},
		RequestsByPath: map[string]int{},
	}})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage?days=7", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestGetUsage_InvalidDays(t *testing.T) {
	r := newUsageRouter(&mockUsageQueryer{})

	for _, d := range []string{"0", "-1", "366", "abc"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage?days="+d, nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("days=%s: status = %d, want %d", d, w.Code, http.StatusBadRequest)
		}
	}
}

func TestGetUsage_ServiceError(t *testing.T) {
	r := newUsageRouter(&mockUsageQueryer{err: errors.New("db down")})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestGetUsage_NilService(t *testing.T) {
	r := newUsageRouter(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestGetUsage_InvalidCustomerID(t *testing.T) {
	r := newUsageRouter(&mockUsageQueryer{})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/usage?customer_id=abc", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// --- MyUsage (customer-facing) ---

func newMyUsageRouter(uq usage.Queryer, customerID any) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, nil, nil, uq, nil, nil, nil, nil, nil, nil, nil)
	r.GET("/v1/usage", func(c *gin.Context) {
		if customerID != nil {
			c.Set("customer_id", customerID)
		}
		c.Next()
	}, h.MyUsage)
	return r
}

func TestMyUsage_ScopedToAuthenticatedCustomer(t *testing.T) {
	mq := &mockUsageQueryer{summary: &usage.UsageSummary{TotalRequests: 7}}
	r := newMyUsageRouter(mq, 42)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/usage?days=7&customer_id=999&api_key_id=5", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// customer_id/api_key_id query params must be ignored — the filter comes
	// from the auth context only.
	if mq.lastCustomerID != 42 {
		t.Errorf("customerID = %d, want 42 (from auth context)", mq.lastCustomerID)
	}
	if mq.lastAPIKeyID != 0 {
		t.Errorf("apiKeyID = %d, want 0 (no key filter)", mq.lastAPIKeyID)
	}
}

func TestMyUsage_MissingAuthContext(t *testing.T) {
	r := newMyUsageRouter(&mockUsageQueryer{}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/usage", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestMyUsage_InvalidDays(t *testing.T) {
	r := newMyUsageRouter(&mockUsageQueryer{}, 42)

	for _, d := range []string{"0", "-1", "366", "abc"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/usage?days="+d, nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("days=%s: status = %d, want 400", d, w.Code)
		}
	}
}

func TestMyUsage_NilService(t *testing.T) {
	r := newMyUsageRouter(nil, 42)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/usage", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}
