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
	summary *usage.UsageSummary
	err     error
}

func (m *mockUsageQueryer) QueryUsage(customerID, apiKeyID int, since, until time.Time) (*usage.UsageSummary, error) {
	return m.summary, m.err
}

func newUsageRouter(uq usage.Queryer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, nil, uq, nil, nil, nil, nil, nil)
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
