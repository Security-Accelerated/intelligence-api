package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

type mockFingerprintService struct {
	rules []domain.TechRule
	err   error
}

func (m *mockFingerprintService) GetRules() []domain.TechRule {
	return m.rules
}

func (m *mockFingerprintService) UpdateRules(_ context.Context, rules []domain.TechRule, _ int) error {
	if m.err != nil {
		return m.err
	}
	m.rules = rules
	return nil
}

func newFingerprintRouter(fpSvc FingerprintAdminService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, fpSvc, nil, nil, "test", nil, nil, nil)

	admin := r.Group("/v1/admin")
	admin.Use(func(c *gin.Context) {
		c.Set("api_key_plan", "admin")
		c.Set("api_key_id", 100)
		c.Next()
	})
	admin.GET("/fingerprints", h.GetFingerprints)
	admin.POST("/fingerprints", h.UpdateFingerprints)

	return r
}

func TestGetFingerprints_ReturnsRules(t *testing.T) {
	fpSvc := &mockFingerprintService{
		rules: []domain.TechRule{
			{Name: "Nginx", Category: "web-server"},
			{Name: "PHP", Category: "language"},
		},
	}
	r := newFingerprintRouter(fpSvc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/fingerprints", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body struct {
		Count int               `json:"count"`
		Rules []domain.TechRule `json:"rules"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Count != 2 {
		t.Errorf("count = %d, want 2", body.Count)
	}
	if len(body.Rules) != 2 {
		t.Errorf("len(rules) = %d, want 2", len(body.Rules))
	}
}

func TestGetFingerprints_EmptyRules(t *testing.T) {
	fpSvc := &mockFingerprintService{}
	r := newFingerprintRouter(fpSvc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/fingerprints", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body struct {
		Count int `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Count != 0 {
		t.Errorf("count = %d, want 0", body.Count)
	}
}

func TestUpdateFingerprints_Success(t *testing.T) {
	fpSvc := &mockFingerprintService{}
	r := newFingerprintRouter(fpSvc)

	w := httptest.NewRecorder()
	body := `[{"name":"Nginx","category":"web-server","headers":{"Server":"nginx"}}]`
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/fingerprints", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp struct {
		Message string `json:"message"`
		Count   int    `json:"count"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 1 {
		t.Errorf("count = %d, want 1", resp.Count)
	}
	if resp.Message != "fingerprint rules updated" {
		t.Errorf("message = %q, want %q", resp.Message, "fingerprint rules updated")
	}
}

func TestUpdateFingerprints_InvalidBody(t *testing.T) {
	fpSvc := &mockFingerprintService{}
	r := newFingerprintRouter(fpSvc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/fingerprints", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestUpdateFingerprints_EmptyArray(t *testing.T) {
	fpSvc := &mockFingerprintService{}
	r := newFingerprintRouter(fpSvc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/fingerprints", strings.NewReader(`[]`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestUpdateFingerprints_ServiceError(t *testing.T) {
	fpSvc := &mockFingerprintService{
		err: errors.New("rule 0: name is required"),
	}
	r := newFingerprintRouter(fpSvc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/fingerprints",
		strings.NewReader(`[{"name":"","category":"web-server"}]`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}
