package middleware

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// mockAuthRepo implements auth.Repository for testing.
type mockAuthRepo struct {
	customer *auth.Customer
	err      error
}

func (m *mockAuthRepo) GetByKey(_ context.Context, _ string) (*auth.Customer, error) {
	return m.customer, m.err
}

func setupAuthRouter(repo auth.Repository, logLevel zapcore.Level) (*gin.Engine, *observer.ObservedLogs) {
	core, logs := observer.New(logLevel)
	logger := zap.New(core)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(APIKeyAuthWithLogger(repo, logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r, logs
}

func doAuthRequest(r *gin.Engine, apiKey string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestAPIKeyAuth_MissingKey(t *testing.T) {
	r, logs := setupAuthRouter(&mockAuthRepo{}, zapcore.WarnLevel)

	w := doAuthRequest(r, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "missing API key" {
		t.Errorf("error = %q, want %q", body["error"], "missing API key")
	}

	if logs.Len() == 0 {
		t.Fatal("expected warn log")
	}
	if logs.All()[0].Message != "auth failed: missing API key" {
		t.Errorf("log message = %q, want %q", logs.All()[0].Message, "auth failed: missing API key")
	}
}

func TestAPIKeyAuth_InvalidKey_NoRows(t *testing.T) {
	repo := &mockAuthRepo{err: sql.ErrNoRows}
	r, logs := setupAuthRouter(repo, zapcore.WarnLevel)

	w := doAuthRequest(r, "bad-key")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "invalid API key" {
		t.Errorf("error = %q, want %q", body["error"], "invalid API key")
	}

	if logs.Len() == 0 {
		t.Fatal("expected warn log")
	}
	if logs.All()[0].Message != "auth failed: invalid API key" {
		t.Errorf("log message = %q, want %q", logs.All()[0].Message, "auth failed: invalid API key")
	}
}

func TestAPIKeyAuth_DatabaseError(t *testing.T) {
	repo := &mockAuthRepo{err: errors.New("connection refused")}
	r, logs := setupAuthRouter(repo, zapcore.WarnLevel)

	w := doAuthRequest(r, "some-key")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "internal error" {
		t.Errorf("error = %q, want %q", body["error"], "internal error")
	}

	if logs.Len() == 0 {
		t.Fatal("expected error log")
	}
	entry := logs.All()[0]
	if entry.Message != "auth failed: database error" {
		t.Errorf("log message = %q, want %q", entry.Message, "auth failed: database error")
	}
	if entry.Level != zapcore.ErrorLevel {
		t.Errorf("log level = %v, want Error", entry.Level)
	}
}

func TestAPIKeyAuth_Success_SetsContextValues(t *testing.T) {
	repo := &mockAuthRepo{
		customer: &auth.Customer{
			APIKeyID: 42,
			Plan:     "pro",
			Active:   true,
		},
	}

	core, _ := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	var gotKeyID int
	var gotPlan string

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(APIKeyAuthWithLogger(repo, logger))
	r.GET("/test", func(c *gin.Context) {
		if v, ok := c.Get("api_key_id"); ok {
			gotKeyID = v.(int)
		}
		if v, ok := c.Get("api_key_plan"); ok {
			gotPlan = v.(string)
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := doAuthRequest(r, "valid-key")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if gotKeyID != 42 {
		t.Errorf("api_key_id = %d, want 42", gotKeyID)
	}
	if gotPlan != "pro" {
		t.Errorf("api_key_plan = %q, want %q", gotPlan, "pro")
	}
}

func TestAPIKeyAuth_InactiveCustomer_Rejected(t *testing.T) {
	repo := &mockAuthRepo{
		customer: &auth.Customer{
			ID:       10,
			APIKeyID: 42,
			Plan:     "pro",
			Active:   false,
		},
	}
	r, logs := setupAuthRouter(repo, zapcore.WarnLevel)

	w := doAuthRequest(r, "valid-but-inactive")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "account inactive" {
		t.Errorf("error = %q, want %q", body["error"], "account inactive")
	}

	if logs.Len() == 0 {
		t.Fatal("expected warn log")
	}
	if logs.All()[0].Message != "auth failed: inactive account" {
		t.Errorf("log message = %q, want %q", logs.All()[0].Message, "auth failed: inactive account")
	}
}

// --- RequireAdmin tests ---

func setupAdminRouter(plan string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if plan != "" {
		r.Use(func(c *gin.Context) {
			c.Set("api_key_plan", plan)
			c.Next()
		})
	}
	r.Use(RequireAdmin())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRequireAdmin_AdminAllowed(t *testing.T) {
	r := setupAdminRouter("admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireAdmin_ProForbidden(t *testing.T) {
	r := setupAdminRouter("pro")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "insufficient permissions" {
		t.Errorf("error = %q, want %q", body["error"], "insufficient permissions")
	}
}

// An unrecognized plan must not reach admin routes. Plans are validated where
// they are set, so this only happens with a hand-edited row, which is exactly
// the case where failing closed matters.
func TestRequireAdmin_UnknownPlanForbidden(t *testing.T) {
	r := setupAdminRouter("unknown")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestRequireAdmin_MissingPlanForbidden(t *testing.T) {
	r := setupAdminRouter("")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}
