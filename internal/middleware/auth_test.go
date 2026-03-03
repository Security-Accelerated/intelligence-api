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
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
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
			Features: []string{"admin", "domain"},
			Tier:     "premium",
		},
	}

	core, _ := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	var gotKeyID int
	var gotFeatures []string
	var gotTier string

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(APIKeyAuthWithLogger(repo, logger))
	r.GET("/test", func(c *gin.Context) {
		if v, ok := c.Get("api_key_id"); ok {
			gotKeyID = v.(int)
		}
		if v, ok := c.Get("api_key_features"); ok {
			gotFeatures = v.([]string)
		}
		if v, ok := c.Get("api_key_tier"); ok {
			gotTier = v.(string)
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
	if len(gotFeatures) != 2 || gotFeatures[0] != "admin" || gotFeatures[1] != "domain" {
		t.Errorf("api_key_features = %v, want [admin domain]", gotFeatures)
	}
	if gotTier != "premium" {
		t.Errorf("api_key_tier = %q, want %q", gotTier, "premium")
	}
}

// --- RequireFeatures tests ---

func setupFeaturesRouter(roles []string, allowed ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if roles != nil {
		r.Use(func(c *gin.Context) {
			c.Set("api_key_features", roles)
			c.Next()
		})
	}
	r.Use(RequireFeatures(allowed...))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRequireFeatures_MatchingRole(t *testing.T) {
	r := setupFeaturesRouter([]string{"admin", "domain"}, "domain", "billing")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireFeatures_NoMatchingRole(t *testing.T) {
	r := setupFeaturesRouter([]string{"viewer"}, "admin", "domain")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
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

func TestRequireFeatures_EmptyRoles(t *testing.T) {
	r := setupFeaturesRouter([]string{}, "admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestRequireFeatures_MissingRolesContext(t *testing.T) {
	// Pass nil to skip setting roles on context at all
	r := setupFeaturesRouter(nil, "admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}
