package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type mockKeyRotator struct {
	rawKey         string
	expiry         time.Time
	err            error
	lastCustomerID int
}

func (m *mockKeyRotator) Rotate(_ context.Context, customerID int) (string, time.Time, error) {
	m.lastCustomerID = customerID
	return m.rawKey, m.expiry, m.err
}

func newKeysRouter(svc KeyRotationService, customerID any) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, nil, nil, nil, svc, nil, nil, nil, nil, nil, nil)
	r.POST("/v1/keys/rotate", func(c *gin.Context) {
		if customerID != nil {
			c.Set("customer_id", customerID)
		}
		c.Next()
	}, h.RotateKey)
	return r
}

func doRotateRequest(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/keys/rotate", nil)
	r.ServeHTTP(w, req)
	return w
}

func TestRotateKey_Success(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	mk := &mockKeyRotator{rawKey: "abc123", expiry: expiry}
	w := doRotateRequest(newKeysRouter(mk, 42))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if mk.lastCustomerID != 42 {
		t.Errorf("customerID = %d, want 42 (from auth context)", mk.lastCustomerID)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["api_key"] != "abc123" {
		t.Errorf("api_key = %v, want abc123", body["api_key"])
	}
	if body["old_keys_expire_at"] == nil {
		t.Error("expected old_keys_expire_at in response")
	}
}

func TestRotateKey_MissingAuthContext(t *testing.T) {
	w := doRotateRequest(newKeysRouter(&mockKeyRotator{}, nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRotateKey_ServiceError(t *testing.T) {
	mk := &mockKeyRotator{err: errors.New("db down")}
	w := doRotateRequest(newKeysRouter(mk, 42))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if got := w.Body.String(); got != `{"error":"key rotation failed"}` {
		t.Errorf("body = %s (must not leak internals)", got)
	}
}

func TestRotateKey_NilService(t *testing.T) {
	w := doRotateRequest(newKeysRouter(nil, 42))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}
