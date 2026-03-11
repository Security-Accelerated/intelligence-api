package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func newObserverLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.InfoLevel)
	return zap.New(core), logs
}

func TestRequestLogger_BasicFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	entry := entries[0]

	wantFields := map[string]bool{
		"request_id": true,
		"method":     true,
		"path":       true,
		"status":     true,
		"latency":    true,
		"client_ip":  true,
		"user_agent": true,
	}
	fieldMap := make(map[string]zap.Field, len(entry.Context))
	for _, f := range entry.Context {
		fieldMap[f.Key] = f
	}
	for key := range wantFields {
		if _, ok := fieldMap[key]; !ok {
			t.Errorf("missing expected log field %q", key)
		}
	}
	if fieldMap["method"].String != "GET" {
		t.Errorf("method = %q, want %q", fieldMap["method"].String, "GET")
	}
	if fieldMap["path"].String != "/test" {
		t.Errorf("path = %q, want %q", fieldMap["path"].String, "/test")
	}
	if fieldMap["user_agent"].String != "test-agent" {
		t.Errorf("user_agent = %q, want %q", fieldMap["user_agent"].String, "test-agent")
	}

	// request_id should be a non-empty UUID in both the log and response header
	logID := fieldMap["request_id"].String
	if logID == "" {
		t.Fatal("request_id log field is empty")
	}
	headerID := w.Header().Get("X-Request-ID")
	if headerID == "" {
		t.Fatal("X-Request-ID response header is empty")
	}
	if logID != headerID {
		t.Errorf("request_id mismatch: log=%q, header=%q", logID, headerID)
	}
}

func TestRequestLogger_AuthFieldsPresent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		c.Set("api_key_id", 42)
		c.Set("api_key_plan", "pro")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	entry := logs.All()[0]
	fieldMap := make(map[string]zap.Field, len(entry.Context))
	for _, f := range entry.Context {
		fieldMap[f.Key] = f
	}

	if f, ok := fieldMap["api_key_id"]; !ok {
		t.Error("api_key_id not found in log entry")
	} else if f.Integer != 42 {
		t.Errorf("api_key_id = %d, want 42", f.Integer)
	}

	if f, ok := fieldMap["api_key_plan"]; !ok {
		t.Error("api_key_plan not found in log entry")
	} else if f.String != "pro" {
		t.Errorf("api_key_plan = %q, want %q", f.String, "pro")
	}
}

func TestRequestLogger_AuthFieldsAbsent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	absent := []string{"api_key_id", "api_key_plan"}
	entry := logs.All()[0]
	for _, f := range entry.Context {
		for _, key := range absent {
			if f.Key == key {
				t.Errorf("%s should not appear when not set", key)
			}
		}
	}
}

func TestRequestLogger_ContextKeysPresent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		for _, key := range ContextKeys {
			c.Set(key, true)
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	entry := logs.All()[0]
	fieldMap := make(map[string]zap.Field, len(entry.Context))
	for _, f := range entry.Context {
		fieldMap[f.Key] = f
	}

	for _, key := range ContextKeys {
		f, ok := fieldMap[key]
		if !ok {
			t.Errorf("context key %q not found in log entry", key)
			continue
		}
		if f.Integer != 1 { // zap encodes true as 1
			t.Errorf("context key %q = %v, want true", key, f.Integer)
		}
	}
}

func TestRequestLogger_IntContextKeysPresent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		c.Set("rate_limit", 120)
		c.Set("rate_limit_remaining", 95)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	entry := logs.All()[0]
	fieldMap := make(map[string]zap.Field, len(entry.Context))
	for _, f := range entry.Context {
		fieldMap[f.Key] = f
	}

	if f, ok := fieldMap["rate_limit"]; !ok {
		t.Error("rate_limit not found in log entry")
	} else if f.Integer != 120 {
		t.Errorf("rate_limit = %d, want 120", f.Integer)
	}

	if f, ok := fieldMap["rate_limit_remaining"]; !ok {
		t.Error("rate_limit_remaining not found in log entry")
	} else if f.Integer != 95 {
		t.Errorf("rate_limit_remaining = %d, want 95", f.Integer)
	}
}

func TestRequestLogger_IntContextKeysAbsent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	entry := logs.All()[0]
	for _, f := range entry.Context {
		for _, key := range IntContextKeys {
			if f.Key == key {
				t.Errorf("%s should not appear when not set", key)
			}
		}
	}
}

func TestRequestLogger_StringContextKeysPresent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		c.Set("client_request_id", "req-abc-123")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	entry := logs.All()[0]
	fieldMap := make(map[string]zap.Field, len(entry.Context))
	for _, f := range entry.Context {
		fieldMap[f.Key] = f
	}

	if f, ok := fieldMap["client_request_id"]; !ok {
		t.Error("client_request_id not found in log entry")
	} else if f.String != "req-abc-123" {
		t.Errorf("client_request_id = %q, want %q", f.String, "req-abc-123")
	}
}

func TestRequestLogger_StringContextKeysAbsent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	entry := logs.All()[0]
	for _, f := range entry.Context {
		for _, key := range StringContextKeys {
			if f.Key == key {
				t.Errorf("%s should not appear when not set", key)
			}
		}
	}
}

func TestRequestLogger_ContextKeysAbsent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObserverLogger()

	r := gin.New()
	r.Use(RequestLoggerWithLogger(logger))
	r.GET("/test", func(c *gin.Context) {
		// No context keys set.
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	entry := logs.All()[0]
	fieldMap := make(map[string]zap.Field, len(entry.Context))
	for _, f := range entry.Context {
		fieldMap[f.Key] = f
	}

	for _, key := range ContextKeys {
		if _, ok := fieldMap[key]; ok {
			t.Errorf("context key %q should not appear in log when not set", key)
		}
	}
}
