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
