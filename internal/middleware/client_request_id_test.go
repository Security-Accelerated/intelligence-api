package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestClientRequestID_Valid(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name  string
		value string
	}{
		{"uuid", "550e8400-e29b-41d4-a716-446655440000"},
		{"short", "req-123"},
		{"alphanumeric", "abc123XYZ"},
		{"with_dots_colons", "trace:abc.def_ghi-123"},
		{"max_length", strings.Repeat("a", 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctxVal string
			r := gin.New()
			r.Use(ClientRequestID())
			r.GET("/test", func(c *gin.Context) {
				if v, ok := c.Get(ClientRequestIDKey); ok {
					ctxVal = v.(string)
				}
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set(ClientRequestIDHeader, tt.value)
			r.ServeHTTP(w, req)

			if ctxVal != tt.value {
				t.Errorf("context value = %q, want %q", ctxVal, tt.value)
			}
			if got := w.Header().Get(ClientRequestIDHeader); got != tt.value {
				t.Errorf("response header = %q, want %q", got, tt.value)
			}
		})
	}
}

func TestClientRequestID_StripsWhitespace(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var ctxVal string
	r := gin.New()
	r.Use(ClientRequestID())
	r.GET("/test", func(c *gin.Context) {
		if v, ok := c.Get(ClientRequestIDKey); ok {
			ctxVal = v.(string)
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(ClientRequestIDHeader, "  req-123  ")
	r.ServeHTTP(w, req)

	if ctxVal != "req-123" {
		t.Errorf("context value = %q, want %q", ctxVal, "req-123")
	}
	if got := w.Header().Get(ClientRequestIDHeader); got != "req-123" {
		t.Errorf("response header = %q, want %q", got, "req-123")
	}
}

func TestClientRequestID_Ignored(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"too_long", strings.Repeat("x", 65)},
		{"spaces_only", "   "},
		{"contains_slash", "req/123"},
		{"contains_semicolon", "req;drop"},
		{"contains_newline", "req\n123"},
		{"contains_angle_bracket", "req<script>"},
		{"contains_backslash", `req\123`},
		{"contains_space_mid", "req 123"},
		{"contains_percent", "req%20id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var found bool
			r := gin.New()
			r.Use(ClientRequestID())
			r.GET("/test", func(c *gin.Context) {
				_, found = c.Get(ClientRequestIDKey)
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set(ClientRequestIDHeader, tt.value)
			r.ServeHTTP(w, req)

			if found {
				t.Errorf("context key should not be set for %q", tt.name)
			}
			if got := w.Header().Get(ClientRequestIDHeader); got != "" {
				t.Errorf("response header should be empty for %q, got %q", tt.name, got)
			}
		})
	}
}

func TestClientRequestID_Missing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var found bool
	r := gin.New()
	r.Use(ClientRequestID())
	r.GET("/test", func(c *gin.Context) {
		_, found = c.Get(ClientRequestIDKey)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if found {
		t.Error("context key should not be set when header is missing")
	}
	if got := w.Header().Get(ClientRequestIDHeader); got != "" {
		t.Errorf("response header should be empty, got %q", got)
	}
}

// TestClientRequestID_SurvivesAbortedResponses pins the behaviour the OpenAPI
// spec publishes: both correlation headers are present on failures, not just on
// success.
//
// This holds because ClientRequestID and RequestLogger write their headers on
// the way in, before any later middleware or handler can abort. Moving either
// below the auth or rate limit stage would silently strip correlation from
// exactly the responses a caller most needs to trace, and no other test would
// notice — the success path would still look perfect.
func TestClientRequestID_SurvivesAbortedResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, code := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			r := gin.New()
			r.Use(ClientRequestID())
			r.Use(RequestLoggerWithLogger(zap.NewNop()))
			r.GET("/", func(c *gin.Context) {
				c.AbortWithStatusJSON(code, gin.H{"error": "failed"})
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(ClientRequestIDHeader, "req-001")
			r.ServeHTTP(w, req)

			if w.Code != code {
				t.Fatalf("status = %d, want %d", w.Code, code)
			}
			if got := w.Header().Get(ClientRequestIDHeader); got != "req-001" {
				t.Errorf("%s = %q, want it echoed on a %d", ClientRequestIDHeader, got, code)
			}
			if w.Header().Get("X-Request-ID") == "" {
				t.Errorf("X-Request-ID missing on a %d; the spec declares it on every response", code)
			}
		})
	}
}
