package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBodyLimit_UnderLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BodyLimit(1024))
	r.POST("/test", func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload too large"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"len": len(body)})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("hello"))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestBodyLimit_OverLimit_MaxBytesReader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BodyLimit(10))
	r.POST("/test", func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload too large"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	body := strings.Repeat("x", 100)
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	// httptest.NewRequest sets Content-Length automatically, so this tests the
	// Content-Length early reject path
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestBodyLimit_ContentLength_EarlyReject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handlerCalled := false
	r := gin.New()
	r.Use(BodyLimit(10))
	r.POST("/test", func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	body := strings.Repeat("x", 100)
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
	if handlerCalled {
		t.Error("handler should not have been called for oversized Content-Length")
	}
	if !strings.Contains(w.Body.String(), "request body too large") {
		t.Errorf("body = %q, want error message containing 'request body too large'", w.Body.String())
	}
}
