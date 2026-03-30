package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func docsRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h.RegisterRoutes(r)
	return r
}

func TestDocs_RootRedirectsToDocs(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusMovedPermanently)
	}
	loc := w.Header().Get("Location")
	if loc != "/docs" {
		t.Errorf("Location = %q, want /docs", loc)
	}
}

func TestDocs_LandingPage(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Domain Intelligence") {
		t.Error("expected landing page to mention Domain Intelligence")
	}
	if !strings.Contains(body, "IP Intelligence") {
		t.Error("expected landing page to mention IP Intelligence")
	}
}

func TestDocs_DomainPage(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/domain", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Domain Intelligence") {
		t.Error("expected domain page content")
	}
}

func TestDocs_IPPage(t *testing.T) {
	r := docsRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/ip", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "IP Intelligence") {
		t.Error("expected IP page content")
	}
}
