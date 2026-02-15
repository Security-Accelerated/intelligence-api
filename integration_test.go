//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/cache"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/domain"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/handler"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/middleware"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/service"
)

func setupRouter(t *testing.T) (*gin.Engine, *miniredis.Miniredis) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	rc := cache.NewRedisCache(mr.Addr(), "", 0)

	svc := service.NewDomainService(rc, 5*time.Minute)
	// Replace real lookups with stubs so we don't hit the network.
	svc.SetLookups(
		func(_ context.Context, _ string) (*domain.WhoisInfo, error) {
			return &domain.WhoisInfo{DomainName: "example.com", Registrar: "Test Registrar"}, nil
		},
		func(_ context.Context, _ string) (*domain.DNSInfo, error) {
			return &domain.DNSInfo{A: []string{"93.184.216.34"}}, nil
		},
		func(_ context.Context, _ string) (*domain.SSLInfo, error) {
			return &domain.SSLInfo{Subject: "example.com", Issuer: "Test CA"}, nil
		},
		func(_ context.Context, _ string) (*domain.HeadersInfo, error) {
			return &domain.HeadersInfo{StatusCode: 200, Headers: map[string]string{"Server": "test"}}, nil
		},
	)

	r := gin.New()
	r.Use(middleware.RequestLogger())
	h := handler.New(svc, "test")
	h.RegisterRoutes(r)

	return r, mr
}

func TestIntegration_DomainLookup_FullFlow(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domain":"example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp domain.DomainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "example.com")
	}
	if resp.Whois == nil || resp.Whois.Registrar != "Test Registrar" {
		t.Errorf("Whois = %+v, want Registrar=Test Registrar", resp.Whois)
	}
	if resp.DNS == nil || len(resp.DNS.A) == 0 {
		t.Errorf("DNS.A = %v, want non-empty", resp.DNS)
	}
	if resp.SSL == nil || resp.SSL.Subject != "example.com" {
		t.Errorf("SSL = %+v, want Subject=example.com", resp.SSL)
	}
	if resp.Headers == nil || resp.Headers.StatusCode != 200 {
		t.Errorf("Headers = %+v, want StatusCode=200", resp.Headers)
	}
	if len(resp.Errors) != 0 {
		t.Errorf("Errors = %v, want none", resp.Errors)
	}
}

func TestIntegration_DomainLookup_CacheRoundTrip(t *testing.T) {
	r, _ := setupRouter(t)

	body := `{"domain":"example.com"}`

	// First request — cache miss, populates cache.
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want %d", w1.Code, http.StatusOK)
	}

	// Second request — should be served from cache with identical data.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("second request: status = %d, want %d", w2.Code, http.StatusOK)
	}

	var resp1, resp2 domain.DomainResponse
	json.Unmarshal(w1.Body.Bytes(), &resp1)
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	if resp1.Domain != resp2.Domain {
		t.Errorf("Domain mismatch: %q vs %q", resp1.Domain, resp2.Domain)
	}
	if resp2.Whois == nil || resp2.Whois.Registrar != "Test Registrar" {
		t.Errorf("cached response Whois = %+v, want Registrar=Test Registrar", resp2.Whois)
	}
}

func TestIntegration_DomainLookup_InvalidDomain(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/domain", strings.NewReader(`{"domain":"notadomain"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIntegration_Hello(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hello", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["message"] != "hello world" {
		t.Errorf("message = %q, want %q", body["message"], "hello world")
	}
}
