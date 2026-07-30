package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

func openapiRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(Deps{})
	h.RegisterRoutes(r)
	return r
}

func TestOpenAPISpec_Endpoint(t *testing.T) {
	r := openapiRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/openapi.yaml", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/yaml") {
		t.Errorf("Content-Type = %q, want application/yaml", ct)
	}
	cc := w.Header().Get("Cache-Control")
	if cc != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=3600")
	}
}

func TestOpenAPISpec_ValidYAMLWithExpectedPaths(t *testing.T) {
	r := openapiRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/openapi.yaml", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var spec map[string]any
	if err := yaml.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatalf("body is not valid YAML: %v", err)
	}

	if v, _ := spec["openapi"].(string); v != "3.1.0" {
		t.Errorf("openapi version = %q, want 3.1.0", v)
	}

	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("spec has no paths object")
	}
	for _, want := range []string{
		"/v1/domain/lookup",
		"/v1/ip/lookup",
		"/v1/usage",
		"/v1/keys/rotate",
	} {
		if _, ok := paths[want]; !ok {
			t.Errorf("expected path %q in spec", want)
		}
	}

	// Internal/admin surfaces must not be documented.
	for _, forbidden := range []string{
		"/v1/hello",
		"/v1/health",
		"/v1/info",
		"/v1/admin/changelog",
		"/v1/admin/usage",
		"/billing/webhook",
	} {
		if _, ok := paths[forbidden]; ok {
			t.Errorf("path %q must not appear in the public spec", forbidden)
		}
	}
}

func TestOpenAPISpec_SecuritySchemeHeader(t *testing.T) {
	r := openapiRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/openapi.yaml", nil)
	r.ServeHTTP(w, req)

	var spec struct {
		Components struct {
			SecuritySchemes map[string]struct {
				Type string `yaml:"type"`
				In   string `yaml:"in"`
				Name string `yaml:"name"`
			} `yaml:"securitySchemes"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatalf("body is not valid YAML: %v", err)
	}

	scheme, ok := spec.Components.SecuritySchemes["ApiKeyAuth"]
	if !ok {
		t.Fatal("expected ApiKeyAuth security scheme")
	}
	if scheme.Type != "apiKey" || scheme.In != "header" || scheme.Name != "X-API-Key" {
		t.Errorf("security scheme = %+v, want apiKey header X-API-Key", scheme)
	}
}
