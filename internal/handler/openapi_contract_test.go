package handler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"gopkg.in/yaml.v3"
)

// TestOpenAPIMatchesLookupContract keeps the published spec honest.
//
// openapi.yaml is served at /docs/openapi.yaml and is what customers generate
// clients from, so drift there produces requests that 400 rather than a merely
// confusing page. It sat on the pre-v0.54.0 contract for three releases —
// per-feature booleans, no lookups array, a bare array response — because
// nothing compared it against the code.
func TestOpenAPIMatchesLookupContract(t *testing.T) {
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Items struct {
						Enum []string `yaml:"enum"`
					} `yaml:"items"`
					Type string `yaml:"type"`
				} `yaml:"properties"`
				Required []string `yaml:"required"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(openapiYAML, &doc); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}

	for _, tc := range []struct {
		schema string
		target string
		names  []string
	}{
		{"DomainRequest", "domains", domain.AllLookupNames},
		{"IPRequest", "ips", domain.AllIPLookupNames},
	} {
		t.Run(tc.schema, func(t *testing.T) {
			sch, ok := doc.Components.Schemas[tc.schema]
			if !ok {
				t.Fatalf("%s is missing from the spec", tc.schema)
			}

			// Both fields are required — lookups has no default set.
			required := append([]string{}, sch.Required...)
			sort.Strings(required)
			want := []string{tc.target, "lookups"}
			sort.Strings(want)
			if len(required) != len(want) || required[0] != want[0] || required[1] != want[1] {
				t.Errorf("required = %v, want %v", sch.Required, want)
			}

			// The enum must list exactly the lookups the code accepts:
			// a missing name reads as invalid, an extra one 400s when used.
			got := append([]string{}, sch.Properties["lookups"].Items.Enum...)
			exp := append([]string{}, tc.names...)
			sort.Strings(got)
			sort.Strings(exp)
			if len(got) != len(exp) {
				t.Fatalf("lookups enum has %d names, code has %d\n spec: %v\n code: %v", len(got), len(exp), got, exp)
			}
			for i := range got {
				if got[i] != exp[i] {
					t.Errorf("lookups enum mismatch at %d: spec %q, code %q", i, got[i], exp[i])
				}
			}

			// No per-feature booleans: those were the v0.54.0 contract.
			for name, prop := range sch.Properties {
				if prop.Type == "boolean" {
					t.Errorf("%s is a boolean request field; lookups are values of the lookups array", name)
				}
			}
		})
	}
}

// TestOpenAPIMatchesCorrelationIDContract pins the published correlation-ID
// rules to the ones actually enforced.
//
// The IP docs page advertised "any string up to 128 chars" while the middleware
// capped it at 64 and rejected most punctuation. Nothing failed: an
// over-length ID is dropped silently, so a customer following the docs would
// send it, get a 200, and quietly lose the tracing they had set up — with no
// error anywhere to explain why the header never came back.
//
// Rather than compare the spec's regex to the middleware's as strings (which
// would pass for two patterns that are textually equal but semantically
// different, and fail for equivalent ones written differently), this runs
// candidate IDs through both and requires the same verdict.
func TestOpenAPIMatchesCorrelationIDContract(t *testing.T) {
	var doc struct {
		Components struct {
			Parameters map[string]struct {
				Name   string `yaml:"name"`
				In     string `yaml:"in"`
				Schema struct {
					MaxLength int    `yaml:"maxLength"`
					Pattern   string `yaml:"pattern"`
				} `yaml:"schema"`
			} `yaml:"parameters"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(openapiYAML, &doc); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}

	p, ok := doc.Components.Parameters["ClientRequestID"]
	if !ok {
		t.Fatal("the spec does not document the X-Client-Request-ID parameter")
	}
	if p.Name != middleware.ClientRequestIDHeader || p.In != "header" {
		t.Errorf("spec documents %s in %q, want %s in header", p.Name, p.In, middleware.ClientRequestIDHeader)
	}
	if p.Schema.MaxLength != middleware.ClientRequestIDMaxLen {
		t.Errorf("spec maxLength = %d, middleware enforces %d", p.Schema.MaxLength, middleware.ClientRequestIDMaxLen)
	}

	specPattern, err := regexp.Compile(p.Schema.Pattern)
	if err != nil {
		t.Fatalf("spec pattern %q does not compile: %v", p.Schema.Pattern, err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ClientRequestID())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, id := range []string{
		"req-001",
		"550e8400-e29b-41d4-a716-446655440000",
		"trace:abc.123_x",
		"has space",
		"has/slash",
		"semi;colon",
		strings.Repeat("a", middleware.ClientRequestIDMaxLen),
		strings.Repeat("a", middleware.ClientRequestIDMaxLen+1),
	} {
		t.Run(id[:min(len(id), 24)], func(t *testing.T) {
			specAccepts := len(id) <= p.Schema.MaxLength && specPattern.MatchString(id)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(middleware.ClientRequestIDHeader, id)
			r.ServeHTTP(w, req)
			apiAccepts := w.Header().Get(middleware.ClientRequestIDHeader) != ""

			if specAccepts != apiAccepts {
				t.Errorf("spec accepts = %v but the API echoes = %v for %q — clients generated from the spec would disagree with the running service",
					specAccepts, apiAccepts, id)
			}
			if apiAccepts && w.Header().Get(middleware.ClientRequestIDHeader) != id {
				t.Errorf("echoed %q, want it back byte for byte", w.Header().Get(middleware.ClientRequestIDHeader))
			}
		})
	}
}

// TestOpenAPIDeclaresCorrelationHeadersOnEveryResponse requires every documented
// response to declare the correlation headers.
//
// ClientRequestID and RequestLogger sit near the top of the middleware chain, so
// both headers are already written before any handler can succeed or fail —
// there is no documented response that legitimately lacks them. Declaring them
// per response is easy to forget, and a caller reading the spec would conclude
// the correlation ID they sent had been dropped on exactly the responses where
// they most need it: the failures.
//
// The X-RateLimit pair is deliberately not required here. The limiter runs after
// authentication and returns early when there is no API key in context, so a 401
// never reaches it.
func TestOpenAPIDeclaresCorrelationHeadersOnEveryResponse(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(openapiYAML, &doc); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}

	want := []string{"X-Request-ID", middleware.ClientRequestIDHeader}

	check := func(t *testing.T, where string, resp any) {
		t.Helper()
		m, ok := resp.(map[string]any)
		if !ok {
			return
		}
		// A $ref delegates to a shared response, which is checked on its own.
		if _, isRef := m["$ref"]; isRef {
			return
		}
		headers, _ := m["headers"].(map[string]any)
		for _, h := range want {
			if headers[h] == nil {
				t.Errorf("%s does not declare the %s response header", where, h)
			}
		}
	}

	comps, _ := doc["components"].(map[string]any)
	shared, _ := comps["responses"].(map[string]any)
	for name, resp := range shared {
		check(t, "components.responses."+name, resp)
	}

	paths, _ := doc["paths"].(map[string]any)
	for path, pv := range paths {
		methods, _ := pv.(map[string]any)
		for method, ov := range methods {
			op, ok := ov.(map[string]any)
			if !ok {
				continue
			}
			responses, _ := op["responses"].(map[string]any)
			for status, resp := range responses {
				check(t, strings.ToUpper(method)+" "+path+" -> "+status, resp)
			}
		}
	}
}
