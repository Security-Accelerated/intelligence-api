package handler

import (
	"sort"
	"testing"

	"github.com/security-accelerated/intelligence-api/internal/domain"
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
