package handler

import (
	"strings"
	"testing"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

// TestDocs_RequestBodyListsOnlyContractFields guards the request-body tables on
// the docs pages against the per-feature booleans removed in v0.54.0.
//
// The contract is two fields — the targets and `lookups`. A stale
// `dns_security | bool | Optional` row survived every other check for three
// releases: the lookup name is legitimately mentioned all over these pages, so
// grepping for it finds nothing wrong, and no test looked at the table itself.
func TestDocs_RequestBodyListsOnlyContractFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		page   string
		target string
	}{
		{"/docs/domain", docsDomainHTML, "domains"},
		{"/docs/ip", docsIPHTML, "ips"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := requestBodyTable(t, tc.page)

			for _, want := range []string{tc.target, "lookups"} {
				if !strings.Contains(table, "<code>"+want+"</code>") {
					t.Errorf("request body table does not document %q", want)
				}
			}

			// Every lookup name is a valid *value* of `lookups`, never a field
			// of its own. One appearing here means a boolean row came back.
			names := append(append([]string{}, domain.AllLookupNames...), domain.AllIPLookupNames...)
			for _, name := range names {
				if name == tc.target || name == "lookups" {
					continue
				}
				if strings.Contains(table, "<code>"+name+"</code>") {
					t.Errorf("request body table lists %q as a field; lookups are values of the lookups array, not request fields", name)
				}
			}

			if strings.Contains(table, "<code>bool</code>") {
				t.Error("request body table contains a bool field; the per-feature booleans were removed in v0.54.0")
			}
		})
	}
}

// requestBodyTable returns the markup of the Request Body section's table.
func requestBodyTable(t *testing.T, page string) string {
	t.Helper()
	start := strings.Index(page, `id="request-body"`)
	if start == -1 {
		t.Fatal("no request-body section")
	}
	end := strings.Index(page[start:], "</table>")
	if end == -1 {
		t.Fatal("unterminated request-body table")
	}
	return page[start : start+end]
}
