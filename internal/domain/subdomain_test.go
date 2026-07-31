package domain

import (
	"encoding/json"
	"testing"
)

func TestParseCrtShResponse_Basic(t *testing.T) {
	entries := []crtShEntry{
		{NameValue: "www.example.com"},
		{NameValue: "mail.example.com"},
		{NameValue: "api.example.com"},
	}
	data, _ := json.Marshal(entries)

	result, _ := parseCrtShResponse(data, "example.com")

	if len(result) != 3 {
		t.Fatalf("count = %d, want 3", len(result))
	}
	// Should be sorted alphabetically
	want := []string{"api.example.com", "mail.example.com", "www.example.com"}
	for i, got := range result {
		if got != want[i] {
			t.Errorf("result[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestParseCrtShResponse_DeduplicatesEntries(t *testing.T) {
	entries := []crtShEntry{
		{NameValue: "www.example.com"},
		{NameValue: "www.example.com"},
		{NameValue: "www.example.com"},
	}
	data, _ := json.Marshal(entries)

	result, _ := parseCrtShResponse(data, "example.com")

	if len(result) != 1 {
		t.Fatalf("count = %d, want 1 (deduplicated)", len(result))
	}
}

func TestParseCrtShResponse_FiltersWildcards(t *testing.T) {
	entries := []crtShEntry{
		{NameValue: "*.example.com"},
		{NameValue: "www.example.com"},
	}
	data, _ := json.Marshal(entries)

	result, _ := parseCrtShResponse(data, "example.com")

	if len(result) != 1 {
		t.Fatalf("count = %d, want 1 (wildcard filtered)", len(result))
	}
	if result[0] != "www.example.com" {
		t.Fatalf("result[0] = %q, want %q", result[0], "www.example.com")
	}
}

func TestParseCrtShResponse_FiltersBaseDomain(t *testing.T) {
	entries := []crtShEntry{
		{NameValue: "example.com"},
		{NameValue: "www.example.com"},
	}
	data, _ := json.Marshal(entries)

	result, _ := parseCrtShResponse(data, "example.com")

	if len(result) != 1 {
		t.Fatalf("count = %d, want 1 (base domain filtered)", len(result))
	}
}

func TestParseCrtShResponse_FiltersForeignDomains(t *testing.T) {
	entries := []crtShEntry{
		{NameValue: "www.example.com"},
		{NameValue: "evil.other.com"},
	}
	data, _ := json.Marshal(entries)

	result, _ := parseCrtShResponse(data, "example.com")

	if len(result) != 1 {
		t.Fatalf("count = %d, want 1 (foreign domain filtered)", len(result))
	}
}

func TestParseCrtShResponse_HandlesMultilineNameValue(t *testing.T) {
	entries := []crtShEntry{
		{NameValue: "www.example.com\nmail.example.com\napi.example.com"},
	}
	data, _ := json.Marshal(entries)

	result, _ := parseCrtShResponse(data, "example.com")

	if len(result) != 3 {
		t.Fatalf("count = %d, want 3", len(result))
	}
}

func TestParseCrtShResponse_NormalizesCase(t *testing.T) {
	entries := []crtShEntry{
		{NameValue: "WWW.EXAMPLE.COM"},
		{NameValue: "www.example.com"},
	}
	data, _ := json.Marshal(entries)

	result, _ := parseCrtShResponse(data, "example.com")

	if len(result) != 1 {
		t.Fatalf("count = %d, want 1 (case-normalized dedup)", len(result))
	}
}

func TestParseCrtShResponse_InvalidJSON(t *testing.T) {
	result, err := parseCrtShResponse([]byte("not json"), "example.com")
	if err == nil {
		t.Error("malformed JSON must be an error, not an empty subdomain list — an empty list is cached for 24h and reads as \"no subdomains exist\"")
	}

	if result != nil {
		t.Fatalf("expected nil for invalid JSON, got %v", result)
	}
}

func TestParseCrtShResponse_EmptyArray(t *testing.T) {
	result, _ := parseCrtShResponse([]byte("[]"), "example.com")

	if len(result) != 0 {
		t.Fatalf("count = %d, want 0", len(result))
	}
}
