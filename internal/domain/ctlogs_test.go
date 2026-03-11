package domain

import "testing"

func TestDedupCTEntries_NoDuplicates(t *testing.T) {
	raw := []crtShCTEntry{
		{SerialNumber: "aaa", IssuerName: "Let's Encrypt", CommonName: "example.com", EntryTimestamp: "2024-01-01"},
		{SerialNumber: "bbb", IssuerName: "DigiCert", CommonName: "*.example.com", EntryTimestamp: "2024-02-01"},
	}
	result := dedupCTEntries(raw)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}
	if result[0].Serial != "aaa" {
		t.Errorf("result[0].Serial = %q, want %q", result[0].Serial, "aaa")
	}
	if result[1].Serial != "bbb" {
		t.Errorf("result[1].Serial = %q, want %q", result[1].Serial, "bbb")
	}
}

func TestDedupCTEntries_RemovesDuplicateSerials(t *testing.T) {
	raw := []crtShCTEntry{
		{SerialNumber: "aaa", IssuerName: "Let's Encrypt", CommonName: "example.com", EntryTimestamp: "2024-01-01"},
		{SerialNumber: "aaa", IssuerName: "Let's Encrypt", CommonName: "example.com", EntryTimestamp: "2024-01-02"},
		{SerialNumber: "bbb", IssuerName: "DigiCert", CommonName: "example.com", EntryTimestamp: "2024-03-01"},
	}
	result := dedupCTEntries(raw)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries after dedup, got %d", len(result))
	}
	// First occurrence kept
	if result[0].LoggedAt != "2024-01-01" {
		t.Errorf("result[0].LoggedAt = %q, want %q (first occurrence)", result[0].LoggedAt, "2024-01-01")
	}
	if result[1].Serial != "bbb" {
		t.Errorf("result[1].Serial = %q, want %q", result[1].Serial, "bbb")
	}
}

func TestDedupCTEntries_SkipsEmptySerial(t *testing.T) {
	raw := []crtShCTEntry{
		{SerialNumber: "", IssuerName: "Let's Encrypt", CommonName: "example.com"},
		{SerialNumber: "aaa", IssuerName: "DigiCert", CommonName: "example.com"},
	}
	result := dedupCTEntries(raw)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry (empty serial skipped), got %d", len(result))
	}
	if result[0].Serial != "aaa" {
		t.Errorf("result[0].Serial = %q, want %q", result[0].Serial, "aaa")
	}
}

func TestDedupCTEntries_EmptyInput(t *testing.T) {
	result := dedupCTEntries(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 entries for nil input, got %d", len(result))
	}

	result = dedupCTEntries([]crtShCTEntry{})
	if len(result) != 0 {
		t.Errorf("expected 0 entries for empty input, got %d", len(result))
	}
}

func TestDedupCTEntries_FieldMapping(t *testing.T) {
	raw := []crtShCTEntry{
		{
			SerialNumber:   "serial1",
			IssuerName:     "CA Name",
			CommonName:     "cn.example.com",
			NameValue:      "san.example.com",
			NotBefore:      "2024-01-01",
			NotAfter:       "2025-01-01",
			EntryTimestamp: "2024-01-15",
		},
	}
	result := dedupCTEntries(raw)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	e := result[0]
	if e.Serial != "serial1" {
		t.Errorf("Serial = %q, want %q", e.Serial, "serial1")
	}
	if e.Issuer != "CA Name" {
		t.Errorf("Issuer = %q, want %q", e.Issuer, "CA Name")
	}
	if e.CommonName != "cn.example.com" {
		t.Errorf("CommonName = %q, want %q", e.CommonName, "cn.example.com")
	}
	if e.NameValue != "san.example.com" {
		t.Errorf("NameValue = %q, want %q", e.NameValue, "san.example.com")
	}
	if e.NotBefore != "2024-01-01" {
		t.Errorf("NotBefore = %q, want %q", e.NotBefore, "2024-01-01")
	}
	if e.NotAfter != "2025-01-01" {
		t.Errorf("NotAfter = %q, want %q", e.NotAfter, "2025-01-01")
	}
	if e.LoggedAt != "2024-01-15" {
		t.Errorf("LoggedAt = %q, want %q", e.LoggedAt, "2024-01-15")
	}
}

func TestDedupCTEntries_AllDuplicates(t *testing.T) {
	raw := []crtShCTEntry{
		{SerialNumber: "same", IssuerName: "CA", EntryTimestamp: "2024-01-01"},
		{SerialNumber: "same", IssuerName: "CA", EntryTimestamp: "2024-02-01"},
		{SerialNumber: "same", IssuerName: "CA", EntryTimestamp: "2024-03-01"},
	}
	result := dedupCTEntries(raw)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry after dedup, got %d", len(result))
	}
	if result[0].LoggedAt != "2024-01-01" {
		t.Errorf("expected first occurrence kept, got LoggedAt = %q", result[0].LoggedAt)
	}
}
