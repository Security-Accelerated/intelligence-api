package domain

import "testing"

func TestParseCymruOrigin_Valid(t *testing.T) {
	record, err := parseCymruOrigin("8.8.8.8", "15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.IP != "8.8.8.8" {
		t.Errorf("IP = %q, want %q", record.IP, "8.8.8.8")
	}
	if record.ASN != 15169 {
		t.Errorf("ASN = %d, want %d", record.ASN, 15169)
	}
	if record.Prefix != "8.8.8.0/24" {
		t.Errorf("Prefix = %q, want %q", record.Prefix, "8.8.8.0/24")
	}
	if record.Country != "US" {
		t.Errorf("Country = %q, want %q", record.Country, "US")
	}
	if record.Registry != "arin" {
		t.Errorf("Registry = %q, want %q", record.Registry, "arin")
	}
}

func TestParseCymruOrigin_ExtraWhitespace(t *testing.T) {
	record, err := parseCymruOrigin("1.2.3.4", "  13335  |  1.0.0.0/24  |  AU  |  apnic  |  2011-08-11  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.ASN != 13335 {
		t.Errorf("ASN = %d, want %d", record.ASN, 13335)
	}
	if record.Prefix != "1.0.0.0/24" {
		t.Errorf("Prefix = %q, want %q", record.Prefix, "1.0.0.0/24")
	}
	if record.Country != "AU" {
		t.Errorf("Country = %q, want %q", record.Country, "AU")
	}
	if record.Registry != "apnic" {
		t.Errorf("Registry = %q, want %q", record.Registry, "apnic")
	}
}

func TestParseCymruOrigin_TooFewParts(t *testing.T) {
	_, err := parseCymruOrigin("1.2.3.4", "15169 | 8.8.8.0/24 | US")
	if err == nil {
		t.Fatal("expected error for too few parts")
	}
}

func TestParseCymruOrigin_InvalidASN(t *testing.T) {
	_, err := parseCymruOrigin("1.2.3.4", "notanumber | 8.8.8.0/24 | US | arin | 2020-01-01")
	if err == nil {
		t.Fatal("expected error for non-numeric ASN")
	}
}

func TestParseCymruOrigin_EmptyString(t *testing.T) {
	_, err := parseCymruOrigin("1.2.3.4", "")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseCymruOrigin_ExactlyFourParts(t *testing.T) {
	// Exactly 4 pipe-delimited parts (no date field) — should still work
	record, err := parseCymruOrigin("10.0.0.1", "64496 | 10.0.0.0/8 | ZZ | other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.ASN != 64496 {
		t.Errorf("ASN = %d, want %d", record.ASN, 64496)
	}
}

func TestParseCymruOrigin_IPPassthrough(t *testing.T) {
	// The IP is passed through directly, not extracted from the TXT record.
	record, err := parseCymruOrigin("192.0.2.1", "64496 | 192.0.2.0/24 | US | arin | 2000-01-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.IP != "192.0.2.1" {
		t.Errorf("IP = %q, want %q", record.IP, "192.0.2.1")
	}
}
