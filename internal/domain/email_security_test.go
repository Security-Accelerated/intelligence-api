package domain

import "testing"

func TestParseSPF_Full(t *testing.T) {
	raw := "v=spf1 include:_spf.google.com ip4:192.0.2.0/24 -all"
	rec := parseSPF(raw)

	if rec.Raw != raw {
		t.Fatalf("Raw = %q, want %q", rec.Raw, raw)
	}
	if rec.Version != "spf1" {
		t.Fatalf("Version = %q, want %q", rec.Version, "spf1")
	}
	if rec.All != "-all" {
		t.Fatalf("All = %q, want %q", rec.All, "-all")
	}
	if len(rec.Mechanisms) != 2 {
		t.Fatalf("Mechanisms count = %d, want 2", len(rec.Mechanisms))
	}
	if rec.Mechanisms[0] != "include:_spf.google.com" {
		t.Fatalf("Mechanisms[0] = %q, want %q", rec.Mechanisms[0], "include:_spf.google.com")
	}
}

func TestParseSPF_SoftFail(t *testing.T) {
	rec := parseSPF("v=spf1 ~all")
	if rec.All != "~all" {
		t.Fatalf("All = %q, want %q", rec.All, "~all")
	}
	if len(rec.Mechanisms) != 0 {
		t.Fatalf("Mechanisms count = %d, want 0", len(rec.Mechanisms))
	}
}

func TestParseSPF_NeutralAll(t *testing.T) {
	rec := parseSPF("v=spf1 ?all")
	if rec.All != "?all" {
		t.Fatalf("All = %q, want %q", rec.All, "?all")
	}
}

func TestParseSPF_PassAll(t *testing.T) {
	rec := parseSPF("v=spf1 +all")
	if rec.All != "+all" {
		t.Fatalf("All = %q, want %q", rec.All, "+all")
	}
}

func TestParseSPF_BareAll(t *testing.T) {
	rec := parseSPF("v=spf1 all")
	if rec.All != "all" {
		t.Fatalf("All = %q, want %q", rec.All, "all")
	}
}

func TestParseSPF_NoMechanisms(t *testing.T) {
	rec := parseSPF("v=spf1 -all")
	if len(rec.Mechanisms) != 0 {
		t.Fatalf("Mechanisms count = %d, want 0", len(rec.Mechanisms))
	}
}

func TestParseDMARC_Full(t *testing.T) {
	raw := "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; sp=quarantine"
	rec := parseDMARC(raw)

	if rec.Raw != raw {
		t.Fatalf("Raw = %q, want %q", rec.Raw, raw)
	}
	if rec.Version != "DMARC1" {
		t.Fatalf("Version = %q, want %q", rec.Version, "DMARC1")
	}
	if rec.Policy != "reject" {
		t.Fatalf("Policy = %q, want %q", rec.Policy, "reject")
	}
	if rec.Pct != 100 {
		t.Fatalf("Pct = %d, want 100", rec.Pct)
	}
	if rec.RUA != "mailto:dmarc@example.com" {
		t.Fatalf("RUA = %q, want %q", rec.RUA, "mailto:dmarc@example.com")
	}
	if rec.RUF != "mailto:forensic@example.com" {
		t.Fatalf("RUF = %q, want %q", rec.RUF, "mailto:forensic@example.com")
	}
	if rec.SP != "quarantine" {
		t.Fatalf("SP = %q, want %q", rec.SP, "quarantine")
	}
}

func TestParseDMARC_Minimal(t *testing.T) {
	rec := parseDMARC("v=DMARC1; p=none")
	if rec.Policy != "none" {
		t.Fatalf("Policy = %q, want %q", rec.Policy, "none")
	}
	if rec.Pct != 0 {
		t.Fatalf("Pct = %d, want 0 (unset)", rec.Pct)
	}
}

func TestParseDMARC_Quarantine(t *testing.T) {
	rec := parseDMARC("v=DMARC1; p=quarantine; pct=50")
	if rec.Policy != "quarantine" {
		t.Fatalf("Policy = %q, want %q", rec.Policy, "quarantine")
	}
	if rec.Pct != 50 {
		t.Fatalf("Pct = %d, want 50", rec.Pct)
	}
}

func TestParseDMARC_ExtraWhitespace(t *testing.T) {
	rec := parseDMARC("v=DMARC1 ;  p = reject ;  pct = 75 ")
	if rec.Policy != "reject" {
		t.Fatalf("Policy = %q, want %q", rec.Policy, "reject")
	}
	if rec.Pct != 75 {
		t.Fatalf("Pct = %d, want 75", rec.Pct)
	}
}

func TestParseDMARC_InvalidPct(t *testing.T) {
	rec := parseDMARC("v=DMARC1; p=none; pct=abc")
	if rec.Pct != 0 {
		t.Fatalf("Pct = %d, want 0 for invalid value", rec.Pct)
	}
}
