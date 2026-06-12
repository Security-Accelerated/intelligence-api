package domain

import "testing"

func TestParseMTASTSRecord(t *testing.T) {
	rec := parseMTASTSRecord("v=STSv1; id=20240115T000000Z;")
	if rec == nil {
		t.Fatal("expected record")
	}
	if rec.ID != "20240115T000000Z" {
		t.Errorf("ID = %q, want 20240115T000000Z", rec.ID)
	}
	if rec.PolicyFetched {
		t.Error("PolicyFetched should be false before policy fetch")
	}
	if parseMTASTSRecord("v=spf1 -all") != nil {
		t.Error("non-STS record should return nil")
	}
}

func TestParseMTASTSPolicy(t *testing.T) {
	body := []byte("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.backup.example.com\nmax_age: 604800\n")
	mode, maxAge, mx, err := parseMTASTSPolicy(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != "enforce" {
		t.Errorf("mode = %q, want enforce", mode)
	}
	if maxAge != 604800 {
		t.Errorf("max_age = %d, want 604800", maxAge)
	}
	if len(mx) != 2 || mx[0] != "mail.example.com" || mx[1] != "*.backup.example.com" {
		t.Errorf("mx = %v", mx)
	}
}

func TestParseMTASTSPolicy_MissingMode(t *testing.T) {
	if _, _, _, err := parseMTASTSPolicy([]byte("version: STSv1\n")); err == nil {
		t.Error("expected error for policy without mode")
	}
}

func TestParseTLSRPT(t *testing.T) {
	rec := parseTLSRPT("v=TLSRPTv1; rua=mailto:tls-reports@example.com")
	if rec == nil {
		t.Fatal("expected record")
	}
	if rec.RUA != "mailto:tls-reports@example.com" {
		t.Errorf("RUA = %q", rec.RUA)
	}
	if parseTLSRPT("v=DMARC1; p=none") != nil {
		t.Error("non-TLSRPT record should return nil")
	}
}

func TestParseBIMI(t *testing.T) {
	rec := parseBIMI("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
	if rec == nil {
		t.Fatal("expected record")
	}
	if rec.Location != "https://example.com/logo.svg" {
		t.Errorf("Location = %q", rec.Location)
	}
	if rec.Authority != "https://example.com/vmc.pem" {
		t.Errorf("Authority = %q", rec.Authority)
	}
	if parseBIMI("v=spf1 -all") != nil {
		t.Error("non-BIMI record should return nil")
	}
}

func TestCutTag(t *testing.T) {
	cases := []struct {
		in       string
		key, val string
		ok       bool
	}{
		{"id=2024", "id", "2024", true},
		{" mode: enforce\n", "mode", "enforce", true},
		{"rua=mailto:r@x.com", "rua", "mailto:r@x.com", true},
		{"l=https://x.com/a.svg?v=1", "l", "https://x.com/a.svg?v=1", true},
		{"noseparator", "", "", false},
	}
	for _, c := range cases {
		k, v, ok := cutTag(c.in)
		if k != c.key || v != c.val || ok != c.ok {
			t.Errorf("cutTag(%q) = (%q, %q, %v), want (%q, %q, %v)", c.in, k, v, ok, c.key, c.val, c.ok)
		}
	}
}
