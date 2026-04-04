package domain

import (
	"testing"

	whoisparser "github.com/likexian/whois-parser"
)

func TestWhoisInfoFromParsed_NilDomainAndRegistrar(t *testing.T) {
	parsed := whoisparser.WhoisInfo{
		Domain:    nil,
		Registrar: nil,
	}
	info := whoisInfoFromParsed(parsed)
	if info == nil {
		t.Fatal("expected non-nil WhoisInfo")
	}
	if info.DomainName != "" {
		t.Errorf("DomainName = %q, want empty", info.DomainName)
	}
	if info.Registrar != "" {
		t.Errorf("Registrar = %q, want empty", info.Registrar)
	}
	if info.CreatedDate != "" || info.UpdatedDate != "" || info.ExpiryDate != "" {
		t.Error("expected empty date fields")
	}
	if len(info.Status) != 0 || len(info.NameServers) != 0 {
		t.Error("expected empty status and nameservers")
	}
}

func TestWhoisInfoFromParsed_WithData(t *testing.T) {
	parsed := whoisparser.WhoisInfo{
		Domain: &whoisparser.Domain{
			Domain:         "example.com",
			CreatedDate:    "2020-01-01",
			ExpirationDate: "2030-01-01",
			NameServers:    []string{"ns1.example.com"},
		},
		Registrar: &whoisparser.Contact{
			Name: "Test Registrar",
		},
	}
	info := whoisInfoFromParsed(parsed)
	if info.DomainName != "example.com" {
		t.Errorf("DomainName = %q, want %q", info.DomainName, "example.com")
	}
	if info.Registrar != "Test Registrar" {
		t.Errorf("Registrar = %q, want %q", info.Registrar, "Test Registrar")
	}
	if len(info.NameServers) != 1 {
		t.Errorf("NameServers count = %d, want 1", len(info.NameServers))
	}
}

func TestContactFromWhois_Nil(t *testing.T) {
	if got := contactFromWhois(nil); got != nil {
		t.Errorf("contactFromWhois(nil) = %+v, want nil", got)
	}
}

func TestContactFromWhois_AllEmpty(t *testing.T) {
	c := &whoisparser.Contact{}
	if got := contactFromWhois(c); got != nil {
		t.Errorf("contactFromWhois(empty) = %+v, want nil", got)
	}
}

func TestContactFromWhois_WhitespaceOnly(t *testing.T) {
	c := &whoisparser.Contact{
		Name:  "   ",
		Email: "  ",
	}
	if got := contactFromWhois(c); got != nil {
		t.Errorf("contactFromWhois(whitespace) = %+v, want nil", got)
	}
}

func TestContactFromWhois_WithData(t *testing.T) {
	c := &whoisparser.Contact{
		Name:         "John Doe",
		Organization: "Acme Corp",
		Country:      "US",
		Email:        "john@acme.com",
	}
	got := contactFromWhois(c)
	if got == nil {
		t.Fatal("contactFromWhois(with data) = nil, want non-nil")
	}
	if got.Name != "John Doe" {
		t.Errorf("Name = %q, want %q", got.Name, "John Doe")
	}
	if got.Organization != "Acme Corp" {
		t.Errorf("Organization = %q, want %q", got.Organization, "Acme Corp")
	}
	if got.Country != "US" {
		t.Errorf("Country = %q, want %q", got.Country, "US")
	}
	if got.Email != "john@acme.com" {
		t.Errorf("Email = %q, want %q", got.Email, "john@acme.com")
	}
}

func TestContactFromWhois_PartialData(t *testing.T) {
	c := &whoisparser.Contact{
		Organization: "Acme Corp",
	}
	got := contactFromWhois(c)
	if got == nil {
		t.Fatal("contactFromWhois(partial) = nil, want non-nil")
	}
	if got.Organization != "Acme Corp" {
		t.Errorf("Organization = %q, want %q", got.Organization, "Acme Corp")
	}
}
