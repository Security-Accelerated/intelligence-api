package domain

import (
	"testing"

	whoisparser "github.com/likexian/whois-parser"
)

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
