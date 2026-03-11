package service

import (
	"testing"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func TestBuildCacheKey_NoOptions(t *testing.T) {
	key := buildCacheKey("example.com", domain.LookupOptions{})
	if key != "example.com" {
		t.Errorf("key = %q, want %q", key, "example.com")
	}
}

func TestBuildCacheKey_SingleOption(t *testing.T) {
	tests := []struct {
		name string
		opts domain.LookupOptions
		want string
	}{
		{"bgp", domain.LookupOptions{BGP: true}, "example.com:bgp"},
		{"ct_logs", domain.LookupOptions{CTLogs: true}, "example.com:ct_logs"},
		{"email_security", domain.LookupOptions{EmailSecurity: true}, "example.com:email_security"},
		{"fingerprint", domain.LookupOptions{Fingerprint: true}, "example.com:fingerprint"},
		{"reputation", domain.LookupOptions{Reputation: true}, "example.com:reputation"},
		{"screenshot", domain.LookupOptions{Screenshot: true}, "example.com:screenshot"},
		{"subdomains", domain.LookupOptions{Subdomains: true}, "example.com:subdomains"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := buildCacheKey("example.com", tt.opts)
			if key != tt.want {
				t.Errorf("key = %q, want %q", key, tt.want)
			}
		})
	}
}

func TestBuildCacheKey_MultipleOptions_Sorted(t *testing.T) {
	// Options should be sorted alphabetically regardless of struct field order.
	opts := domain.LookupOptions{
		Screenshot:    true,
		Reputation:    true,
		EmailSecurity: true,
		BGP:           true,
	}
	key := buildCacheKey("test.org", opts)
	want := "test.org:bgp+email_security+reputation+screenshot"
	if key != want {
		t.Errorf("key = %q, want %q", key, want)
	}
}

func TestBuildCacheKey_AllOptions(t *testing.T) {
	opts := domain.LookupOptions{
		BGP:           true,
		CTLogs:        true,
		EmailSecurity: true,
		Fingerprint:   true,
		Reputation:    true,
		Screenshot:    true,
		Subdomains:    true,
	}
	key := buildCacheKey("all.com", opts)
	want := "all.com:bgp+ct_logs+email_security+fingerprint+reputation+screenshot+subdomains"
	if key != want {
		t.Errorf("key = %q, want %q", key, want)
	}
}

func TestBuildCacheKey_DifferentDomains(t *testing.T) {
	opts := domain.LookupOptions{Reputation: true}
	key1 := buildCacheKey("a.com", opts)
	key2 := buildCacheKey("b.com", opts)
	if key1 == key2 {
		t.Errorf("different domains should produce different keys: %q vs %q", key1, key2)
	}
}
