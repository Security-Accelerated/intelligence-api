package cache

import (
	"strings"
	"testing"
)

func TestLookupKey_Format(t *testing.T) {
	tests := []struct {
		domain string
		lookup string
		want   string
	}{
		{"example.net", "ssl", "lookup:example.net:ssl"},
		{"example.com", "dns", "lookup:example.com:dns"},
		{"sub.example.org", "email_security", "lookup:sub.example.org:email_security"},
		{"example.com", "threat_intel", "lookup:example.com:threat_intel"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := LookupKey(tt.domain, tt.lookup); got != tt.want {
				t.Errorf("LookupKey(%q, %q) = %q, want %q", tt.domain, tt.lookup, got, tt.want)
			}
		})
	}
}

func TestLookupKey_UsesPrefixConstant(t *testing.T) {
	if LookupKeyPrefix != "lookup:" {
		t.Fatalf("LookupKeyPrefix = %q, want %q", LookupKeyPrefix, "lookup:")
	}
	key := LookupKey("example.com", "dns")
	if !strings.HasPrefix(key, LookupKeyPrefix) {
		t.Errorf("key %q does not start with %q", key, LookupKeyPrefix)
	}
}

func TestLookupKey_DoesNotRenormalize(t *testing.T) {
	// Normalization is the handler's job. The builder must pass inputs through
	// verbatim so a missed normalization step surfaces as a distinct key rather
	// than being silently papered over.
	if got := LookupKey("Example.COM", "SSL"); got != "lookup:Example.COM:SSL" {
		t.Errorf("LookupKey re-normalized its inputs: %q", got)
	}
}

func TestLookupKey_DistinctPerDomainAndLookup(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range []string{"a.com", "b.com"} {
		for _, l := range []string{"dns", "ssl", "whois"} {
			k := LookupKey(d, l)
			if seen[k] {
				t.Errorf("duplicate key %q", k)
			}
			seen[k] = true
		}
	}
	if len(seen) != 6 {
		t.Errorf("built %d distinct keys, want 6", len(seen))
	}
}
