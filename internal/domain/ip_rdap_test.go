package domain

import "testing"

// TestRIREndpointForIP covers the first-octet table: one address per RIR, the
// boundaries of a multi-octet range, and every fallback to ARIN. The mapping
// had no test when it was a switch, so a transcription slip in the table that
// replaced it would have been invisible.
func TestRIREndpointForIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{"ripe", "62.0.0.1", rirEndpoints["ripe"]},
		{"apnic", "103.0.0.1", rirEndpoints["apnic"]},
		{"lacnic", "200.0.0.1", rirEndpoints["lacnic"]},
		{"afrinic", "41.0.0.1", rirEndpoints["afrinic"]},
		{"arin by allocation", "8.8.8.8", rirEndpoints["arin"]},

		{"range low boundary", "77.0.0.1", rirEndpoints["ripe"]},
		{"range high boundary", "95.0.0.1", rirEndpoints["ripe"]},
		{"below range", "76.0.0.1", rirEndpoints["arin"]},
		{"above range", "96.0.0.1", rirEndpoints["arin"]},

		{"unallocated octet falls back", "0.0.0.1", rirEndpoints["arin"]},
		{"ipv6 falls back", "2001:db8::1", rirEndpoints["arin"]},
		{"unparseable falls back", "not-an-ip", rirEndpoints["arin"]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rirEndpointForIP(tt.ip); got != tt.want {
				t.Errorf("rirEndpointForIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestExtractEmailFromVCard_Valid(t *testing.T) {
	// Standard jCard: ["vcard", [["version", {}, "text", "4.0"], ["email", {}, "text", "abuse@example.com"]]]
	vcard := []any{
		"vcard",
		[]any{
			[]any{"version", map[string]any{}, "text", "4.0"},
			[]any{"email", map[string]any{}, "text", "abuse@example.com"},
		},
	}
	got := extractEmailFromVCard(vcard)
	if got != "abuse@example.com" {
		t.Errorf("got %q, want %q", got, "abuse@example.com")
	}
}

func TestExtractEmailFromVCard_NoEmail(t *testing.T) {
	vcard := []any{
		"vcard",
		[]any{
			[]any{"version", map[string]any{}, "text", "4.0"},
			[]any{"fn", map[string]any{}, "text", "Network Operations"},
		},
	}
	got := extractEmailFromVCard(vcard)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestExtractEmailFromVCard_Empty(t *testing.T) {
	got := extractEmailFromVCard(nil)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestExtractEmailFromVCard_TooShort(t *testing.T) {
	got := extractEmailFromVCard([]any{"vcard"})
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestExtractEmailFromVCard_MalformedProps(t *testing.T) {
	// Props is not an array
	vcard := []any{"vcard", "not-an-array"}
	got := extractEmailFromVCard(vcard)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestExtractEmailFromVCard_ShortPropEntry(t *testing.T) {
	// Prop entry with fewer than 4 elements
	vcard := []any{
		"vcard",
		[]any{
			[]any{"email", map[string]any{}},
		},
	}
	got := extractEmailFromVCard(vcard)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestFindAbuseEmail_Nested(t *testing.T) {
	entities := []rdapEntity{
		{
			Roles: []string{"registrant"},
			Entities: []rdapEntity{
				{
					Roles: []string{"abuse"},
					VCards: []any{
						"vcard",
						[]any{
							[]any{"email", map[string]any{}, "text", "nested-abuse@example.com"},
						},
					},
				},
			},
		},
	}
	got := findAbuseEmail(entities)
	if got != "nested-abuse@example.com" {
		t.Errorf("got %q, want %q", got, "nested-abuse@example.com")
	}
}

func TestFindAbuseEmail_NoAbuse(t *testing.T) {
	entities := []rdapEntity{
		{Roles: []string{"registrant"}},
		{Roles: []string{"technical"}},
	}
	got := findAbuseEmail(entities)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}
