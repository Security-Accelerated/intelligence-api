package domain

import "testing"

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
