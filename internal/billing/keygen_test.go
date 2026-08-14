package billing

import (
	"testing"
)

func TestGenerateAPIKey_Length(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("key length = %d, want 64", len(key))
	}
}

func TestGenerateAPIKey_Unique(t *testing.T) {
	key1, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	key2, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key1 == key2 {
		t.Error("expected two generated keys to be different")
	}
}

func TestGenerateAPIKey_HexEncoded(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range key {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("key contains non-hex character: %c", c)
		}
	}
}
