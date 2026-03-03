package auth

import "testing"

func TestHashKey_KnownValue(t *testing.T) {
	// Pre-computed: echo -n "test-admin-key" | sha256sum
	want := "944650a7cd0f9e14d5c4fb15edbffb7fa45fb9ed36a4fa9be3d7e5476ae51bd9"
	got := HashKey("test-admin-key")
	if got != want {
		t.Errorf("HashKey(\"test-admin-key\") = %q, want %q", got, want)
	}
}

func TestHashKey_Deterministic(t *testing.T) {
	a := HashKey("same-input")
	b := HashKey("same-input")
	if a != b {
		t.Errorf("HashKey not deterministic: %q != %q", a, b)
	}
}

func TestHashKey_DifferentInputs(t *testing.T) {
	a := HashKey("key-one")
	b := HashKey("key-two")
	if a == b {
		t.Errorf("different inputs produced same hash: %q", a)
	}
}

func TestHashKey_OutputLength(t *testing.T) {
	got := HashKey("any-key")
	if len(got) != 64 {
		t.Errorf("len(HashKey) = %d, want 64", len(got))
	}
}
