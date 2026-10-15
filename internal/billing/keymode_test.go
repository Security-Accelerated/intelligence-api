package billing

import "testing"

func TestKeyMode(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{"standard live", "sk_live_abc123", ModeLive},
		{"restricted live", "rk_live_abc123", ModeLive},
		{"standard test", "sk_test_abc123", ModeTest},
		{"restricted test", "rk_test_abc123", ModeTest},
		{"empty", "", ModeUnknown},
		{"publishable key", "pk_live_abc123", ModeUnknown},
		{"prefix only, wrong case", "SK_LIVE_abc123", ModeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KeyMode(tt.key); got != tt.want {
				t.Errorf("KeyMode(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}
