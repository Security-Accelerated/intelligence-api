package domain

import "testing"

func TestClassifyDBLResponse(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"127.0.1.2", "spam"},
		{"127.0.1.4", "phishing"},
		{"127.0.1.5", "malware"},
		{"127.0.1.6", "botnet_cc"},
		{"127.0.1.102", "abused_spam"},
		{"127.0.1.103", "abused_spammed_redirector"},
		{"127.0.1.104", "abused_phishing"},
		{"127.0.1.105", "abused_malware"},
		{"127.0.1.106", "abused_botnet_cc"},
		{"127.0.1.255", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := classifyDBLResponse(tt.addr)
			if got != tt.want {
				t.Errorf("classifyDBLResponse(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}
