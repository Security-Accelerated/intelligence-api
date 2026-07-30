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

func TestClassifySURBLResponse(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"malware only", "127.0.0.8", "malware"},
		{"abuse only", "127.0.0.16", "abuse"},
		{"cracked only", "127.0.0.32", "cracked"},
		{"suspicious only", "127.0.0.64", "suspicious"},
		{"malware+abuse", "127.0.0.24", "abuse+malware"},
		{"all bits", "127.0.0.120", "suspicious+cracked+abuse+malware"},
		{"zero", "127.0.0.0", ""},
		{"malformed", "garbage", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySURBLResponse(tt.addr)
			if got != tt.want {
				t.Errorf("classifySURBLResponse(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestClassifyURIBLResponse(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"127.0.0.2", "spam"},
		{"127.0.0.4", "grey"},
		{"127.0.0.8", "red"},
		{"127.0.0.99", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := classifyURIBLResponse(tt.addr)
			if got != tt.want {
				t.Errorf("classifyURIBLResponse(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestClassifyZENResponse(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"SBL low", "127.0.0.2", "sbl_spam"},
		{"SBL high", "127.0.0.3", "sbl_spam"},
		{"XBL low", "127.0.0.4", "xbl_exploits"},
		{"XBL high", "127.0.0.7", "xbl_exploits"},
		{"PBL low", "127.0.0.10", "pbl_policy"},
		{"PBL high", "127.0.0.11", "pbl_policy"},
		{"unknown octet", "127.0.0.9", "unknown"},
		{"malformed", "garbage", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyZENResponse(tt.addr)
			if got != tt.want {
				t.Errorf("classifyZENResponse(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestReverseIPv4(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		want   string
		wantOK bool
	}{
		{"normal", "1.2.3.4", "4.3.2.1", true},
		{"all same", "10.10.10.10", "10.10.10.10", true},
		{"too few octets", "1.2.3", "", false},
		{"too many octets", "1.2.3.4.5", "", false},
		{"non-numeric", "a.b.c.d", "", false},
		{"ipv6", "::1", "", false},
		{"empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := reverseIPv4(tt.ip)
			if ok != tt.wantOK {
				t.Errorf("reverseIPv4(%q) ok = %v, want %v", tt.ip, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("reverseIPv4(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestParseLastOctet(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want int
	}{
		{"valid", "127.0.0.4", 4},
		{"zero", "127.0.0.0", 0},
		{"255", "127.0.0.255", 255},
		{"too few parts", "127.0.0", -1},
		{"non-numeric", "127.0.0.abc", -1},
		{"empty", "", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLastOctet(tt.addr)
			if got != tt.want {
				t.Errorf("parseLastOctet(%q) = %d, want %d", tt.addr, got, tt.want)
			}
		})
	}
}

func TestScoreReputation(t *testing.T) {
	tests := []struct {
		name      string
		providers []*ProviderResult
		wantScore int
		wantRisk  string
	}{
		{
			name: "all clean",
			providers: []*ProviderResult{
				{Listed: false, Provider: "spamhaus_dbl"},
				{Listed: false, Provider: "surbl"},
				{Listed: false, Provider: "uribl"},
				{Listed: false, Provider: "spamhaus_zen"},
			},
			wantScore: 0,
			wantRisk:  "clean",
		},
		{
			name: "single listing - DBL phishing",
			providers: []*ProviderResult{
				{Listed: true, Category: "phishing", Provider: "spamhaus_dbl"},
				{Listed: false, Provider: "surbl"},
			},
			wantScore: 35,
			wantRisk:  "medium",
		},
		{
			name: "single listing - URIBL grey (low)",
			providers: []*ProviderResult{
				{Listed: false, Provider: "spamhaus_dbl"},
				{Listed: true, Category: "grey", Provider: "uribl"},
			},
			wantScore: 5,
			wantRisk:  "low",
		},
		{
			name: "multiple listings",
			providers: []*ProviderResult{
				{Listed: true, Category: "malware", Provider: "spamhaus_dbl"},
				{Listed: true, Category: "malware", Provider: "surbl"},
				{Listed: false, Provider: "uribl"},
				{Listed: false, Provider: "spamhaus_zen"},
			},
			wantScore: 70,
			wantRisk:  "high",
		},
		{
			name: "cap at 100",
			providers: []*ProviderResult{
				{Listed: true, Category: "malware", Provider: "spamhaus_dbl"},      // 40
				{Listed: true, Category: "malware", Provider: "surbl"},             // 30
				{Listed: true, Category: "red", Provider: "uribl"},                 // 20
				{Listed: true, Category: "xbl_exploits", Provider: "spamhaus_zen"}, // 20
			},
			wantScore: 100,
			wantRisk:  "high",
		},
		{
			name: "boundary - score 29 is low",
			providers: []*ProviderResult{
				{Listed: true, Category: "spam", Provider: "spamhaus_dbl"}, // 25
			},
			wantScore: 25,
			wantRisk:  "low",
		},
		{
			name: "boundary - score 30 is medium",
			providers: []*ProviderResult{
				{Listed: true, Category: "spam", Provider: "spamhaus_dbl"}, // 25
				{Listed: true, Category: "grey", Provider: "uribl"},        // 5
			},
			wantScore: 30,
			wantRisk:  "medium",
		},
		{
			name: "boundary - score 60 is high",
			providers: []*ProviderResult{
				{Listed: true, Category: "phishing", Provider: "spamhaus_dbl"}, // 35
				{Listed: true, Category: "spam", Provider: "uribl"},            // 15
				{Listed: true, Category: "suspicious", Provider: "surbl"},      // 10
			},
			wantScore: 60,
			wantRisk:  "high",
		},
		{
			name: "SURBL stacking - malware+abuse",
			providers: []*ProviderResult{
				{Listed: true, Category: "abuse+malware", Provider: "surbl"}, // 15+30=45
			},
			wantScore: 45,
			wantRisk:  "medium",
		},
		{
			name:      "nil providers",
			providers: nil,
			wantScore: 0,
			wantRisk:  "clean",
		},
		{
			name:      "empty providers",
			providers: []*ProviderResult{},
			wantScore: 0,
			wantRisk:  "clean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, risk := ScoreReputation(tt.providers)
			if score != tt.wantScore {
				t.Errorf("ScoreReputation() score = %d, want %d", score, tt.wantScore)
			}
			if risk != tt.wantRisk {
				t.Errorf("ScoreReputation() risk = %q, want %q", risk, tt.wantRisk)
			}
		})
	}
}
