package domain

import (
	"sync"
	"testing"
)

func TestDefaultRules(t *testing.T) {
	rules, err := DefaultRules()
	if err != nil {
		t.Fatalf("DefaultRules() error: %v", err)
	}
	if len(rules) < 50 {
		t.Errorf("expected at least 50 default rules, got %d", len(rules))
	}
	for i, r := range rules {
		if r.Name == "" {
			t.Errorf("rule %d: name is empty", i)
		}
		if !ValidCategories[r.Category] {
			t.Errorf("rule %d (%s): invalid category %q", i, r.Name, r.Category)
		}
	}
}

func TestMatch_NginxHeader(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Nginx", Category: "web-server", Headers: map[string]string{"Server": "nginx"}},
	})

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers:    map[string]string{"Server": "nginx/1.24.0"},
	})

	if result.Count != 1 {
		t.Fatalf("Count = %d, want 1", result.Count)
	}
	m := result.Technologies[0]
	if m.Name != "Nginx" {
		t.Errorf("Name = %q, want %q", m.Name, "Nginx")
	}
	if m.Category != "web-server" {
		t.Errorf("Category = %q, want %q", m.Category, "web-server")
	}
	if m.Version != "1.24.0" {
		t.Errorf("Version = %q, want %q", m.Version, "1.24.0")
	}
	if m.Confidence != "header" {
		t.Errorf("Confidence = %q, want %q", m.Confidence, "header")
	}
}

func TestMatch_CaseInsensitive(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Nginx", Category: "web-server", Headers: map[string]string{"Server": "nginx"}},
	})

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers:    map[string]string{"server": "NGINX/1.18.0"},
	})

	if result.Count != 1 {
		t.Fatalf("Count = %d, want 1", result.Count)
	}
	if result.Technologies[0].Name != "Nginx" {
		t.Errorf("Name = %q, want %q", result.Technologies[0].Name, "Nginx")
	}
}

func TestMatch_HeaderExists(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Cloudflare", Category: "cdn", Headers: map[string]string{"CF-RAY": ""}},
	})

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers:    map[string]string{"CF-RAY": "abc123-IAD"},
	})

	if result.Count != 1 {
		t.Fatalf("Count = %d, want 1", result.Count)
	}
	if result.Technologies[0].Name != "Cloudflare" {
		t.Errorf("Name = %q, want %q", result.Technologies[0].Name, "Cloudflare")
	}
	// version should be empty for exists-only match
	if result.Technologies[0].Version != "" {
		t.Errorf("Version = %q, want empty", result.Technologies[0].Version)
	}
}

func TestMatch_CookieMatch(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "PHP", Category: "language", Cookies: []string{"PHPSESSID"}},
	})

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers:    map[string]string{"Set-Cookie": "PHPSESSID=abc123; path=/"},
	})

	if result.Count != 1 {
		t.Fatalf("Count = %d, want 1", result.Count)
	}
	if result.Technologies[0].Name != "PHP" {
		t.Errorf("Name = %q, want %q", result.Technologies[0].Name, "PHP")
	}
	if result.Technologies[0].Confidence != "cookie" {
		t.Errorf("Confidence = %q, want %q", result.Technologies[0].Confidence, "cookie")
	}
}

func TestMatch_MultipleMatches(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Nginx", Category: "web-server", Headers: map[string]string{"Server": "nginx"}},
		{Name: "PHP", Category: "language", Headers: map[string]string{"X-Powered-By": "PHP"}},
		{Name: "Apache", Category: "web-server", Headers: map[string]string{"Server": "Apache"}},
	})

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers: map[string]string{
			"Server":       "nginx/1.24.0",
			"X-Powered-By": "PHP/8.2.1",
		},
	})

	if result.Count != 2 {
		t.Fatalf("Count = %d, want 2", result.Count)
	}

	names := make(map[string]bool)
	for _, m := range result.Technologies {
		names[m.Name] = true
	}
	if !names["Nginx"] {
		t.Error("expected Nginx in matches")
	}
	if !names["PHP"] {
		t.Error("expected PHP in matches")
	}
	if names["Apache"] {
		t.Error("Apache should not match")
	}
}

func TestMatch_Deduplicate(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Cloudflare", Category: "cdn", Headers: map[string]string{"Server": "cloudflare"}},
		{Name: "Cloudflare", Category: "cdn", Headers: map[string]string{"CF-RAY": ""}},
	})

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers: map[string]string{
			"Server": "cloudflare",
			"CF-RAY": "abc123",
		},
	})

	if result.Count != 1 {
		t.Fatalf("Count = %d, want 1 (deduplicated)", result.Count)
	}
}

func TestMatch_NoMatch(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Nginx", Category: "web-server", Headers: map[string]string{"Server": "nginx"}},
	})

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers:    map[string]string{"Server": "Apache/2.4.52"},
	})

	if result.Count != 0 {
		t.Fatalf("Count = %d, want 0", result.Count)
	}
	if len(result.Technologies) != 0 {
		t.Errorf("Technologies should be empty, got %v", result.Technologies)
	}
}

func TestMatch_NilHeaders(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Nginx", Category: "web-server", Headers: map[string]string{"Server": "nginx"}},
	})

	result := engine.Match(nil)
	if result.Count != 0 {
		t.Fatalf("Count = %d, want 0 for nil headers", result.Count)
	}
}

func TestMatch_EmptyHeaders(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Nginx", Category: "web-server", Headers: map[string]string{"Server": "nginx"}},
	})

	result := engine.Match(&HeadersInfo{StatusCode: 200, Headers: map[string]string{}})
	if result.Count != 0 {
		t.Fatalf("Count = %d, want 0 for empty headers", result.Count)
	}
}

func TestMatch_NoRules(t *testing.T) {
	engine := NewFingerprintEngine()

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers:    map[string]string{"Server": "nginx/1.24.0"},
	})

	if result.Count != 0 {
		t.Fatalf("Count = %d, want 0 with no rules", result.Count)
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nginx/1.24.0", "1.24.0"},
		{"PHP/8.2.1", "8.2.1"},
		{"Apache/2.4.52 (Ubuntu)", "2.4.52"},
		{"Microsoft-IIS/10.0", "10.0"},
		{"cloudflare", ""},
		{"", ""},
		{"Express", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractVersion(tt.input)
			if got != tt.want {
				t.Errorf("extractVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoadRules_Atomicity(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Old", Category: "web-server"},
	})

	if engine.RuleCount() != 1 {
		t.Fatalf("RuleCount = %d, want 1", engine.RuleCount())
	}

	engine.LoadRules([]TechRule{
		{Name: "New1", Category: "cdn"},
		{Name: "New2", Category: "cdn"},
	})

	if engine.RuleCount() != 2 {
		t.Fatalf("RuleCount = %d, want 2 after reload", engine.RuleCount())
	}

	rules := engine.Rules()
	if rules[0].Name != "New1" {
		t.Errorf("Rules()[0].Name = %q, want %q", rules[0].Name, "New1")
	}
}

func TestLoadRules_ConcurrentSafety(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{Name: "Nginx", Category: "web-server", Headers: map[string]string{"Server": "nginx"}},
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := engine.Match(&HeadersInfo{
				StatusCode: 200,
				Headers:    map[string]string{"Server": "nginx/1.24.0"},
			})
			if result == nil {
				t.Error("expected non-nil result")
			}
		}()
	}
	wg.Wait()
}

func TestHeaderPreferredOverCookie(t *testing.T) {
	engine := NewFingerprintEngine()
	engine.LoadRules([]TechRule{
		{
			Name:     "PHP",
			Category: "language",
			Headers:  map[string]string{"X-Powered-By": "PHP"},
			Cookies:  []string{"PHPSESSID"},
		},
	})

	result := engine.Match(&HeadersInfo{
		StatusCode: 200,
		Headers: map[string]string{
			"X-Powered-By": "PHP/8.2",
			"Set-Cookie":   "PHPSESSID=abc; path=/",
		},
	})

	if result.Count != 1 {
		t.Fatalf("Count = %d, want 1", result.Count)
	}
	// Header match takes precedence over cookie
	if result.Technologies[0].Confidence != "header" {
		t.Errorf("Confidence = %q, want %q", result.Technologies[0].Confidence, "header")
	}
}
