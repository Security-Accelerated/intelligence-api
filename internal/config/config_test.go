package config

import (
	"testing"
	"time"
)

func TestConfig_ReturnsNonNil(t *testing.T) {
	cfg := Config()
	if cfg == nil {
		t.Fatal("Config() returned nil")
	}
}

func TestConfig_Defaults(t *testing.T) {
	cfg := Config()

	tests := []struct {
		key  string
		want any
	}{
		{"application.port", 8080},
		{"redis.cache_ttl", "60m"},
		{"auth.cache_ttl", "5m"},
		{"screenshot.timeout", "15s"},
		{"typosquatting.timeout", "30s"},
		{"typosquatting.max_permutations", 500},
		{"typosquatting.concurrency", 20},
		{"domain.max_domains.basic", 5},
		{"domain.max_domains.premium", 20},
		{"typosquatting.max_domains.basic", 3},
		{"typosquatting.max_domains.premium", 5},
		{"subdomain.timeout", "30s"},
		{"subdomain.max_results", 500},
		{"ct_logs.max_entries", 100},
		{"subdomain.concurrency", 20},
		{"subdomain.max_domains.basic", 3},
		{"subdomain.max_domains.premium", 5},
		{"rate_limit.basic", 30},
		{"rate_limit.premium", 120},
		// postgres.sslmode default is "require" but local config files may override it
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := cfg.Get(tt.key)
			if got != tt.want {
				t.Errorf("Config().Get(%q) = %v (%T), want %v (%T)", tt.key, got, got, tt.want, tt.want)
			}
		})
	}
}

func TestConfig_ApplicationName(t *testing.T) {
	cfg := Config()
	name := cfg.GetString("application.name")
	if name != "intelligence-api" {
		t.Errorf("application.name = %q, want %q", name, "intelligence-api")
	}
}

func TestConfig_StartTime(t *testing.T) {
	cfg := Config()
	start := cfg.GetTime("application.start.time")
	if start.IsZero() {
		t.Error("application.start.time is zero")
	}
	// Should be set during init(), so it should be in the past or very recent
	if time.Since(start) > 10*time.Minute {
		t.Errorf("application.start.time is too old: %v", start)
	}
}

func TestConfig_SessionID(t *testing.T) {
	cfg := Config()
	session := cfg.GetString("application.session.id")
	if session == "" {
		t.Error("application.session.id is empty")
	}
	// Should be a UUID format (36 chars with hyphens)
	if len(session) != 36 {
		t.Errorf("application.session.id length = %d, want 36 (UUID)", len(session))
	}
}

func TestConfig_EnvironmentInfo(t *testing.T) {
	cfg := Config()

	host := cfg.GetString("environment.host")
	if host == "" {
		t.Error("environment.host is empty")
	}

	goVer := cfg.GetString("environment.golang.version")
	if goVer == "" {
		t.Error("environment.golang.version is empty")
	}

	arch := cfg.GetString("environment.architecture")
	if arch == "" {
		t.Error("environment.architecture is empty")
	}

	osStr := cfg.GetString("environment.os")
	if osStr == "" {
		t.Error("environment.os is empty")
	}
}

func TestCharsToString(t *testing.T) {
	tests := []struct {
		name  string
		input []int8
		want  string
	}{
		{"normal", []int8{104, 101, 108, 108, 111, 0, 0, 0}, "hello"},
		{"no null", []int8{104, 105}, "hi"},
		{"empty", []int8{0}, ""},
		{"all zeros", []int8{0, 0, 0}, ""},
		{"nil", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := charsToString(tt.input)
			if got != tt.want {
				t.Errorf("charsToString(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
