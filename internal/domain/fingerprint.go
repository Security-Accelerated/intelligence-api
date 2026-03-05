package domain

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed fingerprint_rules.json
var defaultRulesJSON []byte

// ValidCategories lists the allowed technology categories.
var ValidCategories = map[string]bool{
	"web-server": true,
	"language":   true,
	"framework":  true,
	"cdn":        true,
	"cms":        true,
	"analytics":  true,
	"security":   true,
	"hosting":    true,
	"cache":      true,
	"javascript": true,
	"other":      true,
}

// TechRule describes a single technology fingerprint rule.
type TechRule struct {
	Name     string            `json:"name"`
	Category string            `json:"category"`
	Website  string            `json:"website,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Cookies  []string          `json:"cookies,omitempty"`
}

// FingerprintMatch represents a single detected technology.
type FingerprintMatch struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
	Confidence string `json:"confidence"`
}

// FingerprintInfo holds the complete fingerprint result for a domain.
type FingerprintInfo struct {
	Count        int                `json:"count"`
	Technologies []FingerprintMatch `json:"technologies"`
}

// versionRegexp extracts a version number after a name separator (/ or space).
var versionRegexp = regexp.MustCompile(`[\s/](\d[\d.]*)`)

// FingerprintEngine holds rules behind a RWMutex and provides thread-safe matching.
type FingerprintEngine struct {
	mu    sync.RWMutex
	rules []TechRule
}

// NewFingerprintEngine creates an engine with no rules loaded.
func NewFingerprintEngine() *FingerprintEngine {
	return &FingerprintEngine{}
}

// LoadRules atomically replaces the current ruleset.
func (e *FingerprintEngine) LoadRules(rules []TechRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// Rules returns a copy of the current ruleset.
func (e *FingerprintEngine) Rules() []TechRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]TechRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// RuleCount returns the number of loaded rules.
func (e *FingerprintEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Match runs all rules against the provided headers and returns detected technologies.
func (e *FingerprintEngine) Match(headers *HeadersInfo) *FingerprintInfo {
	if headers == nil || len(headers.Headers) == 0 {
		return &FingerprintInfo{Technologies: []FingerprintMatch{}}
	}

	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	// Build a lowercase header map for case-insensitive matching.
	lowerHeaders := make(map[string]string, len(headers.Headers))
	for k, v := range headers.Headers {
		lowerHeaders[strings.ToLower(k)] = v
	}

	// Extract Set-Cookie values for cookie matching.
	setCookieVal := lowerHeaders["set-cookie"]

	seen := make(map[string]bool)
	var matches []FingerprintMatch

	for _, rule := range rules {
		if seen[rule.Name] {
			continue
		}

		if m, ok := matchHeaders(rule, lowerHeaders); ok {
			seen[rule.Name] = true
			matches = append(matches, m)
			continue
		}

		if m, ok := matchCookies(rule, setCookieVal); ok {
			seen[rule.Name] = true
			matches = append(matches, m)
		}
	}

	return &FingerprintInfo{
		Count:        len(matches),
		Technologies: matches,
	}
}

// matchHeaders checks if any of the rule's header patterns match.
// Returns the match and true if found.
func matchHeaders(rule TechRule, lowerHeaders map[string]string) (FingerprintMatch, bool) {
	for headerName, pattern := range rule.Headers {
		val, exists := lowerHeaders[strings.ToLower(headerName)]
		if !exists {
			continue
		}
		// Empty pattern means "header exists (any value)".
		if pattern == "" {
			return FingerprintMatch{
				Name:       rule.Name,
				Category:   rule.Category,
				Confidence: "header",
			}, true
		}
		if strings.Contains(strings.ToLower(val), strings.ToLower(pattern)) {
			return FingerprintMatch{
				Name:       rule.Name,
				Category:   rule.Category,
				Version:    extractVersion(val),
				Confidence: "header",
			}, true
		}
	}
	return FingerprintMatch{}, false
}

// matchCookies checks if any of the rule's cookie name patterns appear in Set-Cookie values.
func matchCookies(rule TechRule, setCookieVal string) (FingerprintMatch, bool) {
	if setCookieVal == "" || len(rule.Cookies) == 0 {
		return FingerprintMatch{}, false
	}
	lowerCookie := strings.ToLower(setCookieVal)
	for _, cookieName := range rule.Cookies {
		if strings.Contains(lowerCookie, strings.ToLower(cookieName)) {
			return FingerprintMatch{
				Name:       rule.Name,
				Category:   rule.Category,
				Confidence: "cookie",
			}, true
		}
	}
	return FingerprintMatch{}, false
}

// extractVersion attempts to extract a version number from a header value.
// Examples: "nginx/1.24.0" → "1.24.0", "PHP/8.2.1" → "8.2.1".
func extractVersion(val string) string {
	m := versionRegexp.FindStringSubmatch(val)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// DefaultRules parses and returns the embedded default rules.
func DefaultRules() ([]TechRule, error) {
	var rules []TechRule
	if err := json.Unmarshal(defaultRulesJSON, &rules); err != nil {
		return nil, fmt.Errorf("parse embedded fingerprint rules: %w", err)
	}
	return rules, nil
}
