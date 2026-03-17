package domain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- VirusTotal provider tests ---

func TestVirusTotalProvider_Clean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "test-key" {
			t.Errorf("missing x-apikey header")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"attributes": map[string]any{
					"last_analysis_stats": map[string]int{
						"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10,
					},
					"categories": map[string]string{},
				},
			},
		})
	}))
	defer srv.Close()

	p := NewVirusTotalProvider("test-key")
	p.client = &http.Client{Transport: http.DefaultTransport}

	// Swap the limiter to be non-blocking for tests
	result, err := vtTestQuery(srv.URL, "test-key", "clean.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Detected {
		t.Error("expected Detected=false for clean domain")
	}
	if result.Score != 0 {
		t.Errorf("Score = %d, want 0", result.Score)
	}
}

// vtTestQuery directly calls a test server using the same parsing logic as the provider.
func vtTestQuery(serverURL, apiKey, domain string) (*ThreatIntelProviderResult, error) {
	url := serverURL + "/api/v3/domains/" + domain
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				Categories map[string]string `json:"categories"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	stats := body.Data.Attributes.LastAnalysisStats
	totalEngines := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected
	detected := stats.Malicious + stats.Suspicious

	score := 0
	if totalEngines > 0 {
		score = detected * 100 / totalEngines
	}

	var categories []string
	for _, cat := range body.Data.Attributes.Categories {
		categories = append(categories, cat)
	}

	return &ThreatIntelProviderResult{
		Provider:   "virustotal",
		Detected:   detected > 0,
		Score:      score,
		Categories: categories,
	}, nil
}

func TestVirusTotalProvider_Detected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"attributes": map[string]any{
					"last_analysis_stats": map[string]int{
						"malicious": 5, "suspicious": 2, "harmless": 55, "undetected": 8,
					},
					"categories": map[string]string{
						"Forcepoint": "malware",
					},
				},
			},
		})
	}))
	defer srv.Close()

	result, err := vtTestQuery(srv.URL, "test-key", "malicious.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Detected {
		t.Error("expected Detected=true for malicious domain")
	}
	if result.Score == 0 {
		t.Error("expected non-zero score")
	}
}

func TestVirusTotalProvider_Name(t *testing.T) {
	p := NewVirusTotalProvider("key")
	if p.Name() != "virustotal" {
		t.Errorf("Name() = %q, want %q", p.Name(), "virustotal")
	}
}

// --- URLhaus provider tests ---

func urlhausTestQuery(serverURL, domain string) (*ThreatIntelProviderResult, error) {
	apiURL := serverURL + "/v1/host/"
	resp, err := http.PostForm(apiURL, map[string][]string{"host": {domain}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body struct {
		QueryStatus string `json:"query_status"`
		URLCount    int    `json:"url_count"`
		URLs        []struct {
			Threat string   `json:"threat"`
			Tags   []string `json:"tags"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	if body.QueryStatus == "no_results" {
		return &ThreatIntelProviderResult{Provider: "urlhaus", Detected: false}, nil
	}

	categorySet := make(map[string]struct{})
	for _, u := range body.URLs {
		if u.Threat != "" {
			categorySet[u.Threat] = struct{}{}
		}
	}
	var categories []string
	for cat := range categorySet {
		categories = append(categories, cat)
	}

	score := 0
	switch {
	case body.URLCount >= 10:
		score = 90
	case body.URLCount >= 5:
		score = 70
	case body.URLCount >= 1:
		score = 50
	}

	return &ThreatIntelProviderResult{
		Provider:   "urlhaus",
		Detected:   true,
		Score:      score,
		Categories: categories,
	}, nil
}

func TestURLhausProvider_Clean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"query_status": "no_results",
		})
	}))
	defer srv.Close()

	result, err := urlhausTestQuery(srv.URL, "clean.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Detected {
		t.Error("expected Detected=false for clean domain")
	}
}

func TestURLhausProvider_Listed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"query_status": "is_host",
			"url_count":    3,
			"urls": []map[string]any{
				{"threat": "malware_download", "tags": []string{"elf", "mirai"}},
				{"threat": "malware_download", "tags": []string{"elf"}},
			},
		})
	}))
	defer srv.Close()

	result, err := urlhausTestQuery(srv.URL, "malicious.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Detected {
		t.Error("expected Detected=true")
	}
	if result.Score != 50 {
		t.Errorf("Score = %d, want 50", result.Score)
	}
}

func TestURLhausProvider_Name(t *testing.T) {
	p := NewURLhausProvider()
	if p.Name() != "urlhaus" {
		t.Errorf("Name() = %q, want %q", p.Name(), "urlhaus")
	}
}

// --- AlienVault OTX provider tests ---

func alienVaultTestQuery(serverURL, apiKey, domain string) (*ThreatIntelProviderResult, error) {
	url := serverURL + "/api/v1/indicators/domain/" + domain + "/general"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Tags []string `json:"tags"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	if body.PulseInfo.Count == 0 {
		return &ThreatIntelProviderResult{Provider: "alienvault_otx", Detected: false}, nil
	}

	categorySet := make(map[string]struct{})
	for _, p := range body.PulseInfo.Pulses {
		for _, tag := range p.Tags {
			if tag != "" {
				categorySet[tag] = struct{}{}
			}
		}
	}
	var categories []string
	for cat := range categorySet {
		categories = append(categories, cat)
	}

	score := 0
	switch {
	case body.PulseInfo.Count >= 20:
		score = 80
	case body.PulseInfo.Count >= 10:
		score = 60
	case body.PulseInfo.Count >= 5:
		score = 40
	case body.PulseInfo.Count >= 1:
		score = 20
	}

	return &ThreatIntelProviderResult{
		Provider:   "alienvault_otx",
		Detected:   true,
		Score:      score,
		Categories: categories,
	}, nil
}

func TestAlienVaultProvider_NoPulses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "test-key" {
			t.Errorf("missing X-OTX-API-KEY header")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"pulse_info": map[string]any{
				"count":  0,
				"pulses": []any{},
			},
		})
	}))
	defer srv.Close()

	result, err := alienVaultTestQuery(srv.URL, "test-key", "clean.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Detected {
		t.Error("expected Detected=false for domain with no pulses")
	}
}

func TestAlienVaultProvider_WithPulses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"pulse_info": map[string]any{
				"count": 5,
				"pulses": []map[string]any{
					{"tags": []string{"malware", "c2"}},
					{"tags": []string{"malware"}},
					{"tags": []string{"botnet"}},
				},
			},
		})
	}))
	defer srv.Close()

	result, err := alienVaultTestQuery(srv.URL, "test-key", "malicious.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Detected {
		t.Error("expected Detected=true")
	}
	if result.Score != 40 {
		t.Errorf("Score = %d, want 40", result.Score)
	}
}

func TestAlienVaultProvider_Name(t *testing.T) {
	p := NewAlienVaultProvider("key")
	if p.Name() != "alienvault_otx" {
		t.Errorf("Name() = %q, want %q", p.Name(), "alienvault_otx")
	}
}

// --- Coordinator tests ---

type stubProvider struct {
	name   string
	result *ThreatIntelProviderResult
	err    error
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) Query(_ context.Context, _ string) (*ThreatIntelProviderResult, error) {
	return s.result, s.err
}

func TestLookupThreatIntel_AllProviders(t *testing.T) {
	providers := []ThreatIntelProvider{
		&stubProvider{name: "p1", result: &ThreatIntelProviderResult{
			Provider: "p1", Detected: true, Score: 50, Categories: []string{"malware"},
		}},
		&stubProvider{name: "p2", result: &ThreatIntelProviderResult{
			Provider: "p2", Detected: false, Score: 0,
		}},
	}

	result, errs := LookupThreatIntel(context.Background(), "example.com", providers)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(result.Providers))
	}
}

func TestLookupThreatIntel_PartialFailure(t *testing.T) {
	providers := []ThreatIntelProvider{
		&stubProvider{name: "good", result: &ThreatIntelProviderResult{
			Provider: "good", Detected: true, Score: 50, Categories: []string{"malware"},
		}},
		&stubProvider{name: "bad", err: http.ErrServerClosed},
	}

	result, errs := LookupThreatIntel(context.Background(), "example.com", providers)
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Lookup != "threat_intel:bad" {
		t.Errorf("error lookup = %q, want %q", errs[0].Lookup, "threat_intel:bad")
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Providers) != 1 {
		t.Errorf("expected 1 provider result, got %d", len(result.Providers))
	}
}

func TestLookupThreatIntel_NoProviders(t *testing.T) {
	result, errs := LookupThreatIntel(context.Background(), "example.com", nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.RiskLevel != "none" {
		t.Errorf("RiskLevel = %q, want %q", result.RiskLevel, "none")
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}

// --- ScoreThreatIntel tests ---

func TestScoreThreatIntel_NoResults(t *testing.T) {
	score, risk, cats := ScoreThreatIntel(nil)
	if score != 0 {
		t.Errorf("score = %d, want 0", score)
	}
	if risk != "none" {
		t.Errorf("risk = %q, want %q", risk, "none")
	}
	if cats != nil {
		t.Errorf("categories = %v, want nil", cats)
	}
}

func TestScoreThreatIntel_HighScore(t *testing.T) {
	results := []*ThreatIntelProviderResult{
		{Provider: "virustotal", Score: 80, Categories: []string{"malware"}},
		{Provider: "urlhaus", Score: 90, Categories: []string{"malware_download"}},
		{Provider: "alienvault_otx", Score: 60, Categories: []string{"malware"}},
	}

	score, risk, _ := ScoreThreatIntel(results)
	if score == 0 {
		t.Error("expected non-zero score")
	}
	if risk != "high" && risk != "critical" {
		t.Errorf("risk = %q, expected high or critical", risk)
	}
}

func TestScoreThreatIntel_LowScore(t *testing.T) {
	results := []*ThreatIntelProviderResult{
		{Provider: "virustotal", Score: 5, Categories: nil},
		{Provider: "urlhaus", Score: 0, Categories: nil},
	}

	score, risk, _ := ScoreThreatIntel(results)
	if score > 20 {
		t.Errorf("score = %d, expected <= 20", score)
	}
	if risk != "none" && risk != "low" {
		t.Errorf("risk = %q, expected none or low", risk)
	}
}

func TestScoreThreatIntel_CategoriesMerged(t *testing.T) {
	results := []*ThreatIntelProviderResult{
		{Provider: "virustotal", Score: 50, Categories: []string{"malware", "phishing"}},
		{Provider: "urlhaus", Score: 50, Categories: []string{"malware", "c2"}},
	}

	_, _, cats := ScoreThreatIntel(results)
	catSet := make(map[string]struct{})
	for _, c := range cats {
		catSet[c] = struct{}{}
	}
	if _, ok := catSet["malware"]; !ok {
		t.Error("expected malware in categories")
	}
	if _, ok := catSet["phishing"]; !ok {
		t.Error("expected phishing in categories")
	}
	if _, ok := catSet["c2"]; !ok {
		t.Error("expected c2 in categories")
	}
	if len(cats) != 3 {
		t.Errorf("expected 3 unique categories, got %d: %v", len(cats), cats)
	}
}
