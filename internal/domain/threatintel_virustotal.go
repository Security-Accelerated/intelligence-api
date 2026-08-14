package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// VirusTotalProvider queries the VirusTotal v3 API for domain reputation data.
type VirusTotalProvider struct {
	apiKey  string
	client  *http.Client
	limiter *rate.Limiter
}

// NewVirusTotalProvider creates a provider with a rate limiter matching the VT
// free tier (4 requests/minute → 1 request per 15 seconds).
func NewVirusTotalProvider(apiKey string) *VirusTotalProvider {
	return &VirusTotalProvider{
		apiKey: apiKey,
		client: &http.Client{
			Transport: trustedTransport,
			Timeout:   15 * time.Second,
		},
		limiter: rate.NewLimiter(rate.Every(15*time.Second), 1),
	}
}

func (p *VirusTotalProvider) Name() string { return "virustotal" }

func (p *VirusTotalProvider) Query(ctx context.Context, domain string) (*ThreatIntelProviderResult, error) {
	// Wait, not Allow: a rate-limited provider has no opinion about this
	// domain, and reporting "not detected" would be a verdict we never
	// obtained. ScoreThreatIntel weights VirusTotal at 0.50, so a skipped
	// result returned as clean actively drags the composite toward safe. The
	// coordinator excludes errored providers from scoring, so an error here is
	// the honest answer; ctx bounds the wait.
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("virustotal rate limit: %w", err)
	}

	url := "https://www.virustotal.com/api/v3/domains/" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("virustotal: build request: %w", err)
	}
	req.Header.Set("x-apikey", p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal: HTTP %d", resp.StatusCode)
	}

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
		return nil, fmt.Errorf("virustotal: decode: %w", err)
	}

	stats := body.Data.Attributes.LastAnalysisStats
	totalEngines := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected
	detected := stats.Malicious + stats.Suspicious
	detectedBool := detected > 0

	// Normalize score to 0–100 based on detection ratio.
	score := 0
	if totalEngines > 0 {
		score = detected * 100 / totalEngines
	}

	// Collect unique categories from VT's category mappings.
	categorySet := make(map[string]struct{})
	for _, cat := range body.Data.Attributes.Categories {
		categorySet[cat] = struct{}{}
	}
	var categories []string
	for cat := range categorySet {
		categories = append(categories, cat)
	}

	details := fmt.Sprintf("%d/%d engines detected this domain", detected, totalEngines)

	return &ThreatIntelProviderResult{
		Provider:   "virustotal",
		Detected:   detectedBool,
		Score:      score,
		Categories: categories,
		Details:    details,
	}, nil
}
