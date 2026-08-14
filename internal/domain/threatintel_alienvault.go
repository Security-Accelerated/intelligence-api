package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// AlienVaultProvider queries the AlienVault OTX API for community threat pulses.
type AlienVaultProvider struct {
	apiKey  string
	client  *http.Client
	limiter *rate.Limiter
}

// NewAlienVaultProvider creates a provider with a rate limiter of 10 req/s.
func NewAlienVaultProvider(apiKey string) *AlienVaultProvider {
	return &AlienVaultProvider{
		apiKey: apiKey,
		client: &http.Client{
			Transport: trustedTransport,
			Timeout:   10 * time.Second,
		},
		limiter: rate.NewLimiter(rate.Limit(10), 1),
	}
}

func (p *AlienVaultProvider) Name() string { return "alienvault_otx" }

func (p *AlienVaultProvider) Query(ctx context.Context, domain string) (*ThreatIntelProviderResult, error) {
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("alienvault_otx rate limit: %w", err)
	}

	url := "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/general"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("alienvault_otx: build request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("alienvault_otx: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alienvault_otx: HTTP %d", resp.StatusCode)
	}

	var body struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Tags []string `json:"tags"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("alienvault_otx: decode: %w", err)
	}

	pulseCount := body.PulseInfo.Count
	if pulseCount == 0 {
		return &ThreatIntelProviderResult{
			Provider: "alienvault_otx",
			Detected: false,
		}, nil
	}

	// Collect unique tags from all pulses.
	categorySet := make(map[string]struct{})
	for _, pulse := range body.PulseInfo.Pulses {
		for _, tag := range pulse.Tags {
			if tag != "" {
				categorySet[tag] = struct{}{}
			}
		}
	}
	var categories []string
	for cat := range categorySet {
		categories = append(categories, cat)
	}

	// Score based on pulse count.
	score := 0
	switch {
	case pulseCount >= 20:
		score = 80
	case pulseCount >= 10:
		score = 60
	case pulseCount >= 5:
		score = 40
	case pulseCount >= 1:
		score = 20
	}

	details := fmt.Sprintf("%d threat pulses reference this domain", pulseCount)

	return &ThreatIntelProviderResult{
		Provider:   "alienvault_otx",
		Detected:   true,
		Score:      score,
		Categories: categories,
		Details:    details,
	}, nil
}
