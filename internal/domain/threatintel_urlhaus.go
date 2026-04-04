package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// URLhausProvider queries the Abuse.ch URLhaus API. No API key required.
type URLhausProvider struct {
	client  *http.Client
	limiter *rate.Limiter
}

// NewURLhausProvider creates a provider with a generous rate limiter (5 req/s).
func NewURLhausProvider() *URLhausProvider {
	return &URLhausProvider{
		client: &http.Client{
			Transport: trustedTransport,
			Timeout:   10 * time.Second,
		},
		limiter: rate.NewLimiter(rate.Limit(5), 1),
	}
}

func (p *URLhausProvider) Name() string { return "urlhaus" }

func (p *URLhausProvider) Query(ctx context.Context, domain string) (*ThreatIntelProviderResult, error) {
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("urlhaus rate limit: %w", err)
	}

	apiURL := "https://urlhaus-api.abuse.ch/v1/host/"
	form := url.Values{"host": {domain}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("urlhaus: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlhaus: HTTP %d", resp.StatusCode)
	}

	var body struct {
		QueryStatus string `json:"query_status"`
		URLCount    int    `json:"url_count"`
		URLs        []struct {
			Threat  string   `json:"threat"`
			Tags    []string `json:"tags"`
			URLStatus string `json:"url_status"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("urlhaus: decode: %w", err)
	}

	if body.QueryStatus == "no_results" {
		return &ThreatIntelProviderResult{
			Provider: "urlhaus",
			Detected: false,
		}, nil
	}

	// Domain is listed — extract threat types and tags.
	categorySet := make(map[string]struct{})
	for _, u := range body.URLs {
		if u.Threat != "" {
			categorySet[u.Threat] = struct{}{}
		}
		for _, tag := range u.Tags {
			if tag != "" {
				categorySet[tag] = struct{}{}
			}
		}
	}
	var categories []string
	for cat := range categorySet {
		categories = append(categories, cat)
	}

	// Score based on URL count: more malicious URLs = higher score.
	score := 0
	switch {
	case body.URLCount >= 10:
		score = 90
	case body.URLCount >= 5:
		score = 70
	case body.URLCount >= 1:
		score = 50
	}

	details := fmt.Sprintf("%d malicious URLs associated with this domain", body.URLCount)

	return &ThreatIntelProviderResult{
		Provider:   "urlhaus",
		Detected:   true,
		Score:      score,
		Categories: categories,
		Details:    details,
	}, nil
}
