package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// IPThreatIntelProvider queries a threat intelligence source for IP-specific data.
type IPThreatIntelProvider interface {
	Name() string
	QueryIP(ctx context.Context, ip string) (*ThreatIntelProviderResult, error)
}

// LookupIPThreatIntel queries all IP threat intel providers concurrently and
// returns an aggregated result. Same pattern as LookupThreatIntel for domains.
func LookupIPThreatIntel(ctx context.Context, ip string, providers []IPThreatIntelProvider) (*ThreatIntelInfo, []LookupError) {
	if len(providers) == 0 {
		return &ThreatIntelInfo{
			RiskLevel: "none",
			Score:     0,
			Providers: []*ThreatIntelProviderResult{},
		}, []LookupError{{Lookup: "threat_intel", Message: "no threat intelligence providers configured"}}
	}

	type providerResult struct {
		result *ThreatIntelProviderResult
		err    error
		name   string
	}

	ch := make(chan providerResult, len(providers))
	var wg sync.WaitGroup
	wg.Add(len(providers))

	for _, p := range providers {
		go func(p IPThreatIntelProvider) {
			defer wg.Done()
			r, err := p.QueryIP(ctx, ip)
			ch <- providerResult{result: r, err: err, name: p.Name()}
		}(p)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var results []*ThreatIntelProviderResult
	var errs []LookupError
	for pr := range ch {
		if pr.err != nil {
			msg := pr.err.Error()
			if i := strings.LastIndex(msg, ": "); i != -1 {
				msg = msg[i+2:]
			}
			errs = append(errs, LookupError{
				Lookup:  "threat_intel:" + pr.name,
				Message: msg,
			})
			continue
		}
		results = append(results, pr.result)
	}

	score, riskLevel, categories := ScoreThreatIntel(results)
	return &ThreatIntelInfo{
		RiskLevel:  riskLevel,
		Score:      score,
		Categories: categories,
		Providers:  results,
	}, errs
}

// --- IP-specific provider adapters ---
// These wrap the existing provider instances, sharing their HTTP clients and
// rate limiters, but hit IP-specific API endpoints.

// VTIPProvider adapts VirusTotalProvider for IP lookups.
type VTIPProvider struct {
	inner *VirusTotalProvider
}

func NewVTIPProvider(inner *VirusTotalProvider) *VTIPProvider {
	return &VTIPProvider{inner: inner}
}

func (p *VTIPProvider) Name() string { return "virustotal" }

func (p *VTIPProvider) QueryIP(ctx context.Context, ip string) (*ThreatIntelProviderResult, error) {
	// See the note in threatintel_virustotal.go: a rate-limited provider has
	// no verdict, and returning "not detected" would invent one.
	if err := p.inner.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("virustotal rate limit: %w", err)
	}

	apiURL := "https://www.virustotal.com/api/v3/ip_addresses/" + ip
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("virustotal ip: build request: %w", err)
	}
	req.Header.Set("x-apikey", p.inner.apiKey)

	resp, err := p.inner.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal ip: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal ip: HTTP %d", resp.StatusCode)
	}

	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		return nil, fmt.Errorf("virustotal ip: decode: %w", err)
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	detected := stats.Malicious > 0 || stats.Suspicious > 0
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected
	score := 0
	if total > 0 {
		score = (stats.Malicious + stats.Suspicious) * 100 / total
	}

	var categories []string
	if stats.Malicious > 0 {
		categories = append(categories, "malicious")
	}
	if stats.Suspicious > 0 {
		categories = append(categories, "suspicious")
	}

	return &ThreatIntelProviderResult{
		Provider:   "virustotal",
		Detected:   detected,
		Score:      score,
		Categories: categories,
		Details:    fmt.Sprintf("%d malicious, %d suspicious out of %d engines", stats.Malicious, stats.Suspicious, total),
	}, nil
}

// URLhausIPProvider adapts URLhausProvider for IP lookups.
// URLhaus uses the same /host/ endpoint for both domains and IPs.
type URLhausIPProvider struct {
	inner *URLhausProvider
}

func NewURLhausIPProvider(inner *URLhausProvider) *URLhausIPProvider {
	return &URLhausIPProvider{inner: inner}
}

func (p *URLhausIPProvider) Name() string { return "urlhaus" }

func (p *URLhausIPProvider) QueryIP(ctx context.Context, ip string) (*ThreatIntelProviderResult, error) {
	if err := p.inner.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("urlhaus rate limit: %w", err)
	}

	form := url.Values{"host": {ip}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://urlhaus-api.abuse.ch/v1/host/",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("urlhaus ip: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.inner.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urlhaus ip: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlhaus ip: HTTP %d", resp.StatusCode)
	}

	var uhResp struct {
		QueryStatus string `json:"query_status"`
		URLCount    int    `json:"url_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&uhResp); err != nil {
		return nil, fmt.Errorf("urlhaus ip: decode: %w", err)
	}

	detected := uhResp.URLCount > 0
	score := 0
	if detected {
		score = 80
	}

	return &ThreatIntelProviderResult{
		Provider: "urlhaus",
		Detected: detected,
		Score:    score,
		Details:  fmt.Sprintf("%d malicious URLs hosted", uhResp.URLCount),
	}, nil
}

// OTXIPProvider adapts AlienVaultProvider for IP lookups.
type OTXIPProvider struct {
	inner *AlienVaultProvider
}

func NewOTXIPProvider(inner *AlienVaultProvider) *OTXIPProvider {
	return &OTXIPProvider{inner: inner}
}

func (p *OTXIPProvider) Name() string { return "alienvault_otx" }

func (p *OTXIPProvider) QueryIP(ctx context.Context, ip string) (*ThreatIntelProviderResult, error) {
	if err := p.inner.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("alienvault_otx rate limit: %w", err)
	}

	// OTX uses different paths for IPv4 vs IPv6
	indicator := "IPv4"
	if strings.Contains(ip, ":") {
		indicator = "IPv6"
	}
	apiURL := "https://otx.alienvault.com/api/v1/indicators/" + indicator + "/" + ip + "/general"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("otx ip: build request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", p.inner.apiKey)

	resp, err := p.inner.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("otx ip: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx ip: HTTP %d", resp.StatusCode)
	}

	var otxResp struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
		Reputation int `json:"reputation"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&otxResp); err != nil {
		return nil, fmt.Errorf("otx ip: decode: %w", err)
	}

	detected := otxResp.PulseInfo.Count > 0
	score := 0
	if detected {
		score = min(otxResp.PulseInfo.Count*10, 100)
	}

	return &ThreatIntelProviderResult{
		Provider: "alienvault_otx",
		Detected: detected,
		Score:    score,
		Details:  fmt.Sprintf("%d threat pulses", otxResp.PulseInfo.Count),
	}, nil
}
