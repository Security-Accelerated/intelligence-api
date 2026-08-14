package domain

import (
	"context"
	"strings"
	"sync"
)

// ThreatIntelProvider represents a single threat intelligence data source.
type ThreatIntelProvider interface {
	Name() string
	Query(ctx context.Context, domain string) (*ThreatIntelProviderResult, error)
}

// LookupThreatIntel queries all providers concurrently and returns an aggregated
// threat intelligence result. Per-provider errors are returned separately so
// callers see partial results (same pattern as LookupReputation).
func LookupThreatIntel(ctx context.Context, domain string, providers []ThreatIntelProvider) (*ThreatIntelInfo, []LookupError) {
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
		go func(p ThreatIntelProvider) {
			defer wg.Done()
			r, err := p.Query(ctx, domain)
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

// ScoreThreatIntel computes a weighted aggregate score (0–100), risk level, and
// merged category list from individual provider results.
func ScoreThreatIntel(results []*ThreatIntelProviderResult) (score int, riskLevel string, categories []string) {
	if len(results) == 0 {
		return 0, "none", nil
	}

	// Provider weights for score contribution.
	weights := map[string]float64{
		"virustotal":     0.50,
		"urlhaus":        0.30,
		"alienvault_otx": 0.20,
	}

	totalWeight := 0.0
	weightedScore := 0.0
	categorySet := make(map[string]struct{})

	for _, r := range results {
		w, ok := weights[r.Provider]
		if !ok {
			w = 0.20 // default weight for unknown providers
		}
		totalWeight += w
		weightedScore += float64(r.Score) * w
		for _, cat := range r.Categories {
			categorySet[cat] = struct{}{}
		}
	}

	if totalWeight > 0 {
		score = int(weightedScore / totalWeight)
	}
	if score > 100 {
		score = 100
	}

	for cat := range categorySet {
		categories = append(categories, cat)
	}

	switch {
	case score == 0:
		riskLevel = "none"
	case score <= 20:
		riskLevel = "low"
	case score <= 50:
		riskLevel = "medium"
	case score <= 80:
		riskLevel = "high"
	default:
		riskLevel = "critical"
	}

	return score, riskLevel, categories
}
