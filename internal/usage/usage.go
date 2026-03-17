package usage

import "time"

// UsageEntry represents a single API request to be recorded.
type UsageEntry struct {
	CustomerID    int
	APIKeyID      int
	Plan          string
	Method        string
	Path          string
	StatusCode    int
	LatencyMs     int
	DomainCount   int
	CacheHit      bool
	Screenshot    bool
	Reputation    bool
	EmailSecurity bool
	Subdomains    bool
	CTLogs        bool
	BGP           bool
	Fingerprint   bool
	ThreatIntel   bool
}

// Recorder accepts usage entries for persistent storage.
type Recorder interface {
	Record(entry UsageEntry)
}

// Queryer retrieves aggregated usage statistics.
type Queryer interface {
	QueryUsage(customerID, apiKeyID int, since, until time.Time) (*UsageSummary, error)
}

// UsageSummary is the aggregated response returned by the admin endpoint.
type UsageSummary struct {
	TotalRequests  int                `json:"total_requests"`
	CacheHits      int                `json:"cache_hits"`
	CacheHitRate   float64            `json:"cache_hit_rate"`
	AvgLatencyMs   float64            `json:"avg_latency_ms"`
	TotalDomains   int                `json:"total_domains"`
	StatusCodes    map[string]int     `json:"status_codes"`
	FeatureUsage   map[string]int     `json:"feature_usage"`
	RequestsByPath map[string]int     `json:"requests_by_path"`
	PeriodStart    time.Time          `json:"period_start"`
	PeriodEnd      time.Time          `json:"period_end"`
}

// NoopRecorder silently discards all entries.
type NoopRecorder struct{}

func (NoopRecorder) Record(UsageEntry) {}
