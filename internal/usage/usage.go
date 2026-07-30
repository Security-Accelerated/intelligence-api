package usage

import "time"

// UsageEntry represents a single API request to be recorded.
type UsageEntry struct {
	CustomerID  int
	APIKeyID    int
	Plan        string
	Method      string
	Path        string
	StatusCode  int
	LatencyMs   int
	DomainCount int
	IPCount     int

	// CacheHits and CacheMisses count individual lookups served from cache
	// versus fetched live. They are operational metrics only.
	CacheHits   int
	CacheMisses int

	// Lookups holds the normalized lookup names the caller requested. Feature
	// usage is counted from this, so a cache hit never makes a feature look
	// less used — requested is customer demand regardless of how it was served.
	Lookups []string
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
// CacheHits/CacheMisses count individual lookups, not requests, so the hit rate
// is meaningful for multi-lookup requests where some fields are cached and
// others are not.
type UsageSummary struct {
	TotalRequests  int            `json:"total_requests"`
	CacheHits      int            `json:"cache_hits"`
	CacheMisses    int            `json:"cache_misses"`
	CacheHitRate   float64        `json:"cache_hit_rate"`
	AvgLatencyMs   float64        `json:"avg_latency_ms"`
	TotalDomains   int            `json:"total_domains"`
	TotalIPs       int            `json:"total_ips"`
	StatusCodes    map[string]int `json:"status_codes"`
	FeatureUsage   map[string]int `json:"feature_usage"`
	RequestsByPath map[string]int `json:"requests_by_path"`
	PeriodStart    time.Time      `json:"period_start"`
	PeriodEnd      time.Time      `json:"period_end"`
}

// LookupColumns lists the request_log boolean columns that track which lookups
// each request asked for. It must stay in sync with domain.AllLookupNames and
// with the request_log schema — a test asserts the former.
var LookupColumns = []string{
	"whois",
	"dns",
	"ssl",
	"headers",
	"screenshot",
	"reputation",
	"email_security",
	"subdomains",
	"ct_logs",
	"bgp",
	"fingerprint",
	"threat_intel",
	"dns_security",
	"risk",
}

// NoopRecorder silently discards all entries.
type NoopRecorder struct{}

// Record discards the entry.
func (NoopRecorder) Record(UsageEntry) {}
