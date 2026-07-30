package domain

// --- IP Intelligence Request/Response ---

// Canonical lookup names accepted in IPRequest.Lookups. These names are the
// contract shared by the request body, the per-lookup cache keys, the
// per-lookup TTL config, and usage tracking.
const (
	LookupGeoName          = "geo"
	LookupASNName          = "asn"
	LookupReverseDNSName   = "reverse_dns"
	LookupAbuseContactName = "abuse_contact"
	// threat_intel is shared with the domain catalog — same name, same TTL,
	// separate cache namespace.
)

// AllIPLookupNames lists every valid IP lookup name.
var AllIPLookupNames = []string{
	LookupGeoName,
	LookupASNName,
	LookupReverseDNSName,
	LookupAbuseContactName,
	LookupThreatIntelName,
}

type IPRequest struct {
	IPs     []string `json:"ips" binding:"required,min=1"`
	Lookups []string `json:"lookups"`
}

// IPLookupOptions carries the normalized, deduplicated, validated set of
// lookups to run. Built in exactly one place (the handler); everything
// downstream sees only explicit lookup names.
type IPLookupOptions struct {
	Lookups []string
}

// Has reports whether the named lookup was requested.
func (o IPLookupOptions) Has(name string) bool {
	return sliceContains(o.Lookups, name)
}

type IPResponse struct {
	IP     string   `json:"ip"`
	Inputs []string `json:"inputs,omitempty"`

	Geo          *GeoResult          `json:"geo,omitempty"`
	ASN          *IPASNResult        `json:"asn,omitempty"`
	ReverseDNS   *ReverseDNSResult   `json:"reverse_dns,omitempty"`
	AbuseContact *AbuseContactResult `json:"abuse_contact,omitempty"`
	ThreatIntel  *ThreatIntelResult  `json:"threat_intel,omitempty"`

	Errors []LookupError `json:"errors,omitempty"`
}

// IPResponseEnvelope wraps the per-IP results, matching the domain endpoint so
// every API response is a JSON object.
type IPResponseEnvelope struct {
	Results []*IPResponse `json:"results"`
}

// --- Per-lookup response wrappers ---
//
// Each wrapper embeds the pure lookup payload and adds a cache_hit flag. Only
// the embedded payload is ever marshaled into Redis.

type GeoResult struct {
	CacheHit bool `json:"cache_hit"`
	*GeoIPInfo
}

type IPASNResult struct {
	CacheHit bool `json:"cache_hit"`
	*IPASNInfo
}

type ReverseDNSResult struct {
	CacheHit bool `json:"cache_hit"`
	*ReverseDNSInfo
}

type AbuseContactResult struct {
	CacheHit bool `json:"cache_hit"`
	*AbuseContactInfo
}

// --- GeoIP ---

type GeoIPInfo struct {
	Continent      string  `json:"continent,omitempty"`
	ContinentCode  string  `json:"continent_code,omitempty"`
	Country        string  `json:"country,omitempty"`
	CountryCode    string  `json:"country_code,omitempty"`
	Region         string  `json:"region,omitempty"`
	RegionCode     string  `json:"region_code,omitempty"`
	City           string  `json:"city,omitempty"`
	PostalCode     string  `json:"postal_code,omitempty"`
	Latitude       float64 `json:"latitude,omitempty"`
	Longitude      float64 `json:"longitude,omitempty"`
	Timezone       string  `json:"timezone,omitempty"`
	AccuracyRadius uint16  `json:"accuracy_radius,omitempty"`
}

// --- ASN ---

type IPASNInfo struct {
	ASN          uint32 `json:"asn"`
	Organization string `json:"organization,omitempty"`
	Network      string `json:"network,omitempty"`
}

// --- Reverse DNS ---

type ReverseDNSInfo struct {
	Hostnames []string `json:"hostnames"`
}

// --- Abuse Contact (via RDAP) ---

type AbuseContactInfo struct {
	Network      string `json:"network,omitempty"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	Email        string `json:"email,omitempty"`
}
