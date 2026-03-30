package domain

// --- IP Intelligence Request/Response ---

type IPRequest struct {
	IPs         []string `json:"ips" binding:"required,min=1"`
	ThreatIntel bool     `json:"threat_intel,omitempty"`
}

type IPLookupOptions struct {
	ThreatIntel bool
}

type IPResponse struct {
	IP          string               `json:"ip"`
	CacheHit    bool                 `json:"cache_hit"`
	Geo         *GeoIPInfo           `json:"geo,omitempty"`
	ASN         *IPASNInfo           `json:"asn,omitempty"`
	ReverseDNS  *ReverseDNSInfo      `json:"reverse_dns,omitempty"`
	AbuseContact *AbuseContactInfo   `json:"abuse_contact,omitempty"`
	ThreatIntel *ThreatIntelInfo     `json:"threat_intel,omitempty"`
	Errors      []LookupError        `json:"errors,omitempty"`
}

// --- GeoIP ---

type GeoIPInfo struct {
	Continent     string  `json:"continent,omitempty"`
	ContinentCode string  `json:"continent_code,omitempty"`
	Country       string  `json:"country,omitempty"`
	CountryCode   string  `json:"country_code,omitempty"`
	Region        string  `json:"region,omitempty"`
	RegionCode    string  `json:"region_code,omitempty"`
	City          string  `json:"city,omitempty"`
	PostalCode    string  `json:"postal_code,omitempty"`
	Latitude      float64 `json:"latitude,omitempty"`
	Longitude     float64 `json:"longitude,omitempty"`
	Timezone      string  `json:"timezone,omitempty"`
	AccuracyRadius uint16 `json:"accuracy_radius,omitempty"`
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
