package domain

import (
	"slices"
	"time"
)

// Canonical lookup names accepted in DomainRequest.Lookups. These names are the
// contract shared by the request body, the per-lookup cache keys, the per-lookup
// TTL config, and usage tracking.
const (
	LookupWhoisName         = "whois"
	LookupDNSName           = "dns"
	LookupSSLName           = "ssl"
	LookupHeadersName       = "headers"
	LookupScreenshotName    = "screenshot"
	LookupReputationName    = "reputation"
	LookupEmailSecurityName = "email_security"
	LookupSubdomainsName    = "subdomains"
	LookupCTLogsName        = "ct_logs"
	LookupBGPName           = "bgp"
	LookupFingerprintName   = "fingerprint"
	LookupThreatIntelName   = "threat_intel"
)

// AllLookupNames lists every valid lookup name. Used to enumerate per-lookup TTL
// config keys and to build documentation/error messages.
var AllLookupNames = []string{
	LookupWhoisName,
	LookupDNSName,
	LookupSSLName,
	LookupHeadersName,
	LookupScreenshotName,
	LookupReputationName,
	LookupEmailSecurityName,
	LookupSubdomainsName,
	LookupCTLogsName,
	LookupBGPName,
	LookupFingerprintName,
	LookupThreatIntelName,
}

type DomainRequest struct {
	Domains []string `json:"domains" binding:"required,min=1"`
	Lookups []string `json:"lookups"`
}

// LookupOptions carries the normalized, deduplicated, validated set of lookups
// to run. It is built in exactly one place (the handler); everything downstream
// sees only explicit lookup names.
type LookupOptions struct {
	Lookups []string
}

// Has reports whether the named lookup was requested.
func (o LookupOptions) Has(name string) bool {
	return slices.Contains(o.Lookups, name)
}

// CacheStats reports how many of the requested lookups were served from cache
// versus fetched live. Used for operational metrics, not for the API response.
type CacheStats struct {
	Hits   int
	Misses int
}

type DomainResponse struct {
	Domain string   `json:"domain"`
	Inputs []string `json:"inputs,omitempty"`

	Whois         *WhoisResult         `json:"whois,omitempty"`
	DNS           *DNSResult           `json:"dns,omitempty"`
	SSL           *SSLResult           `json:"ssl,omitempty"`
	Headers       *HeadersResult       `json:"headers,omitempty"`
	Screenshot    *ScreenshotResult    `json:"screenshot,omitempty"`
	Reputation    *ReputationResult    `json:"reputation,omitempty"`
	EmailSecurity *EmailSecurityResult `json:"email_security,omitempty"`
	Subdomains    *SubdomainsResult    `json:"subdomains,omitempty"`
	CTLogs        *CTLogsResult        `json:"ct_logs,omitempty"`
	BGP           *BGPResult           `json:"bgp,omitempty"`
	Fingerprint   *FingerprintResult   `json:"fingerprint,omitempty"`
	ThreatIntel   *ThreatIntelResult   `json:"threat_intel,omitempty"`

	Errors []LookupError `json:"errors,omitempty"`
}

// DomainResponseEnvelope wraps the per-domain results. The envelope exists so
// response-level fields can be added later without breaking clients.
type DomainResponseEnvelope struct {
	Results []*DomainResponse `json:"results"`
}

// --- Per-lookup response wrappers ---
//
// Each wrapper embeds the pure lookup payload and adds a cache_hit flag. Only
// the embedded payload type is ever marshaled into Redis — cache_hit is set at
// response-assembly time and must never be persisted.

type WhoisResult struct {
	CacheHit bool `json:"cache_hit"`
	*WhoisInfo
}

type DNSResult struct {
	CacheHit bool `json:"cache_hit"`
	*DNSInfo
}

type SSLResult struct {
	CacheHit bool `json:"cache_hit"`
	*SSLInfo
}

type HeadersResult struct {
	CacheHit bool `json:"cache_hit"`
	*HeadersInfo
}

type ScreenshotResult struct {
	CacheHit bool `json:"cache_hit"`
	*ScreenshotInfo
}

type ReputationResult struct {
	CacheHit bool `json:"cache_hit"`
	*ReputationInfo
}

type EmailSecurityResult struct {
	CacheHit bool `json:"cache_hit"`
	*EmailSecurityInfo
}

type SubdomainsResult struct {
	CacheHit bool `json:"cache_hit"`
	*SubdomainInfo
}

type CTLogsResult struct {
	CacheHit bool `json:"cache_hit"`
	*CTLogsInfo
}

type BGPResult struct {
	CacheHit bool `json:"cache_hit"`
	*BGPInfo
}

type FingerprintResult struct {
	CacheHit bool `json:"cache_hit"`
	*FingerprintInfo
}

type ThreatIntelResult struct {
	CacheHit bool `json:"cache_hit"`
	*ThreatIntelInfo
}

type ProviderResult struct {
	Listed     bool   `json:"listed"`
	Category   string `json:"category,omitempty"`
	Provider   string `json:"provider"`
	ReturnCode string `json:"return_code,omitempty"`
}

type ReputationInfo struct {
	Score     int               `json:"score"`
	Risk      string            `json:"risk"`
	Providers []*ProviderResult `json:"providers"`
}

type ScreenshotInfo struct {
	StatusCode int    `json:"status_code"`
	PNG        string `json:"png,omitempty"`
}

type WhoisInfo struct {
	DomainName  string   `json:"domain_name,omitempty"`
	Registrar   string   `json:"registrar,omitempty"`
	CreatedDate string   `json:"created_date,omitempty"`
	UpdatedDate string   `json:"updated_date,omitempty"`
	ExpiryDate  string   `json:"expiry_date,omitempty"`
	Status      []string `json:"status,omitempty"`
	NameServers []string `json:"name_servers,omitempty"`
	Registrant  *Contact `json:"registrant,omitempty"`
	Admin       *Contact `json:"admin,omitempty"`
	Tech        *Contact `json:"tech,omitempty"`
}

type Contact struct {
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	Email        string `json:"email,omitempty"`
}

type DNSInfo struct {
	A     []string   `json:"a,omitempty"`
	AAAA  []string   `json:"aaaa,omitempty"`
	MX    []MXRecord `json:"mx,omitempty"`
	NS    []string   `json:"ns,omitempty"`
	TXT   []string   `json:"txt,omitempty"`
	CNAME string     `json:"cname,omitempty"`
}

type MXRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

type SSLInfo struct {
	Subject            string    `json:"subject,omitempty"`
	Issuer             string    `json:"issuer,omitempty"`
	NotBefore          time.Time `json:"not_before,omitempty"`
	NotAfter           time.Time `json:"not_after,omitempty"`
	SANs               []string  `json:"sans,omitempty"`
	SerialNumber       string    `json:"serial_number,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	Expired            bool      `json:"expired"`
	DaysUntilExpiry    int       `json:"days_until_expiry"`
}

type HeadersInfo struct {
	StatusCode      int               `json:"status_code"`
	Headers         map[string]string `json:"headers,omitempty"`
	SecurityHeaders *SecurityHeaders  `json:"security_headers,omitempty"`
}

type SecurityHeaders struct {
	StrictTransportSecurity string `json:"strict_transport_security,omitempty"`
	ContentSecurityPolicy   string `json:"content_security_policy,omitempty"`
	XFrameOptions           string `json:"x_frame_options,omitempty"`
	XContentTypeOptions     string `json:"x_content_type_options,omitempty"`
	XXSSProtection          string `json:"x_xss_protection,omitempty"`
	ReferrerPolicy          string `json:"referrer_policy,omitempty"`
	PermissionsPolicy       string `json:"permissions_policy,omitempty"`
}

type LookupError struct {
	Lookup  string `json:"lookup"`
	Message string `json:"message"`
}

// --- Email Security (optional field on domain lookup) ---

type EmailSecurityInfo struct {
	SPF   *SPFRecord   `json:"spf,omitempty"`
	DMARC *DMARCRecord `json:"dmarc,omitempty"`
	DKIM  []DKIMRecord `json:"dkim,omitempty"`
}

type SPFRecord struct {
	Raw        string   `json:"raw"`
	Version    string   `json:"version,omitempty"`
	Mechanisms []string `json:"mechanisms,omitempty"`
	All        string   `json:"all,omitempty"` // terminal qualifier: "+all", "-all", "~all", "?all"
}

type DMARCRecord struct {
	Raw     string `json:"raw"`
	Version string `json:"version,omitempty"`
	Policy  string `json:"policy,omitempty"` // "none", "quarantine", "reject"
	Pct     int    `json:"pct,omitempty"`
	RUA     string `json:"rua,omitempty"`
	RUF     string `json:"ruf,omitempty"`
	SP      string `json:"sp,omitempty"` // subdomain policy
}

type DKIMRecord struct {
	Selector string `json:"selector"`
	Found    bool   `json:"found"`
	Raw      string `json:"raw,omitempty"`
}

// --- Subdomain Enumeration (optional field on domain lookup) ---

type SubdomainInfo struct {
	Count      int              `json:"count"`
	Capped     bool             `json:"capped"`
	Subdomains []SubdomainEntry `json:"subdomains"`
}

type SubdomainEntry struct {
	Domain string `json:"domain"`
	Source string `json:"source"`
}

type SubdomainOptions struct {
	MaxResults int
}

// --- Certificate Transparency Logs (optional field on domain lookup) ---

type CTLogsInfo struct {
	Count   int          `json:"count"`
	Capped  bool         `json:"capped"`
	Entries []CTLogEntry `json:"entries"`
}

type CTLogEntry struct {
	LoggedAt   string `json:"logged_at"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	Issuer     string `json:"issuer"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	Serial     string `json:"serial"`
}

// --- BGP / ASN Enrichment (optional field on domain lookup) ---

type BGPInfo struct {
	Records []ASNRecord `json:"records"`
}

type ASNRecord struct {
	IP          string `json:"ip"`
	ASN         int    `json:"asn"`
	Prefix      string `json:"prefix"`
	Country     string `json:"country"`
	Registry    string `json:"registry"`
	Description string `json:"description"`
}

// --- Threat Intelligence (optional field on domain lookup) ---

type ThreatIntelProviderResult struct {
	Provider   string   `json:"provider"`
	Detected   bool     `json:"detected"`
	Score      int      `json:"score,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Details    string   `json:"details,omitempty"`
}

type ThreatIntelInfo struct {
	RiskLevel  string                       `json:"risk_level"`
	Score      int                          `json:"score"`
	Categories []string                     `json:"categories,omitempty"`
	Providers  []*ThreatIntelProviderResult `json:"providers"`
}
