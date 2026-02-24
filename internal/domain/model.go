package domain

import "time"

type DomainRequest struct {
	Domains    []string `json:"domains" binding:"required,min=1"`
	Screenshot bool     `json:"screenshot,omitempty"`
}

type LookupOptions struct {
	Screenshot bool
}

type DomainResponse struct {
	Domain     string          `json:"domain"`
	CacheHit   bool            `json:"cache_hit"`
	Whois      *WhoisInfo      `json:"whois,omitempty"`
	DNS        *DNSInfo        `json:"dns,omitempty"`
	SSL        *SSLInfo        `json:"ssl,omitempty"`
	Headers    *HeadersInfo    `json:"headers,omitempty"`
	Screenshot *ScreenshotInfo `json:"screenshot,omitempty"`
	Errors     []LookupError   `json:"errors,omitempty"`
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
