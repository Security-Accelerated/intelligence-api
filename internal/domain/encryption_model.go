package domain

import "time"

// --- Encryption Posture Request/Response ---

// Canonical lookup names accepted in EncryptionRequest.Lookups. These names are
// the contract shared by the request body, the per-lookup cache keys, the
// per-lookup TTL config, and usage tracking.
const (
	LookupProtocolsName   = "protocols"
	LookupKeyExchangeName = "key_exchange"
	LookupCertificateName = "certificate"
)

// AllEncryptionLookupNames lists every valid encryption lookup name.
var AllEncryptionLookupNames = []string{
	LookupProtocolsName,
	LookupKeyExchangeName,
	LookupCertificateName,
}

type EncryptionRequest struct {
	Hosts   []string `json:"hosts" binding:"required,min=1"`
	Lookups []string `json:"lookups"`
}

// EncryptionLookupOptions carries the normalized, deduplicated, validated set
// of lookups to run. Built in exactly one place (the handler); everything
// downstream sees only explicit lookup names.
type EncryptionLookupOptions struct {
	Lookups []string
}

// Has reports whether the named lookup was requested.
func (o EncryptionLookupOptions) Has(name string) bool {
	return sliceContains(o.Lookups, name)
}

type EncryptionResponse struct {
	Host   string   `json:"host"`
	Inputs []string `json:"inputs,omitempty"`

	Protocols   *ProtocolsResult   `json:"protocols,omitempty"`
	KeyExchange *KeyExchangeResult `json:"key_exchange,omitempty"`
	Certificate *CertificateResult `json:"certificate,omitempty"`

	Errors []LookupError `json:"errors,omitempty"`
}

// EncryptionResponseEnvelope wraps the per-host results, matching the domain
// and IP endpoints so every API response is a JSON object.
type EncryptionResponseEnvelope struct {
	Results []*EncryptionResponse `json:"results"`
}

// --- Per-lookup response wrappers ---
//
// Each wrapper embeds the pure lookup payload and adds a cache_hit flag. Only
// the embedded payload is ever marshaled into Redis.

type ProtocolsResult struct {
	CacheHit bool `json:"cache_hit"`
	*ProtocolsInfo
}

type KeyExchangeResult struct {
	CacheHit bool `json:"cache_hit"`
	*KeyExchangeInfo
}

type CertificateResult struct {
	CacheHit bool `json:"cache_hit"`
	*CertificateInfo
}

// Evidence says where and when a result was observed. Every encryption payload
// embeds it, because a cached answer is an older observation and a host with
// several addresses can be configured differently on each.
type Evidence struct {
	IP       string    `json:"ip"`
	ProbedAt time.Time `json:"probed_at"`
}

// --- Protocols ---

type ProtocolsInfo struct {
	Evidence
	Versions []ProtocolVersion `json:"versions"`
	// LegacyAccepted is true when the server accepts TLS 1.0 or TLS 1.1, both
	// deprecated by RFC 8996.
	LegacyAccepted bool `json:"legacy_accepted"`
}

type ProtocolVersion struct {
	Name     string `json:"name"`
	Accepted bool   `json:"accepted"`
}

// --- Key exchange ---

// Key exchange verdicts. Post-quantum here means the host accepts at least one
// post-quantum group, so a client that negotiates it gets session keys safe
// from an attacker who records traffic now and decrypts it later. It is a
// statement of support, not about every connection, and it says nothing about
// the certificate, which has its own verdict.
const (
	KeyExchangePostQuantum = "post_quantum"
	KeyExchangeClassical   = "classical"
)

type KeyExchangeInfo struct {
	Evidence
	Groups []KeyExchangeGroup `json:"groups"`
	// Negotiated is the group the server chose when offered every group at
	// once, post-quantum first. Empty when that combined offer was refused.
	Negotiated string `json:"negotiated,omitempty"`
	Verdict    string `json:"verdict"`
}

type KeyExchangeGroup struct {
	Name        string `json:"name"`
	Accepted    bool   `json:"accepted"`
	PostQuantum bool   `json:"post_quantum"`
}

// --- Certificate ---

// Certificate algorithm verdicts, strongest claim last. A chain is only as
// good as its weakest certificate, so one weak link makes the chain weak and
// one classical link makes it classical.
const (
	AlgorithmsWeak        = "weak"
	AlgorithmsUnknown     = "unknown"
	AlgorithmsClassical   = "classical"
	AlgorithmsPostQuantum = "post_quantum"
)

// Certificate expiry verdicts. There is deliberately no "expiring soon": what
// counts as soon depends on the certificate's lifetime and the caller's
// renewal process, so the response gives days_until_expiry and validity_days
// and leaves the threshold to the caller.
const (
	ExpiryValid       = "valid"
	ExpiryExpired     = "expired"
	ExpiryNotYetValid = "not_yet_valid"
)

// Certificate trust verdicts: whether the chain the server sent leads to a
// root in the public trust store. Judged apart from the leaf's validity dates,
// which expiry_verdict already reports, so an expired certificate from a
// public CA reads "expired" and "trusted" rather than failing twice.
const (
	TrustTrusted   = "trusted"
	TrustUntrusted = "untrusted"
)

// Certificate hostname verdicts: whether the leaf covers the host that was
// asked about.
const (
	HostnameMatch    = "match"
	HostnameMismatch = "mismatch"
)

type CertificateInfo struct {
	Evidence
	// Chain is what the server sent, leaf first.
	Chain []ChainCertificate `json:"chain"`
	// SANs, DaysUntilExpiry and ValidityDays describe the leaf.
	SANs             []string `json:"sans,omitempty"`
	DaysUntilExpiry  int      `json:"days_until_expiry"`
	ValidityDays     int      `json:"validity_days"`
	ExpiryVerdict    string   `json:"expiry_verdict"`
	AlgorithmVerdict string   `json:"algorithm_verdict"`
	TrustVerdict     string   `json:"trust_verdict"`
	HostnameVerdict  string   `json:"hostname_verdict"`
}

type ChainCertificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KeyBits            int       `json:"key_bits,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SelfSigned         bool      `json:"self_signed"`
}
