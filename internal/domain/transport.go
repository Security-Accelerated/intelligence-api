package domain

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

// safeTransport is used for inspecting arbitrary target domains. TLS
// verification is disabled because we need to inspect targets with expired,
// self-signed, or otherwise invalid certificates. MaxResponseHeaderBytes
// caps header memory to prevent abuse from malicious servers.
var safeTransport = &http.Transport{
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	DialContext:            safenet.SafeDialer(10 * time.Second).DialContext,
	MaxResponseHeaderBytes: 1 << 20, // 1 MB
}

// trustedTransport is used for requests to known upstream providers (crt.sh,
// RDAP, VirusTotal, URLhaus, AlienVault OTX). TLS verification is enabled
// so we validate the identity of these trusted APIs.
var trustedTransport = &http.Transport{
	DialContext: safenet.SafeDialer(10 * time.Second).DialContext,
}
