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
//
// The split from trustedTransport below is the control that makes this safe:
// nothing authenticated ever travels over this one. Anything carrying an API
// key or parsed as trusted upstream data must use trustedTransport, which
// verifies.
//
// MinVersion is stated rather than inherited. A Go client has defaulted to TLS
// 1.2 since 1.18, so writing it changes no behavior today — it pins the floor
// so a future default, or a GODEBUG that lowers one, cannot quietly move it.
//
// Deliberately 1.2 and not 1.3 on safeTransport: plenty of real hosts still top
// out at 1.2, and refusing them would turn "here are the target's headers" into
// a lookup failure for exactly the aging infrastructure a customer is most
// likely to be asking about.
var safeTransport = &http.Transport{
	//nolint:gosec // G402: unverified by design, see above; upstreams use trustedTransport.
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	},
	DialContext:            safenet.SafeDialer(10 * time.Second).DialContext,
	MaxResponseHeaderBytes: 1 << 20, // 1 MB
}

// trustedTransport is used for requests to known upstream providers (crt.sh,
// RDAP, VirusTotal, URLhaus, AlienVault OTX). TLS verification is enabled
// so we validate the identity of these trusted APIs.
//
// This is the transport that carries API keys, so the floor is worth stating
// here even more than above. Adding TLSClientConfig does not cost HTTP/2:
// setting DialContext already opted both transports out of the automatic
// upgrade.
var trustedTransport = &http.Transport{
	TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	DialContext:     safenet.SafeDialer(10 * time.Second).DialContext,
}
