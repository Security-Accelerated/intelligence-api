package domain

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

// Shared transports prevent port exhaustion under load by reusing connections.
// InsecureSkipVerify is intentional: as a domain intelligence tool we must
// inspect targets with expired, self-signed, or otherwise invalid certificates.
var (
	safeTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     safenet.SafeDialer(10 * time.Second).DialContext,
	}

	safeFastTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     safenet.SafeDialer(2 * time.Second).DialContext,
	}
)
