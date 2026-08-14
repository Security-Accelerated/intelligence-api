package domain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"syscall"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// expectedWhoisErrors are conditions the WHOIS libraries report about the
// queried domain or its TLD rather than about us. Both libraries export proper
// sentinels, so these are matched by identity rather than by message text —
// a dependency bump can reword them without silently changing what we page on.
//
// whois.ErrDomainEmpty is deliberately absent: that one means we passed an
// empty domain, which is our bug.
var expectedWhoisErrors = []error{
	whoisparser.ErrNotFoundDomain,    // domain is not registered
	whoisparser.ErrReservedDomain,    // reserved by the registry
	whoisparser.ErrPremiumDomain,     // available at premium price
	whoisparser.ErrBlockedDomain,     // blocked for brand protection
	whoisparser.ErrDomainDataInvalid, // registry returned unparseable data
	whoisparser.ErrDomainLimitExceed, // the WHOIS server is rate limiting us
	whois.ErrWhoisServerNotFound,     // no WHOIS server for this TLD
}

// IsExpectedError reports whether err describes something about the target or
// an upstream service, rather than a fault on our side. Expected errors are
// logged and returned to the caller but never raise an alert.
//
// Everything here is matched by type or sentinel. The previous implementation
// matched substrings of err.Error(), which meant a dependency rewording its
// messages would silently change paging behavior with no compile error and no
// failing test.
func IsExpectedError(err error) bool {
	if err == nil {
		return false
	}

	// The caller gave up or ran out of time — a slow upstream, not our failure.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	// DNS resolution problems for the target: NXDOMAIN, SERVFAIL, timeouts.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	// GeoIP databases not yet bootstrapped — a deployment state that the admin
	// refresh endpoint exists to resolve, not an incident.
	if errors.Is(err, ErrDBNotLoaded) {
		return true
	}

	for _, sentinel := range expectedWhoisErrors {
		if errors.Is(err, sentinel) {
			return true
		}
	}

	// Any network timeout, wherever it was wrapped: *net.OpError and
	// *url.Error both satisfy net.Error, which covers both "i/o timeout" and
	// "Client.Timeout exceeded while awaiting headers".
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// The target refused the connection or hung up on us.
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}

	// TLS handshake failures below the certificate layer — a target that is not
	// speaking TLS on 443, or speaking it badly. That is a finding about them.
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return true
	}
	// tls.AlertError covers alerts this side raises. It does not cover the far
	// more common case of one arriving from the peer: crypto/tls reports those
	// as *net.OpError{Op: "remote error", Err: alert}, where the alert type is
	// unexported, so errors.As(&tls.AlertError) is false for every real
	// handshake_failure a target sends us. Op is set to "remote error" in
	// exactly one place in crypto/tls — when a received alert is recorded — so
	// matching it is still a structural check rather than a message match.
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" {
		return true
	}

	// Certificate *verification* failures are deliberately NOT expected.
	//
	// Everything that touches an arbitrary target domain — LookupSSL, and the
	// headers and screenshot lookups via safeTransport — sets
	// InsecureSkipVerify, precisely so it can inspect expired and self-signed
	// certificates. So an x509 error cannot come from a target. It can only
	// come from trustedTransport, which is used solely for crt.sh, RDAP,
	// VirusTotal, URLhaus and AlienVault OTX — services with valid public
	// certificates.
	//
	// An x509 failure there means our CA bundle is missing or broken, someone
	// is intercepting our traffic, or an upstream has genuinely broken their
	// certificate. All three warrant a page, so they fall through to false.
	// This is asserted in TestIsExpectedError_CertificateVerificationIsNotExpected.

	return false
}

// certificateVerificationError reports whether err is an x509 verification
// failure. Exposed for tests and for callers that want to describe the failure;
// classification itself is handled by IsExpectedError falling through.
func certificateVerificationError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCert x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	var verifyErr *tls.CertificateVerificationError
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &invalidCert) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &verifyErr)
}
