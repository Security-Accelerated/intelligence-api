package domain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

func TestIsExpectedError_Expected(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"context deadline", context.DeadlineExceeded},
		{"context cancelled", context.Canceled},
		{"wrapped context deadline", fmt.Errorf("ssl: %w", context.DeadlineExceeded)},

		{"dns nxdomain", &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}},
		{"dns servfail", &net.DNSError{Err: "server misbehaving", Name: "x.example"}},
		{"wrapped dns error", fmt.Errorf("lookup: %w", &net.DNSError{Err: "no such host"})},

		{"geoip not bootstrapped", ErrDBNotLoaded},

		{"whois domain not found", whoisparser.ErrNotFoundDomain},
		{"whois reserved", whoisparser.ErrReservedDomain},
		{"whois premium", whoisparser.ErrPremiumDomain},
		{"whois blocked", whoisparser.ErrBlockedDomain},
		{"whois data invalid", whoisparser.ErrDomainDataInvalid},
		{"whois rate limited", whoisparser.ErrDomainLimitExceed},
		{"no whois server for tld", whois.ErrWhoisServerNotFound},
		{"wrapped whois sentinel", fmt.Errorf("whois: %w", whoisparser.ErrNotFoundDomain)},

		{"net timeout", &net.OpError{Op: "read", Err: timeoutError{}}},
		{"http client timeout", &url.Error{Op: "Get", URL: "https://x", Err: timeoutError{}}},

		{"connection refused", syscall.ECONNREFUSED},
		{"connection reset", fmt.Errorf("read: %w", syscall.ECONNRESET)},

		{"tls record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !IsExpectedError(tt.err) {
				t.Errorf("IsExpectedError(%v) = false, want true — this would page someone", tt.err)
			}
		})
	}
}

func TestIsExpectedError_Unexpected(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"arbitrary failure", errors.New("something broke")},
		{"nil pointer dereference", errors.New("runtime error: invalid memory address")},

		// We passed an empty domain — our bug, not the registry's.
		{"whois empty domain", whois.ErrDomainEmpty},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsExpectedError(tt.err) {
				t.Errorf("IsExpectedError(%v) = true, want false — this would be silently swallowed", tt.err)
			}
		})
	}
}

// TestIsExpectedError_CertificateVerificationIsNotExpected pins a decision that
// looks wrong at a glance and is easy to "fix" back.
//
// The previous implementation matched the substring "certificate" and treated
// it as expected, on the assumption that cert errors describe the target. That
// is impossible here: everything touching an arbitrary target domain sets
// InsecureSkipVerify (LookupSSL directly, headers and screenshot via
// safeTransport) precisely so it can report on expired and self-signed certs.
//
// x509 errors can therefore only come from trustedTransport, which is used
// solely for crt.sh, RDAP, VirusTotal, URLhaus and AlienVault OTX — all with
// valid public certificates. A verification failure against those means our CA
// bundle is broken, someone is intercepting our traffic, or an upstream broke
// their certificate. Every one of those deserves a page.
func TestIsExpectedError_CertificateVerificationIsNotExpected(t *testing.T) {
	certErrors := []struct {
		name string
		err  error
	}{
		{"unknown authority", x509.UnknownAuthorityError{}},
		{"expired or invalid", x509.CertificateInvalidError{Reason: x509.Expired}},
		{"hostname mismatch", x509.HostnameError{Host: "crt.sh"}},
		{"wrapped in url.Error", &url.Error{
			Op:  "Get",
			URL: "https://crt.sh",
			Err: x509.UnknownAuthorityError{},
		}},
	}

	for _, tt := range certErrors {
		t.Run(tt.name, func(t *testing.T) {
			if !certificateVerificationError(tt.err) {
				t.Fatalf("test setup is wrong: %v is not recognised as a cert verification error", tt.err)
			}
			if IsExpectedError(tt.err) {
				t.Errorf("IsExpectedError(%v) = true; certificate verification failures must alert — "+
					"they can only originate from trustedTransport, never from a target domain", tt.err)
			}
		})
	}
}

// TestIsExpectedError_MatchesByTypeNotMessage guards the actual regression this
// change was made for: classification must not depend on the wording of a
// dependency's error strings, since `make deps` rewords them without warning.
func TestIsExpectedError_MatchesByTypeNotMessage(t *testing.T) {
	// Same text the old substring list keyed on, but carrying none of the types
	// or sentinels. Previously these were all classified as expected purely
	// because of their wording.
	imposters := []string{
		"domain is not found",
		"no whois server found",
		"i/o timeout",
		"no such host",
		"server misbehaving",
		"tls connect",
		"certificate",
		"context deadline exceeded",
	}

	for _, msg := range imposters {
		t.Run(msg, func(t *testing.T) {
			if IsExpectedError(errors.New(msg)) {
				t.Errorf("a plain error saying %q was classified as expected — "+
					"classification is still keying on message text", msg)
			}
		})
	}
}

// timeoutError is a minimal net.Error that reports a timeout, for constructing
// wrapped timeout errors without doing real I/O.
type timeoutError struct{}

func (timeoutError) Error() string { return "i/o timeout" }
func (timeoutError) Timeout() bool { return true }
func (timeoutError) Temporary() bool {
	return true
}
