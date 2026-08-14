package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

func TestSanitizeErr_BlockedError(t *testing.T) {
	err := &safenet.BlockedError{IP: netip.MustParseAddr("127.0.0.1")}
	got := sanitizeErr(err)
	want := "domain resolves to a private/reserved IP address"
	if got != want {
		t.Errorf("sanitizeErr(BlockedError) = %q, want %q", got, want)
	}
}

func TestSanitizeErr_WrappedBlockedError(t *testing.T) {
	inner := &safenet.BlockedError{IP: netip.MustParseAddr("10.0.0.1")}
	wrapped := errors.Join(errors.New("dial failed"), inner)
	got := sanitizeErr(wrapped)
	want := "domain resolves to a private/reserved IP address"
	if got != want {
		t.Errorf("sanitizeErr(wrapped BlockedError) = %q, want %q", got, want)
	}
}

func TestSanitizeErr_ColonStripping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "single colon",
			err:  errors.New("whois: connection refused"),
			want: "connection refused",
		},
		{
			name: "nested colons strips to last segment",
			err:  errors.New("lookup: whois: dial tcp: connection refused"),
			want: "connection refused",
		},
		{
			name: "no colon passes through",
			err:  errors.New("something went wrong"),
			want: "something went wrong",
		},
		{
			name: "colon at end",
			err:  errors.New("error: "),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeErr(tt.err)
			if got != tt.want {
				t.Errorf("sanitizeErr(%q) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestSanitizeErr_BlockedErrorTakesPrecedence(t *testing.T) {
	// Even if the error message contains colons, BlockedError should match first.
	inner := &safenet.BlockedError{IP: netip.MustParseAddr("192.168.1.1")}
	wrapped := fmt.Errorf("lookup: headers: %w", inner)
	got := sanitizeErr(wrapped)
	want := "domain resolves to a private/reserved IP address"
	if got != want {
		t.Errorf("sanitizeErr(wrapped with colons) = %q, want %q", got, want)
	}
}

// --- isExpectedError tests ---

func TestIsExpectedError_ContextDeadline(t *testing.T) {
	if !isExpectedError(context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded should be expected")
	}
	if !isExpectedError(fmt.Errorf("whois: %w", context.DeadlineExceeded)) {
		t.Error("wrapped context.DeadlineExceeded should be expected")
	}
}

func TestIsExpectedError_ContextCanceled(t *testing.T) {
	if !isExpectedError(context.Canceled) {
		t.Error("context.Canceled should be expected")
	}
}

func TestIsExpectedError_DNSError(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "example.com"}
	if !isExpectedError(dnsErr) {
		t.Error("net.DNSError should be expected")
	}
	if !isExpectedError(fmt.Errorf("ptr lookup: %w", dnsErr)) {
		t.Error("wrapped net.DNSError should be expected")
	}
}

// These previously asserted on message text, which is what the substring-based
// classifier keyed on. They now construct the errors the lookups really
// produce, so a dependency rewording its messages cannot quietly change what
// pages us. The exhaustive matrix lives in domain/errors_test.go.

func TestIsExpectedError_WhoisNotFound(t *testing.T) {
	if !isExpectedError(whoisparser.ErrNotFoundDomain) {
		t.Error("WHOIS 'domain is not found' should be expected")
	}
	if !isExpectedError(fmt.Errorf("whois lookup: %w", whoisparser.ErrNotFoundDomain)) {
		t.Error("wrapped WHOIS not-found should be expected")
	}
}

func TestIsExpectedError_NoWhoisServer(t *testing.T) {
	if !isExpectedError(whois.ErrWhoisServerNotFound) {
		t.Error("'no whois server found' should be expected")
	}
}

func TestIsExpectedError_WhoisRateLimited(t *testing.T) {
	// Upstream throttling is the registry's limit, not our fault.
	if !isExpectedError(whoisparser.ErrDomainLimitExceed) {
		t.Error("WHOIS rate limiting should be expected")
	}
}

func TestIsExpectedError_IOTimeout(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: &timeoutErr{}}
	if !isExpectedError(timeout) {
		t.Error("i/o timeout should be expected")
	}
	if !isExpectedError(fmt.Errorf("dial tcp 1.2.3.4:443: %w", timeout)) {
		t.Error("wrapped i/o timeout should be expected")
	}
}

func TestIsExpectedError_TLSConnect(t *testing.T) {
	// LookupSSL wraps its dial failure as "tls connect: %w", so the underlying
	// timeout is what classification must see.
	inner := &net.OpError{Op: "dial", Net: "tcp", Err: &timeoutErr{}}
	if !isExpectedError(fmt.Errorf("tls connect: %w", inner)) {
		t.Error("tls connect wrapping a timeout should be expected")
	}
}

// timeoutErr is a minimal net.Error reporting a timeout.
type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }

func TestIsExpectedError_InfraError_NotExpected(t *testing.T) {
	if isExpectedError(errors.New("pq: connection refused")) {
		t.Error("database errors should NOT be expected")
	}
	if isExpectedError(errors.New("redis: broken pipe")) {
		t.Error("redis errors should NOT be expected")
	}
	if isExpectedError(errors.New("unexpected EOF")) {
		t.Error("unexpected EOF should NOT be expected")
	}
}

func TestIsExpectedError_BlockedError_NotExpected(t *testing.T) {
	// SSRF blocks are unexpected — they indicate a domain resolved to a private IP,
	// which may warrant investigation.
	err := &safenet.BlockedError{IP: netip.MustParseAddr("127.0.0.1")}
	if isExpectedError(err) {
		t.Error("safenet.BlockedError should NOT be expected")
	}
}
