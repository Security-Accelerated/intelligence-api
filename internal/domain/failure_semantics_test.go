package domain

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// These tests pin one rule: a lookup must never report "we could not find out"
// as "there is nothing there". The difference is invisible in the response —
// both produce an empty field — but an empty result is cached for hours and
// tells a caller something definite about the domain.

func TestParseCrtShResponse_MalformedJSONIsAnError(t *testing.T) {
	if _, err := parseCrtShResponse([]byte("not json"), "example.com"); err == nil {
		t.Error("malformed crt.sh JSON must be an error; an empty subdomain list is cached for 24h " +
			"and reads as \"this domain has no subdomains\"")
	}
}

// TestParseCrtShResponse_TruncatedJSONIsAnError covers the oversized-response
// path specifically: the body is read through io.LimitReader, so a response
// larger than MaxResponseBody arrives as valid JSON cut mid-structure. That
// used to unmarshal-fail and return an empty list.
func TestParseCrtShResponse_TruncatedJSONIsAnError(t *testing.T) {
	full := `[{"name_value":"a.example.com"},{"name_value":"b.example.com"}]`
	truncated := full[:len(full)-12]

	if _, err := parseCrtShResponse([]byte(truncated), "example.com"); err == nil {
		t.Error("a truncated crt.sh response must be an error, not an empty list")
	}
}

func TestParseCrtShResponse_EmptyArrayIsNotAnError(t *testing.T) {
	got, err := parseCrtShResponse([]byte("[]"), "example.com")
	if err != nil {
		t.Fatalf("an empty crt.sh array is a real answer, not a failure: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want no subdomains", got)
	}
}

func TestLookupBGP_AllOriginLookupsFailingIsAnError(t *testing.T) {
	// Point the resolver at a server that answers the A query but blackholes
	// the Cymru TXT lookups, so every origin lookup fails while the domain
	// itself resolves.
	addr, _ := startDNSServer(t, testZone{A: []string{"93.184.216.34"}})
	useLocalResolver(t, addr)

	info, err := LookupBGP(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("expected an error when every Cymru lookup fails, got %+v", info)
	}
	if info != nil {
		t.Errorf("expected nil info alongside the error, got %+v", info)
	}
	if !strings.Contains(err.Error(), "origin lookups failed") {
		t.Errorf("error should say the lookups failed, got: %v", err)
	}
}

func TestIsDNSAbsence(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"NXDOMAIN is absence", &net.DNSError{Err: "no such host", IsNotFound: true}, true},
		{"timeout is not absence", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, false},
		{"temporary failure is not absence", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, false},
		{"plain error is not absence", errors.New("something broke"), false},
		{"wrapped NXDOMAIN is absence", errors.Join(errors.New("ctx"), &net.DNSError{IsNotFound: true}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDNSAbsence(tt.err); got != tt.want {
				t.Errorf("isDNSAbsence(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestLookupEmailSecurity_NoRecordsIsNotAnError guards the other direction:
// plenty of domains publish no SPF, DMARC or BIMI at all, and that must stay a
// successful empty answer rather than becoming an error once failures are
// tracked.
func TestLookupEmailSecurity_NoRecordsIsNotAnError(t *testing.T) {
	addr, _ := startDNSServer(t, testZone{NXDOMAIN: true})
	useLocalResolver(t, addr)

	info, err := LookupEmailSecurity(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("a domain with no email records must not be an error: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil info for a domain with no records, got %+v", info)
	}
}

// TestLookupEmailSecurity_TotalFailureIsAnError is the complement: when the
// queries cannot complete, an empty result would be cached for four hours and
// read as "this domain has no email security configured".
func TestLookupEmailSecurity_TotalFailureIsAnError(t *testing.T) {
	prev := DefaultDNSPerServerTimeout
	DefaultDNSPerServerTimeout = 150 * time.Millisecond
	t.Cleanup(func() { DefaultDNSPerServerTimeout = prev })

	dead, _ := startBlackholeDNS(t)
	useLocalResolver(t, dead)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := LookupEmailSecurity(ctx, "example.com")
	if err == nil {
		t.Fatalf("expected an error when no lookup could complete, got %+v", info)
	}
	if info != nil {
		t.Errorf("expected nil info alongside the error, got %+v", info)
	}
	if !strings.Contains(err.Error(), "could not complete") {
		t.Errorf("error should distinguish failure from absence, got: %v", err)
	}
}
