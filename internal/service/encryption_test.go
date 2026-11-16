package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

const testHost = "example.com"

// encryptionStubs replaces the three lookups with canned results and counts
// calls.
type encryptionStubs struct {
	mu          sync.Mutex
	calls       map[string]int
	protocolErr error
	panicOnCert bool
}

func (s *encryptionStubs) count(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[name]++
}

func (s *encryptionStubs) install(svc *EncryptionService) {
	s.calls = map[string]int{}
	svc.SetLookups(
		func(context.Context, string) (*domain.ProtocolsInfo, error) {
			s.count(domain.LookupProtocolsName)
			if s.protocolErr != nil {
				return nil, s.protocolErr
			}
			return &domain.ProtocolsInfo{Versions: []domain.ProtocolVersion{{Name: "TLS 1.3", Accepted: true}}}, nil
		},
		func(context.Context, string) (*domain.KeyExchangeInfo, error) {
			s.count(domain.LookupKeyExchangeName)
			return &domain.KeyExchangeInfo{Verdict: domain.KeyExchangePostQuantum}, nil
		},
		func(context.Context, string) (*domain.CertificateInfo, error) {
			s.count(domain.LookupCertificateName)
			if s.panicOnCert {
				panic("boom")
			}
			return &domain.CertificateInfo{ExpiryVerdict: domain.ExpiryValid}, nil
		},
	)
}

func newTestEncryptionService(mc *mockCache, stubs *encryptionStubs) *EncryptionService {
	ttls := map[string]time.Duration{domain.LookupCertificateName: 4 * time.Hour}
	svc := NewEncryptionService(mc, testDefaultTTL, ttls, 5*time.Second, nil, nil)
	stubs.install(svc)
	return svc
}

func encryptionOpts(names ...string) domain.EncryptionLookupOptions {
	return domain.EncryptionLookupOptions{Lookups: names}
}

func TestEncryptionLookup_CachesEachLookupUnderItsOwnKeyAndTTL(t *testing.T) {
	mc := newMockCache()
	stubs := &encryptionStubs{}
	svc := newTestEncryptionService(mc, stubs)
	opts := encryptionOpts(domain.LookupKeyExchangeName, domain.LookupCertificateName)

	first, stats := svc.Lookup(context.Background(), testHost, opts)
	if first.KeyExchange == nil || first.Certificate == nil {
		t.Fatalf("first response missing a requested lookup: %+v", first)
	}
	if first.Protocols != nil {
		t.Error("protocols was returned without being requested")
	}
	if first.KeyExchange.CacheHit || first.Certificate.CacheHit {
		t.Error("first response reported a cache hit")
	}
	if stats.Hits != 0 || stats.Misses != 2 {
		t.Errorf("first stats = %+v, want 0 hits and 2 misses", stats)
	}

	if got := mc.ttl("encryption:example.com:certificate"); got != 4*time.Hour {
		t.Errorf("certificate TTL = %v, want its own 4h", got)
	}
	if got := mc.ttl("encryption:example.com:key_exchange"); got != testDefaultTTL {
		t.Errorf("key_exchange TTL = %v, want the default %v", got, testDefaultTTL)
	}

	second, stats := svc.Lookup(context.Background(), testHost, opts)
	if !second.KeyExchange.CacheHit || !second.Certificate.CacheHit {
		t.Error("second response was not served from cache")
	}
	if second.KeyExchange.Verdict != domain.KeyExchangePostQuantum {
		t.Errorf("cached verdict = %q, want %q", second.KeyExchange.Verdict, domain.KeyExchangePostQuantum)
	}
	if stats.Hits != 2 || stats.Misses != 0 {
		t.Errorf("second stats = %+v, want 2 hits and 0 misses", stats)
	}
	if stubs.calls[domain.LookupKeyExchangeName] != 1 || stubs.calls[domain.LookupCertificateName] != 1 {
		t.Errorf("lookups ran %v times, want once each", stubs.calls)
	}
	if stubs.calls[domain.LookupProtocolsName] != 0 {
		t.Error("protocols ran without being requested")
	}
}

// A host is a domain name, so the same name can be asked about on both
// endpoints. The two must not read each other's entries.
func TestEncryptionLookup_KeyspaceIsSeparateFromDomains(t *testing.T) {
	mc := newMockCache()
	newTestEncryptionService(mc, &encryptionStubs{}).Lookup(context.Background(), testHost, encryptionOpts(domain.LookupCertificateName))

	if mc.has(cache.LookupKey(testHost, domain.LookupCertificateName)) {
		t.Error("encryption result landed in the domain keyspace")
	}
	if !mc.has(cache.EncryptionLookupKey(testHost, domain.LookupCertificateName)) {
		t.Errorf("encryption result missing from its keyspace; store has %v", mc.keys())
	}
}

func TestEncryptionLookup_FailureIsReportedNotCachedAndDoesNotSinkTheRest(t *testing.T) {
	mc := newMockCache()
	stubs := &encryptionStubs{protocolErr: fmt.Errorf("TLS 1.3: connect: %w", errors.New("connection refused"))}
	svc := newTestEncryptionService(mc, stubs)
	opts := encryptionOpts(domain.LookupProtocolsName, domain.LookupKeyExchangeName)

	for range 2 {
		resp, _ := svc.Lookup(context.Background(), testHost, opts)
		if resp.Protocols != nil {
			t.Error("failed lookup still produced a payload")
		}
		if resp.KeyExchange == nil {
			t.Error("a failing lookup removed an unrelated successful one")
		}
		if len(resp.Errors) != 1 || resp.Errors[0].Lookup != domain.LookupProtocolsName || resp.Errors[0].Message != "connection refused" {
			t.Errorf("errors = %+v, want one sanitized protocols error", resp.Errors)
		}
	}

	if stubs.calls[domain.LookupProtocolsName] != 2 {
		t.Errorf("failing lookup ran %d times across two requests, want 2 (never cached)", stubs.calls[domain.LookupProtocolsName])
	}
	if mc.has(cache.EncryptionLookupKey(testHost, domain.LookupProtocolsName)) {
		t.Error("a failed lookup was written to the cache")
	}
}

func TestEncryptionLookup_PanicBecomesInternalError(t *testing.T) {
	svc := newTestEncryptionService(newMockCache(), &encryptionStubs{panicOnCert: true})

	resp, _ := svc.Lookup(context.Background(), testHost, encryptionOpts(domain.LookupCertificateName, domain.LookupKeyExchangeName))
	if resp.Certificate != nil {
		t.Error("panicking lookup produced a payload")
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Message != "internal error" {
		t.Errorf("errors = %+v, want one internal error", resp.Errors)
	}
	if resp.KeyExchange == nil {
		t.Error("sibling lookup should be unaffected by the panic")
	}
}

// Every encryption lookup talks only to the target, so a host that refuses
// every handshake is a finding about that host. If it counted toward alerting,
// one customer scanning hosts with nothing on 443 would page.
func TestEncryptionLookup_RefusedHandshakesDoNotAlert(t *testing.T) {
	rec := &countingRecorder{}
	svc := newTestEncryptionService(newMockCache(), &encryptionStubs{protocolErr: domain.ErrNoHandshake})
	svc.alerter = rec

	resp, _ := svc.Lookup(context.Background(), testHost, encryptionOpts(domain.LookupProtocolsName))

	if len(resp.Errors) != 1 || resp.Errors[0].Message != "no TLS handshake succeeded on port 443" {
		t.Fatalf("errors = %+v, want the refusal reported to the caller", resp.Errors)
	}
	if rec.count.Load() != 0 {
		t.Errorf("recorded %d alerts, want 0 for a host that refused every handshake", rec.count.Load())
	}
}
