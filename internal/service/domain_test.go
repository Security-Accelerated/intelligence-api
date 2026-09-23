package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
)

// mockCache is a hand-written mock for cache.Cache. It records the keys and
// TTLs written so tests can assert on the exact bytes that reach Redis.
type mockCache struct {
	mu        sync.Mutex
	store     map[string][]byte
	ttls      map[string]time.Duration
	getErr    error
	mgetErr   error
	setErr    error
	setCalls  int
	mgetCalls int
	mgetKeys  [][]string

	// Barrier state. MGet is the one point every caller passes through inside
	// Lookup, immediately before the singleflight fetch phase, which makes it
	// the only place a test can synchronize callers on something observable
	// rather than on elapsed time.
	barrier        chan struct{}
	barrierN       int
	barrierArrived int
}

// blockUntilCallers makes MGet hold every caller until n of them have arrived,
// then release them together.
func (m *mockCache) blockUntilCallers(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.barrier = make(chan struct{})
	m.barrierN = n
}

// waitForCallers blocks until every caller has reached the cache and been
// released together, then settles.
//
// Two mechanisms, because neither suffices alone. The barrier is real
// synchronization on an observable point inside Lookup, and it fails with the
// observed count rather than continuing — the earlier helper returned silently
// on timeout, so a caller that never arrived produced a confusing assertion
// failure instead of naming the cause.
//
// The settle covers what the barrier cannot: the few instructions between MGet
// returning and a caller parking inside singleflight, which is not observable
// from outside. Without it the test releases the blocked fetch while callers
// are still in flight, and the coalescing it is meant to prove never happens —
// measured, not assumed: barrier alone failed within ten runs.
//
// Because the barrier releases every caller at the same instant, that window is
// instructions wide rather than scheduling wide, which is what makes a settle
// this short sufficient.
func (m *mockCache) waitForCallers(t *testing.T) {
	t.Helper()

	m.mu.Lock()
	barrier := m.barrier
	m.mu.Unlock()
	if barrier == nil {
		t.Fatal("waitForCallers called without blockUntilCallers")
	}

	select {
	case <-barrier:
	case <-time.After(10 * time.Second):
		m.mu.Lock()
		got, want := m.barrierArrived, m.barrierN
		m.mu.Unlock()
		t.Fatalf("only %d of %d callers reached the cache", got, want)
	}

	time.Sleep(50 * time.Millisecond)
}

func newMockCache() *mockCache {
	return &mockCache{
		store: make(map[string][]byte),
		ttls:  make(map[string]time.Duration),
	}
}

func (m *mockCache) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.store[key], nil
}

func (m *mockCache) MGet(_ context.Context, keys []string) ([][]byte, error) {
	m.mu.Lock()
	m.mgetCalls++
	m.mgetKeys = append(m.mgetKeys, slices.Clone(keys))
	if m.mgetErr != nil {
		err := m.mgetErr
		m.mu.Unlock()
		return nil, err
	}
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = m.store[k]
	}

	// Register at the barrier, if one is set, and release everyone once the
	// last caller arrives.
	barrier := m.barrier
	if barrier != nil {
		m.barrierArrived++
		if m.barrierArrived == m.barrierN {
			close(barrier)
		}
	}
	// Unlocked before waiting: holding the mutex here would deadlock every
	// caller behind the first.
	m.mu.Unlock()

	if barrier != nil {
		<-barrier
	}
	return out, nil
}

func (m *mockCache) Set(_ context.Context, key string, data []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setErr != nil {
		return m.setErr
	}
	m.store[key] = data
	m.ttls[key] = ttl
	m.setCalls++
	return nil
}

// seed writes a pre-marshaled payload straight into the store, simulating a
// warm cache entry written by an earlier request.
func (m *mockCache) seed(t *testing.T, key string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal seed value: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[key] = data
}

func (m *mockCache) has(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.store[key]
	return ok
}

func (m *mockCache) payload(key string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store[key]
}

func (m *mockCache) ttl(key string) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ttls[key]
}

func (m *mockCache) sets() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setCalls
}

// --- stub lookups ---

func okWhois(_ context.Context, _ string) (*domain.WhoisInfo, error) {
	return &domain.WhoisInfo{DomainName: "example.com"}, nil
}
func okDNS(_ context.Context, _ string) (*domain.DNSInfo, error) {
	return &domain.DNSInfo{A: []string{"1.2.3.4"}}, nil
}
func okSSL(_ context.Context, _ string) (*domain.SSLInfo, error) {
	return &domain.SSLInfo{Subject: "example.com"}, nil
}
func okHeaders(_ context.Context, _ string) (*domain.HeadersInfo, error) {
	return &domain.HeadersInfo{StatusCode: 200, Headers: map[string]string{"Server": "test"}}, nil
}

func failWhois(_ context.Context, _ string) (*domain.WhoisInfo, error) {
	return nil, errors.New("whois failed")
}
func failDNS(_ context.Context, _ string) (*domain.DNSInfo, error) {
	return nil, errors.New("dns failed")
}
func failSSL(_ context.Context, _ string) (*domain.SSLInfo, error) {
	return nil, errors.New("ssl failed")
}
func failHeaders(_ context.Context, _ string) (*domain.HeadersInfo, error) {
	return nil, errors.New("headers failed")
}

func okReputation(_ context.Context, _ string) (*domain.ReputationInfo, []domain.LookupError) {
	return &domain.ReputationInfo{
		Score: 35,
		Risk:  "medium",
		Providers: []*domain.ProviderResult{
			{Listed: true, Category: "phishing", Provider: "spamhaus_dbl", ReturnCode: "127.0.1.4"},
			{Listed: false, Provider: "surbl"},
		},
	}, nil
}
func failReputation(_ context.Context, _ string) (*domain.ReputationInfo, []domain.LookupError) {
	return &domain.ReputationInfo{Score: 0, Risk: "clean"}, []domain.LookupError{
		{Lookup: "reputation:spamhaus_dbl", Message: "spamhaus_dbl lookup: connection refused"},
		{Lookup: "reputation:surbl", Message: "surbl lookup: connection refused"},
	}
}

func okEmailSecurity(_ context.Context, _ string) (*domain.EmailSecurityInfo, error) {
	return &domain.EmailSecurityInfo{
		SPF: &domain.SPFRecord{Raw: "v=spf1 -all", Version: "spf1", All: "-all"},
	}, nil
}
func failEmailSecurity(_ context.Context, _ string) (*domain.EmailSecurityInfo, error) {
	return nil, errors.New("email_security failed")
}

func okSubdomains(_ context.Context, _ string, _ domain.SubdomainOptions) (*domain.SubdomainInfo, error) {
	return &domain.SubdomainInfo{
		Count: 2,
		Subdomains: []domain.SubdomainEntry{
			{Domain: "www.example.com", Source: "crt.sh"},
			{Domain: "mail.example.com", Source: "crt.sh"},
		},
	}, nil
}
func failSubdomains(_ context.Context, _ string, _ domain.SubdomainOptions) (*domain.SubdomainInfo, error) {
	return nil, errors.New("subdomains failed")
}

func okCTLogs(_ context.Context, _ string, _ int) (*domain.CTLogsInfo, error) {
	return &domain.CTLogsInfo{
		Count: 1,
		Entries: []domain.CTLogEntry{
			{LoggedAt: "2024-01-15T00:00:00", Issuer: "Let's Encrypt", CommonName: "example.com", Serial: "abc123"},
		},
	}, nil
}
func failCTLogs(_ context.Context, _ string, _ int) (*domain.CTLogsInfo, error) {
	return nil, errors.New("ct_logs failed")
}

func okBGP(_ context.Context, _ string) (*domain.BGPInfo, error) {
	return &domain.BGPInfo{
		Records: []domain.ASNRecord{
			{IP: "93.184.216.34", ASN: 15133, Prefix: "93.184.216.0/24", Country: "US", Registry: "arin", Description: "EDGECAST, US"},
		},
	}, nil
}
func failBGP(_ context.Context, _ string) (*domain.BGPInfo, error) {
	return nil, errors.New("bgp failed")
}

func okThreatIntel(_ context.Context, _ string) (*domain.ThreatIntelInfo, []domain.LookupError) {
	return &domain.ThreatIntelInfo{
		RiskLevel:  "medium",
		Score:      45,
		Categories: []string{"malware"},
		Providers: []*domain.ThreatIntelProviderResult{
			{Provider: "virustotal", Detected: true, Score: 5, Categories: []string{"malware"}},
			{Provider: "urlhaus", Detected: false},
		},
	}, nil
}
func failThreatIntel(_ context.Context, _ string) (*domain.ThreatIntelInfo, []domain.LookupError) {
	return &domain.ThreatIntelInfo{RiskLevel: "none", Score: 0}, []domain.LookupError{
		{Lookup: "threat_intel:virustotal", Message: "virustotal: rate limit"},
	}
}

func okDNSSecurity(_ context.Context, _ string) (*domain.DNSSecurityInfo, error) {
	return &domain.DNSSecurityInfo{
		DNSSEC: &domain.DNSSECInfo{Enabled: true, DSRecords: 1, DNSKEYRecords: 2},
		CAA:    &domain.CAAInfo{Present: true, Records: []domain.CAARecord{{Tag: "issue", Value: "letsencrypt.org"}}},
	}, nil
}

func failDNSSecurity(_ context.Context, _ string) (*domain.DNSSecurityInfo, error) {
	return nil, errors.New("dns_security failed")
}

// testTTLs mirrors the shape of the configured per-lookup TTL table, with a
// distinct value per lookup so tests can tell them apart. `bgp` is
// deliberately absent to exercise the default-TTL fallback.
var testTTLs = map[string]time.Duration{
	domain.LookupWhoisName:         24 * time.Hour,
	domain.LookupDNSName:           30 * time.Minute,
	domain.LookupSSLName:           4 * time.Hour,
	domain.LookupHeadersName:       45 * time.Minute,
	domain.LookupEmailSecurityName: 2 * time.Hour,
	domain.LookupSubdomainsName:    12 * time.Hour,
	domain.LookupCTLogsName:        18 * time.Hour,
	domain.LookupReputationName:    25 * time.Minute,
	domain.LookupThreatIntelName:   35 * time.Minute,
	domain.LookupDNSSecurityName:   6 * time.Hour,
}

const testDefaultTTL = 5 * time.Minute

func newTestService(mc *mockCache) *DomainService {
	return &DomainService{
		cache:               mc,
		defaultCacheTTL:     testDefaultTTL,
		cacheTTLs:           testTTLs,
		lookupTimeout:       30 * time.Second,
		subdomainMaxResults: 500,
		ctLogsMaxEntries:    100,
		alerter:             &notifications.NoopRecorder{},
		lookupWhois:         okWhois,
		lookupDNS:           okDNS,
		lookupSSL:           okSSL,
		lookupHeaders:       okHeaders,
		lookupReputation:    okReputation,
		lookupEmailSecurity: okEmailSecurity,
		lookupSubdomains:    okSubdomains,
		lookupCTLogs:        okCTLogs,
		lookupBGP:           okBGP,
		lookupThreatIntel:   okThreatIntel,
		lookupDNSSecurity:   okDNSSecurity,
	}
}

func opts(names ...string) domain.LookupOptions {
	return domain.LookupOptions{Lookups: names}
}

func allOpts() domain.LookupOptions {
	return domain.LookupOptions{Lookups: slices.Clone(domain.AllLookupNames)}
}

func key(d, lookup string) string { return cache.LookupKey(d, lookup) }

func testEngine(t *testing.T) *domain.FingerprintEngine {
	t.Helper()
	engine := domain.NewFingerprintEngine()
	engine.LoadRules([]domain.TechRule{
		{Name: "TestServer", Category: "web-server", Headers: map[string]string{"Server": "test"}},
	})
	return engine
}

// --- TTL resolution ---

func TestTTLFor_UsesPerLookupValue(t *testing.T) {
	svc := newTestService(newMockCache())
	if got := svc.ttlFor(domain.LookupWhoisName); got != 24*time.Hour {
		t.Errorf("whois ttl = %v, want 24h", got)
	}
	if got := svc.ttlFor(domain.LookupDNSName); got != 30*time.Minute {
		t.Errorf("dns ttl = %v, want 30m", got)
	}
}

func TestTTLFor_FallsBackToDefault(t *testing.T) {
	svc := newTestService(newMockCache())
	// bgp has no entry in testTTLs.
	if got := svc.ttlFor(domain.LookupBGPName); got != testDefaultTTL {
		t.Errorf("bgp ttl = %v, want default %v", got, testDefaultTTL)
	}
	if got := svc.ttlFor("not_a_lookup"); got != testDefaultTTL {
		t.Errorf("unknown ttl = %v, want default %v", got, testDefaultTTL)
	}
}

func TestTTLFor_ZeroConfiguredValueFallsBackToDefault(t *testing.T) {
	svc := newTestService(newMockCache())
	svc.cacheTTLs = map[string]time.Duration{domain.LookupDNSName: 0}
	if got := svc.ttlFor(domain.LookupDNSName); got != testDefaultTTL {
		t.Errorf("dns ttl = %v, want default %v", got, testDefaultTTL)
	}
}

// --- Cache read path ---

func TestLookup_AllHit_NoLookupFunctionsCalled(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	mc.seed(t, key("example.com", domain.LookupDNSName), &domain.DNSInfo{A: []string{"9.9.9.9"}})
	mc.seed(t, key("example.com", domain.LookupSSLName), &domain.SSLInfo{Subject: "cached.example.com"})

	var dnsCalls, sslCalls int
	svc.lookupDNS = func(context.Context, string) (*domain.DNSInfo, error) { dnsCalls++; return okDNS(context.TODO(), "") }
	svc.lookupSSL = func(context.Context, string) (*domain.SSLInfo, error) { sslCalls++; return okSSL(context.TODO(), "") }

	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupSSLName))

	if dnsCalls != 0 || sslCalls != 0 {
		t.Errorf("expected no live lookups, got dns=%d ssl=%d", dnsCalls, sslCalls)
	}
	if stats.Hits != 2 || stats.Misses != 0 {
		t.Errorf("stats = %+v, want 2 hits 0 misses", stats)
	}
	if resp.DNS == nil || !resp.DNS.CacheHit {
		t.Fatalf("expected dns cache_hit=true, got %+v", resp.DNS)
	}
	if resp.DNS.A[0] != "9.9.9.9" {
		t.Errorf("dns served live data %v, want cached", resp.DNS.A)
	}
	if resp.SSL == nil || !resp.SSL.CacheHit {
		t.Fatalf("expected ssl cache_hit=true, got %+v", resp.SSL)
	}
	if mc.sets() != 0 {
		t.Errorf("expected no cache writes on a full hit, got %d", mc.sets())
	}
	if mc.mgetCalls != 1 {
		t.Errorf("expected exactly 1 MGET, got %d", mc.mgetCalls)
	}
}

func TestLookup_AllMiss_WritesEachResultWithItsOwnKeyAndTTL(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, stats := svc.Lookup(context.Background(), "example.com",
		opts(domain.LookupWhoisName, domain.LookupDNSName, domain.LookupBGPName))

	if stats.Hits != 0 || stats.Misses != 3 {
		t.Errorf("stats = %+v, want 0 hits 3 misses", stats)
	}
	for _, f := range []struct {
		name    string
		present bool
		hit     bool
	}{
		{domain.LookupWhoisName, resp.Whois != nil, resp.Whois != nil && resp.Whois.CacheHit},
		{domain.LookupDNSName, resp.DNS != nil, resp.DNS != nil && resp.DNS.CacheHit},
		{domain.LookupBGPName, resp.BGP != nil, resp.BGP != nil && resp.BGP.CacheHit},
	} {
		if !f.present {
			t.Errorf("%s missing from response", f.name)
		}
		if f.hit {
			t.Errorf("%s cache_hit = true, want false on a live fetch", f.name)
		}
		if !mc.has(key("example.com", f.name)) {
			t.Errorf("expected cache entry at %s", key("example.com", f.name))
		}
	}

	if got := mc.ttl(key("example.com", domain.LookupWhoisName)); got != 24*time.Hour {
		t.Errorf("whois TTL = %v, want 24h", got)
	}
	if got := mc.ttl(key("example.com", domain.LookupDNSName)); got != 30*time.Minute {
		t.Errorf("dns TTL = %v, want 30m", got)
	}
	// bgp has no per-lookup TTL configured.
	if got := mc.ttl(key("example.com", domain.LookupBGPName)); got != testDefaultTTL {
		t.Errorf("bgp TTL = %v, want default %v", got, testDefaultTTL)
	}
}

func TestLookup_MixedHitMiss_OnlyMissesFetched(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	mc.seed(t, key("example.com", domain.LookupDNSName), &domain.DNSInfo{A: []string{"9.9.9.9"}})

	var dnsCalls, whoisCalls int
	svc.lookupDNS = func(context.Context, string) (*domain.DNSInfo, error) { dnsCalls++; return okDNS(context.TODO(), "") }
	svc.lookupWhois = func(context.Context, string) (*domain.WhoisInfo, error) {
		whoisCalls++
		return okWhois(context.TODO(), "")
	}

	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupWhoisName))

	if dnsCalls != 0 {
		t.Errorf("dns fetched live despite a cache hit (%d calls)", dnsCalls)
	}
	if whoisCalls != 1 {
		t.Errorf("whois calls = %d, want 1", whoisCalls)
	}
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Errorf("stats = %+v, want 1 hit 1 miss", stats)
	}
	if !resp.DNS.CacheHit {
		t.Error("dns cache_hit = false, want true")
	}
	if resp.Whois.CacheHit {
		t.Error("whois cache_hit = true, want false")
	}
}

func TestLookup_FailedLookupNotCachedAndReportedInErrors(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupDNS = failDNS

	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupSSLName))

	if resp.DNS != nil {
		t.Error("expected dns to be absent from the response after a failure")
	}
	if mc.has(key("example.com", domain.LookupDNSName)) {
		t.Error("failed lookup must not be cached")
	}
	if !mc.has(key("example.com", domain.LookupSSLName)) {
		t.Error("successful sibling lookup should still be cached")
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Lookup != domain.LookupDNSName {
		t.Errorf("errors = %+v, want one dns error", resp.Errors)
	}
	if stats.Misses != 2 {
		t.Errorf("stats = %+v, want 2 misses", stats)
	}
}

// --- Cache failure degradation (fail-open) ---

func TestLookup_CacheReadError_TreatsEverythingAsMiss(t *testing.T) {
	mc := newMockCache()
	mc.mgetErr = errors.New("redis down")
	svc := newTestService(mc)

	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupSSLName))

	if resp.DNS == nil || resp.SSL == nil {
		t.Fatal("expected live lookups to run when the cache read fails")
	}
	if resp.DNS.CacheHit || resp.SSL.CacheHit {
		t.Error("cache_hit must be false when the cache read failed")
	}
	if stats.Hits != 0 || stats.Misses != 2 {
		t.Errorf("stats = %+v, want 0 hits 2 misses", stats)
	}
	if len(resp.Errors) != 0 {
		t.Errorf("cache failures must not surface as response errors, got %+v", resp.Errors)
	}
}

func TestLookup_CorruptCacheEntry_TreatedAsMissAndOverwritten(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	corrupt := []byte("{not json")
	mc.mu.Lock()
	mc.store[key("example.com", domain.LookupDNSName)] = corrupt
	mc.mu.Unlock()

	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName))

	if resp.DNS == nil {
		t.Fatal("expected a live fetch after a corrupt cache entry")
	}
	if resp.DNS.CacheHit {
		t.Error("cache_hit = true for a corrupt entry, want false")
	}
	if stats.Hits != 0 || stats.Misses != 1 {
		t.Errorf("stats = %+v, want 0 hits 1 miss", stats)
	}
	// Self-healing: the live fetch overwrites the unusable entry.
	if got := mc.payload(key("example.com", domain.LookupDNSName)); bytes.Equal(got, corrupt) {
		t.Error("expected the corrupt entry to be overwritten by the live result")
	}
}

func TestLookup_CacheWriteError_StillServesResult(t *testing.T) {
	mc := newMockCache()
	mc.setErr = errors.New("redis write failed")
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName))

	if resp.DNS == nil {
		t.Fatal("expected dns in the response despite the cache write failure")
	}
	if len(resp.Errors) != 0 {
		t.Errorf("cache write failure must not surface to the client, got %+v", resp.Errors)
	}
}

// --- cache_hit assembly and payload hygiene ---

func TestLookup_CacheHitFlagNeverWrittenToCache(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "example.com", allOpts())

	for _, name := range domain.AllLookupNames {
		// fingerprint and risk are derived post-processing, never cached.
		if name == domain.LookupFingerprintName || name == domain.LookupRiskName {
			continue
		}
		payload := mc.payload(key("example.com", name))
		if payload == nil {
			t.Errorf("no cached payload for %s", name)
			continue
		}
		if strings.Contains(string(payload), "cache_hit") {
			t.Errorf("%s payload leaked cache_hit into the cache: %s", name, payload)
		}
		var generic map[string]any
		if err := json.Unmarshal(payload, &generic); err != nil {
			t.Errorf("%s payload is not a JSON object: %v", name, err)
			continue
		}
		if _, ok := generic["cache_hit"]; ok {
			t.Errorf("%s payload contains a cache_hit key", name)
		}
	}
}

func TestLookup_CachedPayloadRoundTripsThroughResponse(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	// First request populates the cache, second serves entirely from it.
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupWhoisName))
	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupWhoisName))

	if stats.Hits != 1 {
		t.Fatalf("stats = %+v, want 1 hit", stats)
	}
	if resp.Whois == nil || !resp.Whois.CacheHit {
		t.Fatalf("expected whois cache_hit=true, got %+v", resp.Whois)
	}
	if resp.Whois.DomainName != "example.com" {
		t.Errorf("cached whois lost data: %+v", resp.Whois.WhoisInfo)
	}

	// The response embeds cache_hit alongside the payload fields.
	encoded, err := json.Marshal(resp.Whois)
	if err != nil {
		t.Fatalf("marshal response field: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal response field: %v", err)
	}
	if decoded["cache_hit"] != true {
		t.Errorf("serialized response field missing cache_hit=true: %s", encoded)
	}
	if decoded["domain_name"] != "example.com" {
		t.Errorf("serialized response field missing payload data: %s", encoded)
	}
}

// --- Selectable lookups ---

func TestLookup_OnlyRequestedLookupsRun(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	calls := map[string]int{}
	var mu sync.Mutex
	count := func(name string) {
		mu.Lock()
		calls[name]++
		mu.Unlock()
	}
	svc.lookupWhois = func(context.Context, string) (*domain.WhoisInfo, error) {
		count("whois")
		return okWhois(context.TODO(), "")
	}
	svc.lookupDNS = func(context.Context, string) (*domain.DNSInfo, error) { count("dns"); return okDNS(context.TODO(), "") }
	svc.lookupSSL = func(context.Context, string) (*domain.SSLInfo, error) { count("ssl"); return okSSL(context.TODO(), "") }
	svc.lookupHeaders = func(context.Context, string) (*domain.HeadersInfo, error) {
		count("headers")
		return okHeaders(context.TODO(), "")
	}

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName))

	if calls["dns"] != 1 {
		t.Errorf("dns calls = %d, want 1", calls["dns"])
	}
	for _, name := range []string{"whois", "ssl", "headers"} {
		if calls[name] != 0 {
			t.Errorf("%s ran despite not being requested (%d calls)", name, calls[name])
		}
	}
	if resp.Whois != nil || resp.SSL != nil || resp.Headers != nil {
		t.Error("response contains lookups that were not requested")
	}
	if resp.DNS == nil {
		t.Error("dns missing from response")
	}
	if mc.mgetKeys[0][0] != key("example.com", domain.LookupDNSName) {
		t.Errorf("MGET keys = %v, want only the dns key", mc.mgetKeys[0])
	}
}

func TestLookup_EachLookupPopulatesItsField(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.SetFingerprintEngine(testEngine(t))

	resp, stats := svc.Lookup(context.Background(), "example.com", allOpts())

	if stats.Misses != len(domain.AllLookupNames) {
		t.Errorf("stats = %+v, want %d misses", stats, len(domain.AllLookupNames))
	}
	checks := map[string]bool{
		domain.LookupDNSSecurityName:   resp.DNSSecurity != nil,
		domain.LookupRiskName:          resp.Risk != nil,
		domain.LookupWhoisName:         resp.Whois != nil,
		domain.LookupDNSName:           resp.DNS != nil,
		domain.LookupSSLName:           resp.SSL != nil,
		domain.LookupHeadersName:       resp.Headers != nil,
		domain.LookupReputationName:    resp.Reputation != nil,
		domain.LookupEmailSecurityName: resp.EmailSecurity != nil,
		domain.LookupSubdomainsName:    resp.Subdomains != nil,
		domain.LookupCTLogsName:        resp.CTLogs != nil,
		domain.LookupBGPName:           resp.BGP != nil,
		domain.LookupFingerprintName:   resp.Fingerprint != nil,
		domain.LookupThreatIntelName:   resp.ThreatIntel != nil,
	}
	for name, present := range checks {
		if !present {
			t.Errorf("%s missing from response", name)
		}
	}
	if len(resp.Errors) != 0 {
		t.Errorf("unexpected errors: %+v", resp.Errors)
	}
}

func TestLookup_EachOptionalLookupFailureIsReported(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupWhois = failWhois
	svc.lookupDNS = failDNS
	svc.lookupSSL = failSSL
	svc.lookupHeaders = failHeaders
	svc.lookupEmailSecurity = failEmailSecurity
	svc.lookupSubdomains = failSubdomains
	svc.lookupCTLogs = failCTLogs
	svc.lookupBGP = failBGP
	svc.lookupReputation = failReputation
	svc.lookupThreatIntel = failThreatIntel
	svc.lookupDNSSecurity = failDNSSecurity

	resp, _ := svc.Lookup(context.Background(), "example.com", allOpts())

	failed := map[string]bool{}
	for _, e := range resp.Errors {
		failed[strings.SplitN(e.Lookup, ":", 2)[0]] = true
	}
	for _, name := range []string{
		domain.LookupWhoisName, domain.LookupDNSName, domain.LookupSSLName, domain.LookupHeadersName,
		domain.LookupEmailSecurityName, domain.LookupSubdomainsName,
		domain.LookupCTLogsName, domain.LookupBGPName, domain.LookupReputationName, domain.LookupThreatIntelName,
		domain.LookupDNSSecurityName,
	} {
		if !failed[name] {
			t.Errorf("no error reported for %s", name)
		}
	}
	if mc.sets() != 0 {
		// Nothing is cached when every lookup failed. reputation and
		// threat_intel return partial data alongside per-provider errors, and
		// those used to be written back — after which every later caller was
		// served the partial result as a complete, error-free success until
		// the TTL expired.
		t.Errorf("cache writes = %d, want 0 — no lookup succeeded", mc.sets())
	}
}

// --- Headers / fingerprint dependency ---

func TestLookup_HeadersAndFingerprint_FetchHeadersExactlyOnce(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.SetFingerprintEngine(testEngine(t))

	var headerCalls int
	var mu sync.Mutex
	svc.lookupHeaders = func(context.Context, string) (*domain.HeadersInfo, error) {
		mu.Lock()
		headerCalls++
		mu.Unlock()
		return okHeaders(context.TODO(), "")
	}

	resp, stats := svc.Lookup(context.Background(), "example.com",
		opts(domain.LookupHeadersName, domain.LookupFingerprintName))

	if headerCalls != 1 {
		t.Errorf("headers lookup called %d times, want exactly 1", headerCalls)
	}
	if resp.Headers == nil {
		t.Error("headers missing from response")
	}
	if resp.Fingerprint == nil {
		t.Error("fingerprint missing from response")
	}
	// Both requested lookups count, even though one fetch served both.
	if stats.Misses != 2 {
		t.Errorf("stats = %+v, want 2 misses", stats)
	}
	if mc.sets() != 1 {
		t.Errorf("cache writes = %d, want 1 (headers only)", mc.sets())
	}
}

func TestLookup_FingerprintOnly_CachesHeadersButOmitsThemFromResponse(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.SetFingerprintEngine(testEngine(t))

	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupFingerprintName))

	if resp.Headers != nil {
		t.Error("headers must stay internal when only fingerprint was requested")
	}
	if resp.Fingerprint == nil {
		t.Fatal("fingerprint missing from response")
	}
	if !mc.has(key("example.com", domain.LookupHeadersName)) {
		t.Error("headers data should still be cached under its own key")
	}
	if mc.has(key("example.com", domain.LookupFingerprintName)) {
		t.Error("fingerprint must never get its own cache key")
	}
	if stats.Misses != 1 {
		t.Errorf("stats = %+v, want 1 miss", stats)
	}
}

func TestLookup_FingerprintCacheHitMirrorsHeadersSource(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.SetFingerprintEngine(testEngine(t))

	mc.seed(t, key("example.com", domain.LookupHeadersName),
		&domain.HeadersInfo{StatusCode: 200, Headers: map[string]string{"Server": "test"}})

	var headerCalls int
	svc.lookupHeaders = func(context.Context, string) (*domain.HeadersInfo, error) {
		headerCalls++
		return okHeaders(context.TODO(), "")
	}

	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupFingerprintName))

	if headerCalls != 0 {
		t.Errorf("headers fetched live (%d calls) despite a warm headers cache entry", headerCalls)
	}
	if resp.Fingerprint == nil || !resp.Fingerprint.CacheHit {
		t.Errorf("fingerprint cache_hit should mirror the headers hit, got %+v", resp.Fingerprint)
	}
	if stats.Hits != 1 || stats.Misses != 0 {
		t.Errorf("stats = %+v, want 1 hit 0 misses", stats)
	}
}

func TestLookup_FingerprintWarmedByEarlierHeadersRequest(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.SetFingerprintEngine(testEngine(t))

	// A headers-only request warms the shared key...
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupHeadersName))
	// ...so a later fingerprint-only request needs no upstream call.
	var headerCalls int
	svc.lookupHeaders = func(context.Context, string) (*domain.HeadersInfo, error) {
		headerCalls++
		return okHeaders(context.TODO(), "")
	}
	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupFingerprintName))

	if headerCalls != 0 {
		t.Errorf("headers refetched (%d calls) after being warmed by a headers request", headerCalls)
	}
	if resp.Fingerprint == nil || !resp.Fingerprint.CacheHit {
		t.Errorf("expected a cached fingerprint, got %+v", resp.Fingerprint)
	}
}

func TestLookup_Fingerprint_NilWhenHeadersFail(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.SetFingerprintEngine(testEngine(t))
	svc.lookupHeaders = failHeaders

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupFingerprintName))
	if resp.Fingerprint != nil {
		t.Error("expected fingerprint to be nil when the headers lookup fails")
	}
}

func TestLookup_Fingerprint_NilEngineIsSafe(t *testing.T) {
	svc := newTestService(newMockCache())
	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupFingerprintName))
	if resp.Fingerprint != nil {
		t.Error("expected fingerprint to be nil when the engine is nil")
	}
}

func TestLookup_Fingerprint_Populated(t *testing.T) {
	svc := newTestService(newMockCache())
	svc.SetFingerprintEngine(testEngine(t))

	resp, _ := svc.Lookup(context.Background(), "example.com",
		opts(domain.LookupHeadersName, domain.LookupFingerprintName))

	if resp.Fingerprint == nil {
		t.Fatal("expected fingerprint to be populated")
	}
	if len(resp.Fingerprint.Technologies) == 0 {
		t.Errorf("expected a matched technology, got %+v", resp.Fingerprint.FingerprintInfo)
	}
}

// --- Cache key correctness ---

func TestLookup_CacheKeysAreFlatPerLookup(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "example.net", opts(domain.LookupSSLName, domain.LookupBGPName))

	for _, want := range []string{"lookup:example.net:ssl", "lookup:example.net:bgp"} {
		if !mc.has(want) {
			t.Errorf("missing cache entry %q; store has %v", want, mc.keys())
		}
	}
}

func TestLookup_KeysAreIndependentOfRequestedCombination(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	// dns alone warms the same key that dns+ssl later reads.
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName))

	var dnsCalls int
	svc.lookupDNS = func(context.Context, string) (*domain.DNSInfo, error) { dnsCalls++; return okDNS(context.TODO(), "") }

	resp, stats := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupSSLName))

	if dnsCalls != 0 {
		t.Errorf("dns refetched (%d calls) in a different lookup combination", dnsCalls)
	}
	if !resp.DNS.CacheHit {
		t.Error("dns cache_hit = false, want true")
	}
	if resp.SSL.CacheHit {
		t.Error("ssl cache_hit = true, want false")
	}
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Errorf("stats = %+v, want 1 hit 1 miss", stats)
	}
}

func TestLookup_DifferentDomainsUseDifferentKeys(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	svc.Lookup(context.Background(), "a.com", opts(domain.LookupDNSName))
	svc.Lookup(context.Background(), "b.com", opts(domain.LookupDNSName))

	if !mc.has(key("a.com", domain.LookupDNSName)) || !mc.has(key("b.com", domain.LookupDNSName)) {
		t.Errorf("expected separate keys per domain, store has %v", mc.keys())
	}
}

func (m *mockCache) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.store))
	for k := range m.store {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// --- Miscellaneous behavior ---

func TestLookup_NoRunners_SkipsCacheEntirely(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, stats := svc.Lookup(context.Background(), "example.com", opts())

	if mc.mgetCalls != 0 {
		t.Errorf("MGET calls = %d, want 0 when nothing is requested", mc.mgetCalls)
	}
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Errorf("stats = %+v, want zero", stats)
	}
	if resp.Domain != "example.com" {
		t.Errorf("domain = %q", resp.Domain)
	}
}

func TestLookup_DomainNameReachesLookups(t *testing.T) {
	svc := newTestService(newMockCache())

	var got string
	svc.lookupDNS = func(_ context.Context, d string) (*domain.DNSInfo, error) {
		got = d
		return okDNS(context.TODO(), "")
	}
	svc.Lookup(context.Background(), "sub.example.org", opts(domain.LookupDNSName))
	if got != "sub.example.org" {
		t.Errorf("lookup received %q, want %q", got, "sub.example.org")
	}
}

func TestLookup_ConcurrentSafety(t *testing.T) {
	svc := newTestService(newMockCache())
	svc.SetFingerprintEngine(testEngine(t))

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			svc.Lookup(context.Background(), "example.com", allOpts())
		})
	}
	wg.Wait()
}

// TestLookup_ReputationPartialFailureIsNotCached pins the fix for partial
// results being frozen into the cache.
//
// The caller still gets whatever data was gathered — that is the point of
// partial-failure tolerance — but it is not written back. Only the payload is
// cached, never the errors, so a stored partial result is replayed to every
// later caller as a complete success with nothing to retry. For threat
// intelligence that means caching a verdict derived from providers that never
// answered.
func TestLookup_ReputationPartialFailureIsNotCached(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupReputation = failReputation

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupReputationName))

	if resp.Reputation == nil {
		t.Fatal("expected the partial reputation result to still be returned to this caller")
	}
	if len(resp.Errors) != 2 {
		t.Errorf("errors = %+v, want 2 provider errors", resp.Errors)
	}
	if mc.has(key("example.com", domain.LookupReputationName)) {
		t.Error("a partial result must not be cached — later callers would see it as an error-free success")
	}
}

func TestLookup_SubdomainMaxResults_Passed(t *testing.T) {
	svc := newTestService(newMockCache())
	svc.subdomainMaxResults = 42

	var got int
	svc.SetSubdomainLookup(func(_ context.Context, _ string, o domain.SubdomainOptions) (*domain.SubdomainInfo, error) {
		got = o.MaxResults
		return okSubdomains(context.TODO(), "", o)
	})
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupSubdomainsName))
	if got != 42 {
		t.Errorf("MaxResults = %d, want 42", got)
	}
}

func TestLookup_CTLogsMaxEntries_Passed(t *testing.T) {
	svc := newTestService(newMockCache())
	svc.ctLogsMaxEntries = 7

	var got int
	svc.SetCTLogsLookup(func(_ context.Context, _ string, maxEntries int) (*domain.CTLogsInfo, error) {
		got = maxEntries
		return okCTLogs(context.TODO(), "", maxEntries)
	})
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupCTLogsName))
	if got != 7 {
		t.Errorf("maxEntries = %d, want 7", got)
	}
}

func TestLookup_AppliesLookupTimeout(t *testing.T) {
	svc := newTestService(newMockCache())
	svc.lookupTimeout = 50 * time.Millisecond

	var deadlineSet bool
	svc.lookupDNS = func(ctx context.Context, _ string) (*domain.DNSInfo, error) {
		_, deadlineSet = ctx.Deadline()
		return okDNS(context.TODO(), "")
	}
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName))
	if !deadlineSet {
		t.Error("expected the lookup context to carry a deadline")
	}
}

func TestLookup_DetachedFromParentCancellation(t *testing.T) {
	svc := newTestService(newMockCache())
	svc.lookupTimeout = 30 * time.Second

	var capturedDeadline time.Time
	svc.lookupDNS = func(ctx context.Context, _ string) (*domain.DNSInfo, error) {
		capturedDeadline, _ = ctx.Deadline()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		return okDNS(context.TODO(), "")
	}

	// The fetch is shared with coalesced callers via singleflight, so one
	// caller's tight deadline must NOT propagate into it — only lookupTimeout
	// applies. Otherwise a client that is about to give up could truncate a
	// fetch other callers are waiting on.
	tight := time.Now().Add(500 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), tight)
	defer cancel()

	resp, _ := svc.Lookup(ctx, "example.com", opts(domain.LookupDNSName))
	if !capturedDeadline.After(tight.Add(time.Second)) {
		t.Errorf("deadline = %v, want ~30s out (detached from the caller's tight deadline)", capturedDeadline)
	}
	if resp.DNS == nil {
		t.Error("expected a dns result despite the tight parent deadline")
	}
}

func TestLookup_SingleflightCoalescesConcurrentFetches(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	var calls atomic.Int32
	release := make(chan struct{})
	svc.lookupDNS = func(context.Context, string) (*domain.DNSInfo, error) {
		calls.Add(1)
		<-release // hold the fetch open so the others pile up behind it
		return okDNS(context.TODO(), "")
	}

	const callers = 8
	mc.blockUntilCallers(callers)

	var wg sync.WaitGroup
	results := make([]*domain.DomainResponse, callers)
	for i := range callers {
		wg.Go(func() {
			results[i], _ = svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName))
		})
	}

	// Every caller is now inside Lookup and past the cache, released together
	// and heading into singleflight. Releasing on the first *fetch* instead —
	// as this used to — proved only that one caller had arrived, let that fetch
	// finish, and had its entry deleted before the stragglers reached it, so
	// they each started a fetch of their own.
	mc.waitForCallers(t)
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("dns fetched %d times, want 1 (coalesced)", got)
	}
	for i, r := range results {
		if r.DNS == nil {
			t.Fatalf("caller %d got no dns result", i)
		}
	}
	// Coalesced callers must not share a pointer — each decodes its own copy.
	for i := 1; i < callers; i++ {
		if results[i].DNS.DNSInfo == results[0].DNS.DNSInfo {
			t.Errorf("caller %d shares a payload pointer with caller 0", i)
		}
	}
}

func TestLookup_SingleflightSharesAcrossDifferentLookupSets(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	var dnsCalls atomic.Int32
	release := make(chan struct{})
	svc.lookupDNS = func(context.Context, string) (*domain.DNSInfo, error) {
		dnsCalls.Add(1)
		<-release
		return okDNS(context.TODO(), "")
	}

	// Per-lookup keying means overlapping-but-different requests still share
	// the overlap — something per-response keying could not do.
	mc.blockUntilCallers(2)

	var wg sync.WaitGroup
	wg.Go(func() {
		svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupSSLName))
	})
	wg.Go(func() {
		svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupWhoisName))
	})

	mc.waitForCallers(t)
	close(release)
	wg.Wait()

	if got := dnsCalls.Load(); got != 1 {
		t.Errorf("dns fetched %d times, want 1 shared across both requests", got)
	}
}

func TestLookup_PanickingLookupDegradesToError(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.lookupDNS = func(context.Context, string) (*domain.DNSInfo, error) {
		panic("boom")
	}

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupSSLName))

	if resp.DNS != nil {
		t.Error("expected dns to be absent after a panic")
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Lookup != domain.LookupDNSName {
		t.Fatalf("errors = %+v, want one dns error", resp.Errors)
	}
	if resp.Errors[0].Message != "internal error" {
		t.Errorf("message = %q, want a sanitized %q", resp.Errors[0].Message, "internal error")
	}
	if mc.has(key("example.com", domain.LookupDNSName)) {
		t.Error("a panicking lookup must not be cached")
	}
	// The sibling lookup is unaffected.
	if resp.SSL == nil {
		t.Error("expected ssl to succeed alongside the panicking lookup")
	}
}

// --- DNS security ---

func TestLookup_DNSSecurity_OptIn(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSSecurityName))
	if resp.DNSSecurity == nil {
		t.Fatal("expected dns_security to be populated")
	}
	if resp.DNSSecurity.DNSSEC == nil || !resp.DNSSecurity.DNSSEC.Enabled {
		t.Errorf("dnssec = %+v, want Enabled", resp.DNSSecurity.DNSSecurityInfo)
	}
	if !mc.has(key("example.com", domain.LookupDNSSecurityName)) {
		t.Error("expected dns_security to be cached under its own key")
	}
	if got := mc.ttl(key("example.com", domain.LookupDNSSecurityName)); got != 6*time.Hour {
		t.Errorf("dns_security TTL = %v, want 6h", got)
	}
}

func TestLookup_DNSSecurity_NotRequested(t *testing.T) {
	svc := newTestService(newMockCache())
	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName))
	if resp.DNSSecurity != nil {
		t.Error("dns_security present without being requested")
	}
}

func TestLookup_DNSSecurity_Failure(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	svc.SetDNSSecurityLookup(failDNSSecurity)

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSSecurityName))
	if resp.DNSSecurity != nil {
		t.Error("expected dns_security to be absent after a failure")
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Lookup != domain.LookupDNSSecurityName {
		t.Errorf("errors = %+v, want one dns_security error", resp.Errors)
	}
	if mc.has(key("example.com", domain.LookupDNSSecurityName)) {
		t.Error("failed lookup must not be cached")
	}
}

// --- Risk ---

func TestLookup_Risk_OptIn(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	resp, _ := svc.Lookup(context.Background(), "example.com",
		opts(domain.LookupSSLName, domain.LookupHeadersName, domain.LookupRiskName))

	if resp.Risk == nil {
		t.Fatal("expected risk to be populated")
	}
	if len(resp.Risk.Components) == 0 {
		t.Errorf("expected scored components, got %+v", resp.Risk.RiskSummary)
	}
	if resp.Risk.Level == "" {
		t.Error("expected a risk level")
	}
	// Derived, so it never gets a cache entry of its own.
	if mc.has(key("example.com", domain.LookupRiskName)) {
		t.Error("risk must never be cached under its own key")
	}
}

func TestLookup_Risk_NotRequested(t *testing.T) {
	svc := newTestService(newMockCache())
	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupSSLName))
	if resp.Risk != nil {
		t.Error("risk present without being requested")
	}
}

func TestLookup_Risk_CacheHitReflectsItsInputs(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)
	request := opts(domain.LookupSSLName, domain.LookupHeadersName, domain.LookupRiskName)

	// Cold: inputs fetched live, so the score is not cache-derived.
	first, _ := svc.Lookup(context.Background(), "example.com", request)
	if first.Risk == nil || first.Risk.CacheHit {
		t.Errorf("first request: risk cache_hit = true, want false")
	}

	// Warm: every scoring input now comes from cache.
	second, _ := svc.Lookup(context.Background(), "example.com", request)
	if second.Risk == nil || !second.Risk.CacheHit {
		t.Errorf("second request: risk cache_hit = false, want true")
	}
}

func TestLookup_Risk_PartiallyCachedInputsCountAsMiss(t *testing.T) {
	mc := newMockCache()
	svc := newTestService(mc)

	// Warm only ssl, then request ssl + headers + risk.
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupSSLName))
	resp, _ := svc.Lookup(context.Background(), "example.com",
		opts(domain.LookupSSLName, domain.LookupHeadersName, domain.LookupRiskName))

	if resp.Risk == nil {
		t.Fatal("expected risk to be populated")
	}
	if resp.Risk.CacheHit {
		t.Error("risk cache_hit = true, want false when one input was fetched live")
	}
}

// --- Setters and constructor ---

// --- Setters and constructor ---

func TestNewDomainService_Defaults(t *testing.T) {
	svc := NewDomainService(newMockCache(), time.Minute, nil, 0, 0, 0, nil, nil, nil)
	if svc.subdomainMaxResults != 500 {
		t.Errorf("subdomainMaxResults = %d, want 500", svc.subdomainMaxResults)
	}
	if svc.ctLogsMaxEntries != 100 {
		t.Errorf("ctLogsMaxEntries = %d, want 100", svc.ctLogsMaxEntries)
	}
	if svc.lookupTimeout != 30*time.Second {
		t.Errorf("lookupTimeout = %v, want 30s", svc.lookupTimeout)
	}
	if svc.alerter == nil {
		t.Error("expected a non-nil alerter")
	}
	// With no per-lookup table, every lookup falls back to the default.
	if got := svc.ttlFor(domain.LookupWhoisName); got != time.Minute {
		t.Errorf("ttlFor(whois) = %v, want the default 1m", got)
	}
}

func TestSetLookups_ReplacesBaseLookups(t *testing.T) {
	svc := newTestService(newMockCache())
	svc.SetLookups(failWhois, failDNS, failSSL, failHeaders, failReputation)

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(domain.LookupWhoisName, domain.LookupDNSName))
	if resp.Whois != nil || resp.DNS != nil {
		t.Error("expected the replaced (failing) lookups to be used")
	}
}

func TestSetters_ReplaceOptionalLookups(t *testing.T) {
	svc := newTestService(newMockCache())

	svc.SetEmailSecurityLookup(failEmailSecurity)
	svc.SetSubdomainLookup(failSubdomains)
	svc.SetCTLogsLookup(failCTLogs)
	svc.SetBGPLookup(failBGP)
	svc.SetThreatIntelLookup(failThreatIntel)

	resp, _ := svc.Lookup(context.Background(), "example.com", opts(
		domain.LookupEmailSecurityName, domain.LookupSubdomainsName,
		domain.LookupCTLogsName, domain.LookupBGPName, domain.LookupThreatIntelName,
	))

	if resp.EmailSecurity != nil || resp.Subdomains != nil || resp.CTLogs != nil || resp.BGP != nil {
		t.Error("expected the replaced (failing) lookups to be used")
	}
	if len(resp.Errors) == 0 {
		t.Error("expected errors from the replaced lookups")
	}
}

func TestSetFingerprintEngine(t *testing.T) {
	svc := newTestService(newMockCache())
	engine := testEngine(t)
	svc.SetFingerprintEngine(engine)
	if svc.fingerprintEngine != engine {
		t.Error("SetFingerprintEngine did not take effect")
	}
}

// --- cacheStats ---

func TestCacheStats_AttributesFingerprintToHeaders(t *testing.T) {
	hits := map[string]bool{domain.LookupHeadersName: true}
	stats := cacheStats(opts(domain.LookupHeadersName, domain.LookupFingerprintName), hits)
	if stats.Hits != 2 || stats.Misses != 0 {
		t.Errorf("stats = %+v, want 2 hits 0 misses", stats)
	}

	stats = cacheStats(opts(domain.LookupFingerprintName), map[string]bool{})
	if stats.Hits != 0 || stats.Misses != 1 {
		t.Errorf("stats = %+v, want 0 hits 1 miss", stats)
	}
}
