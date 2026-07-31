package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
)

// --- stub lookups ---

func okGeo(net.IP) (*domain.GeoIPInfo, error) {
	return &domain.GeoIPInfo{Country: "United States", CountryCode: "US", City: "Mountain View"}, nil
}
func okASN(net.IP) (*domain.IPASNInfo, error) {
	return &domain.IPASNInfo{ASN: 15169, Organization: "GOOGLE"}, nil
}
func okReverseDNS(context.Context, string) (*domain.ReverseDNSInfo, error) {
	return &domain.ReverseDNSInfo{Hostnames: []string{"dns.google"}}, nil
}
func okAbuseContact(context.Context, string) (*domain.AbuseContactInfo, error) {
	return &domain.AbuseContactInfo{Organization: "Google LLC", Country: "US", Email: "network-abuse@google.com"}, nil
}
func okIPThreatIntel(context.Context, string) (*domain.ThreatIntelInfo, []domain.LookupError) {
	return &domain.ThreatIntelInfo{RiskLevel: "low", Score: 15}, nil
}

func failReverseDNS(context.Context, string) (*domain.ReverseDNSInfo, error) {
	return nil, errors.New("reverse dns failed")
}

var testIPTTLs = map[string]time.Duration{
	domain.LookupReverseDNSName:   6 * time.Hour,
	domain.LookupAbuseContactName: 24 * time.Hour,
	domain.LookupThreatIntelName:  35 * time.Minute,
}

func newTestIPService(mc *mockCache) *IPService {
	return &IPService{
		cache:              mc,
		defaultCacheTTL:    testDefaultTTL,
		cacheTTLs:          testIPTTLs,
		lookupTimeout:      30 * time.Second,
		alerter:            &notifications.NoopRecorder{},
		lookupGeo:          okGeo,
		lookupASN:          okASN,
		lookupReverseDNS:   okReverseDNS,
		lookupAbuseContact: okAbuseContact,
		lookupThreatIntel:  okIPThreatIntel,
	}
}

func ipOpts(names ...string) domain.IPLookupOptions {
	return domain.IPLookupOptions{Lookups: names}
}

func ipKey(ip, lookup string) string { return cache.IPLookupKey(ip, lookup) }

const testIP = "8.8.8.8"

type countingRecorder struct{ count atomic.Int32 }

func (r *countingRecorder) RecordLookupError(string) { r.count.Add(1) }

// --- Cache keys and TTLs ---

func TestIPLookup_CacheKeysAreFlatPerLookup(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)

	svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupReverseDNSName, domain.LookupAbuseContactName))

	for _, want := range []string{"ip:8.8.8.8:reverse_dns", "ip:8.8.8.8:abuse_contact"} {
		if !mc.has(want) {
			t.Errorf("missing cache entry %q; store has %v", want, mc.keys())
		}
	}
}

func TestIPLookup_PerLookupTTLs(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)

	svc.Lookup(context.Background(), testIP, ipOpts(
		domain.LookupReverseDNSName, domain.LookupAbuseContactName, domain.LookupThreatIntelName))

	for _, tc := range []struct {
		name string
		want time.Duration
	}{
		{domain.LookupReverseDNSName, 6 * time.Hour},
		{domain.LookupAbuseContactName, 24 * time.Hour},
		{domain.LookupThreatIntelName, 35 * time.Minute},
	} {
		if got := mc.ttl(ipKey(testIP, tc.name)); got != tc.want {
			t.Errorf("%s TTL = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIPLookup_KeyspaceIsSeparateFromDomains(t *testing.T) {
	mc := newMockCache()
	newTestIPService(mc).Lookup(context.Background(), testIP, ipOpts(domain.LookupThreatIntelName))

	// Same lookup name, different endpoint — the two must not collide.
	if mc.has(cache.LookupKey(testIP, domain.LookupThreatIntelName)) {
		t.Error("IP result landed in the domain keyspace")
	}
	if !mc.has(cache.IPLookupKey(testIP, domain.LookupThreatIntelName)) {
		t.Error("IP result missing from the ip: keyspace")
	}
}

// --- geo and asn are never cached ---

func TestIPLookup_GeoAndASNAreNeverCached(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)

	resp, _ := svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupGeoName, domain.LookupASNName))

	if resp.Geo == nil || resp.ASN == nil {
		t.Fatal("expected geo and asn to be populated")
	}
	for _, name := range []string{domain.LookupGeoName, domain.LookupASNName} {
		if mc.has(ipKey(testIP, name)) {
			t.Errorf("%s must never be cached — it is a local mmap read", name)
		}
	}
	if mc.sets() != 0 {
		t.Errorf("cache writes = %d, want 0", mc.sets())
	}
	// Nothing cacheable was requested, so no MGET should have been issued.
	if mc.mgetCalls != 0 {
		t.Errorf("MGET calls = %d, want 0", mc.mgetCalls)
	}
}

func TestIPLookup_GeoAndASNAlwaysReportCacheMiss(t *testing.T) {
	svc := newTestIPService(newMockCache())

	// Twice — an uncached lookup can never become a hit.
	svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupGeoName))
	resp, stats := svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupGeoName))

	if resp.Geo.CacheHit {
		t.Error("geo cache_hit = true, want false (never cached)")
	}
	if stats.Hits != 0 || stats.Misses != 1 {
		t.Errorf("stats = %+v, want 0 hits 1 miss", stats)
	}
}

func TestIPLookup_GeoRunsEveryTime(t *testing.T) {
	svc := newTestIPService(newMockCache())

	var calls int
	svc.lookupGeo = func(net.IP) (*domain.GeoIPInfo, error) { calls++; return okGeo(nil) }

	svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupGeoName))
	svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupGeoName))

	if calls != 2 {
		t.Errorf("geo lookup ran %d times, want 2 — it is recomputed, not cached", calls)
	}
}

// --- Cache read/write paths ---

func TestIPLookup_AllHit_NoLookupFunctionsCalled(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)

	mc.seed(t, ipKey(testIP, domain.LookupReverseDNSName), &domain.ReverseDNSInfo{Hostnames: []string{"cached.example"}})

	var calls int
	svc.lookupReverseDNS = func(context.Context, string) (*domain.ReverseDNSInfo, error) {
		calls++
		return okReverseDNS(context.TODO(), "")
	}

	resp, stats := svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupReverseDNSName))

	if calls != 0 {
		t.Errorf("reverse_dns fetched live despite a cache hit (%d calls)", calls)
	}
	if resp.ReverseDNS == nil || !resp.ReverseDNS.CacheHit {
		t.Fatalf("expected reverse_dns cache_hit=true, got %+v", resp.ReverseDNS)
	}
	if resp.ReverseDNS.Hostnames[0] != "cached.example" {
		t.Errorf("served live data %v, want cached", resp.ReverseDNS.Hostnames)
	}
	if stats.Hits != 1 || stats.Misses != 0 {
		t.Errorf("stats = %+v, want 1 hit 0 misses", stats)
	}
}

func TestIPLookup_MixedHitMiss(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)

	mc.seed(t, ipKey(testIP, domain.LookupReverseDNSName), &domain.ReverseDNSInfo{Hostnames: []string{"cached.example"}})

	resp, stats := svc.Lookup(context.Background(), testIP,
		ipOpts(domain.LookupReverseDNSName, domain.LookupAbuseContactName))

	if !resp.ReverseDNS.CacheHit {
		t.Error("reverse_dns cache_hit = false, want true")
	}
	if resp.AbuseContact.CacheHit {
		t.Error("abuse_contact cache_hit = true, want false")
	}
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Errorf("stats = %+v, want 1 hit 1 miss", stats)
	}
}

func TestIPLookup_FailedLookupNotCached(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)
	svc.lookupReverseDNS = failReverseDNS

	resp, _ := svc.Lookup(context.Background(), testIP,
		ipOpts(domain.LookupReverseDNSName, domain.LookupAbuseContactName))

	if resp.ReverseDNS != nil {
		t.Error("expected reverse_dns to be absent after a failure")
	}
	if mc.has(ipKey(testIP, domain.LookupReverseDNSName)) {
		t.Error("failed lookup must not be cached")
	}
	if !mc.has(ipKey(testIP, domain.LookupAbuseContactName)) {
		t.Error("successful sibling should still be cached")
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Lookup != domain.LookupReverseDNSName {
		t.Errorf("errors = %+v, want one reverse_dns error", resp.Errors)
	}
}

func TestIPLookup_CacheReadError_TreatsEverythingAsMiss(t *testing.T) {
	mc := newMockCache()
	mc.mgetErr = errors.New("redis down")
	svc := newTestIPService(mc)

	resp, stats := svc.Lookup(context.Background(), testIP,
		ipOpts(domain.LookupReverseDNSName, domain.LookupAbuseContactName))

	if resp.ReverseDNS == nil || resp.AbuseContact == nil {
		t.Fatal("expected live lookups when the cache read fails")
	}
	if stats.Hits != 0 || stats.Misses != 2 {
		t.Errorf("stats = %+v, want 0 hits 2 misses", stats)
	}
	if len(resp.Errors) != 0 {
		t.Errorf("cache failures must not surface as response errors: %+v", resp.Errors)
	}
}

func TestIPLookup_CacheWriteError_StillServesResult(t *testing.T) {
	mc := newMockCache()
	mc.setErr = errors.New("redis write failed")
	svc := newTestIPService(mc)

	resp, _ := svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupReverseDNSName))

	if resp.ReverseDNS == nil {
		t.Fatal("expected reverse_dns despite the cache write failure")
	}
	if len(resp.Errors) != 0 {
		t.Errorf("cache write failure must not reach the client: %+v", resp.Errors)
	}
}

func TestIPLookup_CorruptCacheEntry_TreatedAsMiss(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)

	mc.mu.Lock()
	mc.store[ipKey(testIP, domain.LookupReverseDNSName)] = []byte("{not json")
	mc.mu.Unlock()

	resp, stats := svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupReverseDNSName))

	if resp.ReverseDNS == nil || resp.ReverseDNS.CacheHit {
		t.Errorf("expected a live refetch after a corrupt entry, got %+v", resp.ReverseDNS)
	}
	if stats.Misses != 1 {
		t.Errorf("stats = %+v, want 1 miss", stats)
	}
}

// --- Response shape ---

func TestIPLookup_OnlyRequestedLookupsRun(t *testing.T) {
	svc := newTestIPService(newMockCache())

	resp, _ := svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupGeoName))

	if resp.Geo == nil {
		t.Error("geo missing")
	}
	if resp.ASN != nil || resp.ReverseDNS != nil || resp.AbuseContact != nil || resp.ThreatIntel != nil {
		t.Error("response contains lookups that were not requested")
	}
}

func TestIPLookup_CacheHitFlagNeverWrittenToCache(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)

	svc.Lookup(context.Background(), testIP, ipOpts(domain.AllIPLookupNames...))

	for _, name := range []string{domain.LookupReverseDNSName, domain.LookupAbuseContactName, domain.LookupThreatIntelName} {
		payload := mc.payload(ipKey(testIP, name))
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

func TestIPLookup_EachLookupPopulatesItsField(t *testing.T) {
	svc := newTestIPService(newMockCache())

	resp, stats := svc.Lookup(context.Background(), testIP, ipOpts(domain.AllIPLookupNames...))

	checks := map[string]bool{
		domain.LookupGeoName:          resp.Geo != nil,
		domain.LookupASNName:          resp.ASN != nil,
		domain.LookupReverseDNSName:   resp.ReverseDNS != nil,
		domain.LookupAbuseContactName: resp.AbuseContact != nil,
		domain.LookupThreatIntelName:  resp.ThreatIntel != nil,
	}
	for name, present := range checks {
		if !present {
			t.Errorf("%s missing from response", name)
		}
	}
	if stats.Misses != len(domain.AllIPLookupNames) {
		t.Errorf("stats = %+v, want %d misses", stats, len(domain.AllIPLookupNames))
	}
}

// --- Concurrency ---

func TestIPLookup_SingleflightCoalescesConcurrentFetches(t *testing.T) {
	mc := newMockCache()
	svc := newTestIPService(mc)

	var calls atomic.Int32
	release := make(chan struct{})
	svc.lookupAbuseContact = func(context.Context, string) (*domain.AbuseContactInfo, error) {
		calls.Add(1)
		<-release
		return okAbuseContact(context.TODO(), "")
	}

	const callers = 6
	mc.blockUntilCallers(callers)

	var wg sync.WaitGroup
	results := make([]*domain.IPResponse, callers)
	for i := range callers {
		wg.Go(func() {
			results[i], _ = svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupAbuseContactName))
		})
	}

	// Every caller is past the cache and heading into singleflight — see the
	// barrier on mockCache.
	mc.waitForCallers(t)
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("abuse_contact fetched %d times, want 1 (coalesced)", got)
	}
	for i := 1; i < callers; i++ {
		if results[i].AbuseContact.AbuseContactInfo == results[0].AbuseContact.AbuseContactInfo {
			t.Errorf("caller %d shares a payload pointer with caller 0", i)
		}
	}
}

func TestIPLookup_PanickingLookupDegradesToError(t *testing.T) {
	svc := newTestIPService(newMockCache())
	svc.lookupReverseDNS = func(context.Context, string) (*domain.ReverseDNSInfo, error) {
		panic("boom")
	}

	resp, _ := svc.Lookup(context.Background(), testIP,
		ipOpts(domain.LookupReverseDNSName, domain.LookupAbuseContactName))

	if resp.ReverseDNS != nil {
		t.Error("expected reverse_dns to be absent after a panic")
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Message != "internal error" {
		t.Fatalf("errors = %+v, want one sanitized internal error", resp.Errors)
	}
	if resp.AbuseContact == nil {
		t.Error("sibling lookup should be unaffected by the panic")
	}
}

func TestIPLookup_ConcurrentSafety(t *testing.T) {
	svc := newTestIPService(newMockCache())

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			svc.Lookup(context.Background(), testIP, ipOpts(domain.AllIPLookupNames...))
		})
	}
	wg.Wait()
}

// --- GeoIP bootstrap state ---

func TestIPLookup_GeoDBNotLoadedDoesNotAlert(t *testing.T) {
	rec := &countingRecorder{}
	svc := newTestIPService(newMockCache())
	svc.alerter = rec
	svc.lookupGeo = func(net.IP) (*domain.GeoIPInfo, error) { return nil, domain.ErrDBNotLoaded }

	resp, _ := svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupGeoName))

	if resp.Geo != nil {
		t.Error("expected geo to be absent when the database is not loaded")
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("errors = %+v, want one geo error", resp.Errors)
	}
	// A missing GeoIP database is a bootstrap state, not an incident — the
	// admin refresh endpoint exists to resolve it, so it must not page anyone.
	if rec.count.Load() != 0 {
		t.Errorf("recorded %d alerts, want 0 for an unbootstrapped GeoIP database", rec.count.Load())
	}
}

// --- Constructor ---

func TestNewIPService_Defaults(t *testing.T) {
	svc := NewIPService(newMockCache(), time.Minute, nil, 0, nil, nil, nil)
	if svc.lookupTimeout != 30*time.Second {
		t.Errorf("lookupTimeout = %v, want 30s", svc.lookupTimeout)
	}
	if svc.alerter == nil {
		t.Error("expected a non-nil alerter")
	}
	if svc.lookupGeo != nil || svc.lookupASN != nil {
		t.Error("expected geo/asn to stay nil without a reader")
	}
	if got := svc.ttlFor(domain.LookupReverseDNSName); got != time.Minute {
		t.Errorf("ttlFor = %v, want the default 1m", got)
	}
}

func TestIPLookup_NilGeoReaderSkipsGeoAndASN(t *testing.T) {
	svc := newTestIPService(newMockCache())
	svc.lookupGeo = nil
	svc.lookupASN = nil

	resp, stats := svc.Lookup(context.Background(), testIP, ipOpts(domain.LookupGeoName, domain.LookupASNName))

	if resp.Geo != nil || resp.ASN != nil {
		t.Error("expected no geo/asn without a reader")
	}
	// Requested but unrunnable still counts as a miss, not a hit.
	if stats.Hits != 0 {
		t.Errorf("stats = %+v, want no hits", stats)
	}
}
