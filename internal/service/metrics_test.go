package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/metrics"
	"github.com/security-accelerated/intelligence-api/internal/metrics/metricstest"
)

func newTestMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	m, err := metrics.New("test")
	if err != nil {
		t.Fatalf("metrics.New: %v", err)
	}
	return m
}

// lookupSeries returns every lookup, cache and coalescing series in a scrape,
// keyed by name and labels, with its value.
func lookupSeries(t *testing.T, m *metrics.Metrics) map[string]string {
	t.Helper()
	series := make(map[string]string)
	for line := range strings.SplitSeq(metricstest.Scrape(t, m), "\n") {
		for _, prefix := range []string{
			"intelligence_api_lookup_duration_seconds_count{",
			"intelligence_api_cache_requests_total{",
			"intelligence_api_singleflight_coalesced_total{",
		} {
			if strings.HasPrefix(line, prefix) {
				name, value, _ := strings.Cut(line, "} ")
				series[name+"}"] = value
			}
		}
	}
	return series
}

// assertInitMatchesUse runs after a service has fetched every one of its
// lookups once and then read each back from the cache. It fails in both
// directions: a series the requests created that initMetrics had not (a lookup
// added without being initialized, so its first event after a start would be
// invisible to rate()), and an initialized series that the requests never
// moved (a lookup initialized although nothing fetches it).
func assertInitMatchesUse(t *testing.T, before, after map[string]string) {
	t.Helper()
	if len(before) == 0 {
		t.Fatal("initMetrics created no series")
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("series %s appeared on first use; initMetrics should have created it", name)
		}
	}
	for name := range before {
		moved := strings.Contains(name, `outcome="ok"`) || strings.Contains(name, `result="`)
		if moved && after[name] != "1" {
			t.Errorf("series %s = %s after one fetch and one cache hit, want 1; is it initialized for a lookup nothing fetches?", name, after[name])
		}
	}
}

func TestDomainService_InitMetricsMatchesWhatLookupsRecord(t *testing.T) {
	m := newTestMetrics(t)
	svc := newTestService(newMockCache())
	svc.metrics = m
	svc.initMetrics()
	before := lookupSeries(t, m)

	everything := opts(domain.AllLookupNames...)
	svc.Lookup(context.Background(), "example.com", everything)
	svc.Lookup(context.Background(), "example.com", everything)

	assertInitMatchesUse(t, before, lookupSeries(t, m))
}

func TestIPService_InitMetricsMatchesWhatLookupsRecord(t *testing.T) {
	m := newTestMetrics(t)
	svc := newTestIPService(newMockCache())
	svc.metrics = m
	svc.initMetrics()
	before := lookupSeries(t, m)

	everything := domain.IPLookupOptions{Lookups: domain.AllIPLookupNames}
	svc.Lookup(context.Background(), "8.8.8.8", everything)
	// geo is uncached, so a second request would fetch it again while the
	// others are served from the cache. Unwiring it keeps every lookup at
	// exactly one fetch, which is what the assertion counts.
	svc.lookupGeo = nil
	svc.Lookup(context.Background(), "8.8.8.8", everything)

	assertInitMatchesUse(t, before, lookupSeries(t, m))
}

func TestLookupMetrics_CacheHitsAndMisses(t *testing.T) {
	m := newTestMetrics(t)
	svc := newTestService(newMockCache())
	svc.metrics = m

	// First request fetches both; the second finds both in the cache.
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupSSLName))
	svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName, domain.LookupSSLName))

	for _, lookup := range []string{"dns", "ssl"} {
		metricstest.Want(t, m, `intelligence_api_cache_requests_total{lookup="`+lookup+`",result="miss",scope="domain"}`, 1)
		metricstest.Want(t, m, `intelligence_api_cache_requests_total{lookup="`+lookup+`",result="hit",scope="domain"}`, 1)
		// Only the miss ran a fetch. A cache hit must not look like a fast lookup.
		metricstest.Want(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="`+lookup+`",outcome="ok",scope="domain"}`, 1)
	}
}

// fingerprint is computed from headers and has no fetch or cache entry of its
// own, so it shows up under the headers lookup and nowhere else.
func TestLookupMetrics_FingerprintIsRecordedAsHeaders(t *testing.T) {
	m := newTestMetrics(t)
	svc := newTestService(newMockCache())
	svc.metrics = m

	svc.Lookup(context.Background(), "example.com", opts(domain.LookupFingerprintName))

	metricstest.Want(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="headers",outcome="ok",scope="domain"}`, 1)
	metricstest.WantAbsent(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="fingerprint",outcome="ok",scope="domain"}`)
}

func TestLookupMetrics_UncachedLookupIsNotACacheMiss(t *testing.T) {
	m := newTestMetrics(t)
	svc := newTestIPService(newMockCache())
	svc.metrics = m

	svc.Lookup(context.Background(), "8.8.8.8", domain.IPLookupOptions{Lookups: []string{domain.LookupGeoName, domain.LookupASNName}})

	// geo never consults the cache, so it is fetched and timed but counts as
	// neither a hit nor a miss. asn is cached like any other lookup.
	metricstest.Want(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="geo",outcome="ok",scope="ip"}`, 1)
	metricstest.WantAbsent(t, m, `intelligence_api_cache_requests_total{lookup="geo",result="miss",scope="ip"}`)
	metricstest.Want(t, m, `intelligence_api_cache_requests_total{lookup="asn",result="miss",scope="ip"}`, 1)
}

func TestLookupMetrics_Outcomes(t *testing.T) {
	m := newTestMetrics(t)
	svc := newTestService(newMockCache())
	svc.metrics = m

	svc.lookupDNS = failDNS
	// What a slow upstream actually returns: a network timeout wrapped a few
	// layers down, with the lookup's own deadline nowhere near.
	svc.lookupSSL = func(context.Context, string) (*domain.SSLInfo, error) {
		return nil, fmt.Errorf("dial: %w", &net.DNSError{Err: "i/o timeout", IsTimeout: true})
	}
	// A fan-out lookup's partial result: data, plus one provider's error.
	svc.lookupReputation = func(context.Context, string) (*domain.ReputationInfo, []domain.LookupError) {
		return &domain.ReputationInfo{}, []domain.LookupError{{Lookup: "reputation", Message: "provider unavailable"}}
	}

	svc.Lookup(context.Background(), "example.com",
		opts(domain.LookupWhoisName, domain.LookupDNSName, domain.LookupSSLName, domain.LookupReputationName))

	metricstest.Want(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="whois",outcome="ok",scope="domain"}`, 1)
	metricstest.Want(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="dns",outcome="error",scope="domain"}`, 1)
	metricstest.Want(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="ssl",outcome="timeout",scope="domain"}`, 1)
	metricstest.Want(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="reputation",outcome="error",scope="domain"}`, 1)
}

func TestLookupOutcome(t *testing.T) {
	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-expired.Done()

	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()

	failed := []domain.LookupError{{Lookup: "dns", Message: "failed"}}

	tests := []struct {
		name string
		ctx  context.Context
		res  fetchResult
		want string
	}{
		{"no errors", context.Background(), fetchResult{payload: []byte(`{}`)}, metrics.OutcomeOK},
		{"no errors and no data", context.Background(), fetchResult{}, metrics.OutcomeOK},
		{"error", context.Background(), fetchResult{errs: failed}, metrics.OutcomeError},
		{"runner saw a timeout", context.Background(), fetchResult{errs: failed, timedOut: true}, metrics.OutcomeTimeout},
		// The fan-out lookups cannot report what kind of error a provider
		// returned, so an expired deadline is what marks theirs as timeouts.
		{"deadline passed", expired, fetchResult{errs: failed}, metrics.OutcomeTimeout},
		{"partial result after the deadline", expired, fetchResult{payload: []byte(`{}`), errs: failed}, metrics.OutcomeTimeout},
		// A lookup that finished cleanly just as the deadline passed succeeded.
		{"success at the deadline", expired, fetchResult{payload: []byte(`{}`)}, metrics.OutcomeOK},
		{"canceled is not a timeout", canceled, fetchResult{errs: failed}, metrics.OutcomeError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lookupOutcome(tt.ctx, tt.res); got != tt.want {
				t.Errorf("lookupOutcome = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"wrapped deadline exceeded", fmt.Errorf("fetch: %w", context.DeadlineExceeded), true},
		{"dns timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, true},
		{"wrapped net timeout", fmt.Errorf("get: %w", &net.OpError{Op: "read", Err: context.DeadlineExceeded}), true},
		{"dns not found", &net.DNSError{Err: "no such host", IsNotFound: true}, false},
		{"canceled", context.Canceled, false},
		{"plain error", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTimeout(tt.err); got != tt.want {
				t.Errorf("isTimeout(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// Eight callers ask for the same lookup at once: one fetches, seven wait on it.
// The fetch is observed once and the seven are counted as coalesced.
//
// Run in a synctest bubble so "every caller is waiting" is something the test
// can ask for instead of something it sleeps and hopes for. synctest.Wait
// returns only once every goroutine is durably blocked: the one that started
// the flight on the release channel, the other seven inside singleflight.
// Releasing the fetch any earlier lets a straggler arrive after the flight has
// finished and start a second one, which fails the counts below with correct
// instrumentation.
func TestLookupMetrics_CoalescedCallers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newTestMetrics(t)
		svc := newTestService(newMockCache())
		svc.metrics = m

		release := make(chan struct{})
		svc.lookupDNS = func(context.Context, string) (*domain.DNSInfo, error) {
			<-release
			return okDNS(context.TODO(), "")
		}

		const callers = 8
		var wg sync.WaitGroup
		for range callers {
			wg.Go(func() {
				svc.Lookup(context.Background(), "example.com", opts(domain.LookupDNSName))
			})
		}
		synctest.Wait()
		close(release)
		wg.Wait()

		metricstest.Want(t, m, `intelligence_api_lookup_duration_seconds_count{lookup="dns",outcome="ok",scope="domain"}`, 1)
		metricstest.Want(t, m, `intelligence_api_singleflight_coalesced_total{lookup="dns",scope="domain"}`, callers-1)
		// Every caller read the cache and missed; coalescing happens after that.
		metricstest.Want(t, m, `intelligence_api_cache_requests_total{lookup="dns",result="miss",scope="domain"}`, callers)
	})
}
