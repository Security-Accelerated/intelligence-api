package metrics_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/security-accelerated/intelligence-api/internal/metrics"
	"github.com/security-accelerated/intelligence-api/internal/metrics/metricstest"
)

func newMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	m, err := metrics.New("v9.9.9")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestNew_ExposesBuildInfoAndRuntime(t *testing.T) {
	m := newMetrics(t)

	metricstest.Want(t, m, `intelligence_api_build_info{goversion="`+runtime.Version()+`",version="v9.9.9"}`, 1)

	body := metricstest.Scrape(t, m)
	for _, name := range []string{"go_goroutines", "process_start_time_seconds"} {
		if !strings.Contains(body, "\n"+name+" ") {
			t.Errorf("scrape is missing %s", name)
		}
	}
}

// Two instances in one process is every test binary that builds more than one.
// It works only because each owns its registry.
func TestNew_InstancesDoNotCollide(t *testing.T) {
	a, b := newMetrics(t), newMetrics(t)
	a.RateLimitRejected("free")

	metricstest.Want(t, a, `intelligence_api_rate_limit_rejections_total{plan="free"}`, 1)
	metricstest.WantAbsent(t, b, `intelligence_api_rate_limit_rejections_total{plan="free"}`)
}

func TestRecording(t *testing.T) {
	m := newMetrics(t)

	m.ObserveHTTP("/v1/domain/lookup", "POST", "pro", 200, 120*time.Millisecond)
	m.ObserveLookup("domain", "dns", metrics.OutcomeOK, 40*time.Millisecond)
	m.ObserveLookup("domain", "dns", metrics.OutcomeTimeout, 30*time.Second)
	m.CacheResult("ip", "asn", true)
	m.CacheResult("ip", "asn", false)
	m.CacheResult("ip", "asn", false)
	m.Coalesced("domain", "whois")
	m.RateLimitRejected("free")

	for series, want := range map[string]float64{
		`intelligence_api_http_request_duration_seconds_count{method="POST",plan="pro",route="/v1/domain/lookup",status="200"}`: 1,
		// 120ms lands in the 0.25s bucket and not the 0.1s one.
		`intelligence_api_http_request_duration_seconds_bucket{method="POST",plan="pro",route="/v1/domain/lookup",status="200",le="0.1"}`:  0,
		`intelligence_api_http_request_duration_seconds_bucket{method="POST",plan="pro",route="/v1/domain/lookup",status="200",le="0.25"}`: 1,
		`intelligence_api_lookup_duration_seconds_count{lookup="dns",outcome="ok",scope="domain"}`:                                         1,
		`intelligence_api_lookup_duration_seconds_count{lookup="dns",outcome="timeout",scope="domain"}`:                                    1,
		// A lookup that ran to the 30s timeout must still land in a finite bucket.
		`intelligence_api_lookup_duration_seconds_bucket{lookup="dns",outcome="timeout",scope="domain",le="30"}`: 1,
		`intelligence_api_cache_requests_total{lookup="asn",result="hit",scope="ip"}`:                            1,
		`intelligence_api_cache_requests_total{lookup="asn",result="miss",scope="ip"}`:                           2,
		`intelligence_api_singleflight_coalesced_total{lookup="whois",scope="domain"}`:                           1,
		`intelligence_api_rate_limit_rejections_total{plan="free"}`:                                              1,
	} {
		metricstest.Want(t, m, series, want)
	}
}

// Callers hold a possibly-nil *Metrics and call it without a check. The test
// passes by not panicking.
func TestNilMetricsRecordsNothing(_ *testing.T) {
	var m *metrics.Metrics
	m.InitLookup("domain", "dns", true)
	m.InitRateLimitPlan("free")
	m.ObserveHTTP("/", "GET", "none", 200, time.Millisecond)
	m.ObserveLookup("domain", "dns", metrics.OutcomeOK, time.Millisecond)
	m.CacheResult("domain", "dns", true)
	m.Coalesced("domain", "dns")
	m.RateLimitRejected("free")
}

type fakeGeoIP struct {
	built  time.Time
	loaded bool
}

func (f *fakeGeoIP) BuildTime() (time.Time, bool) { return f.built, f.loaded }

func TestRegisterGeoIP(t *testing.T) {
	m := newMetrics(t)
	geo := &fakeGeoIP{}
	if err := m.RegisterGeoIP(geo); err != nil {
		t.Fatalf("RegisterGeoIP: %v", err)
	}

	// Nothing loaded: the build time is absent rather than zero, which a
	// dashboard would render as a database 56 years old.
	metricstest.Want(t, m, "intelligence_api_geoip_database_loaded", 0)
	metricstest.WantAbsent(t, m, "intelligence_api_geoip_database_build_timestamp_seconds")

	// The collector reads at scrape time, so a database that lands later
	// (the background download) shows up without re-registering anything.
	geo.built, geo.loaded = time.Unix(1_790_000_000, 0), true
	metricstest.Want(t, m, "intelligence_api_geoip_database_loaded", 1)
	metricstest.Want(t, m, "intelligence_api_geoip_database_build_timestamp_seconds", 1_790_000_000)
}

func TestRegisterRedisPool(t *testing.T) {
	m := newMetrics(t)
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	if err := m.RegisterRedisPool(client); err != nil {
		t.Fatalf("RegisterRedisPool: %v", err)
	}

	if err := client.Ping(t.Context()).Err(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// One command on a fresh client dials one connection and returns it.
	metricstest.Want(t, m, "intelligence_api_redis_pool_connections", 1)
	metricstest.Want(t, m, "intelligence_api_redis_pool_idle_connections", 1)
	metricstest.Want(t, m, "intelligence_api_redis_pool_misses_total", 1)
}

func TestRegisterTwiceIsAnError(t *testing.T) {
	m := newMetrics(t)
	if err := m.RegisterGeoIP(&fakeGeoIP{}); err != nil {
		t.Fatalf("first RegisterGeoIP: %v", err)
	}
	if err := m.RegisterGeoIP(&fakeGeoIP{}); err == nil {
		t.Error("second RegisterGeoIP returned nil, want an error")
	}
}
