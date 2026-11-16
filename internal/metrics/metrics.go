// Package metrics holds the service's Prometheus instrumentation: the
// collectors, the methods the rest of the code calls to record into them, and
// the handler that renders them in the exposition format.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// namespace prefixes every metric this package defines. The dashboard in
// deploy/grafana queries these names, so renaming one is a change to both.
const namespace = "intelligence_api"

// Lookup outcomes, the values of the lookup histogram's "outcome" label.
const (
	OutcomeOK      = "ok"
	OutcomeError   = "error"
	OutcomeTimeout = "timeout"
)

// Label values for requests that have no better one. A request that matched no
// route is recorded under one fixed route, and a method outside the standard
// set under one fixed method: both come straight from the caller, so recording
// them verbatim would let anyone mint an unbounded number of series.
const (
	RouteUnmatched = "unmatched"
	MethodOther    = "other"
	PlanNone       = "none"
)

// Bucket bounds in seconds. They are part of the metric's schema rather than
// tuning: changing them breaks the continuity of every stored series, so they
// are fixed here and not config keys. Both run past the timeouts that bound
// what they measure (server.write_timeout at 45s, the lookup timeouts at 30s).
var (
	httpBuckets   = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 45}
	lookupBuckets = []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 30}
)

// Metrics records what the service does and renders it for Prometheus.
//
// It owns a registry of its own instead of using the client library's global
// one, so two instances (every test builds its own) never collide on a metric
// name. Recording is always on and costs a few atomic operations; the
// metrics.enabled config key decides only whether a listener serves the
// result.
//
// Every recording method is safe on a nil *Metrics and does nothing there, so
// a caller holding no Metrics needs neither a check nor a stand-in.
type Metrics struct {
	registry *prometheus.Registry

	httpDuration        *prometheus.HistogramVec
	lookupDuration      *prometheus.HistogramVec
	cacheRequests       *prometheus.CounterVec
	coalesced           *prometheus.CounterVec
	rateLimitRejections *prometheus.CounterVec
}

// New builds a Metrics with the request, lookup, cache and rate-limit
// collectors registered, along with the Go runtime and process collectors and
// a build-info gauge carrying version. The dependency collectors are added
// separately (RegisterDB, RegisterRedisPool, RegisterGeoIP) as each dependency
// comes up.
func New(version string) (*Metrics, error) {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		// One histogram per event rather than a histogram and a counter: its
		// _count series is the request counter, so the two cannot disagree.
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency by route template, method, status code and plan. The _count series is the request count.",
			Buckets:   httpBuckets,
		}, []string{"route", "method", "status", "plan"}),
		lookupDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "lookup_duration_seconds",
			Help:      "Duration of live lookup fetches by scope (domain or ip), lookup and outcome (ok, error, timeout). Cache hits and coalesced callers are not observed. The _count series is the outcome count.",
			Buckets:   lookupBuckets,
		}, []string{"scope", "lookup", "outcome"}),
		cacheRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_requests_total",
			Help:      "Lookup cache reads by scope, lookup and result (hit or miss). Lookups that are never cached are not counted.",
		}, []string{"scope", "lookup", "result"}),
		coalesced: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "singleflight_coalesced_total",
			Help:      "Lookup calls served by another caller's in-flight fetch instead of their own, by scope and lookup.",
		}, []string{"scope", "lookup"}),
		rateLimitRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limit_rejections_total",
			Help:      "Requests rejected with 429 by the rate limiter, by plan.",
		}, []string{"plan"}),
	}

	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   namespace,
		Name:        "build_info",
		Help:        "Always 1; the labels carry the running version and the Go version it was built with.",
		ConstLabels: prometheus.Labels{"version": version, "goversion": runtime.Version()},
	})
	buildInfo.Set(1)

	for _, c := range []prometheus.Collector{
		m.httpDuration,
		m.lookupDuration,
		m.cacheRequests,
		m.coalesced,
		m.rateLimitRejections,
		buildInfo,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	} {
		if err := m.registry.Register(c); err != nil {
			return nil, fmt.Errorf("register collector: %w", err)
		}
	}
	return m, nil
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// InitLookup creates one lookup's series at zero. Prometheus cannot see the
// step from "no such series" to its first value, so a series that first appears
// when its first event happens hides that event from rate(): without this, the
// first timeout of a lookup after a start would never reach a graph. cached
// says whether the lookup reads the cache at all; one that does not gets no
// hit or miss series.
func (m *Metrics) InitLookup(scope, lookup string, cached bool) {
	if m == nil {
		return
	}
	for _, outcome := range []string{OutcomeOK, OutcomeError, OutcomeTimeout} {
		m.lookupDuration.WithLabelValues(scope, lookup, outcome)
	}
	m.coalesced.WithLabelValues(scope, lookup)
	if cached {
		m.cacheRequests.WithLabelValues(scope, lookup, "hit")
		m.cacheRequests.WithLabelValues(scope, lookup, "miss")
	}
}

// InitRateLimitPlan creates a plan's rejection counter at zero, for the same
// reason as InitLookup.
func (m *Metrics) InitRateLimitPlan(plan string) {
	if m == nil {
		return
	}
	m.rateLimitRejections.WithLabelValues(plan)
}

// ObserveHTTP records one finished HTTP request. Its series cannot be created
// ahead of time the way the lookup series are: the combinations of route,
// status and plan are not enumerable, so the first request of each is the one
// rate() does not see. route is the route template
// (never the raw path), and the caller is responsible for bounding route,
// method and plan; see RouteUnmatched, MethodOther and PlanNone.
func (m *Metrics) ObserveHTTP(route, method, plan string, status int, d time.Duration) {
	if m == nil {
		return
	}
	m.httpDuration.WithLabelValues(route, method, strconv.Itoa(status), plan).Observe(d.Seconds())
}

// ObserveLookup records one live fetch of a lookup: how long it took and how
// it ended (OutcomeOK, OutcomeError or OutcomeTimeout). scope is "domain" or
// "ip", which keeps the two threat_intel lookups apart.
func (m *Metrics) ObserveLookup(scope, lookup, outcome string, d time.Duration) {
	if m == nil {
		return
	}
	m.lookupDuration.WithLabelValues(scope, lookup, outcome).Observe(d.Seconds())
}

// CacheResult records one cache read for a lookup as a hit or a miss.
func (m *Metrics) CacheResult(scope, lookup string, hit bool) {
	if m == nil {
		return
	}
	result := "miss"
	if hit {
		result = "hit"
	}
	m.cacheRequests.WithLabelValues(scope, lookup, result).Inc()
}

// Coalesced records a lookup call that waited on another caller's fetch
// through singleflight rather than running its own.
func (m *Metrics) Coalesced(scope, lookup string) {
	if m == nil {
		return
	}
	m.coalesced.WithLabelValues(scope, lookup).Inc()
}

// RateLimitRejected records a request the rate limiter turned away.
func (m *Metrics) RateLimitRejected(plan string) {
	if m == nil {
		return
	}
	m.rateLimitRejections.WithLabelValues(plan).Inc()
}
