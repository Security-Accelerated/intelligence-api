package metrics

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/redis/go-redis/v9"
)

// Dependency collectors. Each reads its source when Prometheus scrapes, so
// nothing here runs on the request path and there is no background sampler to
// own or stop.

// RegisterDB exports the Postgres connection pool (database/sql's DBStats) as
// the client library's standard go_sql_* series, labeled db_name="postgres".
func (m *Metrics) RegisterDB(db *sql.DB) error {
	if err := m.registry.Register(collectors.NewDBStatsCollector(db, "postgres")); err != nil {
		return fmt.Errorf("register postgres pool collector: %w", err)
	}
	return nil
}

// RedisPool is the part of the Redis client the pool collector reads.
type RedisPool interface {
	PoolStats() *redis.PoolStats
}

// RegisterRedisPool exports the Redis client's connection pool. The cache and
// the rate limiter share one client, so this one pool is all of the service's
// Redis traffic.
func (m *Metrics) RegisterRedisPool(pool RedisPool) error {
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(namespace, "redis_pool", name), help, nil, nil)
	}
	c := &redisPoolCollector{
		pool:       pool,
		totalConns: desc("connections", "Connections currently in the Redis pool, in use or idle."),
		idleConns:  desc("idle_connections", "Idle connections currently in the Redis pool."),
		hits:       desc("hits_total", "Times a free connection was found in the Redis pool."),
		misses:     desc("misses_total", "Times no free connection was found in the Redis pool and a new one was dialed."),
		timeouts:   desc("timeouts_total", "Times waiting for a Redis pool connection timed out."),
		stale:      desc("stale_connections_total", "Stale connections removed from the Redis pool."),
	}
	if err := m.registry.Register(c); err != nil {
		return fmt.Errorf("register redis pool collector: %w", err)
	}
	return nil
}

// redisPoolCollector takes one PoolStats snapshot per scrape, so the series in
// a scrape are consistent with each other.
type redisPoolCollector struct {
	pool RedisPool

	totalConns, idleConns         *prometheus.Desc
	hits, misses, timeouts, stale *prometheus.Desc
}

func (c *redisPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func (c *redisPoolCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.pool.PoolStats()
	ch <- prometheus.MustNewConstMetric(c.totalConns, prometheus.GaugeValue, float64(s.TotalConns))
	ch <- prometheus.MustNewConstMetric(c.idleConns, prometheus.GaugeValue, float64(s.IdleConns))
	ch <- prometheus.MustNewConstMetric(c.hits, prometheus.CounterValue, float64(s.Hits))
	ch <- prometheus.MustNewConstMetric(c.misses, prometheus.CounterValue, float64(s.Misses))
	ch <- prometheus.MustNewConstMetric(c.timeouts, prometheus.CounterValue, float64(s.Timeouts))
	ch <- prometheus.MustNewConstMetric(c.stale, prometheus.CounterValue, float64(s.StaleConns))
}

// GeoIPDatabase is the part of the GeoIP reader the collector reads.
// BuildTime reports when the loaded database was built, and false when no
// database is loaded.
type GeoIPDatabase interface {
	BuildTime() (time.Time, bool)
}

// RegisterGeoIP exports whether a GeoIP database is loaded and, when one is,
// the time it was built. The build time is exported as a timestamp rather than
// an age so the age is computed where it is read (time() - the gauge) and
// stays correct between scrapes. It is absent, not zero, while nothing is
// loaded: a zero would read as a database built in 1970.
func (m *Metrics) RegisterGeoIP(db GeoIPDatabase) error {
	c := &geoIPCollector{
		db: db,
		loaded: prometheus.NewDesc(prometheus.BuildFQName(namespace, "geoip", "database_loaded"),
			"1 when a GeoIP database is loaded and the geo lookup can answer, 0 otherwise.", nil, nil),
		built: prometheus.NewDesc(prometheus.BuildFQName(namespace, "geoip", "database_build_timestamp_seconds"),
			"Unix time the loaded GeoIP database was built. Absent while no database is loaded.", nil, nil),
	}
	if err := m.registry.Register(c); err != nil {
		return fmt.Errorf("register geoip collector: %w", err)
	}
	return nil
}

type geoIPCollector struct {
	db            GeoIPDatabase
	loaded, built *prometheus.Desc
}

// Describe lists both series explicitly: Collect emits the build time only
// while a database is loaded, so describing by collecting would register a
// different set depending on when the process started.
func (c *geoIPCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.loaded
	ch <- c.built
}

func (c *geoIPCollector) Collect(ch chan<- prometheus.Metric) {
	built, ok := c.db.BuildTime()
	if !ok {
		ch <- prometheus.MustNewConstMetric(c.loaded, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.loaded, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.built, prometheus.GaugeValue, float64(built.Unix()))
}
