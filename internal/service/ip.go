package service

import (
	"context"
	"net"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"golang.org/x/sync/singleflight"
)

type IPService struct {
	cache           cache.Cache
	defaultCacheTTL time.Duration
	cacheTTLs       map[string]time.Duration
	sf              singleflight.Group
	lookupTimeout   time.Duration
	alerter         notifications.ErrorRecorder

	lookupGeo          func(ip net.IP) (*domain.GeoIPInfo, error)
	lookupASN          func(ctx context.Context, ip net.IP) (*domain.IPASNInfo, error)
	lookupReverseDNS   func(ctx context.Context, ip string) (*domain.ReverseDNSInfo, error)
	lookupAbuseContact func(ctx context.Context, ip string) (*domain.AbuseContactInfo, error)
	lookupThreatIntel  func(ctx context.Context, ip string) (*domain.ThreatIntelInfo, []domain.LookupError)
}

// NewIPService wires an IPService to its real lookup implementations.
//
// defaultCacheTTL covers any lookup without an entry in cacheTTLs. geoReader
// may be an empty reader — geo then reports ErrDBNotLoaded until the database
// download lands. A nil geoReader leaves geo unwired; asn never needs it.
func NewIPService(
	c cache.Cache,
	defaultCacheTTL time.Duration,
	cacheTTLs map[string]time.Duration,
	lookupTimeout time.Duration,
	geoReader *domain.GeoIPReader,
	alerter notifications.ErrorRecorder,
	tiProviders []domain.IPThreatIntelProvider,
) *IPService {
	if lookupTimeout <= 0 {
		lookupTimeout = 30 * time.Second
	}
	if alerter == nil {
		alerter = &notifications.NoopRecorder{}
	}

	svc := &IPService{
		cache:              c,
		defaultCacheTTL:    defaultCacheTTL,
		cacheTTLs:          cacheTTLs,
		lookupTimeout:      lookupTimeout,
		alerter:            alerter,
		lookupASN:          domain.LookupIPASN,
		lookupReverseDNS:   domain.LookupReverseDNS,
		lookupAbuseContact: domain.LookupAbuseContact,
		lookupThreatIntel: func(ctx context.Context, ip string) (*domain.ThreatIntelInfo, []domain.LookupError) {
			return domain.LookupIPThreatIntel(ctx, ip, tiProviders)
		},
	}

	if geoReader != nil {
		svc.lookupGeo = geoReader.LookupGeo
	}

	return svc
}

// SetLookups replaces all lookup functions. Test-only: production wiring
// happens in NewIPService.
func (s *IPService) SetLookups(
	geo func(net.IP) (*domain.GeoIPInfo, error),
	asn func(context.Context, net.IP) (*domain.IPASNInfo, error),
	rdns func(context.Context, string) (*domain.ReverseDNSInfo, error),
	abuse func(context.Context, string) (*domain.AbuseContactInfo, error),
	ti func(context.Context, string) (*domain.ThreatIntelInfo, []domain.LookupError),
) {
	s.lookupGeo = geo
	s.lookupASN = asn
	s.lookupReverseDNS = rdns
	s.lookupAbuseContact = abuse
	s.lookupThreatIntel = ti
}

// SetThreatIntelLookup replaces the threat intel lookup function (for testing).
func (s *IPService) SetThreatIntelLookup(
	fn func(context.Context, string) (*domain.ThreatIntelInfo, []domain.LookupError),
) {
	s.lookupThreatIntel = fn
}

// ttlFor returns the cache TTL for a lookup, falling back to the default TTL
// for any lookup without its own configured entry.
func (s *IPService) ttlFor(lookupName string) time.Duration {
	if ttl, ok := s.cacheTTLs[lookupName]; ok && ttl > 0 {
		return ttl
	}
	return s.defaultCacheTTL
}

// ipLookupData holds the raw payloads produced by each lookup, before they are
// wrapped with cache_hit metadata for the response.
type ipLookupData struct {
	geo          *domain.GeoIPInfo
	asn          *domain.IPASNInfo
	reverseDNS   *domain.ReverseDNSInfo
	abuseContact *domain.AbuseContactInfo
	threatIntel  *domain.ThreatIntelInfo
}

// buildRunners returns a runner for every requested lookup.
//
// geo is marked uncached: it reads a local mmap, so a Redis round trip would
// cost more than simply doing the lookup again. Its cache_hit is therefore
// always false, which is honest — the data was computed fresh for this
// request. asn is a DNS query to Team Cymru and is cached like any other
// network lookup.
func (s *IPService) buildRunners(st *runState, d *ipLookupData, opts domain.IPLookupOptions, parsed net.IP) []lookupRunner {
	var runners []lookupRunner

	if opts.Has(domain.LookupGeoName) && s.lookupGeo != nil && parsed != nil {
		r := simpleRunner(s.alerter, st, domain.LookupGeoName, &d.geo,
			func(context.Context) (*domain.GeoIPInfo, error) { return s.lookupGeo(parsed) })
		r.uncached = true
		runners = append(runners, r)
	}
	if opts.Has(domain.LookupASNName) && s.lookupASN != nil && parsed != nil {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupASNName, &d.asn,
			func(ctx context.Context) (*domain.IPASNInfo, error) { return s.lookupASN(ctx, parsed) }))
	}
	if opts.Has(domain.LookupReverseDNSName) && s.lookupReverseDNS != nil {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupReverseDNSName, &d.reverseDNS,
			func(ctx context.Context) (*domain.ReverseDNSInfo, error) {
				return s.lookupReverseDNS(ctx, st.target)
			}))
	}
	if opts.Has(domain.LookupAbuseContactName) && s.lookupAbuseContact != nil {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupAbuseContactName, &d.abuseContact,
			func(ctx context.Context) (*domain.AbuseContactInfo, error) {
				return s.lookupAbuseContact(ctx, st.target)
			}))
	}
	if opts.Has(domain.LookupThreatIntelName) && s.lookupThreatIntel != nil {
		runners = append(runners, multiErrRunner(s.alerter, st, domain.LookupThreatIntelName, &d.threatIntel,
			func(ctx context.Context) (*domain.ThreatIntelInfo, []domain.LookupError) {
				return s.lookupThreatIntel(ctx, st.target)
			}))
	}

	return runners
}

// Lookup resolves the requested lookups for a single canonicalized IP.
//
// Like the domain service it issues one MGET for the cacheable lookups, spawns
// goroutines only for the misses, and writes each result back under its own
// key with its own TTL. Failures are not cached — a failing lookup is retried
// on the next request rather than remembered.
func (s *IPService) Lookup(ctx context.Context, ip string, opts domain.IPLookupOptions) (*domain.IPResponse, domain.CacheStats) {
	resp := &domain.IPResponse{IP: ip}
	data := &ipLookupData{}

	st := &runState{
		errs:        &resp.Errors,
		logger:      logging.Logger(),
		target:      ip,
		targetField: "ip",
		keyFor:      func(name string) string { return cache.IPLookupKey(ip, name) },
	}

	hits := runLookups(ctx, runnerDeps{
		cache:         s.cache,
		sf:            &s.sf,
		lookupTimeout: s.lookupTimeout,
		ttlFor:        s.ttlFor,
	}, st, s.buildRunners(st, data, opts, net.ParseIP(ip)))

	s.assemble(resp, data, opts, hits)
	return resp, ipCacheStats(opts, hits)
}

// assemble builds the response from the collected payloads, tagging each field
// with where it came from.
func (s *IPService) assemble(resp *domain.IPResponse, d *ipLookupData, opts domain.IPLookupOptions, hits map[string]bool) {
	if opts.Has(domain.LookupGeoName) && d.geo != nil {
		resp.Geo = &domain.GeoResult{CacheHit: hits[domain.LookupGeoName], GeoIPInfo: d.geo}
	}
	if opts.Has(domain.LookupASNName) && d.asn != nil {
		resp.ASN = &domain.IPASNResult{CacheHit: hits[domain.LookupASNName], IPASNInfo: d.asn}
	}
	if opts.Has(domain.LookupReverseDNSName) && d.reverseDNS != nil {
		resp.ReverseDNS = &domain.ReverseDNSResult{CacheHit: hits[domain.LookupReverseDNSName], ReverseDNSInfo: d.reverseDNS}
	}
	if opts.Has(domain.LookupAbuseContactName) && d.abuseContact != nil {
		resp.AbuseContact = &domain.AbuseContactResult{CacheHit: hits[domain.LookupAbuseContactName], AbuseContactInfo: d.abuseContact}
	}
	if opts.Has(domain.LookupThreatIntelName) && d.threatIntel != nil {
		resp.ThreatIntel = &domain.ThreatIntelResult{CacheHit: hits[domain.LookupThreatIntelName], ThreatIntelInfo: d.threatIntel}
	}
}

// ipCacheStats counts hits and misses across the lookups the caller requested.
// geo and asn are never cached, so they always count as misses — they cost a
// local read rather than an upstream call, which is what the metric is for.
func ipCacheStats(opts domain.IPLookupOptions, hits map[string]bool) domain.CacheStats {
	var stats domain.CacheStats
	for _, name := range opts.Lookups {
		if hits[name] {
			stats.Hits++
		} else {
			stats.Misses++
		}
	}
	return stats
}
