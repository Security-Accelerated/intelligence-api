package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

type IPService struct {
	cache            cache.Cache
	cacheTTL         time.Duration
	negativeCacheTTL time.Duration
	sf               singleflight.Group
	lookupTimeout    time.Duration
	alerter          notifications.ErrorRecorder

	lookupGeo          func(ip net.IP) (*domain.GeoIPInfo, error)
	lookupASN          func(ip net.IP) (*domain.IPASNInfo, error)
	lookupReverseDNS   func(ctx context.Context, ip string) (*domain.ReverseDNSInfo, error)
	lookupAbuseContact func(ctx context.Context, ip string) (*domain.AbuseContactInfo, error)
	lookupThreatIntel  func(ctx context.Context, ip string) (*domain.ThreatIntelInfo, []domain.LookupError)
}

func NewIPService(
	c cache.Cache,
	cacheTTL, negativeCacheTTL, lookupTimeout time.Duration,
	geoReader *domain.GeoIPReader,
	alerter notifications.ErrorRecorder,
	tiProviders []domain.IPThreatIntelProvider,
) *IPService {
	if lookupTimeout <= 0 {
		lookupTimeout = 30 * time.Second
	}
	if negativeCacheTTL <= 0 {
		negativeCacheTTL = cacheTTL
	}
	if alerter == nil {
		alerter = &notifications.NoopRecorder{}
	}

	svc := &IPService{
		cache:              c,
		cacheTTL:           cacheTTL,
		negativeCacheTTL:   negativeCacheTTL,
		lookupTimeout:      lookupTimeout,
		alerter:            alerter,
		lookupReverseDNS:   domain.LookupReverseDNS,
		lookupAbuseContact: domain.LookupAbuseContact,
		lookupThreatIntel: func(ctx context.Context, ip string) (*domain.ThreatIntelInfo, []domain.LookupError) {
			return domain.LookupIPThreatIntel(ctx, ip, tiProviders)
		},
	}

	if geoReader != nil {
		svc.lookupGeo = geoReader.LookupGeo
		svc.lookupASN = geoReader.LookupASN
	}

	return svc
}

// SetLookups replaces all lookup functions (for testing).
func (s *IPService) SetLookups(
	geo func(net.IP) (*domain.GeoIPInfo, error),
	asn func(net.IP) (*domain.IPASNInfo, error),
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

func buildIPCacheKey(ip string, opts domain.IPLookupOptions) string {
	key := "ip:" + ip
	var suffixes []string
	if opts.ThreatIntel {
		suffixes = append(suffixes, "threat_intel")
	}
	if len(suffixes) == 0 {
		return key
	}
	sort.Strings(suffixes)
	return key + ":" + strings.Join(suffixes, "+")
}

// ipLookupResult carries a completed lookup through singleflight to all
// coalesced callers.
type ipLookupResult struct {
	resp     *domain.IPResponse
	cacheHit bool
}

// Lookup performs concurrent IP intelligence lookups with caching. Concurrent
// requests for the same cache key are coalesced into a single fan-out.
func (s *IPService) Lookup(ctx context.Context, ip string, opts domain.IPLookupOptions) (*domain.IPResponse, bool) {
	cacheKey := buildIPCacheKey(ip, opts)

	v, _, shared := s.sf.Do(cacheKey, func() (any, error) {
		return s.doLookup(context.WithoutCancel(ctx), ip, cacheKey, opts), nil
	})
	res := v.(*ipLookupResult)
	if shared {
		copied := copyViaJSON(res.resp)
		if copied == nil {
			// Never hand a coalesced caller the shared pointer — concurrent
			// mutation (e.g. the handler setting CacheHit) would race.
			logging.Logger().Error("singleflight response copy failed", zap.String("ip", ip))
			return &domain.IPResponse{
				IP:     ip,
				Errors: []domain.LookupError{{Lookup: "internal", Message: "internal error, please retry"}},
			}, false
		}
		return copied, res.cacheHit
	}
	return res.resp, res.cacheHit
}

func (s *IPService) doLookup(ctx context.Context, ip, cacheKey string, opts domain.IPLookupOptions) *ipLookupResult {
	if data, err := s.cache.Get(ctx, cacheKey); err != nil {
		logging.Logger().Warn("cache get failed", zap.String("ip", ip), zap.Error(err))
	} else if data != nil {
		var cached domain.IPResponse
		if err := json.Unmarshal(data, &cached); err != nil {
			logging.Logger().Warn("cache unmarshal failed", zap.String("ip", ip), zap.Error(err))
		} else {
			return &ipLookupResult{resp: &cached, cacheHit: true}
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.lookupTimeout)
	defer cancel()

	resp := &domain.IPResponse{IP: ip}
	parsedIP := net.ParseIP(ip)

	var mu sync.Mutex
	var wg sync.WaitGroup
	var geoDBMissing bool
	logger := logging.Logger()

	// GeoIP (local DB, no network call)
	if s.lookupGeo != nil && parsedIP != nil {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "geo", ip, func() {
			result, err := s.lookupGeo(parsedIP)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				resp.Errors = append(resp.Errors, domain.LookupError{Lookup: "geo", Message: sanitizeErr(err)})
				if errors.Is(err, domain.ErrDBNotLoaded) {
					geoDBMissing = true
					logger.Info("geoip database not loaded", zap.String("ip", ip))
				} else {
					logger.Warn("lookup failed", zap.String("lookup", "geo"), zap.String("ip", ip), zap.Error(err))
					s.alerter.RecordLookupError("geo")
				}
				return
			}
			resp.Geo = result
		})
	}

	// ASN (local DB, no network call)
	if s.lookupASN != nil && parsedIP != nil {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "asn", ip, func() {
			result, err := s.lookupASN(parsedIP)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				resp.Errors = append(resp.Errors, domain.LookupError{Lookup: "asn", Message: sanitizeErr(err)})
				if errors.Is(err, domain.ErrDBNotLoaded) {
					geoDBMissing = true
					logger.Info("asn database not loaded", zap.String("ip", ip))
				} else {
					logger.Warn("lookup failed", zap.String("lookup", "asn"), zap.String("ip", ip), zap.Error(err))
					s.alerter.RecordLookupError("asn")
				}
				return
			}
			resp.ASN = result
		})
	}

	// Reverse DNS
	if s.lookupReverseDNS != nil {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "reverse_dns", ip, func() {
			result, err := s.lookupReverseDNS(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "reverse_dns"), zap.String("ip", ip), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{Lookup: "reverse_dns", Message: sanitizeErr(err)})
				recordIfUnexpected(s.alerter, "reverse_dns", err)
				return
			}
			resp.ReverseDNS = result
		})
	}

	// Abuse contact (RDAP)
	if s.lookupAbuseContact != nil {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "abuse_contact", ip, func() {
			result, err := s.lookupAbuseContact(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "abuse_contact"), zap.String("ip", ip), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{Lookup: "abuse_contact", Message: sanitizeErr(err)})
				recordIfUnexpected(s.alerter, "abuse_contact", err)
				return
			}
			resp.AbuseContact = result
		})
	}

	// Threat intel (optional, pro-only)
	if opts.ThreatIntel && s.lookupThreatIntel != nil {
		tiLookup := s.lookupThreatIntel
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "threat_intel", ip, func() {
			result, errs := tiLookup(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			for _, e := range errs {
				s.alerter.RecordLookupError(e.Lookup)
			}
			resp.Errors = append(resp.Errors, errs...)
			resp.ThreatIntel = result
		})
	}

	wg.Wait()

	// Cache the result unless the GeoIP database wasn't loaded (pre-bootstrap).
	// Only the specific ErrDBNotLoaded case skips caching — transient geo lookup
	// failures (e.g., corrupt record) are still cached normally. Responses with
	// failures get a shorter TTL so transient errors age out quickly.
	if !geoDBMissing {
		ttl := s.cacheTTL
		if len(resp.Errors) > 0 {
			ttl = s.negativeCacheTTL
		}
		if data, err := json.Marshal(resp); err != nil {
			logger.Warn("cache marshal failed", zap.String("ip", ip), zap.Error(err))
		} else {
			if err := s.cache.Set(ctx, cacheKey, data, ttl); err != nil {
				logger.Warn("cache set failed", zap.String("ip", ip), zap.Error(err))
			}
		}
	}

	return &ipLookupResult{resp: resp}
}
