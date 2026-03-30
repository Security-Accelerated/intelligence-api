package service

import (
	"context"
	"encoding/json"
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
)

type IPService struct {
	cache         cache.Cache
	cacheTTL      time.Duration
	lookupTimeout time.Duration
	alerter       notifications.ErrorRecorder

	lookupGeo          func(ip net.IP) (*domain.GeoIPInfo, error)
	lookupASN          func(ip net.IP) (*domain.IPASNInfo, error)
	lookupReverseDNS   func(ctx context.Context, ip string) (*domain.ReverseDNSInfo, error)
	lookupAbuseContact func(ctx context.Context, ip string) (*domain.AbuseContactInfo, error)
	lookupThreatIntel  func(ctx context.Context, ip string) (*domain.ThreatIntelInfo, []domain.LookupError)
}

func NewIPService(
	c cache.Cache,
	cacheTTL, lookupTimeout time.Duration,
	geoReader *domain.GeoIPReader,
	alerter notifications.ErrorRecorder,
	tiProviders []domain.IPThreatIntelProvider,
) *IPService {
	if lookupTimeout <= 0 {
		lookupTimeout = 30 * time.Second
	}

	svc := &IPService{
		cache:         c,
		cacheTTL:      cacheTTL,
		lookupTimeout: lookupTimeout,
		alerter:       alerter,
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

// Lookup performs concurrent IP intelligence lookups with caching.
func (s *IPService) Lookup(ctx context.Context, ip string, opts domain.IPLookupOptions) (*domain.IPResponse, bool) {
	cacheKey := buildIPCacheKey(ip, opts)

	if data, err := s.cache.Get(ctx, cacheKey); err != nil {
		logging.Logger().Warn("cache get failed", zap.String("ip", ip), zap.Error(err))
	} else if data != nil {
		var cached domain.IPResponse
		if err := json.Unmarshal(data, &cached); err != nil {
			logging.Logger().Warn("cache unmarshal failed", zap.String("ip", ip), zap.Error(err))
		} else {
			return &cached, true
		}
	}

	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > s.lookupTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.lookupTimeout)
		defer cancel()
	}

	resp := &domain.IPResponse{IP: ip}
	parsedIP := net.ParseIP(ip)

	var mu sync.Mutex
	var wg sync.WaitGroup
	logger := logging.Logger()

	// GeoIP (local DB, no network call)
	if s.lookupGeo != nil && parsedIP != nil {
		wg.Go(func() {
			result, err := s.lookupGeo(parsedIP)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "geo"), zap.String("ip", ip), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{Lookup: "geo", Message: sanitizeErr(err)})
				s.alerter.RecordLookupError("geo")
				return
			}
			resp.Geo = result
		})
	}

	// ASN (local DB, no network call)
	if s.lookupASN != nil && parsedIP != nil {
		wg.Go(func() {
			result, err := s.lookupASN(parsedIP)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "asn"), zap.String("ip", ip), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{Lookup: "asn", Message: sanitizeErr(err)})
				s.alerter.RecordLookupError("asn")
				return
			}
			resp.ASN = result
		})
	}

	// Reverse DNS
	wg.Go(func() {
		result, err := s.lookupReverseDNS(ctx, ip)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			logger.Warn("lookup failed", zap.String("lookup", "reverse_dns"), zap.String("ip", ip), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{Lookup: "reverse_dns", Message: sanitizeErr(err)})
			s.alerter.RecordLookupError("reverse_dns")
			return
		}
		resp.ReverseDNS = result
	})

	// Abuse contact (RDAP)
	wg.Go(func() {
		result, err := s.lookupAbuseContact(ctx, ip)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			logger.Warn("lookup failed", zap.String("lookup", "abuse_contact"), zap.String("ip", ip), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{Lookup: "abuse_contact", Message: sanitizeErr(err)})
			s.alerter.RecordLookupError("abuse_contact")
			return
		}
		resp.AbuseContact = result
	})

	// Threat intel (optional, pro-only)
	if opts.ThreatIntel {
		wg.Go(func() {
			result, errs := s.lookupThreatIntel(ctx, ip)
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
	// We detect this as: geo lookup is configured but returned nil (error).
	// Other partial failures (missing PTR, provider timeouts) are normal and
	// should be cached to avoid redundant external calls.
	geoMissing := s.lookupGeo != nil && resp.Geo == nil
	if !geoMissing {
		if data, err := json.Marshal(resp); err != nil {
			logger.Warn("cache marshal failed", zap.String("ip", ip), zap.Error(err))
		} else {
			if err := s.cache.Set(ctx, cacheKey, data, s.cacheTTL); err != nil {
				logger.Warn("cache set failed", zap.String("ip", ip), zap.Error(err))
			}
		}
	}

	return resp, false
}
