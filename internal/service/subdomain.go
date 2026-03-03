package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

type SubdomainService struct {
	cache       cache.Cache
	cacheTTL    time.Duration
	timeout     time.Duration
	maxResults  int
	concurrency int

	lookupSubdomains func(ctx context.Context, domainName string, opts domain.SubdomainOptions) (*domain.SubdomainResponse, error)
}

func NewSubdomainService(c cache.Cache, cacheTTL, timeout time.Duration, maxResults, concurrency int) *SubdomainService {
	if maxResults <= 0 {
		maxResults = 500
	}
	if concurrency <= 0 {
		concurrency = 20
	}
	return &SubdomainService{
		cache:            c,
		cacheTTL:         cacheTTL,
		timeout:          timeout,
		maxResults:       maxResults,
		concurrency:      concurrency,
		lookupSubdomains: domain.LookupSubdomains,
	}
}

// SetLookup replaces the real lookup function with a stub (for testing).
func (s *SubdomainService) SetLookup(
	fn func(context.Context, string, domain.SubdomainOptions) (*domain.SubdomainResponse, error),
) {
	s.lookupSubdomains = fn
}

// subdomainCacheKey builds the Redis key for a subdomain lookup.
func subdomainCacheKey(domainName string, checkLive bool) string {
	prefix := "subdomain"
	if checkLive {
		prefix = "subdomain+check_live"
	}
	return prefix + ":" + domainName
}

func (s *SubdomainService) Lookup(ctx context.Context, domainName string, checkLive bool) (*domain.SubdomainResponse, bool) {
	opts := domain.SubdomainOptions{
		CheckLive:   checkLive,
		Timeout:     s.timeout,
		MaxResults:  s.maxResults,
		Concurrency: s.concurrency,
	}

	key := subdomainCacheKey(domainName, checkLive)

	if data, err := s.cache.Get(ctx, key); err != nil {
		logging.Logger().Warn("subdomain cache get failed", zap.String("domain", domainName), zap.Error(err))
	} else if data != nil {
		var cached domain.SubdomainResponse
		if err := json.Unmarshal(data, &cached); err != nil {
			logging.Logger().Warn("subdomain cache unmarshal failed", zap.String("domain", domainName), zap.Error(err))
		} else {
			return &cached, true
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.lookupSubdomains(ctx, domainName, opts)
	if err != nil {
		logging.Logger().Warn("lookup failed", zap.String("lookup", "subdomain"), zap.String("domain", domainName), zap.Error(err))
		return &domain.SubdomainResponse{
			Domain: domainName,
			Errors: []domain.LookupError{{Lookup: "subdomain", Message: err.Error()}},
		}, false
	}

	if data, err := json.Marshal(resp); err != nil {
		logging.Logger().Warn("subdomain cache marshal failed", zap.String("domain", domainName), zap.Error(err))
	} else if err := s.cache.Set(ctx, key, data, s.cacheTTL); err != nil {
		logging.Logger().Warn("subdomain cache set failed", zap.String("domain", domainName), zap.Error(err))
	}

	return resp, false
}
