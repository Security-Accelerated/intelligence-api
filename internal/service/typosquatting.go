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

type TyposquattingService struct {
	cache           cache.Cache
	cacheTTL        time.Duration
	timeout         time.Duration
	maxPermutations int
	concurrency     int

	lookupTyposquatting func(ctx context.Context, domainName string, opts domain.TyposquattingOptions) (*domain.TyposquattingResponse, error)
}

func NewTyposquattingService(c cache.Cache, cacheTTL, timeout time.Duration, maxPerms, concurrency int) *TyposquattingService {
	if maxPerms <= 0 {
		maxPerms = 500
	}
	if concurrency <= 0 {
		concurrency = 20
	}
	return &TyposquattingService{
		cache:               c,
		cacheTTL:            cacheTTL,
		timeout:             timeout,
		maxPermutations:     maxPerms,
		concurrency:         concurrency,
		lookupTyposquatting: domain.LookupTyposquatting,
	}
}

// SetLookup replaces the real lookup function with a stub (for testing).
func (s *TyposquattingService) SetLookup(
	fn func(context.Context, string, domain.TyposquattingOptions) (*domain.TyposquattingResponse, error),
) {
	s.lookupTyposquatting = fn
}

// cacheKey builds the Redis key for a typosquatting lookup.
// Format: typosquatting:domain:depth or typosquatting+check_live:domain:depth
func cacheKey(domainName string, opts domain.TyposquattingOptions) string {
	prefix := "typosquatting"
	if opts.CheckLive {
		prefix = "typosquatting+check_live"
	}
	depth := opts.Depth
	if depth == "" {
		depth = "shallow"
	}
	return prefix + ":" + domainName + ":" + depth
}

func (s *TyposquattingService) Lookup(ctx context.Context, domainName string, checkLive bool, depth string) (*domain.TyposquattingResponse, bool) {
	opts := domain.TyposquattingOptions{
		CheckLive:       checkLive,
		Depth:           depth,
		Timeout:         s.timeout,
		MaxPermutations: s.maxPermutations,
		Concurrency:     s.concurrency,
	}

	key := cacheKey(domainName, opts)

	if data, err := s.cache.Get(ctx, key); err != nil {
		logging.Logger().Warn("typosquatting cache get failed", zap.String("domain", domainName), zap.Error(err))
	} else if data != nil {
		var cached domain.TyposquattingResponse
		if err := json.Unmarshal(data, &cached); err != nil {
			logging.Logger().Warn("typosquatting cache unmarshal failed", zap.String("domain", domainName), zap.Error(err))
		} else {
			return &cached, true
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.lookupTyposquatting(ctx, domainName, opts)
	if err != nil {
		logging.Logger().Warn("lookup failed", zap.String("lookup", "typosquatting"), zap.String("domain", domainName), zap.Error(err))
		return &domain.TyposquattingResponse{
			Domain: domainName,
			Depth:  depth,
			Errors: []domain.LookupError{{Lookup: "typosquatting", Message: err.Error()}},
		}, false
	}

	if data, err := json.Marshal(resp); err != nil {
		logging.Logger().Warn("typosquatting cache marshal failed", zap.String("domain", domainName), zap.Error(err))
	} else if err := s.cache.Set(ctx, key, data, s.cacheTTL); err != nil {
		logging.Logger().Warn("typosquatting cache set failed", zap.String("domain", domainName), zap.Error(err))
	}

	return resp, false
}
