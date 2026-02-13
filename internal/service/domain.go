package service

import (
	"context"
	"sync"
	"time"

	"github.com/securityaccelerateddevelopment/intelligence-api/internal/cache"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/domain"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

type DomainService struct {
	cache    *cache.RedisCache
	cacheTTL time.Duration
}

func NewDomainService(c *cache.RedisCache, cacheTTL time.Duration) *DomainService {
	return &DomainService{cache: c, cacheTTL: cacheTTL}
}

func (s *DomainService) Lookup(ctx context.Context, domainName string) (*domain.DomainResponse, bool) {
	if cached, err := s.cache.Get(ctx, domainName); err != nil {
		logging.Logger().Warn("cache get failed", zap.String("domain", domainName), zap.Error(err))
	} else if cached != nil {
		return cached, true
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp := &domain.DomainResponse{
		Domain: domainName,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(4)

	go func() {
		defer wg.Done()
		result, err := domain.LookupWhois(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "whois",
				Message: err.Error(),
			})
			return
		}
		resp.Whois = result
	}()

	go func() {
		defer wg.Done()
		result, err := domain.LookupDNS(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "dns",
				Message: err.Error(),
			})
			return
		}
		resp.DNS = result
	}()

	go func() {
		defer wg.Done()
		result, err := domain.LookupSSL(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "ssl",
				Message: err.Error(),
			})
			return
		}
		resp.SSL = result
	}()

	go func() {
		defer wg.Done()
		result, err := domain.LookupHeaders(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "headers",
				Message: err.Error(),
			})
			return
		}
		resp.Headers = result
	}()

	wg.Wait()

	hasData := resp.Whois != nil || resp.DNS != nil || resp.SSL != nil || resp.Headers != nil
	if hasData {
		s.cache.Set(ctx, domainName, resp, s.cacheTTL)
	}

	return resp, false
}
