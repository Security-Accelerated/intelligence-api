package service

import (
	"context"
	"sync"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

type DomainCache interface {
	Get(ctx context.Context, key string) (*domain.DomainResponse, error)
	Set(ctx context.Context, key string, resp *domain.DomainResponse, ttl time.Duration)
}

type DomainService struct {
	cache    DomainCache
	cacheTTL time.Duration

	lookupWhois   func(ctx context.Context, d string) (*domain.WhoisInfo, error)
	lookupDNS     func(ctx context.Context, d string) (*domain.DNSInfo, error)
	lookupSSL     func(ctx context.Context, d string) (*domain.SSLInfo, error)
	lookupHeaders func(ctx context.Context, d string) (*domain.HeadersInfo, error)
}

func NewDomainService(c DomainCache, cacheTTL time.Duration) *DomainService {
	return &DomainService{
		cache:         c,
		cacheTTL:      cacheTTL,
		lookupWhois:   domain.LookupWhois,
		lookupDNS:     domain.LookupDNS,
		lookupSSL:     domain.LookupSSL,
		lookupHeaders: domain.LookupHeaders,
	}
}

func (s *DomainService) SetLookups(
	whois func(context.Context, string) (*domain.WhoisInfo, error),
	dns func(context.Context, string) (*domain.DNSInfo, error),
	ssl func(context.Context, string) (*domain.SSLInfo, error),
	headers func(context.Context, string) (*domain.HeadersInfo, error),
) {
	s.lookupWhois = whois
	s.lookupDNS = dns
	s.lookupSSL = ssl
	s.lookupHeaders = headers
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
		result, err := s.lookupWhois(ctx, domainName)
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
		result, err := s.lookupDNS(ctx, domainName)
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
		result, err := s.lookupSSL(ctx, domainName)
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
		result, err := s.lookupHeaders(ctx, domainName)
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
