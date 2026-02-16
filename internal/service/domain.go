package service

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

type DomainService struct {
	cache    cache.Cache
	cacheTTL time.Duration

	lookupWhois   func(ctx context.Context, d string) (*domain.WhoisInfo, error)
	lookupDNS     func(ctx context.Context, d string) (*domain.DNSInfo, error)
	lookupSSL     func(ctx context.Context, d string) (*domain.SSLInfo, error)
	lookupHeaders func(ctx context.Context, d string) (*domain.HeadersInfo, error)
}

func NewDomainService(c cache.Cache, cacheTTL time.Duration) *DomainService {
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
	if data, err := s.cache.Get(ctx, domainName); err != nil {
		logging.Logger().Warn("cache get failed", zap.String("domain", domainName), zap.Error(err))
	} else if data != nil {
		var cached domain.DomainResponse
		if err := json.Unmarshal(data, &cached); err != nil {
			logging.Logger().Warn("cache unmarshal failed", zap.String("domain", domainName), zap.Error(err))
		} else {
			return &cached, true
		}
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
		if data, err := json.Marshal(resp); err != nil {
			logging.Logger().Warn("cache marshal failed", zap.String("domain", domainName), zap.Error(err))
		} else if err := s.cache.Set(ctx, domainName, data, s.cacheTTL); err != nil {
			logging.Logger().Warn("cache set failed", zap.String("domain", domainName), zap.Error(err))
		}
	}

	return resp, false
}
