package service

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

type DomainService struct {
	cache             cache.Cache
	cacheTTL          time.Duration
	screenshotTimeout time.Duration

	lookupWhois      func(ctx context.Context, d string) (*domain.WhoisInfo, error)
	lookupDNS        func(ctx context.Context, d string) (*domain.DNSInfo, error)
	lookupSSL        func(ctx context.Context, d string) (*domain.SSLInfo, error)
	lookupHeaders    func(ctx context.Context, d string) (*domain.HeadersInfo, error)
	lookupScreenshot func(ctx context.Context, d string, timeout time.Duration) (*domain.ScreenshotInfo, error)
	lookupReputation  func(ctx context.Context, d string) (*domain.ReputationInfo, error)
}

func NewDomainService(c cache.Cache, cacheTTL, screenshotTimeout time.Duration) *DomainService {
	return &DomainService{
		cache:             c,
		cacheTTL:          cacheTTL,
		screenshotTimeout: screenshotTimeout,
		lookupWhois:       domain.LookupWhois,
		lookupDNS:         domain.LookupDNS,
		lookupSSL:         domain.LookupSSL,
		lookupHeaders:     domain.LookupHeaders,
		lookupScreenshot:  domain.LookupScreenshot,
		lookupReputation:   domain.LookupReputation,
	}
}

func (s *DomainService) SetLookups(
	whois func(context.Context, string) (*domain.WhoisInfo, error),
	dns func(context.Context, string) (*domain.DNSInfo, error),
	ssl func(context.Context, string) (*domain.SSLInfo, error),
	headers func(context.Context, string) (*domain.HeadersInfo, error),
	screenshot func(context.Context, string, time.Duration) (*domain.ScreenshotInfo, error),
	reputation func(context.Context, string) (*domain.ReputationInfo, error),
) {
	s.lookupWhois = whois
	s.lookupDNS = dns
	s.lookupSSL = ssl
	s.lookupHeaders = headers
	s.lookupScreenshot = screenshot
	s.lookupReputation = reputation
}

func buildCacheKey(domainName string, opts domain.LookupOptions) string {
	var suffixes []string
	if opts.Reputation {
		suffixes = append(suffixes, "reputation")
	}
	if opts.Screenshot {
		suffixes = append(suffixes, "screenshot")
	}
	if len(suffixes) == 0 {
		return domainName
	}
	sort.Strings(suffixes)
	return domainName + ":" + strings.Join(suffixes, "+")
}

func (s *DomainService) Lookup(ctx context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, bool) {
	cacheKey := buildCacheKey(domainName, opts)

	if data, err := s.cache.Get(ctx, cacheKey); err != nil {
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

	if opts.Screenshot {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.lookupScreenshot(ctx, domainName, s.screenshotTimeout)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "screenshot",
					Message: err.Error(),
				})
				return
			}
			resp.Screenshot = result
		}()
	}

	if opts.Reputation {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.lookupReputation(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "reputation",
					Message: err.Error(),
				})
				return
			}
			resp.Reputation = result
		}()
	}

	wg.Wait()

	hasData := resp.Whois != nil || resp.DNS != nil || resp.SSL != nil || resp.Headers != nil || resp.Screenshot != nil || resp.Reputation != nil
	if hasData {
		if data, err := json.Marshal(resp); err != nil {
			logging.Logger().Warn("cache marshal failed", zap.String("domain", domainName), zap.Error(err))
		} else if err := s.cache.Set(ctx, cacheKey, data, s.cacheTTL); err != nil {
			logging.Logger().Warn("cache set failed", zap.String("domain", domainName), zap.Error(err))
		}
	}

	return resp, false
}
