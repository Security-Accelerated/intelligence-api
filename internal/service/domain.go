package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
	"go.uber.org/zap"
)

// sanitizeErr replaces internal error messages with user-friendly descriptions.
// Full details are logged server-side; only safe summaries reach the API response.
func sanitizeErr(err error) string {
	var blocked *safenet.BlockedError
	if errors.As(err, &blocked) {
		return "domain resolves to a private/reserved IP address"
	}
	msg := err.Error()
	// Strip verbose internal details — expose only the final segment after ": ".
	if i := strings.LastIndex(msg, ": "); i != -1 {
		msg = msg[i+2:]
	}
	return msg
}

type DomainService struct {
	cache             cache.Cache
	cacheTTL          time.Duration
	screenshotTimeout time.Duration
	subdomainMaxResults int
	ctLogsMaxEntries    int
	fingerprintEngine   *domain.FingerprintEngine
	alerter             notifications.ErrorRecorder

	lookupWhois      func(ctx context.Context, d string) (*domain.WhoisInfo, error)
	lookupDNS        func(ctx context.Context, d string) (*domain.DNSInfo, error)
	lookupSSL        func(ctx context.Context, d string) (*domain.SSLInfo, error)
	lookupHeaders    func(ctx context.Context, d string) (*domain.HeadersInfo, error)
	lookupScreenshot     func(ctx context.Context, d string, timeout time.Duration) (*domain.ScreenshotInfo, error)
	lookupReputation     func(ctx context.Context, d string) (*domain.ReputationResult, []domain.LookupError)
	lookupEmailSecurity  func(ctx context.Context, d string) (*domain.EmailSecurityInfo, error)
	lookupSubdomains     func(ctx context.Context, d string, opts domain.SubdomainOptions) (*domain.SubdomainInfo, error)
	lookupCTLogs         func(ctx context.Context, d string, maxEntries int) (*domain.CTLogsInfo, error)
	lookupBGP            func(ctx context.Context, d string) (*domain.BGPInfo, error)
	lookupThreatIntel    func(ctx context.Context, d string) (*domain.ThreatIntelInfo, []domain.LookupError)
}

func NewDomainService(c cache.Cache, cacheTTL, screenshotTimeout time.Duration, subdomainMaxResults, ctLogsMaxEntries int, fpEngine *domain.FingerprintEngine, alerter notifications.ErrorRecorder, tiProviders []domain.ThreatIntelProvider) *DomainService {
	if subdomainMaxResults <= 0 {
		subdomainMaxResults = 500
	}
	if ctLogsMaxEntries <= 0 {
		ctLogsMaxEntries = 100
	}
	return &DomainService{
		cache:               c,
		cacheTTL:            cacheTTL,
		screenshotTimeout:   screenshotTimeout,
		subdomainMaxResults: subdomainMaxResults,
		ctLogsMaxEntries:    ctLogsMaxEntries,
		fingerprintEngine:   fpEngine,
		alerter:             alerter,
		lookupWhois:         domain.LookupWhois,
		lookupDNS:           domain.LookupDNS,
		lookupSSL:           domain.LookupSSL,
		lookupHeaders:       domain.LookupHeaders,
		lookupScreenshot:    domain.LookupScreenshot,
		lookupReputation:    domain.LookupReputation,
		lookupEmailSecurity: domain.LookupEmailSecurity,
		lookupSubdomains:    domain.LookupSubdomains,
		lookupCTLogs:        domain.LookupCTLogs,
		lookupBGP:           domain.LookupBGP,
		lookupThreatIntel: func(ctx context.Context, d string) (*domain.ThreatIntelInfo, []domain.LookupError) {
			return domain.LookupThreatIntel(ctx, d, tiProviders)
		},
	}
}

func (s *DomainService) SetLookups(
	whois func(context.Context, string) (*domain.WhoisInfo, error),
	dns func(context.Context, string) (*domain.DNSInfo, error),
	ssl func(context.Context, string) (*domain.SSLInfo, error),
	headers func(context.Context, string) (*domain.HeadersInfo, error),
	screenshot func(context.Context, string, time.Duration) (*domain.ScreenshotInfo, error),
	reputation func(context.Context, string) (*domain.ReputationResult, []domain.LookupError),
) {
	s.lookupWhois = whois
	s.lookupDNS = dns
	s.lookupSSL = ssl
	s.lookupHeaders = headers
	s.lookupScreenshot = screenshot
	s.lookupReputation = reputation
}

// SetEmailSecurityLookup replaces the email security lookup function (for testing).
func (s *DomainService) SetEmailSecurityLookup(
	fn func(context.Context, string) (*domain.EmailSecurityInfo, error),
) {
	s.lookupEmailSecurity = fn
}

// SetSubdomainLookup replaces the subdomain lookup function (for testing).
func (s *DomainService) SetSubdomainLookup(
	fn func(context.Context, string, domain.SubdomainOptions) (*domain.SubdomainInfo, error),
) {
	s.lookupSubdomains = fn
}

// SetCTLogsLookup replaces the CT logs lookup function (for testing).
func (s *DomainService) SetCTLogsLookup(
	fn func(context.Context, string, int) (*domain.CTLogsInfo, error),
) {
	s.lookupCTLogs = fn
}

// SetBGPLookup replaces the BGP/ASN lookup function (for testing).
func (s *DomainService) SetBGPLookup(
	fn func(context.Context, string) (*domain.BGPInfo, error),
) {
	s.lookupBGP = fn
}

// SetThreatIntelLookup replaces the threat intel lookup function (for testing).
func (s *DomainService) SetThreatIntelLookup(
	fn func(context.Context, string) (*domain.ThreatIntelInfo, []domain.LookupError),
) {
	s.lookupThreatIntel = fn
}

// SetFingerprintEngine replaces the fingerprint engine (for testing).
func (s *DomainService) SetFingerprintEngine(engine *domain.FingerprintEngine) {
	s.fingerprintEngine = engine
}

func buildCacheKey(domainName string, opts domain.LookupOptions) string {
	var suffixes []string
	if opts.BGP {
		suffixes = append(suffixes, "bgp")
	}
	if opts.CTLogs {
		suffixes = append(suffixes, "ct_logs")
	}
	if opts.EmailSecurity {
		suffixes = append(suffixes, "email_security")
	}
	if opts.Fingerprint {
		suffixes = append(suffixes, "fingerprint")
	}
	if opts.Reputation {
		suffixes = append(suffixes, "reputation")
	}
	if opts.Screenshot {
		suffixes = append(suffixes, "screenshot")
	}
	if opts.Subdomains {
		suffixes = append(suffixes, "subdomains")
	}
	if opts.ThreatIntel {
		suffixes = append(suffixes, "threat_intel")
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

	logger := logging.Logger()

	go func() {
		defer wg.Done()
		result, err := s.lookupWhois(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			logger.Warn("lookup failed", zap.String("lookup", "whois"), zap.String("domain", domainName), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "whois",
				Message: sanitizeErr(err),
			})
			s.alerter.RecordLookupError("whois")
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
			logger.Warn("lookup failed", zap.String("lookup", "dns"), zap.String("domain", domainName), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "dns",
				Message: sanitizeErr(err),
			})
			s.alerter.RecordLookupError("dns")
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
			logger.Warn("lookup failed", zap.String("lookup", "ssl"), zap.String("domain", domainName), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "ssl",
				Message: sanitizeErr(err),
			})
			s.alerter.RecordLookupError("ssl")
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
			logger.Warn("lookup failed", zap.String("lookup", "headers"), zap.String("domain", domainName), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "headers",
				Message: sanitizeErr(err),
			})
			s.alerter.RecordLookupError("headers")
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
				logger.Warn("lookup failed", zap.String("lookup", "screenshot"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "screenshot",
					Message: sanitizeErr(err),
				})
				s.alerter.RecordLookupError("screenshot")
				return
			}
			resp.Screenshot = result
		}()
	}

	if opts.Reputation {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, errs := s.lookupReputation(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			if len(errs) > 0 {
				s.alerter.RecordLookupError("reputation")
			}
			resp.Errors = append(resp.Errors, errs...)
			resp.Reputation = result
		}()
	}

	if opts.EmailSecurity {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.lookupEmailSecurity(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "email_security"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "email_security",
					Message: sanitizeErr(err),
				})
				s.alerter.RecordLookupError("email_security")
				return
			}
			resp.EmailSecurity = result
		}()
	}

	if opts.Subdomains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.lookupSubdomains(ctx, domainName, domain.SubdomainOptions{
				MaxResults: s.subdomainMaxResults,
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "subdomains"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "subdomains",
					Message: sanitizeErr(err),
				})
				s.alerter.RecordLookupError("subdomains")
				return
			}
			resp.Subdomains = result
		}()
	}

	if opts.CTLogs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.lookupCTLogs(ctx, domainName, s.ctLogsMaxEntries)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "ct_logs"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "ct_logs",
					Message: sanitizeErr(err),
				})
				s.alerter.RecordLookupError("ct_logs")
				return
			}
			resp.CTLogs = result
		}()
	}

	if opts.BGP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.lookupBGP(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "bgp"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "bgp",
					Message: sanitizeErr(err),
				})
				s.alerter.RecordLookupError("bgp")
				return
			}
			resp.BGP = result
		}()
	}

	if opts.ThreatIntel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, errs := s.lookupThreatIntel(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			if len(errs) > 0 {
				s.alerter.RecordLookupError("threat_intel")
			}
			resp.Errors = append(resp.Errors, errs...)
			resp.ThreatIntel = result
		}()
	}

	wg.Wait()

	// Fingerprint runs after all lookups complete — it uses already-fetched headers data.
	if opts.Fingerprint && resp.Headers != nil && s.fingerprintEngine != nil {
		resp.Fingerprint = s.fingerprintEngine.Match(resp.Headers)
	}

	hasData := resp.Whois != nil || resp.DNS != nil || resp.SSL != nil || resp.Headers != nil || resp.Screenshot != nil || resp.Reputation != nil || resp.EmailSecurity != nil || resp.Subdomains != nil || resp.CTLogs != nil || resp.BGP != nil || resp.Fingerprint != nil || resp.ThreatIntel != nil
	if hasData {
		if data, err := json.Marshal(resp); err != nil {
			logging.Logger().Warn("cache marshal failed", zap.String("domain", domainName), zap.Error(err))
		} else if err := s.cache.Set(ctx, cacheKey, data, s.cacheTTL); err != nil {
			logging.Logger().Warn("cache set failed", zap.String("domain", domainName), zap.Error(err))
		}
	}

	return resp, false
}
