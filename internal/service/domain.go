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
	"github.com/security-accelerated/intelligence-api/internal/safenet"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// copyViaJSON deep-copies a response struct so coalesced singleflight callers
// never share (and mutate) the same value. Returns nil if the round-trip fails.
func copyViaJSON[T any](v *T) *T {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	out := new(T)
	if err := json.Unmarshal(data, out); err != nil {
		return nil
	}
	return out
}

// goLookup runs a lookup goroutine with panic recovery. gin.Recovery only
// covers handler goroutines — without this, one panicking lookup (malformed
// cert, bad regex) would kill the entire process. A panic degrades to a
// sanitized lookup error on the response, consistent with partial-failure
// tolerance.
func goLookup(wg *sync.WaitGroup, mu *sync.Mutex, errs *[]domain.LookupError, alerter notifications.ErrorRecorder, lookupName, target string, fn func()) {
	wg.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Logger().Error("lookup panicked",
					zap.String("lookup", lookupName),
					zap.String("target", target),
					zap.Any("panic", r),
					zap.Stack("stack"),
				)
				mu.Lock()
				defer mu.Unlock()
				*errs = append(*errs, domain.LookupError{Lookup: lookupName, Message: "internal error"})
				alerter.RecordLookupError(lookupName)
			}
		}()
		fn()
	})
}

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

// isExpectedError returns true for errors caused by upstream services or
// invalid input rather than infrastructure problems on our end. These errors
// are logged but should not trigger Pushover alerts.
func isExpectedError(err error) bool {
	// Context deadline/cancellation — slow upstream, not our failure.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	// DNS errors (NXDOMAIN, SERVFAIL, timeout) — upstream DNS issues.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	// Match common upstream error messages that aren't wrapped as typed errors.
	msg := err.Error()
	expectedPatterns := []string{
		"domain is not found",       // WHOIS parser: domain doesn't exist
		"no whois server found",     // no WHOIS server for this TLD
		"i/o timeout",               // upstream network timeout
		"no such host",              // DNS resolution failure
		"server misbehaving",        // DNS SERVFAIL
		"tls connect",               // TLS handshake failure on target
		"certificate",               // cert errors on target domain
		"context deadline exceeded", // nested context timeout strings
	}
	for _, p := range expectedPatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}

	return false
}

// recordIfUnexpected records a lookup error for alerting only if it represents
// an infrastructure problem (not a routine upstream failure).
func recordIfUnexpected(alerter notifications.ErrorRecorder, lookupName string, err error) {
	if !isExpectedError(err) {
		alerter.RecordLookupError(lookupName)
	}
}

type DomainService struct {
	cache               cache.Cache
	cacheTTL            time.Duration
	negativeCacheTTL    time.Duration
	sf                  singleflight.Group
	lookupTimeout       time.Duration
	screenshotTimeout   time.Duration
	subdomainMaxResults int
	ctLogsMaxEntries    int
	fingerprintEngine   *domain.FingerprintEngine
	alerter             notifications.ErrorRecorder

	lookupWhois         func(ctx context.Context, d string) (*domain.WhoisInfo, error)
	lookupDNS           func(ctx context.Context, d string) (*domain.DNSInfo, error)
	lookupSSL           func(ctx context.Context, d string) (*domain.SSLInfo, error)
	lookupHeaders       func(ctx context.Context, d string) (*domain.HeadersInfo, error)
	lookupScreenshot    func(ctx context.Context, d string, timeout time.Duration) (*domain.ScreenshotInfo, error)
	lookupReputation    func(ctx context.Context, d string) (*domain.ReputationResult, []domain.LookupError)
	lookupEmailSecurity func(ctx context.Context, d string) (*domain.EmailSecurityInfo, error)
	lookupSubdomains    func(ctx context.Context, d string, opts domain.SubdomainOptions) (*domain.SubdomainInfo, error)
	lookupCTLogs        func(ctx context.Context, d string, maxEntries int) (*domain.CTLogsInfo, error)
	lookupBGP           func(ctx context.Context, d string) (*domain.BGPInfo, error)
	lookupThreatIntel   func(ctx context.Context, d string) (*domain.ThreatIntelInfo, []domain.LookupError)
	lookupDNSSecurity   func(ctx context.Context, d string) (*domain.DNSSecurityInfo, error)
}

func NewDomainService(c cache.Cache, cacheTTL, negativeCacheTTL, lookupTimeout, screenshotTimeout time.Duration, subdomainMaxResults, ctLogsMaxEntries int, fpEngine *domain.FingerprintEngine, alerter notifications.ErrorRecorder, tiProviders []domain.ThreatIntelProvider) *DomainService {
	if subdomainMaxResults <= 0 {
		subdomainMaxResults = 500
	}
	if ctLogsMaxEntries <= 0 {
		ctLogsMaxEntries = 100
	}
	if lookupTimeout <= 0 {
		lookupTimeout = 30 * time.Second
	}
	if negativeCacheTTL <= 0 {
		negativeCacheTTL = cacheTTL
	}
	if alerter == nil {
		alerter = &notifications.NoopRecorder{}
	}
	return &DomainService{
		cache:               c,
		cacheTTL:            cacheTTL,
		negativeCacheTTL:    negativeCacheTTL,
		lookupTimeout:       lookupTimeout,
		screenshotTimeout:   screenshotTimeout,
		subdomainMaxResults: subdomainMaxResults,
		ctLogsMaxEntries:    ctLogsMaxEntries,
		fingerprintEngine:   fpEngine,
		alerter:             alerter,
		lookupWhois:         domain.LookupWhois,
		lookupDNS:           domain.LookupDNS,
		lookupSSL:           domain.LookupSSL,
		lookupHeaders:       domain.LookupHeaders,
		lookupScreenshot: func(ctx context.Context, d string, timeout time.Duration) (*domain.ScreenshotInfo, error) {
			return domain.LookupScreenshot(ctx, d, timeout, domain.DefaultMaxPNGBytes)
		},
		lookupReputation:    domain.LookupReputation,
		lookupEmailSecurity: domain.LookupEmailSecurity,
		lookupSubdomains:    domain.LookupSubdomains,
		lookupCTLogs:        domain.LookupCTLogs,
		lookupBGP:           domain.LookupBGP,
		lookupThreatIntel: func(ctx context.Context, d string) (*domain.ThreatIntelInfo, []domain.LookupError) {
			return domain.LookupThreatIntel(ctx, d, tiProviders)
		},
		lookupDNSSecurity: domain.LookupDNSSecurity,
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

// SetDNSSecurityLookup replaces the DNS security lookup function (for testing).
func (s *DomainService) SetDNSSecurityLookup(
	fn func(context.Context, string) (*domain.DNSSecurityInfo, error),
) {
	s.lookupDNSSecurity = fn
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
	if opts.DNSSecurity {
		suffixes = append(suffixes, "dns_security")
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

// domainLookupResult carries a completed lookup through singleflight to all
// coalesced callers.
type domainLookupResult struct {
	resp     *domain.DomainResponse
	cacheHit bool
}

func (s *DomainService) Lookup(ctx context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, bool) {
	cacheKey := buildCacheKey(domainName, opts)

	// Coalesce concurrent lookups for the same cache key — only one fan-out
	// runs; the rest wait for its result. The executed lookup is detached from
	// the triggering caller's cancellation so one disconnecting client can't
	// poison the result shared with the others.
	v, _, shared := s.sf.Do(cacheKey, func() (any, error) {
		return s.doLookup(context.WithoutCancel(ctx), domainName, cacheKey, opts), nil
	})
	res := v.(*domainLookupResult)
	if shared {
		copied := copyViaJSON(res.resp)
		if copied == nil {
			// Never hand a coalesced caller the shared pointer — concurrent
			// mutation (e.g. the handler setting CacheHit) would race.
			logging.Logger().Error("singleflight response copy failed", zap.String("domain", domainName))
			return &domain.DomainResponse{
				Domain: domainName,
				Errors: []domain.LookupError{{Lookup: "internal", Message: "internal error, please retry"}},
			}, false
		}
		return copied, res.cacheHit
	}
	return res.resp, res.cacheHit
}

func (s *DomainService) doLookup(ctx context.Context, domainName, cacheKey string, opts domain.LookupOptions) *domainLookupResult {
	if data, err := s.cache.Get(ctx, cacheKey); err != nil {
		logging.Logger().Warn("cache get failed", zap.String("domain", domainName), zap.Error(err))
	} else if data != nil {
		var cached domain.DomainResponse
		if err := json.Unmarshal(data, &cached); err != nil {
			logging.Logger().Warn("cache unmarshal failed", zap.String("domain", domainName), zap.Error(err))
		} else {
			return &domainLookupResult{resp: &cached, cacheHit: true}
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.lookupTimeout)
	defer cancel()

	resp := &domain.DomainResponse{
		Domain: domainName,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	logger := logging.Logger()

	goLookup(&wg, &mu, &resp.Errors, s.alerter, "whois", domainName, func() {
		result, err := s.lookupWhois(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			logger.Warn("lookup failed", zap.String("lookup", "whois"), zap.String("domain", domainName), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "whois",
				Message: sanitizeErr(err),
			})
			recordIfUnexpected(s.alerter, "whois", err)
			return
		}
		resp.Whois = result
	})

	goLookup(&wg, &mu, &resp.Errors, s.alerter, "dns", domainName, func() {
		result, err := s.lookupDNS(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			logger.Warn("lookup failed", zap.String("lookup", "dns"), zap.String("domain", domainName), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "dns",
				Message: sanitizeErr(err),
			})
			recordIfUnexpected(s.alerter, "dns", err)
			return
		}
		resp.DNS = result
	})

	goLookup(&wg, &mu, &resp.Errors, s.alerter, "ssl", domainName, func() {
		result, err := s.lookupSSL(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			logger.Warn("lookup failed", zap.String("lookup", "ssl"), zap.String("domain", domainName), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "ssl",
				Message: sanitizeErr(err),
			})
			recordIfUnexpected(s.alerter, "ssl", err)
			return
		}
		resp.SSL = result
	})

	goLookup(&wg, &mu, &resp.Errors, s.alerter, "headers", domainName, func() {
		result, err := s.lookupHeaders(ctx, domainName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			logger.Warn("lookup failed", zap.String("lookup", "headers"), zap.String("domain", domainName), zap.Error(err))
			resp.Errors = append(resp.Errors, domain.LookupError{
				Lookup:  "headers",
				Message: sanitizeErr(err),
			})
			recordIfUnexpected(s.alerter, "headers", err)
			return
		}
		resp.Headers = result
	})

	if opts.Screenshot {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "screenshot", domainName, func() {
			result, err := s.lookupScreenshot(ctx, domainName, s.screenshotTimeout)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "screenshot"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "screenshot",
					Message: sanitizeErr(err),
				})
				recordIfUnexpected(s.alerter, "screenshot", err)
				return
			}
			resp.Screenshot = result
		})
	}

	if opts.Reputation {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "reputation", domainName, func() {
			result, errs := s.lookupReputation(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			for _, e := range errs {
				s.alerter.RecordLookupError(e.Lookup)
			}
			resp.Errors = append(resp.Errors, errs...)
			resp.Reputation = result
		})
	}

	if opts.EmailSecurity {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "email_security", domainName, func() {
			result, err := s.lookupEmailSecurity(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "email_security"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "email_security",
					Message: sanitizeErr(err),
				})
				recordIfUnexpected(s.alerter, "email_security", err)
				return
			}
			resp.EmailSecurity = result
		})
	}

	if opts.Subdomains {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "subdomains", domainName, func() {
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
				recordIfUnexpected(s.alerter, "subdomains", err)
				return
			}
			resp.Subdomains = result
		})
	}

	if opts.CTLogs {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "ct_logs", domainName, func() {
			result, err := s.lookupCTLogs(ctx, domainName, s.ctLogsMaxEntries)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "ct_logs"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "ct_logs",
					Message: sanitizeErr(err),
				})
				recordIfUnexpected(s.alerter, "ct_logs", err)
				return
			}
			resp.CTLogs = result
		})
	}

	if opts.BGP {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "bgp", domainName, func() {
			result, err := s.lookupBGP(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "bgp"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "bgp",
					Message: sanitizeErr(err),
				})
				recordIfUnexpected(s.alerter, "bgp", err)
				return
			}
			resp.BGP = result
		})
	}

	if opts.DNSSecurity {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "dns_security", domainName, func() {
			result, err := s.lookupDNSSecurity(ctx, domainName)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("lookup failed", zap.String("lookup", "dns_security"), zap.String("domain", domainName), zap.Error(err))
				resp.Errors = append(resp.Errors, domain.LookupError{
					Lookup:  "dns_security",
					Message: sanitizeErr(err),
				})
				recordIfUnexpected(s.alerter, "dns_security", err)
				return
			}
			resp.DNSSecurity = result
		})
	}

	if opts.ThreatIntel {
		goLookup(&wg, &mu, &resp.Errors, s.alerter, "threat_intel", domainName, func() {
			result, errs := s.lookupThreatIntel(ctx, domainName)
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

	// Fingerprint runs after all lookups complete — it uses already-fetched headers data.
	if opts.Fingerprint && resp.Headers != nil && s.fingerprintEngine != nil {
		resp.Fingerprint = s.fingerprintEngine.Match(resp.Headers)
	}

	// Aggregate risk score is post-processing over already-fetched data —
	// zero extra network calls, computed from whichever lookups are present.
	resp.Risk = domain.ComputeRiskScore(resp, time.Now())

	hasData := resp.Whois != nil || resp.DNS != nil || resp.SSL != nil || resp.Headers != nil || resp.Screenshot != nil || resp.Reputation != nil || resp.EmailSecurity != nil || resp.Subdomains != nil || resp.CTLogs != nil || resp.BGP != nil || resp.Fingerprint != nil || resp.ThreatIntel != nil || resp.DNSSecurity != nil
	// Responses with failures get a shorter TTL so transient upstream errors
	// aren't served from cache for the full window — but they ARE cached, so a
	// nonexistent domain doesn't trigger a fresh fan-out on every request.
	ttl := s.cacheTTL
	if len(resp.Errors) > 0 {
		ttl = s.negativeCacheTTL
	}
	if hasData || len(resp.Errors) > 0 {
		if data, err := json.Marshal(resp); err != nil {
			logging.Logger().Warn("cache marshal failed", zap.String("domain", domainName), zap.Error(err))
		} else if err := s.cache.Set(ctx, cacheKey, data, ttl); err != nil {
			logging.Logger().Warn("cache set failed", zap.String("domain", domainName), zap.Error(err))
		}
	}

	return &domainLookupResult{resp: resp}
}
