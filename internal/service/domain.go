package service

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"github.com/security-accelerated/intelligence-api/internal/safenet"
	"golang.org/x/sync/singleflight"
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
	defaultCacheTTL     time.Duration
	cacheTTLs           map[string]time.Duration
	sf                  singleflight.Group
	lookupTimeout       time.Duration
	screenshotTimeout   time.Duration
	screenshotSem       chan struct{} // caps concurrent Chromium across ALL in-flight requests
	subdomainMaxResults int
	ctLogsMaxEntries    int
	fingerprintEngine   *domain.FingerprintEngine
	alerter             notifications.ErrorRecorder

	lookupWhois         func(ctx context.Context, d string) (*domain.WhoisInfo, error)
	lookupDNS           func(ctx context.Context, d string) (*domain.DNSInfo, error)
	lookupSSL           func(ctx context.Context, d string) (*domain.SSLInfo, error)
	lookupHeaders       func(ctx context.Context, d string) (*domain.HeadersInfo, error)
	lookupScreenshot    func(ctx context.Context, d string, timeout time.Duration) (*domain.ScreenshotInfo, error)
	lookupReputation    func(ctx context.Context, d string) (*domain.ReputationInfo, []domain.LookupError)
	lookupEmailSecurity func(ctx context.Context, d string) (*domain.EmailSecurityInfo, error)
	lookupSubdomains    func(ctx context.Context, d string, opts domain.SubdomainOptions) (*domain.SubdomainInfo, error)
	lookupCTLogs        func(ctx context.Context, d string, maxEntries int) (*domain.CTLogsInfo, error)
	lookupBGP           func(ctx context.Context, d string) (*domain.BGPInfo, error)
	lookupThreatIntel   func(ctx context.Context, d string) (*domain.ThreatIntelInfo, []domain.LookupError)
	lookupDNSSecurity   func(ctx context.Context, d string) (*domain.DNSSecurityInfo, error)
}

// NewDomainService wires a DomainService to its real lookup implementations.
//
// defaultCacheTTL covers any lookup without an entry in cacheTTLs; see ttlFor.
// screenshotMaxConcurrent sizes the process-wide Chromium semaphore, and
// tiProviders is the set of threat intelligence backends built from config at
// startup. Non-positive numeric arguments fall back to sane defaults, so a
// zero-valued config cannot produce an unusable service.
func NewDomainService(c cache.Cache, defaultCacheTTL time.Duration, cacheTTLs map[string]time.Duration, lookupTimeout, screenshotTimeout time.Duration, screenshotMaxConcurrent, subdomainMaxResults, ctLogsMaxEntries int, fpEngine *domain.FingerprintEngine, alerter notifications.ErrorRecorder, tiProviders []domain.ThreatIntelProvider) *DomainService {
	if subdomainMaxResults <= 0 {
		subdomainMaxResults = 500
	}
	if ctLogsMaxEntries <= 0 {
		ctLogsMaxEntries = 100
	}
	if lookupTimeout <= 0 {
		lookupTimeout = 30 * time.Second
	}
	if screenshotMaxConcurrent <= 0 {
		screenshotMaxConcurrent = 4
	}
	if alerter == nil {
		alerter = &notifications.NoopRecorder{}
	}
	return &DomainService{
		cache:               c,
		defaultCacheTTL:     defaultCacheTTL,
		cacheTTLs:           cacheTTLs,
		lookupTimeout:       lookupTimeout,
		screenshotTimeout:   screenshotTimeout,
		screenshotSem:       make(chan struct{}, screenshotMaxConcurrent),
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

// SetLookups replaces the base lookup functions. Test-only: production wiring
// happens in NewDomainService.
func (s *DomainService) SetLookups(
	whois func(context.Context, string) (*domain.WhoisInfo, error),
	dns func(context.Context, string) (*domain.DNSInfo, error),
	ssl func(context.Context, string) (*domain.SSLInfo, error),
	headers func(context.Context, string) (*domain.HeadersInfo, error),
	screenshot func(context.Context, string, time.Duration) (*domain.ScreenshotInfo, error),
	reputation func(context.Context, string) (*domain.ReputationInfo, []domain.LookupError),
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

// ttlFor returns the cache TTL for a lookup, falling back to the default TTL
// for any lookup without its own configured entry.
func (s *DomainService) ttlFor(lookupName string) time.Duration {
	if ttl, ok := s.cacheTTLs[lookupName]; ok && ttl > 0 {
		return ttl
	}
	return s.defaultCacheTTL
}

// lookupData holds the raw payloads produced by each lookup, before they are
// wrapped with cache_hit metadata for the response. Fields are written either by
// decoding a cached entry (serially, before fan-out) or by a live-fetch
// goroutine (under mu).
type lookupData struct {
	whois         *domain.WhoisInfo
	dns           *domain.DNSInfo
	ssl           *domain.SSLInfo
	headers       *domain.HeadersInfo
	screenshot    *domain.ScreenshotInfo
	reputation    *domain.ReputationInfo
	emailSecurity *domain.EmailSecurityInfo
	subdomains    *domain.SubdomainInfo
	ctLogs        *domain.CTLogsInfo
	bgp           *domain.BGPInfo
	threatIntel   *domain.ThreatIntelInfo
	dnsSecurity   *domain.DNSSecurityInfo
}

// buildRunners returns a runner for every lookup whose data this request needs.
// Requested lookups map one-to-one onto runners, with two exceptions:
//   - fingerprint has no runner of its own — it is pure computation over headers
//     data, so caching headers already caches fingerprint. Requesting it pulls in
//     the headers runner instead.
//   - risk has no runner either — it scores the other lookups already on the
//     response, so it needs no fetch and gets no cache entry.
//   - headers is fetched at most once even when both headers and fingerprint are
//     requested, so shared data costs exactly one upstream call.
func (s *DomainService) buildRunners(st *runState, d *lookupData, opts domain.LookupOptions) []lookupRunner {
	var runners []lookupRunner

	if opts.Has(domain.LookupWhoisName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupWhoisName, &d.whois,
			func(ctx context.Context) (*domain.WhoisInfo, error) { return s.lookupWhois(ctx, st.target) }))
	}
	if opts.Has(domain.LookupDNSName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupDNSName, &d.dns,
			func(ctx context.Context) (*domain.DNSInfo, error) { return s.lookupDNS(ctx, st.target) }))
	}
	if opts.Has(domain.LookupSSLName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupSSLName, &d.ssl,
			func(ctx context.Context) (*domain.SSLInfo, error) { return s.lookupSSL(ctx, st.target) }))
	}
	// One headers fetch serves both headers and fingerprint.
	if opts.Has(domain.LookupHeadersName) || opts.Has(domain.LookupFingerprintName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupHeadersName, &d.headers,
			func(ctx context.Context) (*domain.HeadersInfo, error) { return s.lookupHeaders(ctx, st.target) }))
	}
	if opts.Has(domain.LookupScreenshotName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupScreenshotName, &d.screenshot,
			func(ctx context.Context) (*domain.ScreenshotInfo, error) {
				// Chromium is by far the most expensive lookup, so it takes a
				// slot from a process-wide semaphore rather than fork-bombing
				// under load.
				if s.screenshotSem != nil {
					select {
					case s.screenshotSem <- struct{}{}:
						defer func() { <-s.screenshotSem }()
					case <-ctx.Done():
						return nil, errors.New("screenshot queue timed out, please retry")
					}
				}
				return s.lookupScreenshot(ctx, st.target, s.screenshotTimeout)
			}))
	}
	if opts.Has(domain.LookupReputationName) {
		runners = append(runners, multiErrRunner(s.alerter, st, domain.LookupReputationName, &d.reputation,
			func(ctx context.Context) (*domain.ReputationInfo, []domain.LookupError) {
				return s.lookupReputation(ctx, st.target)
			}))
	}
	if opts.Has(domain.LookupEmailSecurityName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupEmailSecurityName, &d.emailSecurity,
			func(ctx context.Context) (*domain.EmailSecurityInfo, error) {
				return s.lookupEmailSecurity(ctx, st.target)
			}))
	}
	if opts.Has(domain.LookupSubdomainsName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupSubdomainsName, &d.subdomains,
			func(ctx context.Context) (*domain.SubdomainInfo, error) {
				return s.lookupSubdomains(ctx, st.target, domain.SubdomainOptions{MaxResults: s.subdomainMaxResults})
			}))
	}
	if opts.Has(domain.LookupCTLogsName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupCTLogsName, &d.ctLogs,
			func(ctx context.Context) (*domain.CTLogsInfo, error) {
				return s.lookupCTLogs(ctx, st.target, s.ctLogsMaxEntries)
			}))
	}
	if opts.Has(domain.LookupBGPName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupBGPName, &d.bgp,
			func(ctx context.Context) (*domain.BGPInfo, error) { return s.lookupBGP(ctx, st.target) }))
	}
	if opts.Has(domain.LookupThreatIntelName) {
		runners = append(runners, multiErrRunner(s.alerter, st, domain.LookupThreatIntelName, &d.threatIntel,
			func(ctx context.Context) (*domain.ThreatIntelInfo, []domain.LookupError) {
				return s.lookupThreatIntel(ctx, st.target)
			}))
	}
	if opts.Has(domain.LookupDNSSecurityName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupDNSSecurityName, &d.dnsSecurity,
			func(ctx context.Context) (*domain.DNSSecurityInfo, error) {
				return s.lookupDNSSecurity(ctx, st.target)
			}))
	}

	return runners
}

// Lookup resolves the requested lookups for a single normalized domain.
//
// It issues one MGET covering every cacheable lookup the request needs, spawns
// goroutines only for the misses, and lets each goroutine write its own result
// back with that lookup's TTL. Cache problems never fail the request: read
// errors and corrupt entries degrade to live fetches, and write errors are
// logged but leave the response intact.
func (s *DomainService) Lookup(ctx context.Context, domainName string, opts domain.LookupOptions) (*domain.DomainResponse, domain.CacheStats) {
	resp := &domain.DomainResponse{Domain: domainName}
	data := &lookupData{}

	st := &runState{
		errs:        &resp.Errors,
		logger:      logging.Logger(),
		target:      domainName,
		targetField: "domain",
		keyFor:      func(name string) string { return cache.LookupKey(domainName, name) },
	}

	hits := runLookups(ctx, runnerDeps{
		cache:         s.cache,
		sf:            &s.sf,
		lookupTimeout: s.lookupTimeout,
		ttlFor:        s.ttlFor,
	}, st, s.buildRunners(st, data, opts))

	s.assemble(resp, data, opts, hits)
	return resp, cacheStats(opts, hits)
}

// assemble builds the response from the collected payloads, tagging each field
// with where it came from. Only requested lookups appear — headers fetched
// solely to feed fingerprint stays internal.
func (s *DomainService) assemble(resp *domain.DomainResponse, d *lookupData, opts domain.LookupOptions, hits map[string]bool) {
	if opts.Has(domain.LookupWhoisName) && d.whois != nil {
		resp.Whois = &domain.WhoisResult{CacheHit: hits[domain.LookupWhoisName], WhoisInfo: d.whois}
	}
	if opts.Has(domain.LookupDNSName) && d.dns != nil {
		resp.DNS = &domain.DNSResult{CacheHit: hits[domain.LookupDNSName], DNSInfo: d.dns}
	}
	if opts.Has(domain.LookupSSLName) && d.ssl != nil {
		resp.SSL = &domain.SSLResult{CacheHit: hits[domain.LookupSSLName], SSLInfo: d.ssl}
	}
	if opts.Has(domain.LookupHeadersName) && d.headers != nil {
		resp.Headers = &domain.HeadersResult{CacheHit: hits[domain.LookupHeadersName], HeadersInfo: d.headers}
	}
	if opts.Has(domain.LookupScreenshotName) && d.screenshot != nil {
		resp.Screenshot = &domain.ScreenshotResult{CacheHit: hits[domain.LookupScreenshotName], ScreenshotInfo: d.screenshot}
	}
	if opts.Has(domain.LookupReputationName) && d.reputation != nil {
		resp.Reputation = &domain.ReputationResult{CacheHit: hits[domain.LookupReputationName], ReputationInfo: d.reputation}
	}
	if opts.Has(domain.LookupEmailSecurityName) && d.emailSecurity != nil {
		resp.EmailSecurity = &domain.EmailSecurityResult{CacheHit: hits[domain.LookupEmailSecurityName], EmailSecurityInfo: d.emailSecurity}
	}
	if opts.Has(domain.LookupSubdomainsName) && d.subdomains != nil {
		resp.Subdomains = &domain.SubdomainsResult{CacheHit: hits[domain.LookupSubdomainsName], SubdomainInfo: d.subdomains}
	}
	if opts.Has(domain.LookupCTLogsName) && d.ctLogs != nil {
		resp.CTLogs = &domain.CTLogsResult{CacheHit: hits[domain.LookupCTLogsName], CTLogsInfo: d.ctLogs}
	}
	if opts.Has(domain.LookupBGPName) && d.bgp != nil {
		resp.BGP = &domain.BGPResult{CacheHit: hits[domain.LookupBGPName], BGPInfo: d.bgp}
	}
	if opts.Has(domain.LookupThreatIntelName) && d.threatIntel != nil {
		resp.ThreatIntel = &domain.ThreatIntelResult{CacheHit: hits[domain.LookupThreatIntelName], ThreatIntelInfo: d.threatIntel}
	}

	if opts.Has(domain.LookupDNSSecurityName) && d.dnsSecurity != nil {
		resp.DNSSecurity = &domain.DNSSecurityResult{CacheHit: hits[domain.LookupDNSSecurityName], DNSSecurityInfo: d.dnsSecurity}
	}

	// Fingerprint is derived from headers rather than fetched or cached, so its
	// cache_hit mirrors where the headers data came from. Because there is no
	// fingerprint cache entry, admin rule updates take effect immediately.
	if opts.Has(domain.LookupFingerprintName) && d.headers != nil && s.fingerprintEngine != nil {
		if fp := s.fingerprintEngine.Match(d.headers); fp != nil {
			resp.Fingerprint = &domain.FingerprintResult{
				CacheHit:        hits[domain.LookupHeadersName],
				FingerprintInfo: fp,
			}
		}
	}

	// Risk is likewise post-processing: it scores whatever lookups landed on the
	// response, makes no network call, and is never cached. Assembling it last
	// means it sees every other field. Its cache_hit generalizes fingerprint's
	// rule — true only when every lookup it scored over came from cache.
	if opts.Has(domain.LookupRiskName) {
		if summary := domain.ComputeRiskScore(resp, time.Now()); summary != nil {
			resp.Risk = &domain.RiskResult{
				CacheHit:    riskFullyCached(opts, hits),
				RiskSummary: summary,
			}
		}
	}
}

// riskInputs lists the lookups that feed the aggregate risk score.
var riskInputs = []string{
	domain.LookupThreatIntelName,
	domain.LookupReputationName,
	domain.LookupSSLName,
	domain.LookupHeadersName,
	domain.LookupEmailSecurityName,
	domain.LookupWhoisName,
}

// riskFullyCached reports whether every risk input the caller requested was
// served from cache, meaning the score itself is derived entirely from cached
// data. False when no scoring input was requested at all.
func riskFullyCached(opts domain.LookupOptions, hits map[string]bool) bool {
	scored := 0
	for _, name := range riskInputs {
		if !opts.Has(name) {
			continue
		}
		scored++
		if !hits[name] {
			return false
		}
	}
	return scored > 0
}

// cacheStats counts hits and misses across the lookups the caller requested.
// Fingerprint is attributed to the headers entry that produced it.
func cacheStats(opts domain.LookupOptions, hits map[string]bool) domain.CacheStats {
	var stats domain.CacheStats
	for _, name := range opts.Lookups {
		source := name
		switch name {
		case domain.LookupFingerprintName:
			// Fingerprint is served by the headers entry.
			source = domain.LookupHeadersName
		case domain.LookupRiskName:
			// Risk fetches nothing; it counts as a hit only when everything it
			// scored over was cached.
			if riskFullyCached(opts, hits) {
				stats.Hits++
			} else {
				stats.Misses++
			}
			continue
		}
		if hits[source] {
			stats.Hits++
		} else {
			stats.Misses++
		}
	}
	return stats
}
