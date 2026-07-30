package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
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
	lookupReputation    func(ctx context.Context, d string) (*domain.ReputationInfo, []domain.LookupError)
	lookupEmailSecurity func(ctx context.Context, d string) (*domain.EmailSecurityInfo, error)
	lookupSubdomains    func(ctx context.Context, d string, opts domain.SubdomainOptions) (*domain.SubdomainInfo, error)
	lookupCTLogs        func(ctx context.Context, d string, maxEntries int) (*domain.CTLogsInfo, error)
	lookupBGP           func(ctx context.Context, d string) (*domain.BGPInfo, error)
	lookupThreatIntel   func(ctx context.Context, d string) (*domain.ThreatIntelInfo, []domain.LookupError)
}

func NewDomainService(c cache.Cache, defaultCacheTTL time.Duration, cacheTTLs map[string]time.Duration, lookupTimeout, screenshotTimeout time.Duration, subdomainMaxResults, ctLogsMaxEntries int, fpEngine *domain.FingerprintEngine, alerter notifications.ErrorRecorder, tiProviders []domain.ThreatIntelProvider) *DomainService {
	if subdomainMaxResults <= 0 {
		subdomainMaxResults = 500
	}
	if ctLogsMaxEntries <= 0 {
		ctLogsMaxEntries = 100
	}
	if lookupTimeout <= 0 {
		lookupTimeout = 30 * time.Second
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
	}
}

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
}

// lookupRunner is one cacheable lookup for one domain: how to decode a cached
// payload into lookupData, and how to fetch it live.
type lookupRunner struct {
	name string
	// decode populates lookupData from a cached payload. An error means the
	// entry is unusable and the lookup is treated as a miss.
	decode func([]byte) error
	// run performs the live lookup and populates lookupData. It returns the
	// payload to cache, or nil when nothing should be cached (failure or an
	// empty result). Errors are appended to the response by the runner itself.
	run func(ctx context.Context) []byte
}

// runState is the mutable state shared by concurrently running lookups.
type runState struct {
	mu     sync.Mutex
	resp   *domain.DomainResponse
	data   *lookupData
	logger *zap.Logger
	domain string
}

// simpleRunner wires a lookup returning (*T, error) into a lookupRunner. dst
// points at the lookupData field that receives the payload.
func simpleRunner[T any](s *DomainService, st *runState, name string, dst **T, fetch func(context.Context) (*T, error)) lookupRunner {
	return lookupRunner{
		name:   name,
		decode: decodeInto(dst),
		run: func(ctx context.Context) []byte {
			result, err := fetch(ctx)
			st.mu.Lock()
			defer st.mu.Unlock()
			if err != nil {
				st.logger.Warn("lookup failed", zap.String("lookup", name), zap.String("domain", st.domain), zap.Error(err))
				st.resp.Errors = append(st.resp.Errors, domain.LookupError{
					Lookup:  name,
					Message: sanitizeErr(err),
				})
				recordIfUnexpected(s.alerter, name, err)
				return nil
			}
			*dst = result
			return marshalForCache(st, name, result)
		},
	}
}

// multiErrRunner wires a lookup returning (*T, []LookupError) — used by the
// fan-out lookups (reputation, threat intel) that report per-provider errors
// alongside a partial result.
func multiErrRunner[T any](s *DomainService, st *runState, name string, dst **T, fetch func(context.Context) (*T, []domain.LookupError)) lookupRunner {
	return lookupRunner{
		name:   name,
		decode: decodeInto(dst),
		run: func(ctx context.Context) []byte {
			result, errs := fetch(ctx)
			st.mu.Lock()
			defer st.mu.Unlock()
			for _, e := range errs {
				s.alerter.RecordLookupError(e.Lookup)
			}
			st.resp.Errors = append(st.resp.Errors, errs...)
			*dst = result
			return marshalForCache(st, name, result)
		},
	}
}

// decodeInto returns a decoder that unmarshals a cached payload into dst.
// Cached payloads are the bare lookup type — no request metadata, no cache
// flags — so this is a plain unmarshal.
func decodeInto[T any](dst **T) func([]byte) error {
	return func(b []byte) error {
		var v T
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*dst = &v
		return nil
	}
}

// marshalForCache serializes a successful lookup result for storage. Only the
// bare payload type is marshaled, so response-only metadata (cache_hit) can
// never reach Redis. Callers must hold st.mu. A nil result caches nothing.
func marshalForCache[T any](st *runState, name string, result *T) []byte {
	if result == nil {
		return nil
	}
	payload, err := json.Marshal(result)
	if err != nil {
		st.logger.Warn("cache marshal failed", zap.String("lookup", name), zap.String("domain", st.domain), zap.Error(err))
		return nil
	}
	return payload
}

// buildRunners returns a runner for every lookup whose data this request needs.
// Requested lookups map one-to-one onto runners, with two exceptions:
//   - fingerprint has no runner of its own — it is pure computation over headers
//     data, so caching headers already caches fingerprint. Requesting it pulls in
//     the headers runner instead.
//   - headers is fetched at most once even when both headers and fingerprint are
//     requested, so shared data costs exactly one upstream call.
func (s *DomainService) buildRunners(st *runState, opts domain.LookupOptions) []lookupRunner {
	d := st.data
	var runners []lookupRunner

	if opts.Has(domain.LookupWhoisName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupWhoisName, &d.whois,
			func(ctx context.Context) (*domain.WhoisInfo, error) { return s.lookupWhois(ctx, st.domain) }))
	}
	if opts.Has(domain.LookupDNSName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupDNSName, &d.dns,
			func(ctx context.Context) (*domain.DNSInfo, error) { return s.lookupDNS(ctx, st.domain) }))
	}
	if opts.Has(domain.LookupSSLName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupSSLName, &d.ssl,
			func(ctx context.Context) (*domain.SSLInfo, error) { return s.lookupSSL(ctx, st.domain) }))
	}
	// One headers fetch serves both headers and fingerprint.
	if opts.Has(domain.LookupHeadersName) || opts.Has(domain.LookupFingerprintName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupHeadersName, &d.headers,
			func(ctx context.Context) (*domain.HeadersInfo, error) { return s.lookupHeaders(ctx, st.domain) }))
	}
	if opts.Has(domain.LookupScreenshotName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupScreenshotName, &d.screenshot,
			func(ctx context.Context) (*domain.ScreenshotInfo, error) {
				return s.lookupScreenshot(ctx, st.domain, s.screenshotTimeout)
			}))
	}
	if opts.Has(domain.LookupReputationName) {
		runners = append(runners, multiErrRunner(s, st, domain.LookupReputationName, &d.reputation,
			func(ctx context.Context) (*domain.ReputationInfo, []domain.LookupError) {
				return s.lookupReputation(ctx, st.domain)
			}))
	}
	if opts.Has(domain.LookupEmailSecurityName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupEmailSecurityName, &d.emailSecurity,
			func(ctx context.Context) (*domain.EmailSecurityInfo, error) {
				return s.lookupEmailSecurity(ctx, st.domain)
			}))
	}
	if opts.Has(domain.LookupSubdomainsName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupSubdomainsName, &d.subdomains,
			func(ctx context.Context) (*domain.SubdomainInfo, error) {
				return s.lookupSubdomains(ctx, st.domain, domain.SubdomainOptions{MaxResults: s.subdomainMaxResults})
			}))
	}
	if opts.Has(domain.LookupCTLogsName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupCTLogsName, &d.ctLogs,
			func(ctx context.Context) (*domain.CTLogsInfo, error) {
				return s.lookupCTLogs(ctx, st.domain, s.ctLogsMaxEntries)
			}))
	}
	if opts.Has(domain.LookupBGPName) {
		runners = append(runners, simpleRunner(s, st, domain.LookupBGPName, &d.bgp,
			func(ctx context.Context) (*domain.BGPInfo, error) { return s.lookupBGP(ctx, st.domain) }))
	}
	if opts.Has(domain.LookupThreatIntelName) {
		runners = append(runners, multiErrRunner(s, st, domain.LookupThreatIntelName, &d.threatIntel,
			func(ctx context.Context) (*domain.ThreatIntelInfo, []domain.LookupError) {
				return s.lookupThreatIntel(ctx, st.domain)
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
	logger := logging.Logger()

	// Respect any tighter deadline from the parent (e.g. HTTP server write timeout).
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > s.lookupTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.lookupTimeout)
		defer cancel()
	}

	st := &runState{resp: resp, data: &lookupData{}, logger: logger, domain: domainName}
	runners := s.buildRunners(st, opts)

	hits := make(map[string]bool, len(runners))
	misses := s.readCache(ctx, st, runners, hits)

	var wg sync.WaitGroup
	for _, r := range misses {
		wg.Go(func() {
			payload := r.run(ctx)
			if payload == nil {
				return
			}
			if err := s.cache.Set(ctx, cache.LookupKey(domainName, r.name), payload, s.ttlFor(r.name)); err != nil {
				// Fail-open: the caller still gets the freshly fetched result.
				logger.Warn("cache set failed", zap.String("lookup", r.name), zap.String("domain", domainName), zap.Error(err))
			}
		})
	}
	wg.Wait()

	s.assemble(resp, st.data, opts, hits)
	return resp, cacheStats(opts, hits)
}

// readCache issues a single MGET for all runners and decodes the hits into
// lookupData, returning the runners that still need a live fetch. Any cache
// failure (unreachable Redis, corrupt payload) degrades to a miss.
func (s *DomainService) readCache(ctx context.Context, st *runState, runners []lookupRunner, hits map[string]bool) []lookupRunner {
	if len(runners) == 0 {
		return nil
	}

	keys := make([]string, len(runners))
	for i, r := range runners {
		keys[i] = cache.LookupKey(st.domain, r.name)
	}

	cached, err := s.cache.MGet(ctx, keys)
	if err != nil {
		st.logger.Warn("cache mget failed", zap.String("domain", st.domain), zap.Error(err))
		cached = nil
	}

	misses := make([]lookupRunner, 0, len(runners))
	for i, r := range runners {
		if i < len(cached) && cached[i] != nil {
			if err := r.decode(cached[i]); err != nil {
				// Self-healing: the live fetch below overwrites the bad entry.
				st.logger.Warn("cache entry unusable, treating as miss",
					zap.String("lookup", r.name), zap.String("domain", st.domain), zap.Error(err))
			} else {
				hits[r.name] = true
				continue
			}
		}
		misses = append(misses, r)
	}
	return misses
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
}

// cacheStats counts hits and misses across the lookups the caller requested.
// Fingerprint is attributed to the headers entry that produced it.
func cacheStats(opts domain.LookupOptions, hits map[string]bool) domain.CacheStats {
	var stats domain.CacheStats
	for _, name := range opts.Lookups {
		source := name
		if name == domain.LookupFingerprintName {
			source = domain.LookupHeadersName
		}
		if hits[source] {
			stats.Hits++
		} else {
			stats.Misses++
		}
	}
	return stats
}
