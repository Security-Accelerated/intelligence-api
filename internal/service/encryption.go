package service

import (
	"context"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/metrics"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"golang.org/x/sync/singleflight"
)

// EncryptionService runs the encryption lookups (protocols, key_exchange,
// certificate) for one host, caching each lookup under its own key and TTL.
//
// Every lookup here talks only to the target, so nearly every failure is a
// finding about the target and domain.IsExpectedError keeps it from alerting.
// The alerter is still wired, because a panic or an unclassified error is a
// fault on our side like any other.
type EncryptionService struct {
	cache           cache.Cache
	defaultCacheTTL time.Duration
	cacheTTLs       map[string]time.Duration
	sf              singleflight.Group
	lookupTimeout   time.Duration
	alerter         notifications.ErrorRecorder
	metrics         *metrics.Metrics

	lookupProtocols   func(ctx context.Context, host string) (*domain.ProtocolsInfo, error)
	lookupKeyExchange func(ctx context.Context, host string) (*domain.KeyExchangeInfo, error)
	lookupCertificate func(ctx context.Context, host string) (*domain.CertificateInfo, error)
}

// NewEncryptionService wires an EncryptionService to its real lookup
// implementations. defaultCacheTTL covers any lookup without an entry in
// cacheTTLs.
//
// lookupTimeout bounds one lookup, which is several handshakes run in turn;
// domain.EncryptionProbeTimeout bounds each handshake inside it. m may be nil,
// which records no metrics.
func NewEncryptionService(
	c cache.Cache,
	defaultCacheTTL time.Duration,
	cacheTTLs map[string]time.Duration,
	lookupTimeout time.Duration,
	alerter notifications.ErrorRecorder,
	m *metrics.Metrics,
) *EncryptionService {
	if lookupTimeout <= 0 {
		lookupTimeout = 30 * time.Second
	}
	if alerter == nil {
		alerter = &notifications.NoopRecorder{}
	}
	svc := &EncryptionService{
		cache:             c,
		defaultCacheTTL:   defaultCacheTTL,
		cacheTTLs:         cacheTTLs,
		lookupTimeout:     lookupTimeout,
		alerter:           alerter,
		metrics:           m,
		lookupProtocols:   domain.LookupProtocols,
		lookupKeyExchange: domain.LookupKeyExchange,
		lookupCertificate: domain.LookupCertificate,
	}
	svc.initMetrics()
	return svc
}

// initMetrics creates the metric series for every encryption lookup, so each
// exists at zero from startup (see metrics.InitLookup for why). All three are
// cached.
func (s *EncryptionService) initMetrics() {
	for _, name := range domain.AllEncryptionLookupNames {
		s.metrics.InitLookup(scopeHost, name, true)
	}
}

// SetLookups replaces all lookup functions. Test-only: production wiring
// happens in NewEncryptionService.
func (s *EncryptionService) SetLookups(
	protocols func(context.Context, string) (*domain.ProtocolsInfo, error),
	keyExchange func(context.Context, string) (*domain.KeyExchangeInfo, error),
	certificate func(context.Context, string) (*domain.CertificateInfo, error),
) {
	s.lookupProtocols = protocols
	s.lookupKeyExchange = keyExchange
	s.lookupCertificate = certificate
}

// ttlFor returns the cache TTL for a lookup, falling back to the default TTL
// for any lookup without its own configured entry.
func (s *EncryptionService) ttlFor(lookupName string) time.Duration {
	if ttl, ok := s.cacheTTLs[lookupName]; ok && ttl > 0 {
		return ttl
	}
	return s.defaultCacheTTL
}

// encryptionLookupData holds the raw payloads produced by each lookup, before
// they are wrapped with cache_hit metadata for the response.
type encryptionLookupData struct {
	protocols   *domain.ProtocolsInfo
	keyExchange *domain.KeyExchangeInfo
	certificate *domain.CertificateInfo
}

// buildRunners returns a runner for every requested lookup.
func (s *EncryptionService) buildRunners(st *runState, d *encryptionLookupData, opts domain.EncryptionLookupOptions) []lookupRunner {
	var runners []lookupRunner

	if opts.Has(domain.LookupProtocolsName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupProtocolsName, &d.protocols,
			func(ctx context.Context) (*domain.ProtocolsInfo, error) { return s.lookupProtocols(ctx, st.target) }))
	}
	if opts.Has(domain.LookupKeyExchangeName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupKeyExchangeName, &d.keyExchange,
			func(ctx context.Context) (*domain.KeyExchangeInfo, error) { return s.lookupKeyExchange(ctx, st.target) }))
	}
	if opts.Has(domain.LookupCertificateName) {
		runners = append(runners, simpleRunner(s.alerter, st, domain.LookupCertificateName, &d.certificate,
			func(ctx context.Context) (*domain.CertificateInfo, error) { return s.lookupCertificate(ctx, st.target) }))
	}

	return runners
}

// Lookup resolves the requested lookups for a single normalized host.
//
// Like the domain and IP services it issues one MGET for the requested
// lookups, spawns goroutines only for the misses, and writes each result back
// under its own key with its own TTL. Failures are not cached — a failing
// lookup is retried on the next request rather than remembered.
func (s *EncryptionService) Lookup(ctx context.Context, host string, opts domain.EncryptionLookupOptions) (*domain.EncryptionResponse, domain.CacheStats) {
	resp := &domain.EncryptionResponse{Host: host}
	data := &encryptionLookupData{}

	st := &runState{
		errs:        &resp.Errors,
		logger:      logging.Logger(),
		target:      host,
		targetField: scopeHost,
		keyFor:      func(name string) string { return cache.EncryptionLookupKey(host, name) },
	}

	hits := runLookups(ctx, runnerDeps{
		cache:         s.cache,
		sf:            &s.sf,
		lookupTimeout: s.lookupTimeout,
		ttlFor:        s.ttlFor,
		metrics:       s.metrics,
	}, st, s.buildRunners(st, data, opts))

	// A lookup that was not requested or that failed has a nil payload and is
	// left out.
	if data.protocols != nil {
		resp.Protocols = &domain.ProtocolsResult{CacheHit: hits[domain.LookupProtocolsName], ProtocolsInfo: data.protocols}
	}
	if data.keyExchange != nil {
		resp.KeyExchange = &domain.KeyExchangeResult{CacheHit: hits[domain.LookupKeyExchangeName], KeyExchangeInfo: data.keyExchange}
	}
	if data.certificate != nil {
		resp.Certificate = &domain.CertificateResult{CacheHit: hits[domain.LookupCertificateName], CertificateInfo: data.certificate}
	}

	var stats domain.CacheStats
	for _, name := range opts.Lookups {
		if hits[name] {
			stats.Hits++
		} else {
			stats.Misses++
		}
	}
	return resp, stats
}
