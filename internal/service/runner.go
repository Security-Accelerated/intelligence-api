package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/metrics"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// Shared machinery for services that cache and coalesce individual lookups
// rather than whole response documents. DomainService, IPService and
// EncryptionService each build a []lookupRunner and hand it to runLookups;
// everything about which lookups exist, how they are fetched and how the
// response is assembled stays in the owning service.

// The kinds of target. Each is a runState's targetField, which names the
// target in log output and is the "scope" label on every lookup metric. The
// encryption endpoint's is "host" because that is what its target is called in
// the request and the response.
const (
	scopeDomain = "domain"
	scopeIP     = "ip"
	scopeHost   = "host"
)

// lookupRunner is one cacheable lookup for one target: how to decode a payload
// into the caller's own storage, and how to fetch that payload live.
//
// fetch is deliberately free of per-request state so it can be shared between
// concurrent callers via singleflight; every caller then decodes the resulting
// payload into its own storage. Decoding per caller (rather than sharing a
// pointer) gives each request an independent deep copy for free.
type lookupRunner struct {
	name string
	// decode populates the caller's storage from a payload — cached or freshly
	// fetched. An error means the payload is unusable and the lookup counts as
	// a miss.
	decode func([]byte) error
	// fetch performs the live lookup. It touches no per-request state.
	fetch func(ctx context.Context) fetchResult
	// uncached marks a lookup that is never read from or written to the cache.
	// Used for results computed locally, where a Redis round trip would cost
	// more than recomputing (see IPService's geo and asn).
	uncached bool
}

// fetchResult is what one live lookup produced: the payload to hand to every
// coalesced caller, plus any errors to report. A nil payload means nothing
// should be cached — the lookup failed, or returned no data.
type fetchResult struct {
	payload []byte
	errs    []domain.LookupError
	// timedOut marks a failure that was a timeout, for the outcome metric. The
	// errs above carry only sanitized text, so the runner classifies while it
	// still holds the error.
	timedOut bool
}

// isTimeout reports whether a lookup failed by running out of time: the
// lookup's own deadline, or a network timeout further down (a DNS query, an
// HTTP client timeout), which is where most of them come from.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// lookupOutcome classifies a finished fetch for the lookup metric. Any
// reported error makes it a failure, including a fan-out lookup's partial
// result, which is the same line the cache draws when it refuses to store one.
// A failure counts as a timeout when the runner saw a timeout error or the
// fetch's own deadline has passed; the fan-out lookups report sanitized
// per-provider errors only, so the deadline is all there is to go on for them.
func lookupOutcome(ctx context.Context, res fetchResult) string {
	switch {
	case len(res.errs) == 0:
		return metrics.OutcomeOK
	case res.timedOut || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return metrics.OutcomeTimeout
	default:
		return metrics.OutcomeError
	}
}

// runState is the mutable per-request state shared by concurrently running
// lookups. fetch never touches it; only decode and error collection do.
type runState struct {
	mu     sync.Mutex
	errs   *[]domain.LookupError
	logger *zap.Logger
	// target is the domain or IP being looked up, for log context.
	target string
	// targetField names what target is ("domain" or "ip") in log output.
	targetField string
	// keyFor builds the cache key for a lookup name.
	keyFor func(lookupName string) string
}

func (st *runState) logTarget() zap.Field { return zap.String(st.targetField, st.target) }

// decodeInto returns a decoder that unmarshals a payload into dst. Payloads are
// the bare lookup type — no request metadata, no cache flags — so this is a
// plain unmarshal, identical for cached and freshly fetched data.
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

// marshalForCache serializes a successful lookup result. Only the bare payload
// type is marshaled, so response-only metadata (cache_hit) can never reach
// Redis. A nil result produces no payload and so is never cached.
func marshalForCache[T any](st *runState, name string, result *T) []byte {
	if result == nil {
		return nil
	}
	payload, err := json.Marshal(result)
	if err != nil {
		st.logger.Warn("cache marshal failed", zap.String("lookup", name), st.logTarget(), zap.Error(err))
		return nil
	}
	return payload
}

// recoverFetch converts a panicking lookup into an ordinary error result.
// Containment has to happen inside the fetch rather than at the goroutine
// boundary: a panic escaping into singleflight is re-raised in every coalesced
// caller, so one bad lookup would take down unrelated requests.
func recoverFetch(alerter notifications.ErrorRecorder, st *runState, name string, res *fetchResult) {
	if r := recover(); r != nil {
		st.logger.Error("lookup panicked",
			zap.String("lookup", name),
			st.logTarget(),
			zap.Any("panic", r),
			zap.Stack("stack"),
		)
		alerter.RecordLookupError(name)
		*res = fetchResult{errs: []domain.LookupError{{Lookup: name, Message: "internal error"}}}
	}
}

// simpleRunner wires a lookup returning (*T, error) into a lookupRunner. dst
// points at the field that receives the decoded payload.
func simpleRunner[T any](alerter notifications.ErrorRecorder, st *runState, name string, dst **T, fetch func(context.Context) (*T, error)) lookupRunner {
	return lookupRunner{
		name:   name,
		decode: decodeInto(dst),
		fetch: func(ctx context.Context) (res fetchResult) {
			defer recoverFetch(alerter, st, name, &res)
			result, err := fetch(ctx)
			if err != nil {
				st.logger.Warn("lookup failed", zap.String("lookup", name), st.logTarget(), zap.Error(err))
				recordIfUnexpected(alerter, name, err)
				return fetchResult{
					errs: []domain.LookupError{{
						Lookup:  name,
						Message: sanitizeErr(err),
					}},
					timedOut: isTimeout(err),
				}
			}
			return fetchResult{payload: marshalForCache(st, name, result)}
		},
	}
}

// multiErrRunner wires a lookup returning (*T, []LookupError) — used by the
// fan-out lookups (reputation, threat intel) that report per-provider errors
// alongside a partial result.
func multiErrRunner[T any](alerter notifications.ErrorRecorder, st *runState, name string, dst **T, fetch func(context.Context) (*T, []domain.LookupError)) lookupRunner {
	return lookupRunner{
		name:   name,
		decode: decodeInto(dst),
		fetch: func(ctx context.Context) (res fetchResult) {
			defer recoverFetch(alerter, st, name, &res)
			result, errs := fetch(ctx)
			for _, e := range errs {
				alerter.RecordLookupError(e.Lookup)
			}
			return fetchResult{payload: marshalForCache(st, name, result), errs: errs}
		},
	}
}

// runnerDeps is the service-owned collaborators runLookups needs.
type runnerDeps struct {
	cache         cache.Cache
	sf            *singleflight.Group
	lookupTimeout time.Duration
	ttlFor        func(lookupName string) time.Duration
	// metrics may be nil, which records nothing.
	metrics *metrics.Metrics
}

// runLookups resolves every runner: one MGET for the cacheable ones, then a
// goroutine per miss. It returns the set of lookup names served from cache.
//
// Cache problems never fail the request. A failed MGET treats everything as a
// miss, an unusable entry is refetched (and overwritten), and a failed write is
// logged while the caller still gets its freshly fetched result.
func runLookups(ctx context.Context, d runnerDeps, st *runState, runners []lookupRunner) map[string]bool {
	hits := make(map[string]bool, len(runners))
	if len(runners) == 0 {
		return hits
	}

	// The cache read follows the caller's deadline — it is cheap and
	// per-caller. Live fetches deliberately do not; see below.
	readCtx := ctx
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > d.lookupTimeout {
		var cancel context.CancelFunc
		readCtx, cancel = context.WithTimeout(ctx, d.lookupTimeout)
		defer cancel()
	}

	misses := readCachedLookups(readCtx, d, st, runners, hits)

	var wg sync.WaitGroup
	for _, r := range misses {
		wg.Go(func() {
			key := st.keyFor(r.name)

			// Coalesce concurrent fetches of the same lookup for the same
			// target — only one runs and every caller gets its payload. Keying
			// per lookup rather than per response means two requests asking for
			// overlapping-but-different lookup sets still share the overlap.
			//
			// singleflight runs the function on the goroutine of the caller
			// that started the flight, so ran is only ever written here and
			// tells this caller whether it fetched or waited on someone else.
			ran := false
			v, _, _ := d.sf.Do(key, func() (any, error) {
				ran = true
				// Shared work is detached from the triggering caller's context
				// and bounded by the service's own timeout instead. One client
				// disconnecting — or holding a tight deadline — must not cancel
				// or truncate a fetch that other coalesced callers are waiting
				// on. WithoutCancel drops the parent deadline too, so the
				// timeout has to be reapplied here.
				fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.lookupTimeout)
				defer cancel()

				// Timed around the fetch alone, so the cache write below does
				// not count toward the lookup's duration.
				start := time.Now()
				res := r.fetch(fetchCtx)
				d.metrics.ObserveLookup(st.targetField, r.name, lookupOutcome(fetchCtx, res), time.Since(start))
				// Only the goroutine that actually ran the fetch writes it
				// back; coalesced callers would rewrite the identical value.
				//
				// A partial result is never cached. The fan-out lookups
				// (reputation, threat_intel) return data alongside per-provider
				// errors, and only the payload is stored — so caching one would
				// serve it to every later caller as a complete, error-free
				// success, with no retry until the TTL expired. For threat
				// intelligence that means freezing in a verdict derived from
				// providers that never answered.
				if res.payload != nil && len(res.errs) == 0 && !r.uncached {
					if err := d.cache.Set(fetchCtx, key, res.payload, d.ttlFor(r.name)); err != nil {
						// Fail-open: callers still get the fetched result.
						st.logger.Warn("cache set failed", zap.String("lookup", r.name), st.logTarget(), zap.Error(err))
					}
				}
				return res, nil
			})
			res := v.(fetchResult)
			if !ran {
				d.metrics.Coalesced(st.targetField, r.name)
			}

			st.mu.Lock()
			defer st.mu.Unlock()
			*st.errs = append(*st.errs, res.errs...)
			if res.payload != nil {
				if err := r.decode(res.payload); err != nil {
					st.logger.Warn("decoding freshly fetched payload failed",
						zap.String("lookup", r.name), st.logTarget(), zap.Error(err))
				}
			}
		})
	}
	wg.Wait()

	return hits
}

// readCachedLookups issues a single MGET for the cacheable runners and decodes
// the hits, returning the runners that still need a live fetch.
func readCachedLookups(ctx context.Context, d runnerDeps, st *runState, runners []lookupRunner, hits map[string]bool) []lookupRunner {
	misses := make([]lookupRunner, 0, len(runners))

	cacheable := make([]lookupRunner, 0, len(runners))
	for _, r := range runners {
		if r.uncached {
			misses = append(misses, r)
			continue
		}
		cacheable = append(cacheable, r)
	}
	if len(cacheable) == 0 {
		return misses
	}

	keys := make([]string, len(cacheable))
	for i, r := range cacheable {
		keys[i] = st.keyFor(r.name)
	}

	cached, err := d.cache.MGet(ctx, keys)
	if err != nil {
		st.logger.Warn("cache mget failed", st.logTarget(), zap.Error(err))
		cached = nil
	}

	// Hits and misses are counted for the cacheable runners only. An uncached
	// lookup never asked the cache anything, and counting it as a miss would
	// drag the hit ratio down for a reason nobody can act on. A failed MGET and
	// an unusable entry both count as misses, because both end in a live fetch.
	for i, r := range cacheable {
		if i < len(cached) && cached[i] != nil {
			if err := r.decode(cached[i]); err != nil {
				// Self-healing: the live fetch below overwrites the bad entry.
				st.logger.Warn("cache entry unusable, treating as miss",
					zap.String("lookup", r.name), st.logTarget(), zap.Error(err))
			} else {
				hits[r.name] = true
				d.metrics.CacheResult(st.targetField, r.name, true)
				continue
			}
		}
		d.metrics.CacheResult(st.targetField, r.name, false)
		misses = append(misses, r)
	}
	return misses
}
