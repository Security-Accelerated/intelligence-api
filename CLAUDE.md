# CLAUDE.md — Intelligence API

## Project Overview

Domain and IP intelligence REST API built in Go with Gin. Performs concurrent WHOIS, DNS, SSL, HTTP header, screenshot, reputation, email security (SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI), subdomain, certificate transparency, BGP/ASN, technology fingerprinting, threat intelligence, and DNS security (DNSSEC/CAA) lookups for domains, plus a computed aggregate risk score on every domain response. IP lookups provide GeoIP, ASN, reverse DNS, abuse contact (RDAP), and threat intelligence. Results are cached in Redis (with singleflight coalescing and negative caching). Auth is API-key-based with PostgreSQL storage; customers can self-rotate keys and query their own usage. OpenAPI 3.1 spec served at `/docs/openapi.yaml`.

**Module:** `github.com/security-accelerated/intelligence-api`

## Architecture

```
cmd/api/main.go              → Entry point, version via ldflags
internal/app/app.go           → Dependency wiring, bootstrap, shutdown
internal/handler/             → HTTP handlers, route registration, request validation
internal/service/             → Business logic, lookup orchestration, caching
internal/domain/              → Lookup implementations + domain types (model.go)
internal/middleware/           → Auth, rate limiting, logging, security headers, body limit, client request ID
internal/httpapi/             → Gin router assembly, middleware chain, server lifecycle
internal/cache/               → Cache interface + Redis implementation
internal/auth/                → Customer model, PostgreSQL repository, in-memory cached repository, key hashing
internal/billing/              → Stripe billing (webhook handling, key provisioning, noop fallback)
internal/usage/                → Usage tracking (buffered async INSERT, admin query endpoint, noop fallback)
internal/notifications/        → Pushover alerting (upstream throttle + error spike detection)
internal/safenet/             → SSRF prevention (blocks private/reserved IPs at dial time)
internal/logging/             → Zap logger init (ECS format in production, pretty in dev)
internal/config/              → Viper config, YAML files + env var overrides, StatusSnapshot structs
migrations/                   → PostgreSQL schema (applied via Docker initdb on first start only)
scripts/                      → docker-reset.sh, smoke-test.sh, status.sh, info.sh (all dev)
docs/                         → Sales slick; live API docs served via embedded HTML in handler
changelog.yaml                → Symlink to internal/handler/changelog.yaml (edit from project root)
```

## Key Design Decisions

### Function-based dependency injection
Services use function fields (`lookupWhois`, `lookupDNS`, etc.) instead of interfaces for each lookup. The constructor wires in real implementations from the `domain` package. Tests swap them via `SetLookups()` and per-feature setters (`SetEmailSecurityLookup`, `SetSubdomainLookup`). This avoids interface pollution while keeping tests fully deterministic.

### Selectable lookups
There are no default lookups. `DomainRequest.Lookups []string` names exactly what to run, and it is required and must be non-empty after normalization. The handler is the only place that resolves it: normalize (trim + lowercase + dedup) → require non-empty → validate names → validate plan → build `domain.LookupOptions{Lookups []string}`. Everything downstream (service, cache, usage) sees only normalized, explicit names. `internal/handler/domain.go` holds `lookupMinPlan`, a single `map[string]plan` table that drives both name validation (400) and plan gating (403). Canonical names live as constants in `internal/domain/model.go` alongside `AllLookupNames`.

Domains are normalized the same way (scheme/port/path stripping, then trim + lowercase) and deduplicated. Each response element reports the normalized `domain` plus the verbatim `inputs` that mapped to it; array position is explicitly not part of the API contract. Plan domain caps count submitted entries, not unique domains.

### Concurrent fan-out with per-lookup cache pre-flight
`service.Lookup()` builds a `lookupRunner` per requested lookup, issues **one MGET** covering all their keys, decodes the hits, and spawns goroutines **only for the misses** — protected by `sync.Mutex` on shared state. Each goroutine writes its own result back with `SET key json EX <per-lookup TTL>` on success. Failures are not cached. Response assembly happens after `wg.Wait()`, tagging each field with where it came from. A 30-second context timeout covers cache reads, lookups, and cache writes.

The `simpleRunner`/`multiErrRunner` generic helpers keep the per-lookup wiring to one line each; `multiErrRunner` covers the fan-out lookups (reputation, threat intel) that return partial results alongside per-provider errors.
### Shared per-lookup runner core
`internal/service/runner.go` holds the machinery both services use: `lookupRunner`, `fetchResult`, `runState`, the runner constructors, panic recovery, the MGET pre-flight and the singleflight+SET fan-out. `runState` is target-agnostic — a target string, a field name for logs, and a `keyFor` closure — so `DomainService` supplies `lookup:<domain>:<name>` keys and `IPService` supplies `ip:<ip>:<name>`. Each service keeps only what is specific to it: which lookups exist, how they are fetched, and how the response is assembled. A runner may set `uncached` to opt out of Redis entirely (see IP geo/asn).

### Singleflight coalescing
Concurrent fetches of the same lookup for the same target coalesce into one upstream call via `golang.org/x/sync/singleflight`. Keying is **per lookup per domain** (`lookup:<domain>:<name>`), not per response, so two requests asking for overlapping-but-different lookup sets still share the overlap. The shared fetch runs under `context.WithoutCancel` with the service's own `lookupTimeout` reapplied — one caller disconnecting, or holding a tight deadline, must not cancel or truncate work others are waiting on. Coalesced callers each decode the shared payload into their own response, so nobody shares a mutable pointer (this replaces the old `copyViaJSON` guard). Both services use this path — there is no whole-response coalescing left anywhere, and `service/whole_response.go` is gone.

### No negative caching
Failed lookups are not cached on either endpoint — a failing lookup is retried on the next request rather than remembered. Per-lookup TTLs removed the problem `redis.negative_cache_ttl` was compensating for: one flaky provider can no longer shorten every other lookup's cache lifetime, because each lookup expires on its own schedule. That config key is gone.

### IP intelligence uses the same model
`/v1/ip/lookup` takes the same `lookups` array, returns the same `{"results": [...]}` envelope with per-field `cache_hit`, and reports the canonicalized `ip` plus verbatim `inputs`. Keys live under the separate `ip:` namespace, so `threat_intel` on the two endpoints cannot collide, and `ipLookupMinPlan` is a separate table — `whois` is a valid domain lookup but a 400 on an IP.

**`geo` and `asn` are never cached.** They read a local MaxMind mmap, so a Redis round trip costs more than recomputing; the old whole-document cache only stored them because they shared a key with RDAP. Their runners set `uncached`, so they are excluded from the MGET and never written, and their `cache_hit` is always false. This also deleted the "skip caching when the GeoIP database is missing" special case — with geo uncached there is nothing to skip. A missing GeoIP database is now classified in `isExpectedError`, so an unbootstrapped deployment still doesn't page anyone.

### Panic recovery
Every lookup fetch runs behind `recoverFetch`, which degrades a panic to a sanitized `internal error` on the response. Recovery happens inside the fetch rather than at the goroutine boundary on purpose: a panic escaping into singleflight is re-raised in every coalesced caller, so one bad lookup would take down unrelated requests. `IPService` uses the equivalent `goLookup` helper.

### Screenshot concurrency cap
Chromium is by far the most expensive lookup, so the screenshot runner takes a slot from a process-wide semaphore (`screenshot.max_concurrent`, default 4) before running. If no slot frees up before the lookup deadline, the request reports a queue timeout instead of piling up more browsers.

### Aggregate risk score
`internal/domain/risk.go` computes a weighted 0–100 score (`ComputeRiskScore`) from whichever lookup results are present: threat_intel (0.35), reputation (0.25), ssl, security_headers, email_security, domain_age (0.10 each). Weights renormalize over present components. Risk levels use the same thresholds as `ScoreThreatIntel`. Runs as post-processing in `service.assemble()` — zero extra network calls and no cache entry of its own, exactly like `fingerprint`. Opt in by naming `risk` in `lookups`; its `cache_hit` is true only when every scoring input it consumed came from cache.
### DNS security lookup
### Scoped external resolver
`domain.Resolver()` returns the resolver intelligence lookups use — the external servers from `InitResolver`, or the system resolver before that. It is an `atomic.Pointer[net.Resolver]`, **not** `net.DefaultResolver`. Overriding the global sent every resolution in the process to public DNS, including the service's own connections to Postgres and Redis: a dependency addressed by a name only the platform's resolver knows (Docker Compose service, Kubernetes service, Fly `.internal`) stopped resolving. Calling `InitResolver` after those connected only protected the *initial* connections — `database/sql` recycles on `conn_max_lifetime`, and replacements failed with "no such host" (issue #62). Use `domain.Resolver()` wherever the target is a name from user input; infrastructure must keep using the system resolver.

`internal/domain/dnssec.go` uses raw DNS via `miekg/dns` (net.Resolver can't query DS/DNSKEY/CAA) against `domain.ActiveDNSServers()` (set by `InitResolver`). Reports DNSSEC deployment (DS at parent + DNSKEY at zone + algorithms) and CAA records. Truncated UDP responses retry over TCP. Selected by naming `dns_security` in `lookups`, all plans. Tests run a local `miekg/dns` server.
### API key rotation
`POST /v1/keys/rotate` (any authenticated customer) issues a new key and grace-expires all previous keys (`auth.rotation_grace`, default 24h). Migration 012 dropped the one-key-per-customer constraint and added `api_keys.expires_at`; the auth lookup filters expired keys and `DeactivateStaleKeys` only deactivates customers with no fresh live key. `billing.KeyRotationService` depends only on the DB (works without Stripe) and invalidates the auth cache after rotating.
### Health endpoint
`GET /v1/health` (unauthenticated, internal/ops — never in consumer docs, same policy as `/v1/hello`) pings Postgres and Redis with a 2s timeout and reports GeoIP database state. Postgres/Redis down → 503 `degraded`; missing GeoIP does not degrade (it self-bootstraps at startup, and is absent for the first few seconds of a cold start). The uptime workflow hits this endpoint.

### Partial failure tolerance
Each lookup goroutine catches its own errors. Failures are appended to `resp.Errors` with sanitized messages — the rest of the response still returns. Full errors are logged server-side; users see only safe summaries via `sanitizeErr()`. All lookup goroutines launch through `goLookup()` (in `service/domain.go`), which also recovers panics — gin.Recovery only covers handler goroutines, so without this a panicking lookup would kill the process; instead it degrades to an "internal error" entry in `resp.Errors`. Screenshots additionally pass through a global semaphore (`screenshot.max_concurrent`, default 4) capping concurrent Chromium across all in-flight requests.

### Per-lookup cache keys
Keys are flat: `lookup:<domain>:<lookup_name>` (e.g. `lookup:example.net:ssl`), built by `cache.LookupKey()` with the `cache.LookupKeyPrefix` constant. The builder never re-normalizes — normalization is the handler's job, so a missed step surfaces as a distinct key instead of being silently papered over. There is no composite key and no sorted-suffix logic; the combination of lookups a caller requests has no effect on reuse.

Redis stores the **bare lookup payload only** — no request metadata, no cache flags, no timestamps. The response wrapper types (`WhoisResult`, `DNSResult`, …) embed the payload type and add `cache_hit`, which is set at assembly time and can never reach Redis because only the embedded type is ever marshaled.

Per-lookup TTLs come from `cache.default_ttl` + `cache.ttl.<name>` (replacing `redis.cache_ttl`). `config.CacheTTLs()` reads each key individually so Viper's `AutomaticEnv` picks up `CACHE_TTL_WHOIS` and friends — pulling the `cache.ttl` subtree as a map would silently ignore env overrides.

### Cache fail-open
Cache problems never fail a request, matching the rate limiter's philosophy:
- MGET error → every lookup treated as a miss, logged, live lookups run.
- Corrupt/unmarshalable entry → treated as a miss, logged; the live fetch overwrites it (self-healing).
- Failed SET → the lookup still succeeds and is served; the write failure is logged.

None of these ever reach `resp.Errors`, which is reserved for real lookup failures. Expiry is absolute — there is no stale serving.

### Headers/fingerprint dependency
Shared upstream data is fetched exactly once per domain per request. `fingerprint` has no runner and **no cache key of its own**: it is deterministic computation over headers data, so caching `headers` already caches it. Requesting `headers` or `fingerprint` (or both) creates exactly one headers runner. `headers` appears in the response only if it was requested; `fingerprint.cache_hit` mirrors the headers entry it was computed from. This also means admin fingerprint-rule updates take effect immediately with no stale TTL.

### Response envelope
The lookup endpoint returns `{"results": [...]}` rather than a bare array, so every API response is an object (consistent with `{"error": "..."}`) and response-level fields can be added later without breaking clients. There is no top-level `cache_hit`.

### SSRF prevention at the dialer level
The `safenet` package provides a `DialControl` function that rejects connections to private, loopback, link-local, multicast, unspecified, and reserved IPs (CGNAT, 0/8, 192.0.0.0/24, TEST-NET-1/2/3, 198.18.0.0/15 benchmarking, 240.0.0.0/4, 2001:db8::/32). The core check is `IsPrivateAddr(netip.Addr)`, which unmaps IPv4-mapped IPv6 first; `IsPrivateIP(net.IP)` is a compatibility adapter. It fires after DNS resolution (no TOCTOU race). All HTTP clients in the `domain` package use `safenet.SafeDialer()` via shared transports in `domain/transport.go`.

### Handler dependencies
`handler.New` takes a single `Deps` struct rather than positional parameters. Most fields are nilable and several share a type, so a misordered argument list would have compiled silently; naming them also documents which surfaces a given Handler serves — `New(Deps{RedisCache: rc})` instead of `New(nil, nil, nil, nil, nil, nil, nil, nil, rc, nil, nil, nil)`. Every field is optional; a nil service makes its endpoints return 503 rather than panicking, which keeps partially-configured deployments serving what they can. Adding a dependency is now additive: existing call sites are untouched.

### Hashed API keys
Keys are stored as `hex(sha256(key))` — never plaintext. The auth middleware hashes the incoming key and looks it up. The `CachedRepository` wraps PostgreSQL with an in-memory TTL cache (keyed by hash) using RWMutex. Admin endpoint allows cache invalidation after plan changes.

### Plan-based access control
Single `plan` column on `customers` table: `free`, `basic`, `pro`, `admin`. Controls rate limits, premium feature access (screenshot, reputation, threat_intel), and admin endpoint access. `RequireAdmin()` middleware gates admin-only routes. Rate limits: free=5/min, basic=30/min, pro=120/min, admin=unlimited. Free plan: 1 domain per request, no screenshot/reputation/threat_intel.

### Technology fingerprinting
`FingerprintEngine` in `internal/domain/fingerprint.go` holds rules behind `sync.RWMutex`. Default rules are embedded via `go:embed` (~90 curated technologies). `FingerprintService` in `internal/service/fingerprint.go` persists rules in PostgreSQL (append-only `fingerprint_rules` table) and loads the latest on startup. Admin endpoints (`GET/POST /v1/admin/fingerprints`) allow hot-reloading rules without redeploying.

### Threat intelligence
`internal/domain/threatintel.go` defines the `ThreatIntelProvider` interface (`Name()`, `Query()`) and the `LookupThreatIntel` coordinator that fans out to all providers concurrently (same pattern as `LookupReputation`). Three providers: **VirusTotal** (v3 API, `x-apikey` header, 4 req/min rate limit), **URLhaus** (Abuse.ch, free, no key needed), **AlienVault OTX** (`X-OTX-API-KEY` header, 10 req/s). Each provider uses `safeTransport` for SSRF protection and `golang.org/x/time/rate` for per-provider token bucket rate limiting. `ScoreThreatIntel()` computes a weighted aggregate score (VT 50%, URLhaus 30%, OTX 20%) mapped to risk levels: none/low/medium/high/critical. Providers are built conditionally at startup in `app.go` based on config keys — URLhaus always enabled, VT/OTX enabled when API keys are present. Pro/admin plan only. Config: `THREAT_INTEL_VIRUSTOTAL_API_KEY`, `THREAT_INTEL_ALIENVAULT_API_KEY`.

### Error sanitization
`sanitizeErr()` strips internal error details before including them in API responses. `safenet.BlockedError` gets a specific user-friendly message. Other errors are truncated to the final segment after `: `. Full context is always logged server-side.

### Stripe billing
`internal/billing/` follows the notifications pattern (interface + real impl + noop fallback). `Service` interface defines `HandleWebhook` and `GetProvisionedKey`. `StripeService` verifies webhook signatures, handles checkout/subscription/payment events, and provisions API keys. `NoopService` returns "billing not configured" errors. `Repository` wraps billing-specific DB operations (customer+key creation, provisioned key storage, plan updates, stale key cleanup). Key provisioning: on checkout, generates a random API key, stores hash in `api_keys`, stores raw key in `provisioned_keys` (1hr expiry, one-time retrieval — the plaintext is blanked in the same statement that marks the row retrieved, and a startup goroutine sweeps expired rows every `billing.cleanup_interval`, default 10m). `keygen.go` generates 64-char hex keys via `crypto/rand`. Auth cache is invalidated after any plan change. `last_used_at` on `api_keys` is updated on auth cache-miss lookups (batched via `auth.LastUsedBatcher`). `StripeService` accepts a `notifications.Notifier` and sends async Pushover notifications on all billing events (new signup, plan change, cancellation, payment failure). Customer Portal link is configurable via `STRIPE_PORTAL_LINK` and shown on docs/success pages. Config: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICES_BASIC_MONTHLY`, `STRIPE_PRICES_PRO_MONTHLY`, `STRIPE_PAYMENT_LINK_BASIC`, `STRIPE_PAYMENT_LINK_PRO`, `STRIPE_PORTAL_LINK`, `BILLING_STALE_KEY_DAYS`.

### Usage tracking
`internal/usage/` follows the notifications/billing pattern (interface + real impl + noop). `Recorder` interface accepts `UsageEntry` values; `Queryer` interface returns aggregated `UsageSummary`. `UsageLogger` buffers entries on a channel and batch-inserts to PostgreSQL's `request_log` table on a timer (default 5s) or when the batch hits 50 entries. Channel full = silent drop with warning log. `NoopRecorder` discards entries when usage tracking isn't needed (tests). `QueryService` runs aggregation SQL for the admin endpoint. Middleware `UsageLog()` collects request metadata after `c.Next()` and calls `recorder.Record()`, reading the `lookups_requested`, `cache_hits`, and `cache_misses` context keys set by the handlers. `feature_usage` counts **requested** lookups regardless of how they were served — a cache hit must not make a feature look less used. `cache_hits`/`cache_misses` are separate operational counters on `request_log` (migration `012`), counting individual lookups rather than requests; the old per-request `cache_hit` boolean is gone. `usage.LookupColumns` mirrors `domain.AllLookupNames` and the `request_log` schema — a test asserts they stay in sync, so a new lookup fails loudly in CI rather than silently in prod. Admin endpoint: `GET /v1/admin/usage?days=30&customer_id=X&api_key_id=Y`. Config: `USAGE_BUFFER_SIZE`, `USAGE_FLUSH_INTERVAL`.

### StatusSnapshot for unified status
`internal/config/status.go` defines typed structs (`SystemStatus`, `DatabaseConfig`, `CacheConfig`, `LookupConfig`, `ServicesStatus` with sub-structs) held in a `StatusSnapshot`. Built once at startup via `NewStatusSnapshot(version, domain.AllLookupNames)`, then progressively populated as services initialize in `app.go`. Used for both structured startup logging (`zap.Any("config", section)`) and the `/v1/info` admin endpoint response — adding a field to any struct automatically surfaces it in both places. Live data (runtime stats, DB pool, Redis ping, auth cache size) is computed at request time in the info handler and merged with the static snapshot. JSON response groups: `system`, `database`, `cache` (static config + live stats), `lookups`, `services`, `runtime`, `postgres_pool`.

### Changelog
`internal/handler/changelog.yaml` (symlinked from project root as `changelog.yaml`) is the single source of truth for all changes. Each entry has a `version`, `date`, and list of `changes` with `audience` tags (`public` or `internal`). Embedded via `go:embed` in the handler package, parsed at startup. The docs pages (`/docs`, `/docs/domain`, `/docs/ip`) render only `public` entries in a "What's New" section. The admin endpoint (`GET /v1/admin/changelog`) returns all entries unfiltered. Update this file with every release.

### Notifications
`internal/notifications/` provides interface-driven alerting. `Notifier` interface abstracts the delivery channel (currently Pushover); `ErrorRecorder` interface abstracts error tracking (currently `Alerter`). The `Alerter` uses sliding-window counters behind a mutex to detect per-lookup throttling (default: 5 failures in 5m) and global error spikes (default: 15 errors in 5m). Alerts fire asynchronously with a 15-minute cooldown to prevent alert fatigue. `DomainService` depends on `ErrorRecorder`; when Pushover credentials are absent, a `NoopRecorder` is wired in. Config: `PUSHOVER_API_TOKEN`, `PUSHOVER_USER_KEY`, `ALERTS_THROTTLE_THRESHOLD`, `ALERTS_THROTTLE_WINDOW`, `ALERTS_SPIKE_THRESHOLD`, `ALERTS_SPIKE_WINDOW`, `ALERTS_COOLDOWN`.

### IP intelligence
`internal/domain/geoip.go` provides `GeoIPReader` — holds MaxMind GeoLite2 City and ASN databases behind `sync.RWMutex` for concurrent reads with atomic hot-reload via `Reload()`. `DownloadAndReload()` fetches latest databases from MaxMind using a license key, validates them, and swaps atomically. `internal/domain/ip_rdns.go` does PTR lookups via `net.DefaultResolver`. `internal/domain/ip_rdap.go` queries RDAP bootstrap (`rdap.org/ip/`) for abuse contacts — returns structured JSON, no WHOIS parsing needed. `internal/domain/ip_threatintel.go` defines `IPThreatIntelProvider` interface and adapter types (`VTIPProvider`, `URLhausIPProvider`, `OTXIPProvider`) that wrap existing domain providers, sharing their HTTP clients and rate limiters but hitting IP-specific API endpoints. `internal/service/ip.go` follows the same concurrent fan-out pattern as `service/domain.go` with function-based DI and `ip:` prefixed cache keys. `internal/handler/ip.go` validates IPs via `netip.ParseAddr`, rejects non-globally-routable addresses, and gates `threat_intel` to pro/admin. `internal/handler/geoip_admin.go` provides a bodyless admin endpoint for app-managed database refresh. `internal/app/geoip.go` opens the databases at startup and downloads them in a background goroutine when they are missing, unreadable, or older than `maxmind.max_age` (default 168h) — the download is ~80MB, so blocking startup on it would hold the listener past Fly's health checks on every cold start. `planGeoIP` isolates the load/download decision so it is testable without network. A stale database is loaded first and refreshed behind it. Config: `MAXMIND_LICENSE_KEY`, `MAXMIND_DB_PATH`, `IP_LOOKUP_TIMEOUT`, `IP_MAX_IPS_FREE/BASIC/PRO`.

## Middleware Chain (order matters)

1. `gin.Recovery()` — catches panics, returns 500
2. `SecurityHeaders()` — adds defensive headers (X-Content-Type-Options, X-Frame-Options, Cache-Control: no-store, Strict-Transport-Security, Referrer-Policy, and a strict `default-src 'none'` Content-Security-Policy for the JSON API; HTML pages override the CSP with `htmlPageCSP` in the handler package — no inline JS, page scripts are served externally at `/docs/*.js`)
3. `BodyLimit(1MB)` — rejects oversized request bodies
4. `ClientRequestID()` — validates/echoes X-Client-Request-ID header, sets context key
5. `RequestLogger()` — structured request logging with context keys (runs after `c.Next()` returns)
6. *(protected routes only)* `APIKeyAuth()` — validates key, sets customer_id/api_key_id/api_key_plan in context
7. *(protected routes only)* `RateLimit()` — per-key sliding window via Redis, fail-open, admin bypass
8. *(protected + admin routes)* `UsageLog()` — records request metadata to usage.Recorder after response
9. *(admin routes only)* `RequireAdmin()` — checks plan == "admin"

## Development Workflow

- `make test` — unit tests with race detector (always run before presenting work as done)
- `make test-integration` — integration tests using miniredis + stub auth
- `make test-all` — runs both unit and integration tests with pass/fail summary
- `make docker-reset` — **dev only**, wipes volumes and rebuilds everything
- `./scripts/smoke-test.sh` — **dev only**, hits every endpoint with every key/plan combo
- `./scripts/info.sh` — **dev only**, pretty-prints `/v1/info` admin endpoint (reads `SMOKE_ADMIN_KEY` from `.env`)
- `make deploy` — deploys to Fly.io with git version baked in
- `make release V=v0.X.Y` — tags and pushes a release
- `make deps` — runs `go get -u ./...` and `go mod tidy` (run explicitly to upgrade dependencies)

### Commit conventions
- Commit directly to main or short-lived branches that merge immediately
- Only push to `main` — push to `release` only when explicitly asked
- No Co-Authored-By lines
- Keep README.md in sync when changes affect endpoints, config, make targets, or structure

## Testing Strategy

### Unit tests
Each package has `*_test.go` files. Handler tests use `httptest` with a gin test router. Service tests swap lookup functions via `SetLookups()`. Middleware tests inject `zap.NewNop()` via `*WithLogger()` variants.

### Integration tests
`integration_test.go` at project root, gated behind `//go:build integration`. Uses `miniredis` for an in-memory Redis and `stubRepo` for auth. Tests the full middleware → handler → service → (stubbed) domain flow. Covers auth, plan-based access, caching, validation, and rate limiting.

### Smoke tests
`scripts/smoke-test.sh` hits a running instance with curl. Checks every endpoint with every API key and verifies expected HTTP status codes. Catches issues that unit/integration tests miss (like database migration problems). Accepts an optional host argument (defaults to `http://localhost:8080`). API keys can be overridden via `.env` file or `SMOKE_*` env vars for production testing.

### Status check
`scripts/status.sh` checks Fly.io deployment health — machine state, endpoint reachability, and (with `SMOKE_ADMIN_KEY`) detailed status from the `/v1/info` endpoint.

## Config

Viper-based. Reads YAML from `../../config/`, `../config/`, `config/` (relative, first match wins), or `/etc/security-accelerated/` (production). Environment variables override config: `POSTGRES_HOST` → `postgres.host`. Defaults are set in `config/config.go` for all values.

Sample config: `internal/config/sample-config.yml`

## Database

PostgreSQL with migrations in `migrations/`. Docker initdb only runs scripts on first volume creation — existing volumes require manual migration. For production (Neon), apply new migrations via `psql "$NEON_CONNECTION_STRING" -c "..."` using the connection string from `.env`.

Tables: `customers` (plan, email, stripe_customer_id), `api_keys` (key_hash, last_used_at, expires_at — multiple keys per customer allowed during rotation grace windows), `fingerprint_rules` (append-only JSONB rules), `provisioned_keys` (one-time key retrieval after Stripe checkout), `request_log` (usage tracking — per-request metadata for admin and customer analytics, includes `domain_count`, `ip_count`, and per-feature flags including `dns_security`).

## Infrastructure

- **Docker Compose** for local dev (API + Redis + PostgreSQL with healthchecks)
- **Fly.io** for production deployment (iad region, auto-stop/start machines)
- **Fly volume `maxmind_data`** mounted at `/data/maxmind`, persisting the GeoIP databases. Machine filesystems are a blank slate on every start, so without it the ~80MB databases are re-downloaded on each cold start. Fly requires **one volume per machine** — two machines, two volumes. Volumes mount root-owned and Fly offers no uid/gid option, so `docker-entrypoint.sh` chowns the mount as root and then execs the app as `appuser` via `su-exec`; the container no longer sets `USER`, though the application itself still runs unprivileged. Without that step the GeoIP download fails with permission denied on every boot, silently.
- **Neon** for production PostgreSQL
- **Upstash** for production Redis (via Fly)
- **GitHub Actions** — three workflows:
  - `docker.yml`: builds Docker images on push to `main` or version tags, pushes to GHCR
  - `fly-deploy.yml`: deploys to Fly.io on push to `release` branch, with git version baked in via `--build-arg`
  - `uptime.yml`: pings `/v1/hello` every 5 minutes, sends Pushover alert on failure
- Version is baked in at build time via `-ldflags "-X main.version=..."` — passed as Docker build arg
- Deploy workflow: push to main → `make release V=v0.X.Y` → `git push origin main:release`
- `.env` file (gitignored) holds API keys for `smoke-test.sh` and `status.sh` against production

## Adding a New Lookup Type

1. Create `internal/domain/newlookup.go` with a function matching the pattern: `func LookupThing(ctx context.Context, domain string) (*ThingInfo, error)`
2. Add the payload type (`ThingInfo`) and its response wrapper (`ThingResult` — embeds `*ThingInfo`, adds `cache_hit`) to `internal/domain/model.go`, plus a `LookupThingName` constant and an entry in `AllLookupNames`
3. Add the field to `DomainResponse`
4. Add a function field to `DomainService` in `internal/service/domain.go` and wire it in `NewDomainService()`
5. Add a runner in `buildRunners()` (one `simpleRunner`/`multiErrRunner` line) and an assembly branch in `assemble()`
6. Add a row to `lookupMinPlan` in `internal/handler/domain.go` — that alone makes the name valid and sets its plan gate. There is no bool to thread through the request, options, or cache key
7. Add a TTL default: `cache.ttl.<name>` in `internal/config/config.go` and `sample-config.yml`
8. Add the column to `usage.LookupColumns` and a migration for `request_log` (the drift test will fail until you do)
9. Add a setter method for tests (`SetThingLookup`)
10. Update all test files that call `New()` or `SetLookups()`
11. Update README, docs HTML (request table, valid-lookups table, response field section with its `cache_hit` row, caching TTL table), api.http, smoke test, integration tests, changelog.yaml

## Adding a New Endpoint

1. Define request/response types in `internal/domain/model.go`
2. Create a service in `internal/service/`
3. Add a handler method in `internal/handler/`
4. Define a service interface in `internal/handler/handler.go`
5. Register the route in `RegisterProtectedRoutes()` with `RequireAdmin()` if admin-only
6. Wire the service in `internal/app/app.go`
7. Add a field to `handler.Deps` and set it in `app.go` — existing test call sites need no change, since they name only the dependencies they use
8. Add context keys to `middleware/request_logger.go` if needed
9. Update README, api.http, smoke test, integration tests, changelog.yaml
