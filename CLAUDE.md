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

### Concurrent fan-out with shared response
`service.Lookup()` spawns goroutines for each lookup type, protected by `sync.Mutex` on the shared `DomainResponse`. Four base lookups always run; optional lookups (screenshot, reputation, email_security, subdomains, ct_logs, bgp, threat_intel, dns_security) only spawn when requested. Fingerprint and the aggregate risk score run as post-processing after `wg.Wait()` using already-fetched data (zero extra network calls). A 30-second context timeout covers the entire operation.

### Singleflight coalescing + negative caching
Concurrent lookups for the same cache key coalesce into one fan-out via `golang.org/x/sync/singleflight` (in both `DomainService` and `IPService`); coalesced callers get deep copies via `copyViaJSON` so they never share mutable state. The executed lookup runs under `context.WithoutCancel` so one disconnecting client can't poison the shared result. Responses containing lookup errors — including fully-failed lookups — are cached with a shorter TTL (`redis.negative_cache_ttl`, default 5m) instead of the full `redis.cache_ttl` (60m), so transient upstream failures age out quickly and dead domains don't trigger a fresh fan-out per request.

### Aggregate risk score
`internal/domain/risk.go` computes a weighted 0–100 score (`ComputeRiskScore`) from whichever lookup results are present: threat_intel (0.35), reputation (0.25), ssl, security_headers, email_security, domain_age (0.10 each). Weights renormalize over present components. Risk levels use the same thresholds as `ScoreThreatIntel`. Runs as post-processing in `service.Lookup()` — zero extra network calls. Returned as `risk` on every domain response.

### DNS security lookup
`internal/domain/dnssec.go` uses raw DNS via `miekg/dns` (net.Resolver can't query DS/DNSKEY/CAA) against `domain.ActiveDNSServers()` (set by `InitResolver`). Reports DNSSEC deployment (DS at parent + DNSKEY at zone + algorithms) and CAA records. Truncated UDP responses retry over TCP. Opt-in via `dns_security` flag, all plans. Tests run a local `miekg/dns` server.

### API key rotation
`POST /v1/keys/rotate` (any authenticated customer) issues a new key and grace-expires all previous keys (`auth.rotation_grace`, default 24h). Migration 012 dropped the one-key-per-customer constraint and added `api_keys.expires_at`; the auth lookup filters expired keys and `DeactivateStaleKeys` only deactivates customers with no fresh live key. `billing.KeyRotationService` depends only on the DB (works without Stripe) and invalidates the auth cache after rotating.

### Health endpoint
`GET /v1/health` (unauthenticated, internal/ops — never in consumer docs, same policy as `/v1/hello`) pings Postgres and Redis with a 2s timeout and reports GeoIP database state. Postgres/Redis down → 503 `degraded`; missing GeoIP does not degrade (absent until bootstrapped). The uptime workflow hits this endpoint.

### Partial failure tolerance
Each lookup goroutine catches its own errors. Failures are appended to `resp.Errors` with sanitized messages — the rest of the response still returns. Full errors are logged server-side; users see only safe summaries via `sanitizeErr()`.

### Composite cache keys
Cache keys are built from the domain name plus sorted feature suffixes: `example.com:bgp+email_security+reputation`. This ensures each feature combination caches independently.

### SSRF prevention at the dialer level
The `safenet` package provides a `DialControl` function that rejects connections to private, loopback, link-local, multicast, unspecified, and CGNAT IPs. It fires after DNS resolution (no TOCTOU race). All HTTP clients in the `domain` package use `safenet.SafeDialer()` via shared transports in `domain/transport.go`.

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
`internal/billing/` follows the notifications pattern (interface + real impl + noop fallback). `Service` interface defines `HandleWebhook` and `GetProvisionedKey`. `StripeService` verifies webhook signatures, handles checkout/subscription/payment events, and provisions API keys. `NoopService` returns "billing not configured" errors. `Repository` wraps billing-specific DB operations (customer+key creation, provisioned key storage, plan updates, stale key cleanup). Key provisioning: on checkout, generates a random API key, stores hash in `api_keys`, stores raw key in `provisioned_keys` (1hr expiry, one-time retrieval). `keygen.go` generates 64-char hex keys via `crypto/rand`. Auth cache is invalidated after any plan change. `last_used_at` on `api_keys` is updated on auth cache-miss lookups (batched via `auth.LastUsedBatcher`). `StripeService` accepts a `notifications.Notifier` and sends async Pushover notifications on all billing events (new signup, plan change, cancellation, payment failure). Customer Portal link is configurable via `STRIPE_PORTAL_LINK` and shown on docs/success pages. Config: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICES_BASIC_MONTHLY`, `STRIPE_PRICES_PRO_MONTHLY`, `STRIPE_PAYMENT_LINK_BASIC`, `STRIPE_PAYMENT_LINK_PRO`, `STRIPE_PORTAL_LINK`, `BILLING_STALE_KEY_DAYS`.

### Usage tracking
`internal/usage/` follows the notifications/billing pattern (interface + real impl + noop). `Recorder` interface accepts `UsageEntry` values; `Queryer` interface returns aggregated `UsageSummary`. `UsageLogger` buffers entries on a channel and batch-inserts to PostgreSQL's `request_log` table on a timer (default 5s) or when the batch hits 50 entries. Channel full = silent drop with warning log. `NoopRecorder` discards entries when usage tracking isn't needed (tests). `QueryService` runs aggregation SQL for the admin endpoint. Middleware `UsageLog()` collects request metadata after `c.Next()` and calls `recorder.Record()`. Admin endpoint: `GET /v1/admin/usage?days=30&customer_id=X&api_key_id=Y`. Config: `USAGE_BUFFER_SIZE`, `USAGE_FLUSH_INTERVAL`.

### StatusSnapshot for unified status
`internal/config/status.go` defines typed structs (`SystemStatus`, `DatabaseConfig`, `CacheConfig`, `LookupConfig`, `ServicesStatus` with sub-structs) held in a `StatusSnapshot`. Built once at startup via `NewStatusSnapshot(version)`, then progressively populated as services initialize in `app.go`. Used for both structured startup logging (`zap.Any("config", section)`) and the `/v1/info` admin endpoint response — adding a field to any struct automatically surfaces it in both places. Live data (runtime stats, DB pool, Redis ping, auth cache size) is computed at request time in the info handler and merged with the static snapshot. JSON response groups: `system`, `database`, `cache` (static config + live stats), `lookups`, `services`, `runtime`, `postgres_pool`.

### Changelog
`internal/handler/changelog.yaml` (symlinked from project root as `changelog.yaml`) is the single source of truth for all changes. Each entry has a `version`, `date`, and list of `changes` with `audience` tags (`public` or `internal`). Embedded via `go:embed` in the handler package, parsed at startup. The docs pages (`/docs`, `/docs/domain`, `/docs/ip`) render only `public` entries in a "What's New" section. The admin endpoint (`GET /v1/admin/changelog`) returns all entries unfiltered. Update this file with every release.

### Notifications
`internal/notifications/` provides interface-driven alerting. `Notifier` interface abstracts the delivery channel (currently Pushover); `ErrorRecorder` interface abstracts error tracking (currently `Alerter`). The `Alerter` uses sliding-window counters behind a mutex to detect per-lookup throttling (default: 5 failures in 5m) and global error spikes (default: 15 errors in 5m). Alerts fire asynchronously with a 15-minute cooldown to prevent alert fatigue. `DomainService` depends on `ErrorRecorder`; when Pushover credentials are absent, a `NoopRecorder` is wired in. Config: `PUSHOVER_API_TOKEN`, `PUSHOVER_USER_KEY`, `ALERTS_THROTTLE_THRESHOLD`, `ALERTS_THROTTLE_WINDOW`, `ALERTS_SPIKE_THRESHOLD`, `ALERTS_SPIKE_WINDOW`, `ALERTS_COOLDOWN`.

### IP intelligence
`internal/domain/geoip.go` provides `GeoIPReader` — holds MaxMind GeoLite2 City and ASN databases behind `sync.RWMutex` for concurrent reads with atomic hot-reload via `Reload()`. `DownloadAndReload()` fetches latest databases from MaxMind using a license key, validates them, and swaps atomically. `internal/domain/ip_rdns.go` does PTR lookups via `net.DefaultResolver`. `internal/domain/ip_rdap.go` queries RDAP bootstrap (`rdap.org/ip/`) for abuse contacts — returns structured JSON, no WHOIS parsing needed. `internal/domain/ip_threatintel.go` defines `IPThreatIntelProvider` interface and adapter types (`VTIPProvider`, `URLhausIPProvider`, `OTXIPProvider`) that wrap existing domain providers, sharing their HTTP clients and rate limiters but hitting IP-specific API endpoints. `internal/service/ip.go` follows the same concurrent fan-out pattern as `service/domain.go` with function-based DI and `ip:` prefixed cache keys. `internal/handler/ip.go` validates IPs via `netip.ParseAddr`, rejects non-globally-routable addresses, and gates `threat_intel` to pro/admin. `internal/handler/geoip_admin.go` provides a bodyless admin endpoint for app-managed database refresh. Config: `MAXMIND_LICENSE_KEY`, `MAXMIND_DB_PATH`, `IP_LOOKUP_TIMEOUT`, `IP_MAX_IPS_FREE/BASIC/PRO`.

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
2. Add the result type to `internal/domain/model.go`
3. Add a function field to `DomainService` in `internal/service/domain.go`
4. Wire it in `NewDomainService()` constructor
5. Add a goroutine in `service.Lookup()` following the existing pattern (wg.Go, mu.Lock)
6. If opt-in, add a bool to `DomainRequest`, `LookupOptions`, and the cache key builder
7. Update handler to pass the option through
8. Add a setter method for tests (`SetThingLookup`)
9. Update all test files that call `New()` or `SetLookups()`
10. Update README, integration tests, changelog.yaml

## Adding a New Endpoint

1. Define request/response types in `internal/domain/model.go`
2. Create a service in `internal/service/`
3. Add a handler method in `internal/handler/`
4. Define a service interface in `internal/handler/handler.go`
5. Register the route in `RegisterProtectedRoutes()` with `RequireAdmin()` if admin-only
6. Wire the service in `internal/app/app.go`
7. Update handler `New()` signature and all test call sites
8. Add context keys to `middleware/request_logger.go` if needed
9. Update README, api.http, smoke test, integration tests, changelog.yaml
