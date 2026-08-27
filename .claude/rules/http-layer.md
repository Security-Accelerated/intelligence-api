---
paths:
  - "internal/middleware/**"
  - "internal/httpapi/**"
  - "internal/app/**"
  - "internal/config/**"
  - "internal/handler/handler.go"
  - "internal/handler/health.go"
  - "internal/handler/hello.go"
  - "internal/handler/info.go"
---

# HTTP layer: middleware, wiring, config, status

## Middleware chain — order matters

1. `gin.Recovery()` — panics → 500 (handler goroutines only; lookups recover themselves)
2. `SecurityHeaders()` — X-Content-Type-Options, X-Frame-Options, `Cache-Control:
   no-store`, HSTS, Referrer-Policy, and a strict `default-src 'none'` CSP for the JSON
   API. HTML pages override the CSP with `htmlPageCSP` in the handler package.
3. `BodyLimit(1MB)`
4. `ClientRequestID()` — validates/echoes `X-Client-Request-ID`, sets a context key
5. `RequestLogger()` — structured logging; runs after `c.Next()` returns
6. *(protected)* `APIKeyAuth()` — sets `customer_id`, `api_key_id`, `api_key_plan`
7. *(protected)* `RateLimit()` — per-key sliding window in Redis, **fail-open**, admin
   bypass
8. *(protected + admin)* `UsageLog()` — records to `usage.Recorder` after the response
9. *(admin)* `RequireAdmin()` — `plan == "admin"`

Adding middleware means choosing a position in this list, and the position is part of the
change. Auth must precede rate limiting (the limit is per key); usage logging must follow
auth (it needs the key) and must be after `c.Next()` so it sees the outcome.

## Handler construction

`handler.New` takes a single `Deps` struct. **Every field is optional**; a nil service
makes its endpoints return 503 rather than panicking, so a partially-configured deployment
serves what it can. Adding a dependency is additive — existing call sites are untouched.
Never revert to positional parameters.

Routes: `RegisterProtectedRoutes()`, with `RequireAdmin()` for admin-only. The endpoint
checklist is in the `adding-features` skill.

## Wiring — `internal/app`

`app.go` builds every collaborator from config and injects it. Collaborators with a real
second implementation are interfaces (`cache.Cache`, `notifications.Notifier`,
`usage.Recorder`, `billing.Service`, `domain.ThreatIntelProvider`,
`domain.ScreenshotProvider`); each has a `Name()` where several can run, one method for
the work, construction chosen here from config, and **an unknown name is a startup error**,
never a silent fallback. Lookups with one implementation are function fields, swapped in
tests via `SetLookups()` and per-feature setters — do not wrap those in interfaces.

`cmd/api/main.go` is split into `main` and `run` so the log flush is deferred once and
every exit path gets it. Keep new exit paths inside `run`.

## Config — `internal/config`

Viper. YAML from `../../config/`, `../config/`, `config/` (first match) or
`/etc/security-accelerated/` in production. Env vars override with `POSTGRES_HOST` →
`postgres.host`. **Every value has a default in `config.go`**; a new key without one is
incomplete. Sample: `internal/config/sample-config.yml` — update it with the key.

`config.CacheTTLs()` reads each `cache.ttl.<name>` individually so env overrides work;
reading the subtree as a map breaks them.

## Status — `internal/config/status.go`

`StatusSnapshot` holds typed structs (`SystemStatus`, `DatabaseConfig`, `CacheConfig`,
`LookupConfig`, `ServicesStatus`), built once via `NewStatusSnapshot(version,
domain.AllLookupNames)` and populated progressively in `app.go`. It feeds both the
structured startup log and `GET /v1/info` — **adding a field to a struct surfaces it in
both places**. Live data (runtime stats, DB pool, Redis ping, auth cache size) is computed
at request time in the info handler and merged in. Response groups: `system`, `database`,
`cache`, `lookups`, `services`, `runtime`, `postgres_pool`. `./scripts/info.sh`
pretty-prints it (needs `SMOKE_ADMIN_KEY` from `.env`).

## Health

`GET /v1/health` — unauthenticated, ops-only, never in customer docs (same policy as
`/v1/hello`). Pings Postgres and Redis with a 2s timeout. Either down → 503 `degraded`.
**Missing GeoIP does not degrade** — it self-bootstraps and is absent for the first seconds
of a cold start. The uptime workflow hits this endpoint.

## Responses

Every response is a JSON object: `{"results": [...]}` for lookups, `{"error": "..."}` for
failures. There is no top-level `cache_hit`. Never return a bare array.
