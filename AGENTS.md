# Intelligence API — agent guide

Domain and IP intelligence REST API in Go with Gin. Concurrent WHOIS, DNS, SSL, HTTP
headers, screenshots, reputation, email security (SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI),
subdomains, certificate transparency, BGP/ASN, technology fingerprinting, threat
intelligence, and DNS security (DNSSEC/CAA) for domains, plus an aggregate risk score. IP
lookups: GeoIP, ASN, reverse DNS, RDAP abuse contact, threat intelligence. Results are
cached per lookup in Redis with singleflight coalescing; failures are never cached. Auth is
API-key based with PostgreSQL; customers self-rotate keys and query their own usage.
OpenAPI 3.1 at `/docs/openapi.yaml`.

**Module:** `github.com/security-accelerated/intelligence-api`

## Where things are

```
cmd/api/main.go          entry point, version via ldflags
cmd/sactl/               operator CLI: interactive menu with no args, flags otherwise
internal/app/            dependency wiring, bootstrap, shutdown
internal/handler/        HTTP handlers, route registration, request validation, docs pages
internal/service/        lookup orchestration, caching, fan-out
internal/domain/         lookup implementations + types (model.go)
internal/middleware/     auth, rate limit, logging, security headers, body limit, request ID
internal/httpapi/        Gin router assembly, middleware chain, server lifecycle
internal/cache/          Cache interface + Redis
internal/auth/           customers, plans, key hashing, cached repository
internal/adminops/       customer/key operations behind the CLI
internal/database/       shared PostgreSQL connection
internal/billing/        Stripe webhooks, key provisioning, noop fallback
internal/usage/          buffered usage logging, admin query
internal/notifications/  Pushover alerting, throttle and spike detection
internal/safenet/        SSRF prevention at dial time
internal/logging/        Zap (ECS in prod, pretty in dev)
internal/config/         Viper, YAML + env overrides, StatusSnapshot
migrations/              PostgreSQL schema
scripts/                 docker-reset.sh, smoke-test.sh, status.sh, info.sh — dev only
changelog.yaml           symlink to internal/handler/changelog.yaml; edit from the root
```

## Where the detail lives

This file is what is true everywhere in the repo. Package-specific rules and the reasoning
behind them live elsewhere, so read the one that matches before editing:

| Working in | Read |
|---|---|
| `internal/service`, `cache`, `notifications` | `.claude/rules/service-layer.md` |
| `internal/domain`, `safenet`, lookup handlers | `.claude/rules/lookups.md` |
| `internal/handler/docs*` | `.claude/rules/docs-pages.md` |
| `internal/auth`, `billing`, `usage`, `adminops`, `cmd/sactl`, `migrations` | `.claude/rules/auth-billing.md` |
| `internal/middleware`, `httpapi`, `app`, `config` | `.claude/rules/http-layer.md` |
| Anything that looks removable | `docs/decisions.md` — it may be load-bearing |
| Adding a lookup type or endpoint | the `adding-features` skill (`.claude/skills/`) |
| Releasing | `RELEASE.md` |

Claude Code loads the rules automatically when a matching file is read. Codex does not;
open the file.

## Commands

- `make verify` — **the one that answers "did it work?"**: gofmt, vet, lint on new
  findings, unit tests with `-race`, integration tests. Non-destructive. Run it before
  presenting work as done and report the real output.
- `make test` / `make test-integration` / `make test-all` — the pieces, when you want one
- `make lint` — whole tree, including the known backlog; `make lint-new` is what CI gates
- `make build-cli` / `make install-cli` — `sactl`
- `make deps` — `go get -u ./...` + tidy, only when asked to upgrade
- `make docker-reset` — **dev only**, wipes volumes and rebuilds
- `./scripts/smoke-test.sh [host]` — every endpoint × every plan; default
  `http://localhost:8080`, against production only when asked in the session. Keys come
  from `.env` / `SMOKE_*` vars. It pools free-plan keys (`SMOKE_FREE_KEY_2`, `_3`, … or
  `SMOKE_FREE_KEYS`) because the limiter is per key per minute, and reserves
  `SMOKE_RATELIMIT_KEY` for the rate-limit check, which must exhaust one key's window;
  without it that check is skipped, not run wrongly.
- `./scripts/docker-reset.sh` bounds its readiness wait with `RESET_TIMEOUT` (300s) and
  names the dependency that timed out. `./scripts/status.sh` checks Fly machine state and
  endpoint reachability.

## Conventions

- Feature branch → PR into `main`. No direct pushes to `main`. Open the PR, do not merge
  it. `release` is reached only by PR from `main` — see `RELEASE.md`.
- No `Co-Authored-By` trailers. Fleet attribution rules apply (`Assisted-by:`).
- `go mod tidy` before committing. `gofmt` is not optional.
- Keep `README.md` in sync when a change touches endpoints, config, make targets, or
  structure.
- A new lookup needs a `usage.LookupColumns` entry and a `request_log` migration; a drift
  test fails until it has both. That failure is the design.
- Tests: handlers use `httptest` with a gin test router; services swap lookups via
  `SetLookups()`; middleware tests inject `zap.NewNop()` via `*WithLogger()` variants.
  Integration tests live in `integration_test.go` behind `//go:build integration`, using
  `miniredis` and `stubRepo` for auth; they cover the full middleware → handler → service
  → (stubbed) domain path.

## Safety boundaries

- Never touch production data, rotate credentials, or apply migrations to Neon unless asked
  in the session. Production migrations are manual (`psql "$NEON_CONNECTION_STRING"`) and
  a release does not run them.
- `docker-reset` destroys local state. Never run it as a side effect of something else.
- Never log secrets or raw sensitive payloads. Error text reaching a response goes through
  `sanitizeErr()`.
- Every outbound HTTP client goes through `safenet` — a new one that doesn't is a
  vulnerability, not a style issue.

## Infrastructure

Docker Compose locally (API + Redis + Postgres). Production on Fly.io (iad, auto-stop) with
Neon Postgres and Upstash Redis. A Fly volume `maxmind_data` at `/data/maxmind` persists
the GeoIP databases; `docker-entrypoint.sh` chowns it as root then drops to `appuser`.
Version is baked in via `-ldflags "-X main.version=..."`. GitHub Actions: `test.yml`,
`docker.yml` (GHCR on push to `main`/tags), `fly-deploy.yml` (deploys on push to
`release`), `uptime.yml` (pings `/v1/hello` every 5 min, Pushover on failure). `.env`
(gitignored) holds keys for the scripts.

## Session start

`.claude/hooks/session-start.sh`, registered in `.claude/settings.json`, fetches,
fast-forwards only when unambiguous, and lists open PRs — because #75 and #76 once
collided in `changelog.yaml`. It never pulls over a dirty or diverged tree. Network steps
are bounded by `SESSION_START_NET_TIMEOUT` (15s) and every failure degrades to a line of
output rather than blocking startup.
