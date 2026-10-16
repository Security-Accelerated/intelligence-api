# Intelligence API

[![Build](https://github.com/Security-Accelerated/intelligence-api/actions/workflows/docker.yml/badge.svg?branch=main)](https://github.com/Security-Accelerated/intelligence-api/actions/workflows/docker.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/Security-Accelerated/intelligence-api)](go.mod)
[![Release](https://img.shields.io/github/v/tag/Security-Accelerated/intelligence-api?label=release&sort=semver)](https://github.com/Security-Accelerated/intelligence-api/tags)
[![Go Report Card](https://goreportcard.com/badge/github.com/security-accelerated/intelligence-api)](https://goreportcard.com/report/github.com/security-accelerated/intelligence-api)

A domain and IP intelligence REST API in Go. One request fans out to concurrent lookups
(WHOIS, DNS, TLS, HTTP headers, email security, certificate transparency, BGP/ASN,
technology fingerprinting, reputation, threat intelligence, DNSSEC/CAA, GeoIP, reverse
DNS, abuse contacts) and returns one JSON document with a per-lookup cache flag and an
optional aggregate risk score. It is a paid, metered service with self-service API keys,
Stripe billing, and per-plan rate limits, running in production at
**<https://api.securityaccelerated.com>**.

- **Live docs:** <https://api.securityaccelerated.com/docs> — rendered reference with
  examples in several languages
- **OpenAPI 3.1:** <https://api.securityaccelerated.com/docs/openapi.yaml>
- **Release notes:** <https://api.securityaccelerated.com/docs/changelog>

## One request

```sh
curl -s https://api.securityaccelerated.com/v1/domain/lookup \
  -H 'X-API-Key: YOUR_KEY' -H 'Content-Type: application/json' \
  -d '{"domains":["example.com"],"lookups":["dns","ssl","email_security","risk"]}'
```

```json
{
  "results": [
    {
      "domain": "example.com",
      "dns":            { "cache_hit": false, "a": ["23.192.228.80"], "ns": ["a.iana-servers.net", "b.iana-servers.net"] },
      "ssl":            { "cache_hit": true,  "issuer": "DigiCert Global G3 TLS ECC SHA384 2020 CA1", "not_after": "2027-01-15T23:59:59Z", "days_until_expiry": 91 },
      "email_security": { "cache_hit": false, "spf": { "raw": "v=spf1 -all", "all": "-all" }, "dmarc": { "raw": "v=DMARC1; p=reject", "policy": "reject" } },
      "risk":           { "cache_hit": false, "score": 12, "risk_level": "low" }
    }
  ]
}
```

Every lookup carries its own `cache_hit`, because each one is cached on its own TTL. The
response above is trimmed; the full field reference is in
[docs/api-reference.md](docs/api-reference.md).

## Architecture

```text
client ──> Gin router ──> middleware chain ──> handler ──> service ──> domain lookups
                         recovery, security          validate     fan-out per lookup,
                         headers, body limit,        request,     Redis cache per lookup
                         request ID, logging,        plan gate    with singleflight,
                         API key auth, rate limit,                failures never cached
                         usage logging
```

| Package | Responsibility |
|---|---|
| `internal/httpapi`, `internal/middleware` | Router assembly, the middleware chain in a fixed order, graceful shutdown |
| `internal/handler` | Request validation, plan gating, the embedded docs pages and OpenAPI document |
| `internal/service` | Fan-out orchestration, per-lookup Redis caching with singleflight coalescing, risk scoring |
| `internal/domain` | One file per lookup, plus the response types in `model.go` |
| `internal/safenet` | SSRF prevention at dial time: every outbound HTTP client in the server goes through it |
| `internal/auth`, `internal/billing`, `internal/usage` | Hashed API keys with rotation, Stripe webhooks and key provisioning, buffered usage logging |
| `internal/notifications` | Pushover alerting with throttle and spike detection |
| `internal/cache`, `internal/database`, `internal/config`, `internal/logging` | Redis, PostgreSQL, Viper config with env overrides, Zap in ECS format |
| `cmd/api`, `cmd/sactl` | The server, and the operator CLI that reuses the server's own packages |

Production runs on Fly.io with Neon PostgreSQL and Upstash Redis. A `v*` tag on `main` is
the deploy. The procedure is in [RELEASE.md](RELEASE.md).

## Engineering notes

A few choices that are easy to miss from the outside:

- **Failures are never cached.** A lookup that errors is recorded in the response's
  `errors` and retried on the next request, so a flaky upstream never poisons the cache.
  Concurrent requests for the same key are coalesced with `singleflight`, and the shared
  fetch runs under `context.WithoutCancel` so one caller giving up does not fail the rest.
- **Outbound requests cannot reach private networks.** `internal/safenet` resolves and
  checks every dial target against loopback, private, link-local, multicast, and reserved
  ranges before connecting, which covers cloud metadata endpoints. A new HTTP client that bypasses it is treated as a vulnerability, not
  a style issue.
- **API keys are stored only as SHA-256 hashes.** Customers rotate their own keys with
  `POST /v1/keys/rotate`; the old key keeps working for a grace window so deployed clients
  switch over without downtime. The one place a plaintext key exists is the one-time
  retrieval row written at Stripe checkout, blanked on read and swept on expiry.
- **Billing is a webhook, not a dashboard.** Stripe Checkout completes, the webhook
  provisions the customer and key in one transaction, and the success page shows the key
  once. Plan changes, cancellations, and payment failures flow back the same way.
- **Usage logging has a drift test.** Every lookup gets a column in `request_log`; a new
  lookup without its migration and `usage.LookupColumns` entry fails CI by design.
- **Operations go through one CLI.** `sactl` reuses the server's hashing, plan, and
  rotation code rather than reimplementing them, and every mutating command needs an
  explicit `--allow-writes`.
- **The reasoning is written down.** [docs/decisions.md](docs/decisions.md) records the
  controls that look removable and are not, with the incident or constraint behind each.

## Run it locally

```sh
docker compose up --build        # API on :8080, Redis, PostgreSQL with migrations and seed data
curl -s localhost:8080/v1/domain/lookup \
  -H 'X-API-Key: test-admin-key' -H 'Content-Type: application/json' \
  -d '{"domains":["example.com"],"lookups":["dns"]}'
```

The seed data creates admin, pro, and free customers with keys named `test-admin-key`,
`test-pro-key`, and `test-free-key`. Configuration, the full environment variable list,
running without Docker, the admin CLI, and the smoke test are in
[docs/operations.md](docs/operations.md).

## Development

```sh
make verify              # gofmt, vet, lint on new findings, unit tests with -race, integration tests
make test                # unit tests only
make test-integration    # middleware → handler → service path with miniredis and stubbed lookups
```

`make verify` is the gate that CI runs. Handlers are tested with `httptest`, services swap
lookups with `SetLookups()`, and integration tests live behind the `integration` build
tag. Every pull request merges as a merge commit; the one-line history is
`git log --first-parent main`.

Guidance for contributors and agents lives in [AGENTS.md](AGENTS.md), with package-level
rules under `.claude/rules/`. Security reports go to the address in
[SECURITY.md](SECURITY.md).

## Development with AI assistance

This codebase is written with AI coding agents in the loop. Commits that an agent helped
with carry an `Assisted-by:` trailer naming the model, so the history says which changes
were assisted and by what. The author reviews, tests, and owns every commit; the agent is
never the author or a co-author. The instructions the agents work from are in the repo:
`AGENTS.md`, `.claude/rules/`, and `.claude/skills/`.

## Documentation map

| File | What it covers |
|---|---|
| [docs/api-reference.md](docs/api-reference.md) | Authentication, plans, rate limits, every endpoint, every response field, caching rules |
| [docs/operations.md](docs/operations.md) | Configuration, database setup, running locally, deployment, Fly secrets, `sactl`, smoke tests, alerting, billing internals |
| [docs/decisions.md](docs/decisions.md) | Design decisions that are load-bearing and why |
| [RELEASE.md](RELEASE.md) | Cutting a release, rolling back |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |
| [changelog.yaml](changelog.yaml) | Every release, with public entries rendered at `/docs/changelog` |

## License

Source-available, all rights reserved. The code is published so it can be read and
evaluated. No license is granted to use, copy, modify, or redistribute it.
