# Intelligence API — operations

Running, configuring, deploying, and administering the service. The caller-facing API
reference is in [api-reference.md](api-reference.md); the release procedure is in
[../RELEASE.md](../RELEASE.md).

## Getting Started

### Prerequisites

- Go 1.27+
- Redis (or use the included Docker Compose)
- PostgreSQL (or use the included Docker Compose)

### Configuration

The application looks for `intelligence-api.yaml` in the following locations (first match wins):

1. `../../config/` (relative to working directory)
2. `../config/` (relative to working directory)
3. `config/` (relative to working directory)
4. `/etc/security-accelerated/` (recommended for production)

Copy the sample config to your preferred location:

```sh
sudo cp internal/config/sample-config.yml /etc/security-accelerated/intelligence-api.yaml
```

Every config key can be overridden by an environment variable: replace dots with underscores and uppercase (e.g. `server.write_timeout` → `SERVER_WRITE_TIMEOUT`). Environment variables take precedence over the YAML file. All active config values plus live runtime metrics are visible at `GET /v1/info` (admin only) — see the [Application Status](api-reference.md#get-v1info--application-status-admin-only) section for the full response structure.

Config values:

| Key | Default | Description |
|-----|---------|-------------|
| `application.mode` | `""` | `local` or `production` |
| `application.port` | `8080` | HTTP server port |
| `server.read_timeout` | `10s` | HTTP server read timeout |
| `server.write_timeout` | `45s` | HTTP server write timeout |
| `server.idle_timeout` | `60s` | HTTP server idle connection timeout |
| `server.shutdown_timeout` | `15s` | Graceful shutdown deadline |
| `server.body_limit` | `1048576` | Maximum request body size in bytes (1 MB) |
| `redis.addr` | `localhost:6379` | Redis address |
| `redis.password` | `""` | Redis password |
| `redis.db` | `0` | Redis database number |
| `cache.default_ttl` | `60m` | Fallback cache TTL for lookups without their own entry |
| `cache.ttl.<lookup>` | see [Caching](api-reference.md#ttls) | Per-lookup cache TTL, e.g. `cache.ttl.whois: 24h` (env: `CACHE_TTL_WHOIS`) |
| `gin.mode` | `""` | Gin framework mode (`debug`, `release`, `test`) |
| `auth.cache_ttl` | `5m` | TTL for in-memory auth cache |
| `auth.rotation_grace` | `24h` | How long old keys keep working after `POST /v1/keys/rotate` |
| `auth.last_used_buffer_size` | `256` | Buffer size for batched last_used_at updates |
| `auth.last_used_flush_interval` | `10s` | How often last_used_at updates are flushed to PostgreSQL |
| `subdomain.max_results` | `500` | Maximum number of subdomains returned per domain |
| `subdomain.max_response_bytes` | `10485760` | Maximum crt.sh response body size in bytes (10 MB) |
| `subdomain.http_timeout` | `15s` | End-to-end timeout for the crt.sh subdomain request |
| `ct_logs.max_entries` | `100` | Maximum number of CT log entries returned per domain |
| `ct_logs.http_timeout` | `15s` | End-to-end timeout for the crt.sh CT logs request |
| `threat_intel.virustotal_api_key` | `""` | VirusTotal API key (enables VirusTotal provider) |
| `threat_intel.alienvault_api_key` | `""` | AlienVault OTX API key (enables AlienVault provider) |
| `dns.servers` | `[]` | External DNS resolvers (default: Google, Cloudflare, OpenDNS) |
| `dns.timeout` | `30s` | Per-server DNS dial timeout |
| `geoip.db_path` | `/data/geoip` | Directory for the GeoIP database file |
| `geoip.city_db` | `dbip-city-lite.mmdb` | GeoIP city database filename |
| `geoip.max_age` | `720h` | Re-download a database older than this at startup (DB-IP publishes monthly); `0` pins whatever is on disk |
| `ip.lookup_timeout` | `30s` | Overall timeout for all concurrent IP lookups |
| `ip.max_ips.free` | `1` | Maximum IPs per request for free plan |
| `ip.max_ips.pro` | `20` | Maximum IPs per request for pro plan |
| `domain.lookup_timeout` | `30s` | Overall timeout for all concurrent lookups per domain |
| `domain.max_domains.free` | `1` | Maximum domains per request for free plan |
| `domain.max_domains.pro` | `20` | Maximum domains per request for pro plan |
| `subdomain.max_domains.free` | `1` | Maximum domains per request when `subdomains: true` (free plan) |
| `subdomain.max_domains.pro` | `5` | Maximum domains per request when `subdomains: true` (pro plan) |
| `rate_limit.free` | `5` | Requests per minute for free plan customers |
| `rate_limit.pro` | `120` | Requests per minute for pro plan customers |
| `postgres.host` | `localhost` | PostgreSQL host |
| `postgres.port` | `5432` | PostgreSQL port |
| `postgres.user` | `intelligence` | PostgreSQL user |
| `postgres.password` | `intelligence` | PostgreSQL password |
| `postgres.dbname` | `intelligence_api` | PostgreSQL database name |
| `postgres.sslmode` | `require` | PostgreSQL SSL mode (`disable` for local dev) |
| `postgres.max_open_conns` | `25` | Maximum open database connections |
| `postgres.max_idle_conns` | `5` | Maximum idle database connections |
| `postgres.conn_max_lifetime` | `5m` | Maximum connection lifetime |
| `postgres.conn_max_idle_time` | `2m` | Maximum idle time before connection is closed |
| `pushover.api_token` | `""` | Pushover application API token (enables alerting) |
| `pushover.user_key` | `""` | Pushover user key (enables alerting) |
| `alerts.throttle_threshold` | `5` | Per-lookup failures to trigger throttle alert |
| `alerts.throttle_window` | `5m` | Time window for throttle detection |
| `alerts.spike_threshold` | `15` | Total errors across all lookups to trigger spike alert |
| `alerts.spike_window` | `5m` | Time window for spike detection |
| `alerts.cooldown` | `15m` | Minimum time between duplicate alerts |
| `alerts.max_concurrent_sends` | `5` | Maximum concurrent notification goroutines |
| `alerts.max_window_size` | `1000` | Maximum error timestamps tracked per sliding window |
| `stripe.secret_key` | `""` | Stripe secret key (enables billing) |
| `stripe.webhook_secret` | `""` | Stripe webhook signing secret |
| `stripe.prices.pro_monthly` | `""` | Stripe Price ID for pro monthly plan |
| `stripe.payment_link.pro` | `""` | Stripe Payment Link URL for pro plan |
| `stripe.portal_link` | `""` | Stripe Customer Portal URL for subscription management |
| `billing.stale_key_days` | `365` | Days of inactivity before key deactivation |
| `billing.cleanup_interval` | `10m` | Sweep cadence for expired provisioned keys |
| `usage.buffer_size` | `256` | Channel buffer size for async usage logging |
| `usage.flush_interval` | `5s` | How often buffered usage entries are flushed to PostgreSQL |

### Database Setup

The `migrations/` directory contains SQL files that are automatically applied when using Docker Compose (mounted to `/docker-entrypoint-initdb.d/`). **Note:** PostgreSQL's `initdb` only runs these scripts on first volume creation. For existing databases (including production on Neon), new migrations must be applied manually via `psql`.

- `001_create_api_keys.sql` — creates the `customers`, `api_keys`, and `customer_roles` tables
- `002_add_customer_tier.sql` — adds the `tier` column to `customers`
- `003_hash_api_keys.sql` — replaces the plaintext `key` column with `key_hash` (SHA-256, hex-encoded)
- `004_rename_roles_to_features.sql` — renames `customer_roles` to `customer_features`
- `005_fingerprint_rules.sql` — creates the `fingerprint_rules` table (append-only, JSONB rules column)
- `006_features_to_plan.sql` — replaces `tier` + `customer_features` with a single `plan` column
- `007_billing.sql` — adds `email`, `stripe_customer_id` to customers; `last_used_at` to api_keys; creates `provisioned_keys` table
- `008_request_log.sql` — creates the `request_log` table for usage tracking (indexed on `created_at`, `customer_id`, `api_key_id`)
- `009_request_log_threat_intel.sql` — adds `threat_intel` column to the `request_log` table
- `010_drop_name_unique.sql` — drops the unique constraint on `customers.name` (allows same-name Stripe signups)
- `011_request_log_ip.sql` — adds `ip_count` column to `request_log` for IP lookup analytics
- `012_key_rotation.sql` — drops the one-key-per-customer constraint and adds `api_keys.expires_at` for self-service rotation
- `013_request_log_dns_security.sql` — adds `dns_security` column to `request_log`
- `014_request_log_cache_metrics.sql` — replaces the per-request `cache_hit` boolean with `cache_hits`/`cache_misses` counts, and adds `whois`/`dns`/`ssl`/`headers`/`risk` columns now that the base lookups and the risk score are individually selectable
- `015_request_log_ip_lookups.sql` — adds `geo`/`asn`/`reverse_dns`/`abuse_contact` columns now that IP lookups are individually selectable
- `016_drop_request_log_cache_hit.sql` — drops the superseded `cache_hit` column. **Apply only after a build that no longer writes it (v0.55.0+) is deployed** — see below
- `017_merge_basic_into_pro.sql` — moves any `basic` customer to `pro` and resets the `plan` column default from `basic` to `free`. **Apply before deploying the build that removes the plan (v0.73.0+)** — a surviving `basic` row is an unrecognized plan to that build and reads as `free` until this runs
- `seed.sql` — inserts test customers (admin, pro, free) with hashed keys

API keys are stored as SHA-256 hashes. When inserting a key manually, hash it first:

```sql
INSERT INTO customers (name, plan) VALUES ('Acme Corp', 'pro');
INSERT INTO api_keys (customer_id, key_hash)
    VALUES (1, encode(digest('my-secret-key', 'sha256'), 'hex'));
```

### Run with Docker (recommended)

Build and run the full stack locally:

```sh
docker compose up --build
```

This starts the API, Redis, and PostgreSQL. The API is available at `http://localhost:8080`. The migration and seed files run automatically on first start.

### Run from GitHub Container Registry

On any machine with Docker — no code checkout needed:

```sh
docker login ghcr.io -u <github-username>
```

Create a `migrations/` directory with the SQL files from the repository (see `migrations/` in the source), then create a `docker-compose.yml`:

```yaml
services:
  api:
    image: ghcr.io/security-accelerated/intelligence-api:main
    ports:
      - "8080:8080"
    depends_on:
      - redis
      - postgres
  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: intelligence
      POSTGRES_PASSWORD: intelligence
      POSTGRES_DB: intelligence_api
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d

volumes:
  redis-data:
  postgres-data:
```

Then run:

```sh
docker compose up
```

### Run without Docker

Start Redis and PostgreSQL:

```sh
docker compose up -d redis postgres
```

Build and run:

```sh
make        # runs tests, then builds
make run    # builds and starts the server
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make` | Run unit tests, then build |
| `make build` | Compile the server binary to `bin/` |
| `make build-cli` | Compile the `sactl` admin CLI to `bin/` |
| `make install-cli` | Install `sactl` onto `PATH` (`GOBIN`, or `GOPATH/bin`) |
| `make deps` | Update all dependencies (`go get -u`) and tidy go.mod |
| `make test` | Run unit tests with race detector |
| `make test-integration` | Run integration tests |
| `make test-all` | Run unit + integration tests with pass/fail summary |
| `make run` | Build and run the server |
| `make clean` | Remove build artifacts |
| `make release V=v0.1.0` | Tag and push a release |
| `make deploy` | Deploy to Fly.io with git version baked in |
| `make docker-reset` | **Dev only.** Tear down containers, wipe volumes, rebuild, and wait for healthy startup. The wait is bounded by `RESET_TIMEOUT` (default 300s), after which it names the dependency that never came up |
| `./scripts/smoke-test.sh [host]` | Hit every endpoint with every key/plan combo and check expected status codes. Defaults to `http://localhost:8080` |
| `./scripts/status.sh` | Check Fly.io deployment health, Postgres, and Redis status |
| `./scripts/info.sh [host]` | Pretty-print the `/v1/info` admin endpoint. Defaults to production |

## Production Deployment

The API is deployed on **Fly.io** with **Neon** (PostgreSQL) and **Upstash** (Redis).

### CI/CD

- **Pull requests** — `test.yml` runs gofmt, vet, lint on new findings, unit tests with `-race`, and integration tests
- **Push to `main`** — `docker.yml` builds and pushes an image to GHCR
- **`v*` tag** — `fly-deploy.yml` runs the tests, builds the image with the version baked in, and deploys it to Fly.io. **The tag is the deploy.** The deploy job runs in the `production` GitHub environment, which requires a reviewer, so the run pauses at "Review deployments" after the tests until it is approved. Re-running it with `workflow_dispatch` and an existing tag redeploys that version, which is the rollback path, through the same approval
- **Uptime monitor** — `uptime.yml` pings `/v1/health` every 5 minutes and sends a Pushover alert on failure

Every third-party action is pinned to a commit SHA, with the version in a trailing comment. Dependabot opens a PR when a pinned action has a new release.

### Deployment workflow

A release is a `v*` tag on `main`, created with `make release`. The full procedure, including the changelog entry and the rollback path, is in `RELEASE.md`.

```sh
make release V=v0.X.Y             # tag main and push the tag; the tag is the deploy, gated on the production reviewer
```

### Environment variables (Fly secrets)

| Variable | Description |
|----------|-------------|
| `POSTGRES_URL` | Complete PostgreSQL connection string. Takes precedence over the individual `POSTGRES_*` settings below. Prefer it with managed providers: their URLs carry parameters in the query string (endpoint IDs, channel binding, pooler options) that are lost when the URL is split into parts and reassembled, which then fails as an authentication error rather than as missing configuration |
| `POSTGRES_HOST` | Neon PostgreSQL host |
| `POSTGRES_PORT` | PostgreSQL port (5432) |
| `POSTGRES_USER` | PostgreSQL user |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `POSTGRES_DBNAME` | PostgreSQL database name |
| `POSTGRES_SSLMODE` | PostgreSQL SSL mode (`require` for production) |
| `REDIS_ADDR` | Upstash Redis host:port |
| `REDIS_PASSWORD` | Upstash Redis password |
| `GIN_MODE` | Gin framework mode (`release` for production) |
| `APPLICATION_MODE` | Application mode (`production`) |
| `PUSHOVER_API_TOKEN` | Pushover app API token (enables alerting) |
| `PUSHOVER_USER_KEY` | Pushover user key (enables alerting) |
| `ALERTS_THROTTLE_THRESHOLD` | Per-lookup failure threshold (default: 5) |
| `ALERTS_SPIKE_THRESHOLD` | Global error spike threshold (default: 15) |
| `ALERTS_COOLDOWN` | Cooldown between duplicate alerts (default: 15m) |
| `STRIPE_SECRET_KEY` | Stripe secret key (enables billing) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `STRIPE_PRICES_PRO_MONTHLY` | Stripe Price ID for pro monthly plan |
| `STRIPE_PAYMENT_LINK_PRO` | Stripe Payment Link URL for pro plan |
| `STRIPE_PORTAL_LINK` | Stripe Customer Portal URL for subscription management |
| `USAGE_BUFFER_SIZE` | Channel buffer size for async usage logging (default: 256) |
| `USAGE_FLUSH_INTERVAL` | Flush interval for usage batch inserts (default: 5s) |
| `THREAT_INTEL_VIRUSTOTAL_API_KEY` | VirusTotal API key (enables VirusTotal threat intel provider) |
| `THREAT_INTEL_ALIENVAULT_API_KEY` | AlienVault OTX API key (enables AlienVault threat intel provider) |
| `GEOIP_DB_PATH` | Directory for the GeoIP database file (default: `/data/geoip`). No key is needed; the database downloads on first boot |
| `IP_LOOKUP_TIMEOUT` | Timeout for IP intelligence lookups (default: 30s) |
| `IP_MAX_IPS_FREE` | Max IPs per request for free plan (default: 1) |
| `IP_MAX_IPS_PRO` | Max IPs per request for pro plan (default: 20) |

### Admin CLI (`sactl`)

`sactl` is the operator CLI. It goes through the same packages the server does,
so it cannot disagree with the running service about key format, hashing, plan
names, or key-rotation grace semantics — the failure mode of doing this by hand
in `psql` is a key stored unhashed, which simply never authenticates and reports
no error explaining why.

```sh
make build-cli          # bin/sactl
make install-cli        # onto PATH
go run ./cmd/sactl      # or just run it from source
```

Run it with **no arguments for an interactive menu**, or pass a command for
scripted and CI use:

```sh
sactl                                        # interactive menu
sactl lookup domain example.com --lookups dns,ssl,risk
sactl lookup ip 8.8.8.8 --lookups all
sactl customer list
sactl customer create --name "Acme" --plan pro --email ops@acme.com
sactl customer plan --id 12 --plan pro
sactl customer rename --id 12 --name "Acme Corp"
sactl key list --customer 12
sactl key rotate --customer 12
sactl status
sactl info --json
sactl usage --days 7 --customer 12
```

Commands that change **deployed** state additionally require **`--allow-writes`**:

```sh
sactl customer create --name Acme --plan pro
# sactl: writes are disabled: refusing to create customer "Acme".
#        Re-run with --allow-writes to permit changes

sactl --allow-writes customer create --name Acme --plan pro
```

Read-only inspection is the common case, often against production and often in
a hurry, and the mutating commands sit one word away from the read-only ones
(`customer list` vs `customer plan`). The flag makes every change a decision
taken before the command is composed rather than one confirmed after it is
typed. It works in any position, including `sactl --allow-writes` on its own to
start the menu with changes enabled.

### Smoke test keys

`./scripts/smoke-test.sh` runs every lookup against every plan, so it needs one
key per plan. The rate limiter is **per key per minute** and free allows 5, so
free-plan keys are **pooled and rotated** — one key alone makes a full run spend
minutes waiting out windows. Numbered siblings are picked up automatically:

| Variable | Purpose |
|---|---|
| `SMOKE_ADMIN_KEY` / `SMOKE_PRO_KEY` / `SMOKE_FREE_KEY` | One per plan |
| `SMOKE_FREE_KEY_2`, `_3`, … | Extra free keys, pooled round-robin |
| `SMOKE_FREE_KEYS` | Comma-separated alternative to the numbered form |
| `SMOKE_RATELIMIT_KEY` | A free key **reserved** for the rate limit check and held out of the pool |

`SMOKE_RATELIMIT_KEY` is separate because that check has to exhaust one key's
window, which is the opposite of what the pool is for: rotating would spread the
load and never reach the limit, and reusing a pooled key would stall whichever
later check drew it. Without it, the check is skipped rather than run wrongly.
Against a local stack the seeded dev keys from `migrations/seed.sql` are used
automatically, including the reserved one.

Mint more with the CLI itself:

```sh
sactl --allow-writes customer create --name "Smoke Free 4" --plan free
```

Every command reads `./.env` first, so credentials kept there work with no extra
setup; `--env-file` points elsewhere. **Do not `source` that file** — connection
strings contain `&`, which the shell treats as a background operator and
truncates the value at. `sactl` parses it properly instead.

The database connection is taken from `--database-url`, then `POSTGRES_URL`,
`DATABASE_URL`, `NEON_CONNECTION_STRING`, then the individual `POSTGRES_*`
settings. Mutating commands print the target database and prompt before acting;
`--yes` skips the prompt, and a non-interactive stdin without `--yes` is refused
rather than assumed to mean yes.

Copy `.env.example` to `.env` and fill in your keys:

```sh
cp .env.example .env
```

### Scripts

The shell scripts are the source of truth for the smoke test and the local
docker reset; the rest overlap with `sactl` commands. They load API keys from
`.env` the same way.

```sh
./scripts/smoke-test.sh https://api.securityaccelerated.com
./scripts/docker-reset.sh                                     # or: make docker-reset
./scripts/status.sh                                           # or: sactl status
./scripts/info.sh                                             # or: sactl info
./scripts/usage.sh 30                                         # or: sactl usage --days 30
```

## Alerting

The API sends Pushover notifications when upstream lookup services start failing. Set `PUSHOVER_API_TOKEN` and `PUSHOVER_USER_KEY` to enable.

Two alert types:

- **Upstream throttle** — a single lookup type (e.g., WHOIS, DNS) fails repeatedly within a time window (default: 5 failures in 5 minutes)
- **Error spike** — total lookup errors across all types exceed a threshold (default: 15 errors in 5 minutes)

Alerts include a cooldown period (default: 15 minutes) to prevent alert fatigue. When credentials are not configured, alerting is silently disabled.

Additionally, a GitHub Actions workflow monitors uptime by pinging the API every 5 minutes and sending a Pushover alert on failure.

## Billing

Self-service billing via Stripe. Customers click a Stripe Payment Link on the docs page, pay through Stripe Checkout, and receive an API key on a one-time success page.

### Flow

1. Customer visits docs at `/`, clicks the Pro Payment Link
2. Stripe hosts the checkout — no card numbers touch our servers
3. On payment, Stripe sends a `checkout.session.completed` webhook to `POST /billing/webhook`
4. Webhook handler creates customer + API key in DB, stores raw key temporarily in `provisioned_keys`
5. Stripe redirects to `GET /billing/success?session_id={CHECKOUT_SESSION_ID}`
6. Success page shows the API key once, warns to save it, marks as retrieved (1-hour expiry)

### Subscription lifecycle

- **Plan change** (`customer.subscription.updated`): maps Stripe Price ID to plan name, updates customer
- **Cancellation** (`customer.subscription.deleted`): downgrades to free
- **Payment failure** (`invoice.payment_failed`): downgrades to free
- Auth cache is invalidated after any plan change
- Pushover notifications are sent for all billing events (new signup, plan change, cancellation, payment failure)

### Subscription management

Customers can manage their subscription (cancel, update payment method) via the Stripe Customer Portal. The portal link is shown on the docs page and checkout success page when `STRIPE_PORTAL_LINK` is configured.

### Stale key cleanup

`api_keys.last_used_at` is updated on auth cache-miss lookups, batched through `auth.LastUsedBatcher` (a buffered channel flushed to PostgreSQL on an interval — see `auth.last_used_buffer_size` and `auth.last_used_flush_interval`). Keys unused for 12 months (configurable via `billing.stale_key_days`) can be deactivated via the billing repository's `DeactivateStaleKeys` method.

### Configuration

Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` to enable. Without them, the app starts with a noop billing service. Map Stripe Price IDs to plans via `STRIPE_PRICES_PRO_MONTHLY`. Configure the Payment Link URL via `STRIPE_PAYMENT_LINK_PRO` to show the subscribe button on the docs page. Set `STRIPE_PORTAL_LINK` to show a "Manage subscription" link on the docs and success pages.

## Testing

```sh
make test                # unit tests with race detector
make test-integration    # integration tests (in-memory Redis, stub auth)
make test-all            # both unit + integration with pass/fail summary
```
