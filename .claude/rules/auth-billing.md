---
paths:
  - "internal/auth/**"
  - "internal/billing/**"
  - "internal/usage/**"
  - "internal/adminops/**"
  - "cmd/sactl/**"
  - "internal/handler/keys.go"
  - "internal/handler/billing.go"
  - "internal/handler/usage.go"
  - "migrations/**"
---

# Auth, plans, billing, usage, and the operator CLI

## API keys

Stored as `hex(sha256(key))`, never plaintext. The auth middleware hashes the incoming key
and looks it up. `CachedRepository` wraps PostgreSQL with an in-memory TTL cache keyed by
hash (`RWMutex`); the admin endpoint invalidates it after plan changes. `last_used_at` is
updated on cache-miss lookups, batched by `auth.LastUsedBatcher`.

**Rotation** — `POST /v1/keys/rotate` (any authenticated customer) issues a new key and
grace-expires all previous ones (`auth.rotation_grace`, default 24h). Migration 012 dropped
the one-key-per-customer constraint and added `api_keys.expires_at`; the auth lookup
filters expired keys and `DeactivateStaleKeys` only deactivates customers with no fresh
live key. `billing.KeyRotationService` depends only on the DB — it works without Stripe —
and invalidates the auth cache after rotating.

## Plans

One `plan` column on `customers`: `free`, `basic`, `pro`, `admin`. It controls rate limits
(free 5/min, basic 30/min, pro 120/min, admin unlimited), premium lookups (screenshot,
reputation, threat_intel), and admin routes via `RequireAdmin()`. Free plan: 1 domain per
request. The lookup→plan tables live with the handlers (see the lookups rule), not here.

## Stripe — `internal/billing`

Interface + real impl + noop, same pattern as notifications. `Service` has `HandleWebhook`
and `GetProvisionedKey`. `StripeService` verifies webhook signatures, handles checkout /
subscription / payment events, and provisions keys. `NoopService` returns "billing not
configured".

Provisioning on checkout: generate a key (`keygen.go`, 64-char hex from `crypto/rand`),
store the hash in `api_keys`, store the raw key in `provisioned_keys` for **one-time**
retrieval (1h expiry) — the plaintext is blanked in the same statement that marks the row
retrieved, and a startup goroutine sweeps expired rows every `billing.cleanup_interval`
(10m). Auth cache is invalidated on any plan change. Billing events fan out to the
`Notifier` asynchronously. The Customer Portal link (`STRIPE_PORTAL_LINK`) is shown on the
docs and success pages. Config: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`,
`STRIPE_PRICES_BASIC_MONTHLY`, `STRIPE_PRICES_PRO_MONTHLY`, `STRIPE_PAYMENT_LINK_BASIC`,
`STRIPE_PAYMENT_LINK_PRO`, `STRIPE_PORTAL_LINK`, `BILLING_STALE_KEY_DAYS`.

## Usage — `internal/usage`

`Recorder` accepts `UsageEntry`; `Queryer` returns `UsageSummary`, and `QueryService` runs
the aggregation SQL behind it. `UsageLogger` buffers on a channel and batch-inserts to
`request_log` every 5s or 50 entries; a full channel drops with a warning. `NoopRecorder`
discards entries when tracking isn't wanted (tests). `request_log` rows carry per-request
metadata including `domain_count`, `ip_count`, and a per-feature flag per lookup. The `UsageLog()` middleware runs after `c.Next()` and reads the
`lookups_requested`, `cache_hits`, `cache_misses` context keys the handlers set.

Two rules a drift test enforces:

- `feature_usage` counts **requested** lookups, however served. `cache_hits` /
  `cache_misses` are separate per-lookup counters on `request_log`.
- `usage.LookupColumns` mirrors `domain.AllLookupNames` and the `request_log` schema. A new
  lookup needs a column and a migration or CI fails — that is the intended failure.

Admin endpoint: `GET /v1/admin/usage?days=30&customer_id=X&api_key_id=Y`. Config:
`USAGE_BUFFER_SIZE`, `USAGE_FLUSH_INTERVAL`.

## Operator CLI — `cmd/sactl`

Interactive menu with no args, flags otherwise; both call the same `run*` functions. It
reuses the server's own packages — `billing.GenerateAPIKey`, `auth.HashKey`, `auth.Plans`,
`billing.KeyRotationService` — because hand-administering in `psql` is where silent
failures live. `internal/adminops` holds its SQL rather than reusing
`billing.ProvisionCustomer`, which is Stripe-shaped and would store a second retrievable
copy of the key.

- **Anything that changes deployed state needs `--allow-writes`**, enforced by
  `requireWrites` at each mutation site. Do not replace that with a field on the command.
- Lookups go through the HTTP API as a customer's would; the CLI imports `internal/domain`
  only for lookup *name* constants.
- Credentials come from `./.env`, **parsed by the CLI, not sourced** — connection strings
  contain `&`. Mutating commands print the target DB (credentials stripped) and prompt;
  `--yes` skips it; non-interactive stdin without `--yes` is refused.
- The smoke test and docker reset are deliberately **not** in the CLI. `scripts/*.sh` are
  the single source of truth for both.

## Database

Tables: `customers`, `api_keys`, `fingerprint_rules` (append-only JSONB),
`provisioned_keys`, `request_log`. Migrations in `migrations/`. Docker `initdb` runs them
only on first volume creation; production (Neon) migrations are applied by hand with
`psql "$NEON_CONNECTION_STRING"`. **A release does not apply migrations** — see
`RELEASE.md`.
