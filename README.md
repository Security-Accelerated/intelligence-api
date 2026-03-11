# Security Accelerated
## Intelligence API

A domain intelligence API that performs concurrent WHOIS, DNS, SSL, HTTP header, page screenshot, reputation, email security, subdomain enumeration, certificate transparency, BGP/ASN, and technology fingerprinting lookups for one or more domains, with Redis caching.

**Production URL:** `https://api.securityaccelerated.com`

## Authentication

All endpoints except `/v1/hello` require an API key passed via the `X-API-Key` header. Keys are stored in PostgreSQL and belong to a customer. Each customer has one API key and a plan.

### Customer Plans

Each customer has a `plan` that controls rate limits, access to premium options, and admin access:

| Plan | Capabilities |
|------|-------------|
| `basic` | Standard domain lookups (WHOIS, DNS, SSL, headers) + email security (SPF/DKIM/DMARC) + subdomain enumeration + CT logs + BGP/ASN + technology fingerprinting |
| `pro` | All basic capabilities + page screenshots + reputation checks |
| `admin` | All pro capabilities + admin endpoints (info, fingerprint management, cache invalidation) + no rate limit |

The plan is stored in the `customers` table. New customers default to `basic`.

Requests without a valid key receive `401 Unauthorized`. Requests from non-admin plans to admin-only endpoints receive `403 Forbidden`. Basic plan requests for pro-only options (screenshot, reputation) receive `403 Forbidden`. The `/v1/hello` health check requires no authentication.

### Rate Limiting

All authenticated endpoints are rate-limited per API key using a sliding-window counter backed by Redis. Admin plan bypasses rate limiting entirely. Limits are configurable per plan:

| Plan | Default Limit |
|------|---------------|
| `basic` | 30 requests/minute |
| `pro` | 120 requests/minute |
| `admin` | No limit |

Every response includes rate limit headers:
- `X-RateLimit-Limit` — the maximum requests allowed per minute
- `X-RateLimit-Remaining` — how many requests remain in the current window

When the limit is exceeded, the API returns `429 Too Many Requests` with a `Retry-After` header indicating seconds until the current window resets. If Redis is unavailable, rate limiting fails open (requests are allowed).

## API Endpoints

| Method | Path | Plan | Description |
|--------|------|------|-------------|
| GET | `/v1/hello` | None | Health check, returns `{"message": "hello world"}` |
| GET | `/v1/info` | `admin` | Application and environment info |
| POST | `/v1/domain/lookup` | All plans | Domain intelligence lookup |
| POST | `/v1/admin/auth/cache/invalidate` | `admin` | Invalidate the in-memory auth cache |
| GET | `/v1/admin/fingerprints` | `admin` | Get technology fingerprint rules |
| POST | `/v1/admin/fingerprints` | `admin` | Update technology fingerprint rules |

### POST /v1/domain/lookup

**Request:**
```json
{
  "domains": ["example.com", "example.org"],
  "screenshot": true,
  "reputation": true,
  "email_security": true,
  "subdomains": true,
  "ct_logs": true,
  "bgp": true,
  "fingerprint": true
}
```

The `domains` field accepts an array of domain names. Each entry accepts raw domains, URLs with `http://`/`https://` prefixes, and trailing slashes — all are normalized automatically. Domains are looked up concurrently.

The optional `screenshot` field (default `false`) requests a page screenshot for each domain. This requires a **pro** or **admin** plan — basic plan customers receive `403 Forbidden`.

The optional `reputation` field (default `false`) checks each domain against multiple DNS-based blocklists concurrently (Spamhaus DBL, SURBL, URIBL, Spamhaus ZEN) and returns a computed risk score. This requires a **pro** or **admin** plan — basic plan customers receive `403 Forbidden`.

The optional `email_security` field (default `false`) checks SPF, DMARC, and DKIM records for each domain via DNS lookups. Available to **all plans**. DKIM probes 8 common selectors (`google`, `default`, `selector1`, `selector2`, `k1`, `s1`, `mail`, `dkim`).

The optional `subdomains` field (default `false`) enumerates subdomains via Certificate Transparency logs (crt.sh). Available to **all plans**. Results are deduplicated, wildcards are filtered, and a hard cap (default 500, configurable via `subdomain.max_results`) prevents unbounded results.

The optional `ct_logs` field (default `false`) queries Certificate Transparency logs via crt.sh for all certificates ever issued for the domain. Returns full certificate metadata (issuer, dates, serial number, SANs). Available to **all plans**. Results are deduplicated by serial number, sorted newest-first, and capped (default 100, configurable via `ct_logs.max_entries`).

The optional `bgp` field (default `false`) resolves the domain's IP addresses and queries Team Cymru's DNS-based IP-to-ASN mapping service for BGP/ASN information. Returns ASN number, IP prefix, country, registry, and organization name. Available to **all plans**. Useful for identifying hosting providers and detecting bulletproof hosting.

The optional `fingerprint` field (default `false`) detects web technologies (servers, frameworks, CDNs, CMS platforms, languages) from HTTP response headers. No extra HTTP requests are made — detection piggybacks on the headers already fetched. Returns technology name, category, version (when detectable), and which signal matched. Available to **all plans**. Rules are stored in PostgreSQL and can be updated via the admin API without redeploying.

**Example:**
```sh
curl -X POST http://localhost:8080/v1/domain/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: test-admin-key' \
  -d '{"domains":["example.com"]}'
```

**Response:**
```json
[
  {
    "domain": "example.com",
    "cache_hit": false,
    "whois": { "domain_name": "...", "registrar": "...", "..." : "..." },
    "dns": { "a": ["93.184.216.34"], "mx": [], "ns": [], "..." : "..." },
    "ssl": { "subject": "...", "issuer": "...", "..." : "..." },
    "headers": { "status_code": 200, "headers": {}, "security_headers": {} },
    "screenshot": { "status_code": 200, "png": "<base64-encoded PNG>" },
    "reputation": {
      "score": 35,
      "risk": "medium",
      "providers": [
        { "listed": true, "category": "phishing", "provider": "spamhaus_dbl", "return_code": "127.0.1.4" },
        { "listed": false, "provider": "surbl" },
        { "listed": false, "provider": "uribl" },
        { "listed": false, "provider": "spamhaus_zen" }
      ]
    },
    "email_security": {
      "spf": {
        "raw": "v=spf1 include:_spf.google.com -all",
        "version": "spf1",
        "mechanisms": ["include:_spf.google.com"],
        "all": "-all"
      },
      "dmarc": {
        "raw": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        "version": "DMARC1",
        "policy": "reject",
        "rua": "mailto:dmarc@example.com"
      },
      "dkim": [
        { "selector": "google", "found": true, "raw": "v=DKIM1; k=rsa; p=MIGf..." },
        { "selector": "default", "found": false }
      ]
    },
    "subdomains": {
      "count": 3,
      "capped": false,
      "subdomains": [
        { "domain": "api.example.com", "source": "crt.sh" },
        { "domain": "mail.example.com", "source": "crt.sh" },
        { "domain": "www.example.com", "source": "crt.sh" }
      ]
    },
    "ct_logs": {
      "count": 2,
      "capped": false,
      "entries": [
        {
          "logged_at": "2024-01-15T00:00:00",
          "not_before": "2024-01-15T00:00:00",
          "not_after": "2024-04-14T23:59:59",
          "issuer": "C=US, O=Let's Encrypt, CN=R3",
          "common_name": "example.com",
          "name_value": "example.com",
          "serial": "04:3a:f5:..."
        }
      ]
    },
    "bgp": {
      "records": [
        {
          "ip": "93.184.216.34",
          "asn": 15133,
          "prefix": "93.184.216.0/24",
          "country": "US",
          "registry": "arin",
          "description": "EDGECAST, US"
        }
      ]
    },
    "fingerprint": {
      "count": 2,
      "technologies": [
        { "name": "Nginx", "category": "web-server", "version": "1.24.0", "confidence": "header" },
        { "name": "PHP", "category": "language", "version": "8.2", "confidence": "header" }
      ]
    },
    "errors": []
  }
]
```

Invalid domains in a multi-domain request are included in the response with a validation error instead of failing the entire request:
```json
[
  { "domain": "example.com", "whois": {}, "dns": {}, "..." : "..." },
  { "domain": "notadomain", "errors": [{"lookup": "validation", "message": "invalid domain name"}] }
]
```

## Response Fields

### Domain Lookup (`/v1/domain/lookup`)

### `domain` / `cache_hit` / `errors`

- **`domain`** — Which domain this result is for, since you can submit multiple in one request.
- **`cache_hit`** — Whether the result was served from Redis cache (`true`) or fetched live (`false`). Useful for understanding data freshness.
- **`errors`** — Per-lookup errors when an individual lookup fails (e.g. WHOIS timed out but DNS succeeded). Partial failures don't block the rest of the response.

### `whois` — Domain Registration & Ownership

WHOIS tells you who owns a domain and when it expires.

| Field | What it means |
|-------|---------------|
| `domain_name` | The registered domain name |
| `registrar` | The company the domain was registered through (e.g. GoDaddy, Namecheap) |
| `created_date` | When the domain was first registered — newly created domains are often higher risk |
| `updated_date` | When the registration was last modified |
| `expiry_date` | When the registration expires — domains pending expiration or in redemption are red flags |
| `status` | EPP status codes like `clientTransferProhibited` that reveal lock state |
| `name_servers` | Which DNS provider is authoritative — changes here can indicate hijacking |
| `registrant` / `admin` / `tech` | Contact details (organization, country, email) that help attribute ownership, though often redacted behind WHOIS privacy |

### `dns` — Domain Name System Records

DNS is the internet's phone book. When you type a domain into a browser, your computer looks up the "phone number" (IP address) to connect to. Each record type serves a different purpose:

| Field | What it means |
|-------|---------------|
| `a` | The IPv4 addresses (like `93.184.216.34`) the domain points to. This is the most fundamental record — it's the actual address a browser connects to. A domain can have multiple A records to spread traffic across servers. |
| `aaaa` | Same as A records but for the newer IPv6 format (like `2606:2800:220:1:248:1893:25c8:1946`). IPv4 addresses are running out, so IPv6 provides a vastly larger address space. |
| `mx` | Mail Exchange records — where to deliver email for that domain. If you send email to `someone@example.com`, the sending server looks up MX records to find the right mail server. The `priority` number determines the order: lower numbers get tried first, higher numbers are backups. |
| `ns` | Name Server records — the authoritative source of truth for all DNS records on this domain. Think of it as "which phone book is the official one." Whoever controls the nameservers controls where the domain points, so unauthorized changes here mean an attacker can redirect all traffic. |
| `txt` | Free-form text entries that have become critical for email security: **SPF** (which servers can send email for this domain), **DKIM** (a public key to verify emails weren't tampered with in transit), **DMARC** (what to do when emails fail SPF/DKIM checks), and **verification tokens** that services use to prove domain ownership. |
| `cname` | Canonical Name — an alias that points to another domain instead of an IP address, like call forwarding. Often used to route traffic through CDNs like Cloudflare or AWS CloudFront. A "dangling CNAME" pointing to an unclaimed service is a known vulnerability — an attacker could claim that service and serve content on your domain. |

### `ssl` — TLS Certificate

SSL/TLS is what puts the padlock in your browser's address bar. This section shows the HTTPS certificate the server presents.

| Field | What it means |
|-------|---------------|
| `subject` | The entity the certificate was issued to |
| `issuer` | Which Certificate Authority issued it (e.g. Let's Encrypt vs. a paid CA) |
| `not_before` / `not_after` | The certificate's validity window |
| `expired` | Whether the certificate has expired — expired certs break browser trust |
| `days_until_expiry` | How many days remain — low values signal maintenance risk |
| `sans` | Subject Alternative Names — all hostnames the cert covers, which reveals related subdomains and services sharing infrastructure |
| `serial_number` | Unique identifier for the certificate |
| `signature_algorithm` | The cryptographic algorithm used (e.g. SHA-256); weaker algorithms like SHA-1 are deprecated |

### `headers` — HTTP Response & Security Headers

This section shows how the web server responds and what browser security policies it enforces.

| Field | What it means |
|-------|---------------|
| `status_code` | Whether the domain serves content (200), redirects (301/302), or is down (5xx) |
| `headers` | Raw response headers that can reveal server software, caching behavior, and CDN info |

The `security_headers` subsection audits defensive headers that protect users:

| Header | What it does |
|--------|--------------|
| `strict_transport_security` | Forces HTTPS — without it, connections can be downgraded to unencrypted HTTP |
| `content_security_policy` | Controls what resources (scripts, images, etc.) can load on the page — the primary defense against cross-site scripting (XSS) |
| `x_frame_options` | Prevents the page from being embedded in an iframe on another site — stops clickjacking attacks |
| `x_content_type_options` | Prevents the browser from guessing file types — stops MIME-sniffing attacks |
| `x_xss_protection` | Legacy browser XSS filter (mostly deprecated but still checked in audits) |
| `referrer_policy` | Controls how much URL information leaks when users click links to other sites |
| `permissions_policy` | Restricts browser features like camera, microphone, and geolocation |

### `screenshot` — Page Screenshot (Pro/Admin Only)

A visual screenshot of the domain's web page, captured with headless Chrome at 1280x720. Only present when `"screenshot": true` is included in the request.

| Field | What it means |
|-------|---------------|
| `status_code` | The HTTP status code from probing the domain. The screenshot only captures the page on `200 OK`. |
| `png` | Base64-encoded PNG image of the page. Empty for non-200 responses. |

The screenshot lookup first tries HTTPS, then falls back to HTTP. Non-200 responses still populate the `screenshot` section with the status code but no image data.

### `reputation` — Domain Reputation (Pro/Admin Only)

Checks the domain against 4 DNS-based blocklists concurrently and computes a risk score. Only present when `"reputation": true` is included in the request.

| Field | What it means |
|-------|---------------|
| `score` | Computed risk score from 0 (clean) to 100 (maximum risk) |
| `risk` | Risk level: `clean` (0), `low` (1–29), `medium` (30–59), `high` (60–100) |
| `providers` | Array of per-provider results |

Each provider entry contains:

| Field | What it means |
|-------|---------------|
| `listed` | Whether the domain appears on this blocklist |
| `category` | The classification if listed (varies by provider) |
| `provider` | Which blocklist was queried |
| `return_code` | The raw DNS return code. Only present when listed. |

**Providers:**

| Provider | Type | Categories |
|----------|------|-----------|
| `spamhaus_dbl` | Domain blocklist | `spam`, `phishing`, `malware`, `botnet_cc`, `abused_spam`, `abused_spammed_redirector`, `abused_phishing`, `abused_malware`, `abused_botnet_cc` |
| `surbl` | Domain blocklist | `malware`, `abuse`, `cracked`, `suspicious` (bitmask — categories stack with `+`, e.g. `malware+abuse`) |
| `uribl` | Domain blocklist | `spam`, `grey`, `red` |
| `spamhaus_zen` | IP-based (resolves domain A records first) | `sbl_spam`, `xbl_exploits`, `pbl_policy` |

**Scoring:** Each provider listing adds points based on category severity. Multiple listings across providers stack. The score is capped at 100. Higher-trust, domain-specific providers (Spamhaus DBL) carry more weight than IP-based providers (Spamhaus ZEN).

### `email_security` — Email Security (All Plans)

Checks SPF, DMARC, and DKIM DNS records for the domain. Only present when `"email_security": true` is included in the request.

**`spf`** — Sender Policy Framework record:

| Field | What it means |
|-------|---------------|
| `raw` | The full SPF TXT record |
| `version` | SPF version (typically `spf1`) |
| `mechanisms` | Parsed mechanisms like `include:`, `ip4:`, `ip6:`, `a`, `mx` |
| `all` | Terminal qualifier: `-all` (hard fail), `~all` (soft fail), `?all` (neutral), `+all` (pass all — dangerous) |

**`dmarc`** — Domain-based Message Authentication, Reporting and Conformance:

| Field | What it means |
|-------|---------------|
| `raw` | The full DMARC TXT record at `_dmarc.<domain>` |
| `version` | DMARC version (typically `DMARC1`) |
| `policy` | What to do with failing mail: `none` (monitor), `quarantine` (spam folder), `reject` (drop) |
| `pct` | Percentage of messages the policy applies to (0–100) |
| `rua` | Aggregate report destination (e.g. `mailto:dmarc@example.com`) |
| `ruf` | Forensic report destination |
| `sp` | Subdomain policy override |

**`dkim`** — DomainKeys Identified Mail (probes 8 common selectors):

| Field | What it means |
|-------|---------------|
| `selector` | The DKIM selector name that was probed |
| `found` | Whether a DKIM record exists at `<selector>._domainkey.<domain>` |
| `raw` | The full DKIM TXT record (only when found) |

### `subdomains` — Subdomain Enumeration (All Plans)

Enumerates subdomains via Certificate Transparency logs (crt.sh). Only present when `"subdomains": true` is included in the request.

| Field | What it means |
|-------|---------------|
| `count` | Total number of subdomains returned |
| `capped` | Whether the results cap was hit (results truncated) |
| `subdomains` | Array of discovered subdomains |

Each subdomain entry contains:

| Field | What it means |
|-------|---------------|
| `domain` | The discovered subdomain |
| `source` | Data source (`crt.sh` — Certificate Transparency logs) |

### `ct_logs` — Certificate Transparency Logs (All Plans)

Queries Certificate Transparency logs via crt.sh for all certificates ever issued for the domain. Only present when `"ct_logs": true` is included in the request.

| Field | What it means |
|-------|---------------|
| `count` | Total number of certificate entries returned |
| `capped` | Whether the results cap was hit (results truncated) |
| `entries` | Array of certificate log entries, sorted newest-first |

Each entry contains:

| Field | What it means |
|-------|---------------|
| `logged_at` | When the certificate was logged to the CT log |
| `not_before` | Certificate validity start date |
| `not_after` | Certificate validity end date |
| `issuer` | Certificate Authority that issued the certificate |
| `common_name` | The CN field of the certificate |
| `name_value` | All names covered by the certificate (may include wildcards) |
| `serial` | Unique serial number of the certificate |

Useful for detecting phishing infrastructure (unexpected issuers), identifying related domains, and tracking certificate issuance patterns.

### `bgp` — BGP / ASN Enrichment (All Plans)

Resolves the domain's IP addresses and queries Team Cymru's DNS-based IP-to-ASN mapping service. Only present when `"bgp": true` is included in the request.

| Field | What it means |
|-------|---------------|
| `records` | Array of ASN records, deduplicated by ASN |

Each record contains:

| Field | What it means |
|-------|---------------|
| `ip` | The resolved IP address |
| `asn` | Autonomous System Number |
| `prefix` | IP prefix (CIDR notation) |
| `country` | Country code of the ASN registration |
| `registry` | Regional Internet Registry (arin, ripe, apnic, etc.) |
| `description` | Organization name and country |

Useful for identifying hosting providers, detecting bulletproof hosting, and pivot analysis. Multiple IPs sharing the same ASN are merged (only the first IP is shown).

### `fingerprint` — Technology Fingerprinting (All Plans)

Detects web servers, frameworks, CDNs, CMS platforms, and programming languages from HTTP response headers. Only present when `"fingerprint": true` is included in the request. No extra HTTP requests are made — detection uses the headers already fetched.

| Field | What it means |
|-------|---------------|
| `count` | Number of detected technologies |
| `technologies` | Array of detected technologies |

Each technology entry contains:

| Field | What it means |
|-------|---------------|
| `name` | Technology name (e.g. `Nginx`, `PHP`, `Cloudflare`) |
| `category` | Category: `web-server`, `language`, `framework`, `cdn`, `cms`, `analytics`, `security`, `hosting`, `cache`, `javascript`, `other` |
| `version` | Version extracted from header value (e.g. `nginx/1.24.0` → `1.24.0`), empty if not detectable |
| `confidence` | Which signal matched: `header` or `cookie` |

Rules are stored in PostgreSQL and loaded into memory at startup. The default ruleset covers ~90 technologies. Admin users can update rules via `POST /v1/admin/fingerprints` without redeploying.

## Caching

Lookup results are cached in Redis. Repeated lookups for the same domain return the cached result until the TTL expires. Each response includes a `cache_hit` field indicating whether the result was served from cache. The TTL is configurable via `redis.cache_ttl` (default `60m`).

Optional features use composite cache keys built from sorted feature suffixes. Each key is fully self-contained — all lookups for that feature combination are cached together:
- `domain` — base lookups (WHOIS, DNS, SSL, headers)
- `domain:email_security` — base + email security
- `domain:reputation` — base + reputation
- `domain:screenshot` — base + screenshot
- `domain:subdomains` — base + subdomain enumeration
- `domain:bgp` — base + BGP/ASN
- `domain:ct_logs` — base + CT logs
- `domain:fingerprint` — base + technology fingerprinting
- `domain:bgp+ct_logs+email_security+fingerprint+reputation+screenshot+subdomains` — base + all optional features

## Getting Started

### Prerequisites

- Go 1.26+
- Redis (or use the included Docker Compose)
- PostgreSQL (or use the included Docker Compose)
- Chromium or Google Chrome (for page screenshot feature; Docker image includes it)

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

Config values:

| Key | Default | Description |
|-----|---------|-------------|
| `application.mode` | `""` | `local` or `production` |
| `application.port` | `8080` | HTTP server port |
| `redis.addr` | `localhost:6379` | Redis address |
| `redis.password` | `""` | Redis password |
| `redis.db` | `0` | Redis database number |
| `redis.cache_ttl` | `60m` | Cache TTL for domain lookups |
| `gin.mode` | `""` | Gin framework mode (`debug`, `release`, `test`) |
| `auth.cache_ttl` | `5m` | TTL for in-memory auth cache |
| `screenshot.timeout` | `15s` | Timeout for page screenshot capture (probe + render) |
| `subdomain.max_results` | `500` | Maximum number of subdomains returned per domain |
| `ct_logs.max_entries` | `100` | Maximum number of CT log entries returned per domain |
| `domain.max_domains.basic` | `5` | Maximum domains per request for basic plan |
| `domain.max_domains.pro` | `20` | Maximum domains per request for pro plan |
| `subdomain.timeout` | `30s` | Timeout for subdomain enumeration |
| `subdomain.concurrency` | `20` | Max concurrent subdomain lookups |
| `subdomain.max_domains.basic` | `3` | Maximum domains per request for basic plan (subdomains) |
| `subdomain.max_domains.pro` | `5` | Maximum domains per request for pro plan (subdomains) |
| `rate_limit.basic` | `30` | Requests per minute for basic plan customers |
| `rate_limit.pro` | `120` | Requests per minute for pro plan customers |
| `postgres.host` | `localhost` | PostgreSQL host |
| `postgres.port` | `5432` | PostgreSQL port |
| `postgres.user` | `intelligence` | PostgreSQL user |
| `postgres.password` | `intelligence` | PostgreSQL password |
| `postgres.dbname` | `intelligence_api` | PostgreSQL database name |
| `postgres.sslmode` | `require` | PostgreSQL SSL mode (`disable` for local dev) |
| `pushover.api_token` | `""` | Pushover application API token (enables alerting) |
| `pushover.user_key` | `""` | Pushover user key (enables alerting) |
| `alerts.throttle_threshold` | `5` | Per-lookup failures to trigger throttle alert |
| `alerts.throttle_window` | `5m` | Time window for throttle detection |
| `alerts.spike_threshold` | `15` | Total errors across all lookups to trigger spike alert |
| `alerts.spike_window` | `5m` | Time window for spike detection |
| `alerts.cooldown` | `15m` | Minimum time between duplicate alerts |

### Database Setup

The `migrations/` directory contains SQL files that are automatically applied when using Docker Compose (mounted to `/docker-entrypoint-initdb.d/`).

- `001_create_api_keys.sql` — creates the `customers`, `api_keys`, and `customer_roles` tables
- `002_add_customer_tier.sql` — adds the `tier` column to `customers`
- `003_hash_api_keys.sql` — replaces the plaintext `key` column with `key_hash` (SHA-256, hex-encoded)
- `004_rename_roles_to_features.sql` — renames `customer_roles` to `customer_features`
- `005_fingerprint_rules.sql` — creates the `fingerprint_rules` table (append-only, JSONB rules column)
- `006_features_to_plan.sql` — replaces `tier` + `customer_features` with a single `plan` column (`basic`/`pro`/`admin`)
- `seed.sql` — inserts test customers (admin, basic, pro) with hashed keys

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
| `make build` | Compile the binary to `bin/` |
| `make test` | Run unit tests with race detector |
| `make test-integration` | Run integration tests |
| `make run` | Build and run the server |
| `make clean` | Remove build artifacts |
| `make release V=v0.1.0` | Tag and push a release |
| `make deploy` | Deploy to Fly.io with git version baked in |
| `make docker-reset` | **Dev only.** Tear down containers, wipe volumes, rebuild, and wait for healthy startup |
| `./scripts/smoke-test.sh [host]` | Hit every endpoint with every key/plan combo and check expected status codes. Defaults to `http://localhost:8080` |
| `./scripts/status.sh` | Check Fly.io deployment health, Postgres, and Redis status |

## Production Deployment

The API is deployed on **Fly.io** with **Neon** (PostgreSQL) and **Upstash** (Redis).

### CI/CD

- **Push to `main`** — GitHub Actions builds and pushes a Docker image to GHCR
- **Push to `release`** — GitHub Actions deploys to Fly.io with the git version baked in
- **Version tags** (`make release V=v0.X.Y`) — tags and pushes to trigger GHCR image builds
- **Uptime monitor** — GitHub Actions pings `api.securityaccelerated.com/v1/hello` every 5 minutes and sends a Pushover alert on failure

### Deployment workflow

```sh
git push origin main              # push changes
make release V=v0.X.Y             # tag the version
git push origin main:release      # trigger Fly deploy
```

### Environment variables (Fly secrets)

| Variable | Description |
|----------|-------------|
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

### Scripts

Both `smoke-test.sh` and `status.sh` load API keys from a `.env` file in the project root (gitignored). Copy `.env.example` to `.env` and fill in your keys:

```sh
cp .env.example .env
```

Run the smoke test against production:

```sh
./scripts/smoke-test.sh https://api.securityaccelerated.com
```

Check deployment health:

```sh
./scripts/status.sh
```

## Alerting

The API sends Pushover notifications when upstream lookup services start failing. Set `PUSHOVER_API_TOKEN` and `PUSHOVER_USER_KEY` to enable.

Two alert types:

- **Upstream throttle** — a single lookup type (e.g., WHOIS, DNS) fails repeatedly within a time window (default: 5 failures in 5 minutes)
- **Error spike** — total lookup errors across all types exceed a threshold (default: 15 errors in 5 minutes)

Alerts include a cooldown period (default: 15 minutes) to prevent alert fatigue. When credentials are not configured, alerting is silently disabled.

Additionally, a GitHub Actions workflow monitors uptime by pinging the API every 5 minutes and sending a Pushover alert on failure.

## Testing

```sh
make test                # unit tests
make test-integration    # integration tests (uses in-memory Redis, stub auth)
```
