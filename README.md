# Security Accelerated
## Intelligence API

A domain intelligence API that performs concurrent WHOIS, DNS, SSL, HTTP header, and page screenshot lookups for one or more domains, with Redis caching.

## Authentication

All endpoints except `/api/v1/hello` require an API key passed via the `X-API-Key` header. Keys are stored in PostgreSQL and belong to a customer. Each customer has one API key and can be assigned multiple roles.

### Customer Tiers

Each customer has a `tier` that controls access to premium features:

| Tier | Features |
|------|----------|
| `basic` | Standard domain lookups (WHOIS, DNS, SSL, headers) |
| `premium` | All basic features + page screenshots + typosquatting detection |

The tier is stored in the `customers` table. New customers default to `basic`.

### Roles

| Role | Access |
|------|--------|
| `admin` | All endpoints (`/hello`, `/info`, `/domain`, `/domain/typosquatting`) |
| `domain` | `POST /api/v1/domain` and `POST /api/v1/domain/typosquatting` |

A customer with both `admin` and `domain` roles has access to all endpoints. Requests without a valid key receive `401 Unauthorized`. Requests with a key whose customer lacks the required role receive `403 Forbidden`. The `/api/v1/hello` health check requires no authentication.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/hello` | None | Health check, returns `{"message": "hello world"}` |
| GET | `/api/v1/info` | `admin` | Application and environment info |
| POST | `/api/v1/domain` | `admin`, `domain` | Domain intelligence lookup |
| POST | `/api/v1/domain/typosquatting` | `admin`, `domain` | Typosquatting detection (premium) |
| POST | `/api/v1/admin/auth/cache/invalidate` | `admin` | Invalidate the in-memory auth cache |

### POST /api/v1/domain

**Request:**
```json
{
  "domains": ["example.com", "example.org"],
  "screenshot": true
}
```

The `domains` field accepts an array of domain names. Each entry accepts raw domains, URLs with `http://`/`https://` prefixes, and trailing slashes — all are normalized automatically. Domains are looked up concurrently.

The optional `screenshot` field (default `false`) requests a page screenshot for each domain. This requires a **premium** tier customer — basic tier customers receive `403 Forbidden`.

**Example:**
```sh
curl -X POST http://localhost:8080/api/v1/domain \
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

### POST /api/v1/domain/typosquatting

Generates typosquatting permutations for one or more domains to detect potential brand impersonation. Requires a **premium** tier customer.

**Request:**
```json
{
  "domains": ["example.com"],
  "depth": "shallow",
  "active": true
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `domains` | *(required)* | Array of domain names to check |
| `depth` | `"shallow"` | `"shallow"` (4 algorithms, ~30-80 results) or `"deep"` (10 algorithms, hundreds of results) |
| `active` | `false` | When `true`, also checks DNS registration and HTTP liveness for each permutation |

**Depth levels:**
- **`shallow`** — character omission, character swap, homoglyphs, wrong TLD. Produces a manageable number of results for most domains.
- **`deep`** — all 10 algorithms including adjacent key substitution, character repeat, vowel swap, missing dot, character addition, and bitsquatting. Useful for thorough brand protection audits.

**Example:**
```sh
curl -X POST http://localhost:8080/api/v1/domain/typosquatting \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: test-admin-key' \
  -d '{"domains":["example.com"],"active":true}'
```

**Response:**
```json
[
  {
    "domain": "example.com",
    "cache_hit": false,
    "depth": "shallow",
    "count": 42,
    "capped": false,
    "permutations": [
      {
        "domain": "examp1e.com",
        "technique": "homoglyph",
        "registered": true,
        "live": true
      },
      {
        "domain": "examlpe.com",
        "technique": "character_swap",
        "registered": false
      }
    ]
  }
]
```

When `active` is `false`, `registered` and `live` fields are omitted. When `active` is `true` but a domain is not registered, `live` is omitted. A hard cap on permutations (default 500, configurable via `typosquatting.max_permutations`) prevents unbounded results — `capped: true` indicates truncation.

## Response Fields

### Domain Lookup (`/api/v1/domain`)

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

### `screenshot` — Page Screenshot (Premium Only)

A visual screenshot of the domain's web page, captured with headless Chrome at 1280x720. Only present when `"screenshot": true` is included in the request.

| Field | What it means |
|-------|---------------|
| `status_code` | The HTTP status code from probing the domain. The screenshot only captures the page on `200 OK`. |
| `png` | Base64-encoded PNG image of the page. Empty for non-200 responses. |

The screenshot lookup first tries HTTPS, then falls back to HTTP. Non-200 responses still populate the `screenshot` section with the status code but no image data.

### Typosquatting Detection (`/api/v1/domain/typosquatting`)

| Field | What it means |
|-------|---------------|
| `domain` | The domain that was checked |
| `cache_hit` | Whether the result was served from cache |
| `depth` | Which depth level was used (`shallow` or `deep`) |
| `count` | Total number of permutations returned |
| `capped` | Whether the permutation cap was hit (results truncated) |
| `permutations` | Array of typosquatting candidates |
| `errors` | Any errors that occurred during generation or active checks |

Each permutation contains:

| Field | What it means |
|-------|---------------|
| `domain` | The typosquatting candidate domain |
| `technique` | Which algorithm generated it (`character_omission`, `character_swap`, `homoglyph`, `wrong_tld`, `adjacent_char`, `character_repeat`, `vowel_swap`, `missing_dot`, `addition`, `bitsquatting`) |
| `registered` | Whether the domain has DNS A records (only present when `active: true`) |
| `live` | Whether the domain responds to HTTP requests (only present when registered) |

## Caching

Lookup results are cached in Redis. Repeated lookups for the same domain return the cached result until the TTL expires. Each response includes a `cache_hit` field indicating whether the result was served from cache. The TTL is configurable via `redis.cache_ttl` (default `60m`).

Screenshot and non-screenshot requests use separate cache keys (`domain` vs `domain:screenshot`). Each key is fully self-contained — a screenshot request caches all 5 lookups together, and a non-screenshot request caches the 4 base lookups.

Typosquatting results are cached under their own keys based on depth and active flag (e.g., `typosquatting:example.com:shallow`, `typosquatting+active:example.com:deep`).

## Getting Started

### Prerequisites

- Go 1.25+
- Redis (or use the included Docker Compose)
- PostgreSQL (or use the included Docker Compose)
- Chromium or Google Chrome (for page screenshot feature; Docker image includes it)

### Configuration

The application looks for `intelligence-api.yaml` in the following locations (first match wins):

1. `/etc/security-accelerated/` (recommended for production)
2. `config/` (relative to working directory)

Copy the sample config to your preferred location:

```sh
sudo cp internal/config/sample-config.yml /etc/security-accelerated/intelligence-api.yaml
```

Config values:

| Key | Default | Description |
|-----|---------|-------------|
| `application.mode` | `local` | `local` or `production` |
| `application.port` | `8080` | HTTP server port |
| `redis.addr` | `localhost:6379` | Redis address |
| `redis.password` | `""` | Redis password |
| `redis.db` | `0` | Redis database number |
| `redis.cache_ttl` | `60m` | Cache TTL for domain lookups |
| `auth.cache_ttl` | `5m` | TTL for in-memory auth cache |
| `screenshot.timeout` | `15s` | Timeout for page screenshot capture (probe + render) |
| `typosquatting.timeout` | `30s` | Timeout for typosquatting detection (generation + active checks) |
| `typosquatting.max_permutations` | `500` | Maximum number of permutations returned per domain |
| `typosquatting.concurrency` | `20` | Max concurrent DNS/HTTP checks during active scanning |
| `postgres.host` | `localhost` | PostgreSQL host |
| `postgres.port` | `5432` | PostgreSQL port |
| `postgres.user` | `intelligence` | PostgreSQL user |
| `postgres.password` | `intelligence` | PostgreSQL password |
| `postgres.dbname` | `intelligence_api` | PostgreSQL database name |
| `postgres.sslmode` | `disable` | PostgreSQL SSL mode |

### Database Setup

The `migrations/` directory contains SQL files that are automatically applied when using Docker Compose (mounted to `/docker-entrypoint-initdb.d/`).

- `001_create_api_keys.sql` — creates the `customers`, `api_keys`, and `customer_roles` tables
- `002_add_customer_tier.sql` — adds the `tier` column to `customers` (defaults to `basic`)
- `seed.sql` — inserts test customers with keys and roles, sets Test Admin to `premium` tier

To manage customers and API keys manually:

```sql
INSERT INTO customers (name) VALUES ('Acme Corp');
INSERT INTO api_keys (customer_id, key) VALUES (1, 'my-secret-key');
INSERT INTO customer_roles (customer_id, role) VALUES (1, 'admin'), (1, 'domain');
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

Create a `docker-compose.yml`:

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

## Testing

```sh
make test                # unit tests
make test-integration    # integration tests (uses in-memory Redis, stub auth)
```
