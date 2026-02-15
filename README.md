# Security Accelerated
## Intelligence API

A domain intelligence API that performs concurrent WHOIS, DNS, SSL, and HTTP header lookups for one or more domains, with Redis caching.

## Authentication

All endpoints except `/api/v1/hello` require an API key passed via the `X-API-Key` header. Keys are stored in PostgreSQL.

### Roles

| Role | Access |
|------|--------|
| `admin` | All endpoints (`/hello`, `/info`, `/domain`) |
| `domain` | Only `POST /api/v1/domain` |

Requests without a valid key receive `401 Unauthorized`. Requests with a key that lacks permission for the endpoint receive `403 Forbidden`. The `/api/v1/hello` health check requires no authentication.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/hello` | None | Health check, returns `{"message": "hello world"}` |
| GET | `/api/v1/info` | `admin` | Application and environment info |
| POST | `/api/v1/domain` | `admin`, `domain` | Domain intelligence lookup |

### POST /api/v1/domain

**Request:**
```json
{
  "domains": ["example.com", "example.org"]
}
```

The `domains` field accepts an array of domain names. Each entry accepts raw domains, URLs with `http://`/`https://` prefixes, and trailing slashes — all are normalized automatically. Domains are looked up concurrently.

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

## Caching

Lookup results are cached in Redis. Repeated lookups for the same domain return the cached result until the TTL expires. Each response includes a `cache_hit` field indicating whether the result was served from cache. The TTL is configurable via `redis.cache_ttl` (default `60m`).

## Getting Started

### Prerequisites

- Go 1.25+
- Redis (or use the included Docker Compose)
- PostgreSQL (or use the included Docker Compose)

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
| `postgres.host` | `localhost` | PostgreSQL host |
| `postgres.port` | `5432` | PostgreSQL port |
| `postgres.user` | `intelligence` | PostgreSQL user |
| `postgres.password` | `intelligence` | PostgreSQL password |
| `postgres.dbname` | `intelligence_api` | PostgreSQL database name |
| `postgres.sslmode` | `disable` | PostgreSQL SSL mode |

### Database Setup

The `migrations/` directory contains SQL files that are automatically applied when using Docker Compose (mounted to `/docker-entrypoint-initdb.d/`).

- `001_create_api_keys.sql` — creates the `api_keys` table
- `seed.sql` — inserts test keys (`test-admin-key` and `test-domain-key`)

To manage API keys manually:

```sql
INSERT INTO api_keys (key, role) VALUES ('my-secret-key', 'admin');
INSERT INTO api_keys (key, role) VALUES ('my-domain-key', 'domain');
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
