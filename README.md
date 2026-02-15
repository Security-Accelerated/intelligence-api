# Security Accelerated
## Intelligence API

A domain intelligence API that performs concurrent WHOIS, DNS, SSL, and HTTP header lookups for a given domain, with Redis caching.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/hello` | Health check, returns `{"message": "hello world"}` |
| GET | `/api/v1/version` | Returns build version, e.g. `{"version": "v0.1.0"}` |
| POST | `/api/v1/domain` | Domain intelligence lookup |

### POST /api/v1/domain

**Request:**
```json
{
  "domain": "example.com"
}
```

The domain field accepts raw domains, URLs with `http://`/`https://` prefixes, and trailing slashes — all are normalized automatically.

**Response:**
```json
{
  "domain": "example.com",
  "whois": { "domain_name": "...", "registrar": "...", "..." : "..." },
  "dns": { "a": ["93.184.216.34"], "mx": [], "ns": [], "..." : "..." },
  "ssl": { "subject": "...", "issuer": "...", "..." : "..." },
  "headers": { "status_code": 200, "headers": {}, "security_headers": {} },
  "errors": []
}
```

## Getting Started

### Prerequisites

- Go 1.25+
- Redis (or use the included Docker Compose)

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

### Run with Docker (recommended)

Build and run the full stack locally:

```sh
docker compose up --build
```

This starts both the API and Redis. The API is available at `http://localhost:8080`.

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
  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

Then run:

```sh
docker compose up
```

### Run without Docker

Start Redis:

```sh
docker compose up -d redis
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
make test-integration    # integration tests (uses in-memory Redis)
```
