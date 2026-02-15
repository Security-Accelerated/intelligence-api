# Security Accelerated
## Intelligence API

A domain intelligence API that performs concurrent WHOIS, DNS, SSL, and HTTP header lookups for a given domain, with Redis caching.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/hello` | Health check, returns `{"message": "hello world"}` |
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
2. `/etc/intelligence-api/`
3. `config/` (relative to working directory)

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

### Start Redis

```sh
docker compose up -d
```

### Build and Run

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

## Project Structure

```
cmd/api/
  main.go                  # application entrypoint, wiring, graceful shutdown
internal/
  cache/
    redis.go               # Redis cache (Get/Set with JSON serialization)
  config/
    config.go              # Viper-based configuration
  domain/
    model.go               # request/response types
    whois.go               # WHOIS lookup
    dns.go                 # DNS lookup
    ssl.go                 # TLS/SSL certificate lookup
    headers.go             # HTTP header + security header lookup
  handler/
    handler.go             # route registration, DomainLookupService interface
    domain.go              # POST /api/v1/domain handler
    hello.go               # GET /api/v1/hello handler
  logging/
    logging.go             # Zap logger setup
  middleware/
    request_logger.go      # request logging middleware
  service/
    domain.go              # orchestrates concurrent lookups + caching
integration_test.go        # full HTTP flow integration tests
```
