# Intelligence API — Developer Guide

Base URL: `https://api.securityaccelerated.com/api/v1`

## Authentication

All requests require an API key passed in the `X-API-Key` header:

```
X-API-Key: your-api-key-here
```

Missing or invalid keys return `401 Unauthorized`. Requests to endpoints not included in your plan return `403 Forbidden`.

## Rate Limiting

Requests are rate-limited per API key. Every response includes these headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed per minute |
| `X-RateLimit-Remaining` | Requests remaining in the current window |
| `Retry-After` | Seconds until the window resets (only on `429`) |

When the limit is exceeded, the API returns `429 Too Many Requests`. Back off until the `Retry-After` period expires.

| Plan | Limit |
|------|-------|
| Basic | 30 requests/minute |
| Premium | 120 requests/minute |

## Request Correlation

You can pass a `X-Client-Request-ID` header with your own correlation ID. The API echoes it back in the response headers and includes it in server-side logs for end-to-end tracing.

Requirements:
- Maximum 64 characters
- Alphanumeric characters, hyphens, underscores, dots, and colons only
- Invalid or missing IDs are silently ignored (the request still succeeds)

```
X-Client-Request-ID: my-trace-id-12345
```

## Response Conventions

- All responses are JSON
- Successful responses return `200 OK`
- Multi-domain endpoints return an array, even for single-domain requests
- Each result includes `cache_hit` (`true` if served from cache, `false` if fetched live)
- Partial failures are reported per-lookup in the `errors` array — one failing lookup does not block the others
- Fields for unrequested optional features are omitted from the response

---

# Endpoints

## Domain Lookup

```
POST /api/v1/domain/lookup
```

Look up one or more domains concurrently. Returns WHOIS, DNS, SSL, and HTTP header data for each domain. Optional flags enable additional lookups.

**Plans:** Basic, Premium

### Request

```json
{
  "domains": ["example.com", "example.org"],
  "screenshot": false,
  "reputation": false,
  "email_security": false,
  "subdomains": false,
  "ct_logs": false,
  "bgp": false
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domains` | string[] | Yes | — | Domain names to look up (max 5 basic, 20 premium) |
| `screenshot` | bool | No | `false` | Capture a page screenshot (premium only) |
| `reputation` | bool | No | `false` | Check domain against threat blocklists (premium only) |
| `email_security` | bool | No | `false` | Check SPF, DMARC, and DKIM records |
| `subdomains` | bool | No | `false` | Enumerate subdomains via Certificate Transparency logs |
| `ct_logs` | bool | No | `false` | Query Certificate Transparency logs for all issued certificates |
| `bgp` | bool | No | `false` | Look up BGP/ASN information for the domain's IP addresses |

Domain names are normalized automatically: `http://` and `https://` prefixes are stripped, trailing slashes are removed. Raw IP addresses are rejected.

### Response

```json
[
  {
    "domain": "example.com",
    "cache_hit": false,
    "whois": { },
    "dns": { },
    "ssl": { },
    "headers": { },
    "screenshot": { },
    "reputation": { },
    "email_security": { },
    "subdomains": { },
    "ct_logs": { },
    "bgp": { },
    "errors": []
  }
]
```

Optional fields (`screenshot`, `reputation`, `email_security`, `subdomains`, `ct_logs`, `bgp`) are only present when requested.

### Example

```sh
curl -X POST https://api.securityaccelerated.com/api/v1/domain/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-api-key' \
  -H 'X-Client-Request-ID: req-001' \
  -d '{
    "domains": ["example.com"],
    "email_security": true,
    "subdomains": true
  }'
```

### Invalid Domains

Invalid domains in a multi-domain request don't fail the entire request. They're included in the response with a validation error:

```json
[
  {
    "domain": "example.com",
    "cache_hit": false,
    "whois": { "domain_name": "example.com", "..." : "..." },
    "dns": { },
    "ssl": { },
    "headers": { }
  },
  {
    "domain": "notadomain",
    "errors": [{ "lookup": "validation", "message": "invalid domain name" }]
  }
]
```

---

## Typosquatting Detection

```
POST /api/v1/domain/typosquatting
```

Generate typosquatting permutations for one or more domains. Optionally check which permutations are actually registered and serving live content.

**Plans:** Available as an add-on to any plan

### Request

```json
{
  "domains": ["example.com"],
  "depth": "shallow",
  "check_live": false
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domains` | string[] | Yes | — | Domain names to check (max 3 basic, 5 premium) |
| `depth` | string | No | `"shallow"` | `"shallow"` or `"deep"` |
| `check_live` | bool | No | `false` | Check DNS registration and HTTP liveness for each permutation |

### Depth Levels

**Shallow** (4 algorithms, ~30-80 results per domain):
- Character omission (`exmple.com`)
- Character swap (`exmaple.com`)
- Homoglyphs (`examp1e.com`)
- Wrong TLD (`example.net`)

**Deep** (10 algorithms, hundreds of results per domain):
All shallow algorithms plus:
- Adjacent key substitution (`rxample.com`)
- Character repeat (`exaample.com`)
- Vowel swap (`exomple.com`)
- Missing dot (`examplecom.com`)
- Character addition (`examplee.com`)
- Bitsquatting (`dxample.com`)

### Response

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

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | The domain that was checked |
| `cache_hit` | bool | Whether the result was served from cache |
| `depth` | string | Depth level used |
| `count` | int | Number of permutations returned |
| `capped` | bool | `true` if results were truncated at the cap |
| `permutations` | array | Typosquatting candidates |

Each permutation:

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | The lookalike domain |
| `technique` | string | Algorithm that generated it |
| `registered` | bool | Has DNS A records (only when `check_live: true`) |
| `live` | bool | Responds to HTTP (only when registered) |

### Example

```sh
curl -X POST https://api.securityaccelerated.com/api/v1/domain/typosquatting \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-api-key' \
  -d '{
    "domains": ["yourcompany.com"],
    "depth": "deep",
    "check_live": true
  }'
```

---

# Response Field Reference

## `whois` — Domain Registration

| Field | Type | Description |
|-------|------|-------------|
| `domain_name` | string | The registered domain name |
| `registrar` | string | Registrar (e.g. GoDaddy, Namecheap) |
| `created_date` | string | Registration date — new domains are higher risk |
| `updated_date` | string | Last modification date |
| `expiry_date` | string | Expiration date — expiring domains are red flags |
| `status` | string[] | EPP status codes (e.g. `clientTransferProhibited`) |
| `name_servers` | string[] | Authoritative DNS servers |
| `registrant` | object | Registrant contact (name, organization, country, email) |
| `admin` | object | Administrative contact |
| `tech` | object | Technical contact |

Contact fields are often redacted by WHOIS privacy services.

## `dns` — DNS Records

| Field | Type | Description |
|-------|------|-------------|
| `a` | string[] | IPv4 addresses |
| `aaaa` | string[] | IPv6 addresses |
| `mx` | object[] | Mail servers (`host`, `priority`) |
| `ns` | string[] | Name servers |
| `txt` | string[] | TXT records (SPF, verification tokens, etc.) |
| `cname` | string | Canonical name alias |

## `ssl` — TLS Certificate

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | Entity the certificate was issued to |
| `issuer` | string | Certificate authority |
| `not_before` | string | Start of validity period |
| `not_after` | string | End of validity period |
| `expired` | bool | Whether the certificate has expired |
| `days_until_expiry` | int | Days remaining until expiration |
| `sans` | string[] | Subject Alternative Names — all hostnames the cert covers |
| `serial_number` | string | Certificate serial number |
| `signature_algorithm` | string | Cryptographic algorithm (e.g. SHA-256) |

## `headers` — HTTP Response

| Field | Type | Description |
|-------|------|-------------|
| `status_code` | int | HTTP status code (200, 301, 404, etc.) |
| `headers` | object | Raw response headers |
| `security_headers` | object | Security header audit (see below) |

Security headers checked:

| Field | Header |
|-------|--------|
| `strict_transport_security` | Strict-Transport-Security (HSTS) |
| `content_security_policy` | Content-Security-Policy (CSP) |
| `x_frame_options` | X-Frame-Options |
| `x_content_type_options` | X-Content-Type-Options |
| `x_xss_protection` | X-XSS-Protection |
| `referrer_policy` | Referrer-Policy |
| `permissions_policy` | Permissions-Policy |

## `screenshot` — Page Screenshot (Premium)

| Field | Type | Description |
|-------|------|-------------|
| `status_code` | int | HTTP status code from probing the domain |
| `png` | string | Base64-encoded PNG image (empty for non-200 responses) |

The screenshot tries HTTPS first, then falls back to HTTP. Captured at 1280x720 with headless Chrome.

## `reputation` — Domain Reputation (Premium)

| Field | Type | Description |
|-------|------|-------------|
| `score` | int | Risk score from 0 (clean) to 100 (maximum risk) |
| `risk` | string | `clean`, `low`, `medium`, or `high` |
| `providers` | array | Per-provider results |

Each provider:

| Field | Type | Description |
|-------|------|-------------|
| `listed` | bool | Whether the domain appears on this blocklist |
| `category` | string | Classification if listed (e.g. `phishing`, `malware`) |
| `provider` | string | Blocklist name |
| `return_code` | string | Raw DNS return code (only when listed) |

Providers checked: Spamhaus DBL, SURBL, URIBL, Spamhaus ZEN.

## `email_security` — Email Authentication

**`spf`** — Sender Policy Framework:

| Field | Type | Description |
|-------|------|-------------|
| `raw` | string | Full SPF TXT record |
| `version` | string | SPF version (typically `spf1`) |
| `mechanisms` | string[] | Parsed mechanisms (`include:`, `ip4:`, etc.) |
| `all` | string | Terminal qualifier: `-all`, `~all`, `?all`, or `+all` |

**`dmarc`** — DMARC policy:

| Field | Type | Description |
|-------|------|-------------|
| `raw` | string | Full DMARC TXT record |
| `version` | string | DMARC version (typically `DMARC1`) |
| `policy` | string | `none`, `quarantine`, or `reject` |
| `pct` | int | Percentage of messages the policy applies to |
| `rua` | string | Aggregate report destination |
| `ruf` | string | Forensic report destination |
| `sp` | string | Subdomain policy |

**`dkim`** — DKIM records (probes 8 common selectors):

| Field | Type | Description |
|-------|------|-------------|
| `selector` | string | Selector name probed |
| `found` | bool | Whether a DKIM record exists |
| `raw` | string | Full DKIM TXT record (only when found) |

Selectors probed: `google`, `default`, `selector1`, `selector2`, `k1`, `s1`, `mail`, `dkim`.

## `subdomains` — Subdomain Enumeration

| Field | Type | Description |
|-------|------|-------------|
| `count` | int | Number of subdomains returned |
| `capped` | bool | `true` if results were truncated at the cap (500) |
| `subdomains` | array | Discovered subdomains |

Each subdomain:

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | The subdomain |
| `source` | string | Data source (`crt.sh`) |

## `ct_logs` — Certificate Transparency Logs

| Field | Type | Description |
|-------|------|-------------|
| `count` | int | Number of certificate entries returned |
| `capped` | bool | `true` if results were truncated at the cap (100) |
| `entries` | array | Certificate log entries, sorted newest-first |

Each entry:

| Field | Type | Description |
|-------|------|-------------|
| `logged_at` | string | When the certificate was logged to CT |
| `not_before` | string | Certificate validity start |
| `not_after` | string | Certificate validity end |
| `issuer` | string | Certificate Authority |
| `common_name` | string | Certificate CN field |
| `name_value` | string | All names covered by the certificate |
| `serial` | string | Certificate serial number |

Reveals infrastructure, related domains, and issuance patterns. Useful for detecting phishing campaigns and tracking certificate history.

## `bgp` — BGP / ASN Enrichment

| Field | Type | Description |
|-------|------|-------------|
| `records` | array | ASN records, deduplicated by ASN |

Each record:

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | Resolved IP address |
| `asn` | int | Autonomous System Number |
| `prefix` | string | IP prefix (CIDR notation) |
| `country` | string | Country code |
| `registry` | string | Regional Internet Registry (arin, ripe, apnic, etc.) |
| `description` | string | Organization name |

Identifies who owns the IP behind the domain. Useful for pivot analysis and detecting bulletproof hosting.

## `errors` — Partial Failures

Individual lookups can fail without blocking the rest of the response. Each error contains:

| Field | Type | Description |
|-------|------|-------------|
| `lookup` | string | Which lookup failed (e.g. `whois`, `dns`, `ssl`) |
| `message` | string | Human-readable error description |

---

# Error Responses

| Status | Meaning |
|--------|---------|
| `400 Bad Request` | Invalid request body, missing `domains` field, or invalid domain name |
| `401 Unauthorized` | Missing or invalid API key |
| `403 Forbidden` | Your plan doesn't include this endpoint or feature |
| `429 Too Many Requests` | Rate limit exceeded — check `Retry-After` header |
| `500 Internal Server Error` | Server error — contact support |

All error responses have the format:

```json
{
  "error": "description of the problem"
}
```

---

# Caching

Results are cached for 60 minutes. The `cache_hit` field on each response tells you whether the data was served from cache or fetched live. Requesting different option combinations (e.g. with vs. without `reputation`) produces separate cache entries, so adding a new option to a repeat request will fetch fresh data for that option.
