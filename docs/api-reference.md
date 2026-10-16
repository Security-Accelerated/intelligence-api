# Intelligence API — API reference

The caller-facing reference for every endpoint, request field, response field, and cache
rule. The rendered version lives at <https://api.securityaccelerated.com/docs>, with the
OpenAPI 3.1 document at `/docs/openapi.yaml`; this file is the same material for reading
alongside the source. Operator material (configuration, deployment, the `sactl` CLI,
billing internals) is in [operations.md](operations.md).

## Authentication

Most API endpoints require an API key passed via the `X-API-Key` header. Keys are stored in PostgreSQL as `hex(sha256(key))` and belong to a customer, who has a plan. A customer normally holds one live key, but holds several during a rotation grace window: `POST /v1/keys/rotate` issues a new key and leaves the previous ones authenticating until `auth.rotation_grace` (default 24h) elapses, so deployed clients can be switched over without downtime. The following routes are public (no API key required): `/` (redirect), `/docs`, `/docs/domain`, `/docs/ip`, `/docs/account`, `/docs/changelog`, `/docs/openapi.yaml`, `/v1/hello`, `/v1/health`, `/billing/webhook` (Stripe signature), and `/billing/success` (session token).

### Customer Plans

Each customer has a `plan` that controls rate limits, access to premium options, and admin access:

| Plan | Capabilities |
|------|-------------|
| `free` | All lookups except `reputation` and `threat_intel`. 1 domain per request. |
| `pro` | All free capabilities + reputation checks + threat intelligence, up to 20 domains per request |
| `admin` | All pro capabilities + admin endpoints (info, fingerprint management, cache invalidation) + no rate limit |

The plan is stored in the `customers` table, defaulting to `free`. New customers provisioned via Stripe checkout receive the plan they purchased. An unrecognized plan value is treated as `free` by both the rate limiter and lookup gating, so a bad value fails closed.

Requests without a valid key receive `401 Unauthorized`. Requests from non-admin plans to admin-only endpoints receive `403 Forbidden`. Requests naming a lookup outside the caller's plan (`reputation`, `threat_intel` require pro) receive `403 Forbidden`. The `/v1/hello` and `/v1/health` checks require no authentication. Self-service endpoints (`GET /v1/usage`, `POST /v1/keys/rotate`) are available to every plan.

### Rate Limiting

All authenticated endpoints are rate-limited per API key using a sliding-window counter backed by Redis. Admin plan bypasses rate limiting entirely. Limits are configurable per plan:

| Plan | Default Limit |
|------|---------------|
| `free` | 5 requests/minute |
| `pro` | 120 requests/minute |
| `admin` | No limit |

Every response includes rate limit headers:
- `X-RateLimit-Limit` — the maximum requests allowed per minute
- `X-RateLimit-Remaining` — how many requests remain in the current window

When the limit is exceeded, the API returns `429 Too Many Requests` with a `Retry-After` header indicating seconds until the current window resets. If Redis is unavailable, rate limiting fails open (requests are allowed).

## API Endpoints

| Method | Path | Plan | Description |
|--------|------|------|-------------|
| GET | `/` | None | Redirects to `/docs` |
| GET | `/docs` | None | API documentation landing page |
| GET | `/docs/domain` | None | Domain Intelligence API docs |
| GET | `/docs/ip` | None | IP Intelligence API docs |
| GET | `/docs/account` | None | Usage statistics and key rotation docs |
| GET | `/docs/changelog` | None | Public release notes |
| GET | `/docs/openapi.yaml` | None | OpenAPI specification for the public API |
| GET | `/v1/hello` | None | Health check, returns `{"message": "hello world"}` |
| GET | `/v1/health` | None | Dependency health (Postgres, Redis, GeoIP) for ops monitoring |
| POST | `/billing/webhook` | None (Stripe signature) | Stripe webhook endpoint |
| GET | `/billing/success` | None (session_id token) | Post-checkout API key retrieval page |
| any | *(unmatched)* | None | 404 — `{"error": "not found"}` under `/v1` and `/billing`, docs-styled HTML page for every other path |
| GET | `/v1/info` | `admin` | Application and environment info |
| POST | `/v1/domain/lookup` | All plans | Domain intelligence lookup |
| POST | `/v1/ip/lookup` | All plans | IP intelligence lookup |
| GET | `/v1/usage` | All plans | Caller's own usage statistics |
| POST | `/v1/keys/rotate` | All plans | Rotate the caller's API key (old keys keep working for a grace window) |
| POST | `/v1/admin/geoip/refresh` | `admin` | Download and reload the DB-IP GeoIP database |
| POST | `/v1/admin/auth/cache/invalidate` | `admin` | Invalidate the in-memory auth cache |
| GET | `/v1/admin/fingerprints` | `admin` | Get technology fingerprint rules |
| POST | `/v1/admin/fingerprints` | `admin` | Update technology fingerprint rules |
| GET | `/v1/admin/usage` | `admin` | Aggregated API usage statistics |
| GET | `/v1/admin/changelog` | `admin` | Full changelog with audience tags |

The 404 chooses its form by path prefix, not by `Accept`, so a mistyped endpoint returns the error envelope to any client. Neither form echoes the requested path back: reflecting caller-chosen text onto our own domain would turn the 404 into a place to host arbitrary wording under `api.securityaccelerated.com`.

### POST /v1/domain/lookup

**Request:**
```json
{
  "domains": ["example.com", "example.org"],
  "lookups": ["whois", "dns", "ssl", "headers"]
}
```

Both fields are **required**.

#### `domains`

An array of domain names. You can pass bare domains or full URLs with any scheme — the API extracts the hostname by stripping scheme prefixes, userinfo, ports, paths, query strings, and fragments, then trims whitespace and lowercases the result (e.g. `  HTTPS://Example.COM/path?q=1  ` → `example.com`). DNS names are case-insensitive, so lowercasing is always safe.

Entries that normalize to the same domain are **deduplicated** — they are looked up once and returned as a single result. Plan domain limits count the entries you submitted, not the unique domains they collapse into. Domains are looked up concurrently.

#### `lookups`

An array naming which lookups to run. It must be present and non-empty — there is no default set and no `"all"` value. Names are trimmed, lowercased, and deduplicated before validation, so `[" SSL ", "ssl", "SSL"]` is simply `["ssl"]`.

| Lookup | Plan | Description |
|--------|------|-------------|
| `whois` | All | Registration, registrar, expiry, nameservers, contacts |
| `dns` | All | A, AAAA, MX, NS, TXT, CNAME records |
| `ssl` | All | TLS certificate subject, issuer, validity, SANs |
| `headers` | All | HTTP response headers and security header analysis |
| `email_security` | All | SPF, DMARC, and DKIM records. DKIM probes 8 common selectors (`google`, `default`, `selector1`, `selector2`, `k1`, `s1`, `mail`, `dkim`) |
| `subdomains` | All | Subdomain enumeration via Certificate Transparency logs (crt.sh). Deduplicated, wildcards filtered, capped (default 500, via `subdomain.max_results`) |
| `ct_logs` | All | Full certificate history from crt.sh with issuer, dates, serial, SANs. Deduplicated by serial, newest first, capped (default 100, via `ct_logs.max_entries`) |
| `bgp` | All | BGP/ASN enrichment via Team Cymru — ASN, prefix, country, registry, organization |
| `fingerprint` | All | Web technology detection (servers, frameworks, CDNs, CMS, languages) from HTTP headers. Makes no extra network calls — see [Caching](#caching) |
| `dns_security` | All | DNSSEC deployment (DS + DNSKEY + algorithms) and CAA records |
| `risk` | All | Weighted 0–100 aggregate risk score over the *other* lookups you requested. Makes no network call and is never cached — see [Caching](#caching) |
| `reputation` | **Pro** | DNS blocklist checks (Spamhaus DBL, SURBL, URIBL, Spamhaus ZEN) with a computed risk score |
| `threat_intel` | **Pro** | VirusTotal, URLhaus, and AlienVault OTX with a composite risk score |

Requesting a lookup your plan does not include returns `403 Forbidden`. An unrecognized name returns `400 Bad Request` naming the offending entry.

**Example:**
```sh
curl -X POST http://localhost:8080/v1/domain/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: test-admin-key' \
  -d '{"domains":["example.com"],"lookups":["dns","ssl"]}'
```

#### Response envelope and result identification

Responses are wrapped in a `{"results": [...]}` envelope. Every API response is a JSON object, matching the `{"error": "..."}` error format, and leaves room for response-level fields (warnings, metadata) to be added without breaking clients.

`results` contains **one element per unique normalized domain**. Each element carries:

- **`domain`** — the normalized form. Match results by this field.
- **`inputs`** — the original request entries, verbatim and untrimmed, that mapped to this domain. This lets you reconcile results against your request without reimplementing normalization.

**Array position is not part of the API contract.** Do not assume `results[i]` corresponds to `domains[i]`.

```json
{
  "results": [
    {
      "domain": "example.com",
      "inputs": ["HTTPS://Example.COM/", "example.com"],
      "dns": { "cache_hit": true, "a": ["93.184.216.34"] }
    }
  ]
}
```

Each result contains only the lookups you requested — never any you did not — plus `domain`, `inputs`, and `errors` when a lookup failed. A lookup that failed is omitted rather than returned empty, so you can get fewer fields than you asked for.

**Full response example** (every lookup requested):
```json
{
  "results": [
    {
      "domain": "example.com",
      "inputs": ["example.com"],
      "whois": { "cache_hit": false, "domain_name": "...", "registrar": "...", "..." : "..." },
      "dns": { "cache_hit": true, "a": ["93.184.216.34"], "mx": [], "ns": [], "..." : "..." },
      "ssl": { "cache_hit": false, "subject": "...", "issuer": "...", "..." : "..." },
      "headers": { "cache_hit": false, "status_code": 200, "headers": {}, "security_headers": {} },
      "reputation": {
        "cache_hit": false,
        "score": 35,
        "risk": "medium",
        "providers": [
          { "listed": true, "category": "phishing", "provider": "spamhaus_dbl", "return_code": "127.0.1.4" },
          { "listed": false, "provider": "surbl" },
          { "listed": false, "provider": "uribl" },
          { "listed": false, "provider": "spamhaus_zen" }
        ]
      },
      "threat_intel": {
        "cache_hit": false,
        "risk_level": "medium",
        "score": 45,
        "categories": ["malware"],
        "providers": [
          { "provider": "virustotal", "detected": true, "score": 3, "categories": ["malware"], "details": "3/70 engines detected this domain" },
          { "provider": "urlhaus", "detected": false },
          { "provider": "alienvault_otx", "detected": true, "score": 5, "categories": ["malware"], "details": "5 threat pulses reference this domain" }
        ]
      },
      "email_security": {
        "cache_hit": false,
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
        "cache_hit": false,
        "count": 3,
        "capped": false,
        "subdomains": [
          { "domain": "api.example.com", "source": "crt.sh" },
          { "domain": "mail.example.com", "source": "crt.sh" },
          { "domain": "www.example.com", "source": "crt.sh" }
        ]
      },
      "ct_logs": {
        "cache_hit": false,
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
        "cache_hit": false,
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
        "cache_hit": false,
        "count": 2,
        "technologies": [
          { "name": "Nginx", "category": "web-server", "version": "1.24.0", "confidence": "header" },
          { "name": "PHP", "category": "language", "version": "8.2", "confidence": "header" }
        ]
      }
    }
  ]
}
```

Invalid domains in a multi-domain request are included in the response with a validation error instead of failing the entire request:
```json
{
  "results": [
    { "domain": "example.com", "inputs": ["example.com"], "dns": { "cache_hit": false, "..." : "..." } },
    { "domain": "notadomain", "inputs": ["notadomain"], "errors": [{"lookup": "validation", "message": "invalid domain name"}] }
  ]
}
```

A request whose *only* domain is invalid returns `400 Bad Request`.

#### Error handling

Errors are returned as `{"error": "..."}`. Validation runs in a fixed order: the body is parsed, then lookups and domains are normalized and deduplicated, then `lookups` is checked for emptiness, then each name is validated, then plan access is checked, then domain caps are applied.

| Status | Condition | Example message |
|--------|-----------|-----------------|
| `400` | Body is not valid JSON, or `domains` is missing/empty | `invalid request: domains field is required and must be a non-empty array` |
| `400` | `lookups` missing, or empty after normalization (`[]`, `[""]`, `[" "]`) | `lookups is required, e.g. ["dns", "ssl"]` |
| `400` | Unrecognized lookup name | `invalid lookup "banana"; valid lookups: whois, dns, ssl, ...` |
| `400` | More domains than the plan allows | `too many domains: maximum 20 allowed for pro plan` |
| `400` | More domains than the tighter subdomain cap allows | `too many domains: maximum 5 allowed for pro plan when subdomains is requested` |
| `400` | The single submitted domain is invalid | `invalid domain name` / `raw IP addresses are not accepted; provide a domain name` |
| `401` | Missing or invalid API key | `invalid API key` |
| `403` | Lookup not included in the caller's plan | `reputation requires a pro plan` |
| `413` | Request body over the 1 MB limit | `request body too large` |
| `429` | Rate limit exceeded | see [Rate Limiting](#rate-limiting) |

Failures *inside* a lookup do not produce an error status. They appear in that result's `errors` array while the remaining lookups return normally, and the failed lookup's field is omitted. Cache failures are never surfaced — see [Caching](#cache-failures-never-fail-a-request).

## Response Fields

### Domain Lookup (`/v1/domain/lookup`)

### `domain` / `inputs` / `cache_hit` / `errors`

- **`domain`** — The normalized domain this result is for, since you can submit multiple in one request. Match results by this field, not by array position.
- **`inputs`** — The original request entries, verbatim, that normalized to this domain.
- **`cache_hit`** — Present on **each lookup object**, not at the top level. `true` means that lookup was served from Redis, `false` that it was fetched live. Different fields in the same result can differ, since each lookup is cached separately with its own TTL.
- **`errors`** — Per-lookup errors when an individual lookup fails (e.g. WHOIS timed out but DNS succeeded). Partial failures don't block the rest of the response, and a failed lookup is omitted from the result rather than returned empty.

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

### `reputation` — Domain Reputation (Pro/Admin Only)

Checks the domain against 4 DNS-based blocklists concurrently and computes a risk score. Only present when `"reputation"` is included in `lookups`.

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

### `threat_intel` — Threat Intelligence (Pro/Admin Only)

Queries multiple threat intelligence providers to assess whether a domain is associated with malicious activity. Only present when `"threat_intel"` is included in `lookups`.

| Field | What it means |
|-------|---------------|
| `risk_level` | Composite risk level: `none`, `low`, `medium`, `high`, `critical` |
| `score` | Composite risk score from 0 (clean) to 100 (maximum risk) |
| `categories` | Aggregated threat categories across all providers (e.g. `malware`, `phishing`, `c2`) |
| `providers` | Array of per-provider results |

Each provider entry contains:

| Field | What it means |
|-------|---------------|
| `provider` | Which threat intel source was queried |
| `detected` | Whether this provider flagged the domain as malicious |
| `score` | Provider-specific detection score (only when detected) |
| `categories` | Threat categories from this provider (only when detected) |
| `details` | Human-readable summary of the detection (only when detected) |

**Providers:**

| Provider | Source | What it checks |
|----------|--------|---------------|
| `virustotal` | VirusTotal | Aggregates results from 70+ antivirus engines and URL scanners |
| `urlhaus` | URLhaus (Abuse.ch) | Database of malicious URLs used for malware distribution |
| `alienvault_otx` | AlienVault OTX | Open threat exchange with community-contributed threat pulses |

**Scoring:** Each provider contributes to the composite score based on detection severity. Multiple detections across providers stack. The score is capped at 100. The `risk_level` maps from the composite score: `none` (0), `low` (1–20), `medium` (21–50), `high` (51–80), `critical` (81–100).

### `email_security` — Email Security (All Plans)

Checks SPF, DMARC, and DKIM DNS records for the domain. Only present when `"email_security"` is included in `lookups`.

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

**`mta_sts`** — SMTP MTA Strict Transport Security (RFC 8461). Only present when a record exists at `_mta-sts.<domain>`:

| Field | What it means |
|-------|---------------|
| `raw` | The full MTA-STS TXT record |
| `id` | The `id=` tag identifying the current policy version |
| `policy_fetched` | Whether the policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` was retrieved |
| `mode` | Policy mode from the policy file: `enforce`, `testing`, or `none` |
| `max_age` | How long (seconds) senders should cache the policy |
| `mx_patterns` | MX host patterns the policy allows |

**`tls_rpt`** — SMTP TLS Reporting (RFC 8460). Only present when a record exists at `_smtp._tls.<domain>`:

| Field | What it means |
|-------|---------------|
| `raw` | The full TLS-RPT TXT record |
| `rua` | Report destination (e.g. `mailto:tlsrpt@example.com`) |

**`bimi`** — Brand Indicators for Message Identification. Only present when a record exists at `default._bimi.<domain>`:

| Field | What it means |
|-------|---------------|
| `raw` | The full BIMI TXT record |
| `location` | `l=` tag — URL of the brand logo SVG |
| `authority` | `a=` tag — URL of the Verified Mark Certificate |

### `subdomains` — Subdomain Enumeration (All Plans)

Enumerates subdomains via Certificate Transparency logs (crt.sh). Only present when `"subdomains"` is included in `lookups`.

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

Queries Certificate Transparency logs via crt.sh for all certificates ever issued for the domain. Only present when `"ct_logs"` is included in `lookups`.

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

Resolves the domain's IP addresses and queries Team Cymru's DNS-based IP-to-ASN mapping service. Only present when `"bgp"` is included in `lookups`.

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

Detects web servers, frameworks, CDNs, CMS platforms, and programming languages from HTTP response headers. Only present when `"fingerprint"` is included in `lookups`. No extra HTTP requests are made — detection uses the headers already fetched, and requesting `headers` alongside it does not double the fetch. See [Caching](#fingerprint-has-no-cache-key).

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

### `dns_security` — DNSSEC & CAA (All Plans)

Checks DNSSEC deployment and CAA records via raw DNS queries against the configured resolvers. Only present when `"dns_security"` is included in `lookups`.

**`dnssec`** — DNSSEC deployment status:

| Field | What it means |
|-------|---------------|
| `enabled` | `true` when both a DS record at the parent and a DNSKEY record at the zone exist — the chain of trust is in place |
| `ds_records` | Number of DS records at the parent zone |
| `dnskey_records` | Number of DNSKEY records at the zone |
| `algorithms` | Signing algorithms from the DS records (e.g. `ECDSAP256SHA256`, `RSASHA256`) |

**`caa`** — Certification Authority Authorization records:

| Field | What it means |
|-------|---------------|
| `present` | Whether any CAA records exist |
| `records` | Array of CAA records (`flag`, `tag`, `value`) — `tag` is `issue`, `issuewild`, or `iodef` |

Missing DNSSEC means DNS responses can be spoofed; missing CAA means any certificate authority can issue certificates for the domain.

### `risk` — Aggregate Risk Score (All Plans)

A computed 0–100 weighted risk score. Only present when `"risk"` is included in `lookups`. It makes no extra network calls and is never cached — the score is derived from whichever *other* requested lookups landed on the response, renormalized over the weights of the components that have data. Its `cache_hit` is `true` only when every scoring input came from cache.

| Field | What it means |
|-------|---------------|
| `score` | Weighted aggregate risk score from 0 (clean) to 100 (maximum risk) |
| `risk_level` | `none` (0), `low` (1–20), `medium` (21–50), `high` (51–80), `critical` (81–100) — same thresholds as `threat_intel` |
| `components` | Per-component breakdown |

Each component entry contains:

| Field | What it means |
|-------|---------------|
| `component` | Which signal contributed (see weights below) |
| `score` | This component's 0–100 score |
| `weight` | The component's weight in the aggregate |
| `detail` | Human-readable explanation (e.g. `certificate expires in 12 days`) |

**Component weights:** `threat_intel` (0.35), `reputation` (0.25), `ssl` (0.10), `security_headers` (0.10), `email_security` (0.10), `domain_age` (0.10). Components only contribute when their underlying lookup ran and returned data — a base-lookup-only request scores from SSL, security headers, and domain age alone.

### POST /v1/ip/lookup

**Request:**
```json
{
  "ips": [" 8.8.8.8 ", "8.8.8.8"],
  "lookups": ["geo", "asn", "reverse_dns"]
}
```

Both fields are **required**, and the endpoint follows the same contract as the domain lookup: `lookups` must be non-empty, names are trimmed/lowercased/deduplicated before validation, and results come back in a `{"results": [...]}` envelope with per-lookup `cache_hit`.

#### `ips`

An array of IP addresses. Each is canonicalized before use, so `2001:DB8::1` and `2001:db8:0:0:0:0:0:1` are the same address, collapse to one result, and share one cache key. Entries that canonicalize to the same address are deduplicated. Plan IP limits count the entries you submitted, not the unique addresses they collapse into.

Private, loopback, link-local, multicast, unspecified, and CGNAT addresses are rejected at input validation.

#### `lookups`

| Lookup | Plan | Description |
|--------|------|-------------|
| `geo` | All | Continent, country, region, city, coordinates (DB-IP Lite City, local database) |
| `asn` | All | ASN number, organization, announced prefix (Team Cymru DNS) |
| `reverse_dns` | All | PTR record hostnames |
| `abuse_contact` | All | Network owner, country, abuse email (via RDAP) |
| `threat_intel` | **Pro** | VirusTotal, URLhaus, and AlienVault OTX with a composite risk score |

The IP and domain catalogs are separate. `threat_intel` appears in both and behaves the same way; every other name belongs to one endpoint only, so asking for `whois` on an IP returns `400`.

**Response:**
```json
{
  "results": [
    {
      "ip": "8.8.8.8",
      "inputs": [" 8.8.8.8 ", "8.8.8.8"],
      "geo": { "cache_hit": false, "country": "United States", "city": "Mountain View" },
      "asn": { "cache_hit": false, "asn": 15169, "organization": "GOOGLE - Google LLC", "network": "8.8.8.0/24" },
      "reverse_dns": { "cache_hit": true, "hostnames": ["dns.google"] }
    }
  ]
}
```

Each element carries the canonicalized `ip` and the verbatim `inputs` that mapped to it. As with domains, **array position is not part of the API contract** — match results by `ip`.

**Response fields:**

| Field | Description |
|-------|-------------|
| `ip` | The queried IP address (canonicalized) |
| `inputs` | The original request entries, verbatim, that canonicalized to this address |
| `geo` | GeoIP: continent, country, region, city, coordinates (DB-IP Lite City) |
| `asn` | ASN number, organization, announced prefix (Team Cymru DNS) |
| `reverse_dns` | PTR record hostnames |
| `abuse_contact` | Network owner, country, abuse email (via RDAP) |
| `threat_intel` | Aggregated threat intelligence with risk score and per-provider results |
| `errors` | Per-lookup errors (partial failures still return other fields) |

#### `geo` is never cached

It reads a local memory-mapped database with no network call, so a Redis round trip would cost *more* than simply doing the lookup again. It is recomputed on every request and its `cache_hit` is always `false` — which is accurate, since the data really was produced for that request. `asn` is a DNS query and is cached like the other network lookups.

#### Data sources and licensing

`geo` uses the [DB-IP](https://db-ip.com) Lite City database under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), which permits commercial use with attribution; `/docs/ip` carries the attribution. It has no postal code, timezone, accuracy radius, or subdivision code, so the response has no fields for them. The app downloads it (about 60 MB compressed) in the background when it is missing or older than `geoip.max_age`, and persists it on the volume. `asn` uses Team Cymru's free IP-to-ASN DNS service, the same source as the domain `bgp` lookup, and needs no local file.

MaxMind GeoLite2 was used until the switch; its EULA restricts disclosing the data to third parties, which a paid API does. See `docs/decisions.md`.

### `GET /v1/usage` — My Usage (All Plans)

Returns aggregated usage statistics for the authenticated customer. The customer filter always comes from the auth context — callers can only ever see their own usage. The response shape matches `GET /v1/admin/usage` below.

**Query parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `days` | `30` | Number of days to look back (1–365) |

### `POST /v1/keys/rotate` — API Key Rotation (All Plans)

Rotates the caller's API key. The new key is returned exactly once; previous keys keep working until the grace window ends (configurable via `auth.rotation_grace`, default 24h) so deployed clients can be switched over without downtime. No request body.

**Response:**
```json
{
  "api_key": "new-64-char-hex-key",
  "old_keys_expire_at": "2026-06-12T15:04:05Z",
  "message": "store this key now — it cannot be retrieved again; previous keys stop working at old_keys_expire_at"
}
```

### `GET /v1/health` — Dependency Health (No Auth)

Internal/ops endpoint for load balancers and uptime monitoring. Returns component states only — never addresses, versions, or other internals. Postgres or Redis being down returns `503` with `status: "degraded"`; the GeoIP database is optional, so its state is reported but does not degrade overall health.

**Response:**
```json
{ "status": "ok", "components": { "postgres": "ok", "redis": "ok", "geoip": "ok" } }
```

### `GET /docs/openapi.yaml` — OpenAPI Specification (No Auth)

Serves the OpenAPI spec for the public API. Useful for generating clients or importing into tools like Postman and Insomnia.

### `GET /v1/admin/usage` — Usage Statistics (Admin Only)

Returns aggregated API usage statistics for a configurable time window.

**Query parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `days` | `30` | Number of days to look back (1–365) |
| `customer_id` | — | Filter by customer ID |
| `api_key_id` | — | Filter by API key ID |

**Response:**
```json
{
  "total_requests": 1247,
  "cache_hits": 3120,
  "cache_misses": 1480,
  "cache_hit_rate": 67.83,
  "avg_latency_ms": 842.5,
  "total_domains": 1580,
  "total_ips": 420,
  "status_codes": {"200": 1190, "400": 32, "403": 15, "429": 10},
  "feature_usage": {
    "whois": 900, "dns": 1100, "ssl": 870, "headers": 640,
    "reputation": 120, "threat_intel": 95, "email_security": 310,
    "subdomains": 200, "ct_logs": 85, "bgp": 60, "fingerprint": 400
  },
  "requests_by_path": {"/v1/domain/lookup": 1200, "/v1/admin/fingerprints": 12},
  "period_start": "2026-03-04T00:00:00Z",
  "period_end": "2026-03-11T00:00:00Z"
}
```

`cache_hits` and `cache_misses` count **individual lookups**, not requests — a request that serves three cached fields and fetches one live counts as 3 hits and 1 miss. `cache_hit_rate` is `hits / (hits + misses) * 100`.

`feature_usage` counts requests that **asked for** each lookup, whether or not it was served from cache. A cache hit is still customer demand.

### `GET /v1/info` — Application Status (Admin Only)

Returns application configuration, service status, and live runtime metrics. The response is built from a `StatusSnapshot` populated at startup (static config) plus live data computed per-request.

**Response sections:**

| Section | Description |
|---------|-------------|
| `system` | App name, version, mode, session ID, start time, uptime, host, OS, kernel, arch, Go version, server timeouts |
| `database` | PostgreSQL host, port, dbname, sslmode, connection pool settings |
| `cache` | Redis addr/db, cache TTL, auth cache TTL, plus live: key count, memory used, ping latency (ms), auth cache size |
| `lookups` | Lookup timeout, subdomain/CT log limits, rate limits and max domains per plan |
| `services` | Notifications (enabled + alert config), billing (enabled, Stripe key mode `live`/`test`, config), threat intel (provider names), fingerprint (source + rule count), usage (buffer config) |
| `runtime` | Goroutines, heap alloc/inuse (MB), sys memory (MB), GC count |
| `postgres_pool` | Connection pool: open, in use, idle, wait count, wait duration |

### `GET /v1/admin/changelog` — Changelog (Admin Only)

Returns the full changelog with audience tags. Each entry includes `version`, `date`, and `changes` (array of `{text, audience}`). The public changelog page at `/docs/changelog` renders only `public` entries; the other docs pages link to it rather than duplicating the list.

The changelog is maintained in `changelog.yaml` at the project root (symlink to `internal/handler/changelog.yaml`). Update it with every release.

## Caching

Lookup results are cached in Redis **per lookup, per domain** — not per response. Each key holds one lookup's result for one domain:

```
lookup:<domain>:<lookup_name>     # domain lookups, e.g. lookup:example.net:ssl
ip:<ip>:<lookup_name>             # IP lookups, e.g. ip:8.8.8.8:reverse_dns
```

The two namespaces are separate, so `threat_intel` on a domain and on an IP never collide. Keys are built only from the normalized domain and lookup name, so the combination of lookups you request has no effect on cache reuse: a `dns`-only request warms the same `lookup:example.com:dns` entry that a later `dns` + `ssl` request reads from.

Each lookup object in the response carries its own `cache_hit` flag, so a single result can mix cached and freshly fetched fields. Redis stores the lookup payload and nothing else — no request metadata, no cache flags, no timestamps.

### TTLs

Every lookup has its own TTL, reflecting how fast that data actually changes. Anything not listed falls back to `cache.default_ttl`.

| Lookup | Default TTL |
|--------|-------------|
| `whois` | 24h |
| `ct_logs` | 24h |
| `subdomains` | 24h |
| `bgp` | 24h |
| `ssl` | 4h |
| `email_security` | 4h |
| `dns` | 30m |
| `headers` | 30m |
| `reputation` | 30m |
| `threat_intel` | 30m |
| `dns_security` | 4h |
| `reverse_dns` *(IP)* | 6h |
| `abuse_contact` *(IP)* | 24h |
| `asn` *(IP)* | 24h |
| `geo` *(IP)* | never cached — local database read |
| *(anything else)* | `cache.default_ttl` (60m) |

Override individually with env vars — `CACHE_TTL_WHOIS=48h`, `CACHE_DEFAULT_TTL=30m` — or in the config file under `cache.ttl.*`.

Expiry is absolute: an expired entry is gone and the lookup is refetched. There is no stale-serving.

### `fingerprint` and `risk` have no cache keys

Both are pure computation over data already fetched for other lookups, so they make no network call and get no Redis entry of their own.

`risk` scores whichever of `threat_intel`, `reputation`, `ssl`, `headers`, `email_security` and `whois` you also requested, renormalizing over whatever is present. Its `cache_hit` is `true` only when *every* scoring input came from cache.

Technology fingerprinting is deterministic computation over the `headers` payload, so caching `headers` already caches fingerprint. Consequences:

- Requesting `headers` and `fingerprint` together fetches headers **exactly once**.
- Requesting `fingerprint` alone fetches and caches headers internally, but the `headers` object is not included in the response.
- `fingerprint.cache_hit` reflects where its headers input came from.
- Admin fingerprint-rule updates take effect immediately — there is no stale fingerprint TTL to wait out.

### Cache failures never fail a request

The cache is fail-open, matching the rate limiter:

| Failure | Behavior |
|---------|----------|
| Redis unreachable on read | All lookups treated as misses; logged; live lookups run |
| Corrupt or unreadable cached entry | Treated as a miss; logged; the live fetch overwrites the bad entry (self-healing) |
| Cache write fails | The lookup still succeeds and is returned; the write failure is logged |

Cache problems never appear in the response `errors` array — those are reserved for actual lookup failures.

