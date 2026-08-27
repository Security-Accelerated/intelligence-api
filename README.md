# Security Accelerated
## Intelligence API

A domain intelligence API that performs concurrent WHOIS, DNS, SSL, HTTP header, page screenshot, reputation, email security, subdomain enumeration, certificate transparency, BGP/ASN, technology fingerprinting, and threat intelligence lookups for one or more domains, with Redis caching.

**Production URL:** `https://api.securityaccelerated.com`

## Authentication

Most API endpoints require an API key passed via the `X-API-Key` header. Keys are stored in PostgreSQL as `hex(sha256(key))` and belong to a customer, who has a plan. A customer normally holds one live key, but holds several during a rotation grace window: `POST /v1/keys/rotate` issues a new key and leaves the previous ones authenticating until `auth.rotation_grace` (default 24h) elapses, so deployed clients can be switched over without downtime. The following routes are public (no API key required): `/` (redirect), `/docs`, `/docs/domain`, `/docs/ip`, `/docs/account`, `/docs/changelog`, `/docs/openapi.yaml`, `/v1/hello`, `/v1/health`, `/billing/webhook` (Stripe signature), and `/billing/success` (session token).

### Customer Plans

Each customer has a `plan` that controls rate limits, access to premium options, and admin access:

| Plan | Capabilities |
|------|-------------|
| `free` | All lookups except `screenshot`, `reputation`, and `threat_intel`. 1 domain per request. |
| `pro` | All free capabilities + page screenshots + reputation checks + threat intelligence, up to 20 domains per request |
| `admin` | All pro capabilities + admin endpoints (info, fingerprint management, cache invalidation) + no rate limit |

The plan is stored in the `customers` table, defaulting to `free`. New customers provisioned via Stripe checkout receive the plan they purchased. An unrecognized plan value is treated as `free` by both the rate limiter and lookup gating, so a bad value fails closed.

Requests without a valid key receive `401 Unauthorized`. Requests from non-admin plans to admin-only endpoints receive `403 Forbidden`. Requests naming a lookup outside the caller's plan (`screenshot`, `reputation`, `threat_intel` require pro) receive `403 Forbidden`. The `/v1/hello` and `/v1/health` checks require no authentication. Self-service endpoints (`GET /v1/usage`, `POST /v1/keys/rotate`) are available to every plan.

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
| POST | `/v1/admin/geoip/refresh` | `admin` | Download and reload MaxMind GeoIP databases |
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
| `screenshot` | **Pro** | Page screenshot as a base64 PNG |
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

Each result contains exactly the lookups you requested — plus `domain`, `inputs`, and `errors` — and nothing else.

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
      "screenshot": { "cache_hit": false, "status_code": 200, "png": "<base64-encoded PNG>" },
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
      },
      "errors": []
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
| `403` | Lookup not included in the caller's plan | `screenshot requires a pro plan` |
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

### `screenshot` — Page Screenshot (Pro/Admin Only)

A visual screenshot of the domain's web page, captured with headless Chrome at 1280x720. Only present when `"screenshot"` is included in `lookups`.

| Field | What it means |
|-------|---------------|
| `status_code` | The HTTP status code from probing the domain. The screenshot only captures the page on `200 OK`. |
| `png` | Base64-encoded PNG image of the page. Empty for non-200 responses. |

The screenshot lookup first tries HTTPS, then falls back to HTTP. Non-200 responses still populate the `screenshot` section with the status code but no image data.

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
| `geo` | All | Country, city, region, coordinates, timezone (MaxMind GeoLite2) |
| `asn` | All | ASN number, organization, network (MaxMind GeoLite2 ASN) |
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
      "asn": { "cache_hit": false, "asn": 15169, "organization": "GOOGLE" },
      "reverse_dns": { "cache_hit": true, "hostnames": ["dns.google"] },
      "errors": []
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
| `geo` | GeoIP: country, city, region, coordinates, timezone (MaxMind GeoLite2) |
| `asn` | ASN number, organization, network (MaxMind GeoLite2 ASN) |
| `reverse_dns` | PTR record hostnames |
| `abuse_contact` | Network owner, country, abuse email (via RDAP) |
| `threat_intel` | Aggregated threat intelligence with risk score and per-provider results |
| `errors` | Per-lookup errors (partial failures still return other fields) |

#### `geo` and `asn` are never cached

Both read a local MaxMind memory-mapped database with no network call, so a Redis round trip would cost *more* than simply doing the lookup again. They are recomputed on every request and their `cache_hit` is always `false` — which is accurate, since the data really was produced for that request. Only `reverse_dns`, `abuse_contact` and `threat_intel` get cache entries.

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

Internal/ops endpoint for load balancers and uptime monitoring. Returns component states only — never addresses, versions, or other internals. Postgres or Redis being down returns `503` with `status: "degraded"`; GeoIP databases are optional, so their state is reported but does not degrade overall health.

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
    "screenshot": 45, "reputation": 120, "threat_intel": 95, "email_security": 310,
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
| `lookups` | Lookup timeout, screenshot config, subdomain/CT log limits, rate limits and max domains per plan |
| `services` | Notifications (enabled + alert config), billing (enabled + config), threat intel (provider names), fingerprint (source + rule count), usage (buffer config) |
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
| `screenshot` | 60m |
| `dns_security` | 4h |
| `reverse_dns` *(IP)* | 6h |
| `abuse_contact` *(IP)* | 24h |
| `geo`, `asn` *(IP)* | never cached — local database reads |
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

Every config key can be overridden by an environment variable: replace dots with underscores and uppercase (e.g. `server.write_timeout` → `SERVER_WRITE_TIMEOUT`). Environment variables take precedence over the YAML file. All active config values plus live runtime metrics are visible at `GET /v1/info` (admin only) — see the [Application Status](#get-v1info--application-status-admin-only) section for the full response structure.

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
| `cache.ttl.<lookup>` | see [Caching](#ttls) | Per-lookup cache TTL, e.g. `cache.ttl.whois: 24h` (env: `CACHE_TTL_WHOIS`) |
| `gin.mode` | `""` | Gin framework mode (`debug`, `release`, `test`) |
| `auth.cache_ttl` | `5m` | TTL for in-memory auth cache |
| `auth.rotation_grace` | `24h` | How long old keys keep working after `POST /v1/keys/rotate` |
| `auth.last_used_buffer_size` | `256` | Buffer size for batched last_used_at updates |
| `auth.last_used_flush_interval` | `10s` | How often last_used_at updates are flushed to PostgreSQL |
| `screenshot.timeout` | `15s` | Timeout for page screenshot capture (probe + render) |
| `screenshot.max_png_bytes` | `5242880` | Maximum screenshot PNG size in bytes (5 MB) |
| `screenshot.max_concurrent` | `4` | Global cap on concurrent Chromium screenshot processes |
| `subdomain.max_results` | `500` | Maximum number of subdomains returned per domain |
| `subdomain.max_response_bytes` | `10485760` | Maximum crt.sh response body size in bytes (10 MB) |
| `subdomain.http_timeout` | `15s` | End-to-end timeout for the crt.sh subdomain request |
| `ct_logs.max_entries` | `100` | Maximum number of CT log entries returned per domain |
| `ct_logs.http_timeout` | `15s` | End-to-end timeout for the crt.sh CT logs request |
| `threat_intel.virustotal_api_key` | `""` | VirusTotal API key (enables VirusTotal provider) |
| `threat_intel.alienvault_api_key` | `""` | AlienVault OTX API key (enables AlienVault provider) |
| `dns.servers` | `[]` | External DNS resolvers (default: Google, Cloudflare, OpenDNS) |
| `dns.timeout` | `30s` | Per-server DNS dial timeout |
| `maxmind.license_key` | `""` | MaxMind license key for GeoIP database downloads |
| `maxmind.db_path` | `/data/maxmind` | Directory path for MaxMind GeoLite2 database files |
| `maxmind.city_db` | `GeoLite2-City.mmdb` | MaxMind city database filename |
| `maxmind.asn_db` | `GeoLite2-ASN.mmdb` | MaxMind ASN database filename |
| `maxmind.max_age` | `168h` | Re-download databases older than this at startup; `0` pins whatever is on disk |
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
| `MAXMIND_LICENSE_KEY` | MaxMind license key (required for the startup download and `POST /v1/admin/geoip/refresh`). Docker Compose reads it from `.env`; without it `geo` and `asn` are unavailable locally |
| `MAXMIND_DB_PATH` | Directory for MaxMind .mmdb files (default: `/data/maxmind`) |
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
