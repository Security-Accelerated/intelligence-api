# Intelligence API — Domain Lookup

A single API call that pulls together everything you'd normally have to check across a dozen different tools and browser tabs. Submit one or more domains and get back a consolidated intelligence picture in seconds.

## What It Does

You POST a list of domains. The API runs all lookups concurrently and returns a single structured response with everything it found. Each lookup is independent — if one fails (WHOIS times out, for example), the rest still come back. Failures show up in an `errors` array so you know what's missing.

Results are cached for 60 minutes. The `cache_hit` field tells you whether you're looking at live data or a cached result.

### Base Lookups (always included)

**WHOIS — Registration & Ownership**
Who registered the domain, when, through which registrar, and when it expires. Includes registrant/admin/tech contacts when available (often redacted behind WHOIS privacy). Useful for attribution, timeline analysis, and spotting freshly registered domains.

**DNS — Name Resolution**
A records (IPv4), AAAA (IPv6), MX (mail servers), NS (nameservers), TXT (SPF, verification tokens), and CNAME (aliases). Shows you where the domain actually points, who handles its email, and who controls its DNS. Dangling CNAMEs and nameserver changes are common indicators of compromise or hijacking.

**SSL/TLS — Certificate Details**
The HTTPS certificate: who issued it, what hostnames it covers (SANs), when it was issued, when it expires, and the crypto algorithm. Expired certs, unusual issuers, or SANs that reveal related infrastructure all tell a story.

**HTTP Headers — Server Response & Security Posture**
Status code, raw response headers, and a security header audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). Headers leak server software, CDN info, and caching behavior. The security audit shows how seriously the operator takes browser-side defenses.

### Optional Lookups (request by setting the flag to `true`)

**Email Security** — Checks SPF, DMARC, and DKIM records via DNS. SPF defines which servers are authorized to send mail for the domain. DMARC sets the policy for what happens when authentication fails (none/quarantine/reject). DKIM probes 8 common selectors for signing keys. A domain with `p=none` or no DMARC at all is easy to spoof.

**Subdomains** — Enumerates subdomains via Certificate Transparency logs. Returns up to 500 deduplicated results. Reveals infrastructure you might not find otherwise: staging environments, internal tools, forgotten services.

**Certificate Transparency Logs** — Full certificate history from CT logs: every cert ever issued for the domain, sorted newest-first. Shows issuance patterns, which CAs are in use, and can surface unexpected certificates that indicate phishing infrastructure or unauthorized issuance.

**BGP/ASN** — Resolves the domain's IPs and maps them to Autonomous System Numbers via Team Cymru. Returns ASN, IP prefix, country, registry, and organization. Tells you who's actually hosting the infrastructure. Useful for identifying bulletproof hosting, shared infrastructure, and pivot analysis.

**Technology Fingerprinting** — Detects web servers, frameworks, CDNs, CMS platforms, and programming languages from the HTTP response headers already fetched (no extra requests). Returns technology name, category, version when extractable, and what signal matched (header or cookie). Covers ~90 technologies out of the box.

**Screenshot** — Captures a PNG screenshot of the page using headless Chrome at 1280x720. Tries HTTPS first, falls back to HTTP. Returned as base64-encoded data.

**Reputation** — Checks the domain against four DNS-based blocklists concurrently (Spamhaus DBL, SURBL, URIBL, Spamhaus ZEN) and computes a risk score from 0 (clean) to 100 (maximum risk). Each provider result includes whether the domain is listed and the category (phishing, malware, spam, botnet C2, etc.).

**Threat Intel** — Queries VirusTotal, URLhaus (Abuse.ch), and AlienVault OTX for threat intelligence data on the domain. Returns malware detections, campaign attribution, and indicator of compromise (IOC) details. Each source is queried concurrently and results are merged into a unified view: detection ratios, malware families, associated campaigns, and last-seen timestamps. Pro and admin plans only.

## How To Use It

### Basic lookup

```sh
curl -X POST https://api.securityaccelerated.com/v1/domain/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-api-key' \
  -d '{"domains": ["suspicious-domain.com"]}'
```

Returns WHOIS, DNS, SSL, and HTTP headers for the domain.

### Full investigation

```sh
curl -X POST https://api.securityaccelerated.com/v1/domain/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-api-key' \
  -d '{
    "domains": ["suspicious-domain.com"],
    "email_security": true,
    "subdomains": true,
    "ct_logs": true,
    "bgp": true,
    "fingerprint": true,
    "reputation": true,
    "screenshot": true,
    "threat_intel": true
  }'
```

Returns everything the API can gather on the domain in a single call.

### Multiple domains at once

```sh
curl -X POST https://api.securityaccelerated.com/v1/domain/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-api-key' \
  -d '{
    "domains": [
      "suspicious-domain.com",
      "related-domain.net",
      "another-lead.org"
    ],
    "bgp": true,
    "fingerprint": true
  }'
```

All domains are looked up concurrently. You get back an array with one result per domain. Invalid domains don't fail the whole request — they come back with a validation error while the valid ones still return data.

Domain input is flexible: raw domains, URLs with `http://`/`https://` prefixes, trailing slashes — all normalized automatically.

## Example Response

```json
[
  {
    "domain": "example.com",
    "cache_hit": false,
    "whois": {
      "domain_name": "EXAMPLE.COM",
      "registrar": "RESERVED-Internet Assigned Numbers Authority",
      "created_date": "1995-08-14T04:00:00Z",
      "updated_date": "2024-08-14T07:01:38Z",
      "expiry_date": "2025-08-13T04:00:00Z",
      "status": ["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"],
      "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
    },
    "dns": {
      "a": ["93.184.216.34"],
      "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
      "mx": [{"host": ".", "priority": 0}],
      "ns": ["a.iana-servers.net", "b.iana-servers.net"],
      "txt": ["v=spf1 -all"]
    },
    "ssl": {
      "subject": "www.example.org",
      "issuer": "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
      "not_before": "2024-01-30T00:00:00Z",
      "not_after": "2025-03-01T23:59:59Z",
      "expired": false,
      "days_until_expiry": 180,
      "sans": ["www.example.org", "example.net", "example.edu", "example.com", "www.example.com"],
      "serial_number": "0F:BE:08:B0:85:4D:05:73:8A:B0:CC:E1:C9:AF:EE:C8",
      "signature_algorithm": "SHA256-RSA"
    },
    "headers": {
      "status_code": 200,
      "headers": {
        "Content-Type": "text/html; charset=UTF-8",
        "Server": "ECAcc (dcd/7D5A)",
        "Cache-Control": "max-age=604800"
      },
      "security_headers": {
        "x_content_type_options": "nosniff",
        "x_frame_options": "DENY"
      }
    },
    "email_security": {
      "spf": {
        "raw": "v=spf1 -all",
        "version": "spf1",
        "mechanisms": [],
        "all": "-all"
      },
      "dmarc": {
        "raw": "v=DMARC1; p=reject; sp=reject",
        "version": "DMARC1",
        "policy": "reject",
        "sp": "reject"
      },
      "dkim": [
        {"selector": "google", "found": false},
        {"selector": "default", "found": false}
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
      "count": 1,
      "technologies": [
        {"name": "Edgecast CDN", "category": "cdn", "version": "", "confidence": "header"}
      ]
    },
    "errors": []
  }
]
```

## What You're Looking At — Quick Reference

| Section | Key Questions It Answers |
|---------|-------------------------|
| **whois** | Who owns this? When was it registered? Is it about to expire? Who's the registrar? |
| **dns** | Where does it point? Who handles its mail? Who controls its DNS? Any suspicious aliases? |
| **ssl** | Is the cert valid? Who issued it? What other hostnames share this cert? |
| **headers** | What's the server running? Is it behind a CDN? What security defenses are in place? |
| **email_security** | Can this domain be spoofed? What's the DMARC policy? Is SPF configured correctly? |
| **subdomains** | What other subdomains exist? Any staging/dev/internal services exposed? |
| **ct_logs** | What certificates have been issued? Any unexpected issuers? What's the issuance pattern? |
| **bgp** | Who's hosting this? What country? Is it a known bulletproof hoster? Same ASN as other targets? |
| **fingerprint** | What web technologies are running? What server/framework/CDN/CMS? What version? |
| **reputation** | Is this domain on any blocklists? What category (phishing, malware, spam, botnet)? |
| **threat_intel** | Any malware detections? What campaigns is it tied to? What IOCs are associated? |
| **screenshot** | What does the page actually look like? |

## Partial Failures

If a single lookup fails (say WHOIS times out or a CT log query errors), the rest of the response still comes back. The failed lookup appears in the `errors` array:

```json
{
  "domain": "example.com",
  "cache_hit": false,
  "whois": null,
  "dns": {"a": ["93.184.216.34"], "...": "..."},
  "ssl": {"subject": "...", "...": "..."},
  "headers": {"status_code": 200, "...": "..."},
  "errors": [
    {"lookup": "whois", "message": "lookup timed out"}
  ]
}
```

You always get what's available. Nothing blocks on a single failure.
