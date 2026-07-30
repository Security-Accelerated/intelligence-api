# Security Accelerated Intelligence API

## Know more about any domain or IP in seconds.

The Intelligence API gives your team instant, comprehensive visibility into any domain's or IP address's security posture, infrastructure, and risk profile — all from a single API call.

---

### The Problem

Security teams waste hours manually checking domains and IPs across dozens of disconnected tools. When a suspicious link lands in an employee's inbox, when a new vendor needs vetting, when a suspicious IP appears in your logs, or when a brand impersonation attempt surfaces — the clock is ticking and the answers are scattered.

### The Solution

One API. One call. Every signal that matters.

Submit a domain or IP address and get back a complete intelligence profile in seconds. For domains: who owns it, where it's hosted, whether its certificates are valid, how its email security is configured, whether it appears on threat blocklists, what subdomains exist, what technologies it runs, whether it's linked to known malware campaigns, and even a visual screenshot of the page. For IPs: geolocation, ASN ownership, reverse DNS, abuse contacts, and threat intelligence. Batch multiple domains or IPs in a single request. Results are cached for fast repeat lookups.

---

## What You Get

### Domain Intelligence
The core lookup returns WHOIS registration, DNS records, SSL certificate details, and HTTP security headers — concurrently, for one or more domains at once.

- **WHOIS** — Registrar, creation date, expiry, ownership contacts. Spot newly registered domains, expiring infrastructure, and ownership changes.
- **DNS** — A, AAAA, MX, NS, TXT, and CNAME records. See where a domain points, who handles its email, and whether it uses a CDN.
- **SSL/TLS** — Certificate issuer, expiry, subject alternative names, signature algorithm. Detect expired certificates, weak algorithms, and shared hosting.
- **HTTP Headers** — Status codes, server headers, and a full security header audit (HSTS, CSP, X-Frame-Options, and more).

### Email Security Analysis
Audit a domain's email authentication posture: SPF, DMARC, and DKIM. See exactly how a domain is configured to prevent spoofing — or whether it's left wide open.

### Domain Reputation
Check domains against multiple DNS-based threat intelligence feeds (Spamhaus, SURBL, URIBL) and get a computed risk score from 0 to 100 with a clear risk level: clean, low, medium, or high.

### Threat Intelligence
Query multiple threat intelligence sources — VirusTotal, URLhaus (Abuse.ch), and AlienVault OTX — in a single call. Get malware detection verdicts, campaign attribution from known threat actors, and community threat pulses. Know whether a domain is actively distributing malware, part of a botnet, or flagged by the security research community.

### Page Screenshots
Capture a visual screenshot of any domain's web page with headless Chrome. See what users see without visiting the site. Invaluable for phishing investigations and brand monitoring.

### Subdomain Enumeration
Discover subdomains via Certificate Transparency logs. Find forgotten infrastructure, staging environments, and shadow IT — the entry points attackers look for first.

### Certificate Transparency Logs
Query CT logs for every certificate ever issued for a domain. Track certificate issuance patterns, detect unauthorized certificates, and identify related infrastructure through shared certificates.

### BGP/ASN Enrichment
Map domains to their hosting infrastructure via IP-to-ASN lookups. Identify hosting providers, detect bulletproof hosting, and perform pivot analysis across shared autonomous systems.

### Technology Fingerprinting
Detect web servers, frameworks, CDNs, CMS platforms, and programming languages from HTTP response headers — with zero extra network requests. Identify technology stacks for vulnerability assessment and attack surface mapping.

### IP Intelligence
Profile any public IP address with a single call. Get geolocation (country, city, coordinates), ASN ownership, reverse DNS hostnames, and abuse contact information via RDAP. Add threat intelligence to check if an IP is associated with known malicious activity across VirusTotal, URLhaus, and AlienVault OTX. Powered by MaxMind GeoLite2 databases with hot-reload support.

---

## How It Works

```http
POST /v1/domain/lookup
{
  "domains": ["example.com"],
  "lookups": [
    "whois", "dns", "ssl", "headers",
    "reputation", "email_security", "screenshot", "subdomains",
    "ct_logs", "bgp", "fingerprint", "threat_intel"
  ]
}
```

```http
POST /v1/ip/lookup
{
  "ips": ["8.8.8.8"],
  "threat_intel": true
}
```

That's it. One request, one comprehensive response.

---

## Built for Integration

- **RESTful JSON API** — works with any language, any platform
- **Batch requests** — submit multiple domains in a single call
- **Modular lookups** — name exactly the data you need, pay for nothing else
- **Per-lookup caching** — each lookup caches on its own schedule, so repeat requests return instantly regardless of the combination
- **Rate limit headers** — build backoff logic without guessing
- **Request correlation** — pass your own request ID for end-to-end tracing

---

## Plans

| Capability | Free | Basic | Pro |
|-----------|------|-------|-----|
| Domain lookup (WHOIS, DNS, SSL, headers) | Included | Included | Included |
| IP lookup (GeoIP, ASN, reverse DNS, abuse contact) | Included | Included | Included |
| Email security (SPF, DMARC, DKIM) | Included | Included | Included |
| Subdomain enumeration | Included | Included | Included |
| Certificate transparency logs | Included | Included | Included |
| BGP/ASN enrichment | Included | Included | Included |
| Technology fingerprinting | Included | Included | Included |
| Page screenshots | — | — | Included |
| Domain reputation scoring | — | — | Included |
| Threat intelligence (domain + IP) | — | — | Included |
| Rate limit | 5 req/min | 30 req/min | 120 req/min |
| Batch size (domains) | 1 | 5 | 20 |
| Batch size (IPs) | 1 | 5 | 20 |

---

## Use Cases

**Security Operations** — Triage suspicious domains from phishing reports, SIEM alerts, and threat feeds. Cross-reference against VirusTotal, URLhaus, and AlienVault OTX in the same call. Get the full picture in seconds instead of hours.

**Brand Protection** — Investigate domains impersonating your brand. Use subdomain enumeration, CT logs, and reputation scoring to assess threats.

**Vendor Risk Assessment** — Evaluate third-party domains for certificate hygiene, email authentication, and blocklist presence during procurement.

**Incident Response** — During an active incident, rapidly profile attacker infrastructure: hosting, registration, related subdomains, reputation, and known malware associations.

**Compliance & Audit** — Assess your own domains for security header compliance, email authentication, and certificate management.

---

## Get Started

Sign up at [api.securityaccelerated.com](https://api.securityaccelerated.com) and get your API key instantly. No SDK required — just HTTPS and JSON.

**Security Accelerated** — securityaccelerated.com
