# Security Accelerated Intelligence API

## Know more about any domain in seconds.

The Intelligence API gives your team instant, comprehensive visibility into any domain's security posture, infrastructure, and risk profile — all from a single API call.

---

### The Problem

Security teams waste hours manually checking domains across dozens of disconnected tools. When a suspicious link lands in an employee's inbox, when a new vendor needs vetting, or when a brand impersonation attempt surfaces — the clock is ticking and the answers are scattered.

### The Solution

One API. One call. Every signal that matters.

Submit a domain and get back a complete intelligence profile in seconds: who owns it, where it's hosted, whether its certificates are valid, how its email security is configured, whether it appears on threat blocklists, what subdomains exist, what technologies it runs, and even a visual screenshot of the page. Batch multiple domains in a single request. Results are cached for fast repeat lookups.

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

---

## How It Works

```
POST /v1/domain/lookup
{
  "domains": ["example.com"],
  "reputation": true,
  "email_security": true,
  "screenshot": true,
  "subdomains": true,
  "ct_logs": true,
  "bgp": true,
  "fingerprint": true
}
```

That's it. One request, one comprehensive response.

---

## Built for Integration

- **RESTful JSON API** — works with any language, any platform
- **Batch requests** — submit multiple domains in a single call
- **Modular options** — only request the data you need
- **Cached results** — repeat lookups return instantly
- **Rate limit headers** — build backoff logic without guessing
- **Request correlation** — pass your own request ID for end-to-end tracing

---

## Plans

| Capability | Basic | Pro |
|-----------|-------|-----|
| Domain lookup (WHOIS, DNS, SSL, headers) | Included | Included |
| Email security (SPF, DMARC, DKIM) | Included | Included |
| Subdomain enumeration | Included | Included |
| Certificate transparency logs | Included | Included |
| BGP/ASN enrichment | Included | Included |
| Technology fingerprinting | Included | Included |
| Page screenshots | — | Included |
| Domain reputation scoring | — | Included |
| Rate limit | 30 req/min | 120 req/min |
| Batch size (domain lookup) | 5 domains | 20 domains |

---

## Use Cases

**Security Operations** — Triage suspicious domains from phishing reports, SIEM alerts, and threat feeds. Get the full picture in seconds instead of hours.

**Brand Protection** — Investigate domains impersonating your brand. Use subdomain enumeration, CT logs, and reputation scoring to assess threats.

**Vendor Risk Assessment** — Evaluate third-party domains for certificate hygiene, email authentication, and blocklist presence during procurement.

**Incident Response** — During an active incident, rapidly profile attacker infrastructure: hosting, registration, related subdomains, and reputation.

**Compliance & Audit** — Assess your own domains for security header compliance, email authentication, and certificate management.

---

## Get Started

Contact us for an API key and start making calls in minutes. No SDK required — just HTTPS and JSON.

**Security Accelerated** — securityaccelerated.com
