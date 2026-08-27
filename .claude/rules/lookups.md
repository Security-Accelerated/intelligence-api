---
paths:
  - "internal/domain/**"
  - "internal/safenet/**"
  - "internal/handler/domain.go"
  - "internal/handler/ip.go"
  - "internal/handler/fingerprint.go"
  - "internal/handler/geoip_admin.go"
---

# Lookups: the domain package and its handlers

Rationale for the choices below is in `docs/decisions.md`. This file is the operating
contract.

## Selectable lookups — there are no defaults

`DomainRequest.Lookups []string` names exactly what runs. It is required and must be
non-empty after normalization. **The handler is the only place that resolves it**:
normalize (trim + lowercase + dedup) → require non-empty → validate names → validate plan →
build `domain.LookupOptions{Lookups}`. Everything downstream sees only normalized,
explicit names.

`internal/handler/domain.go` holds `lookupMinPlan`, one `map[string]plan` that drives both
name validation (400) and plan gating (403). Canonical names are constants in
`internal/domain/model.go` beside `AllLookupNames`. Adding a row to `lookupMinPlan` is what
makes a name valid — there is no bool to thread through request, options, or cache key.

Domains are normalized the same way (scheme/port/path stripped, trim + lowercase) and
deduplicated. Each response element reports the normalized `domain` plus the verbatim
`inputs` that mapped to it; **array position is not part of the API contract**. Plan
domain caps count submitted entries, not unique domains.

## IP lookups use the same model

`/v1/ip/lookup` takes the same `lookups` array and returns the same `{"results": [...]}`
envelope. `internal/handler/ip.go` validates with `netip.ParseAddr`, rejects
non-globally-routable addresses, and gates `threat_intel` to pro/admin. `ipLookupMinPlan`
is a separate table — `whois` is valid for a domain and a 400 for an IP. Keys live under
`ip:`, so `threat_intel` on the two endpoints cannot collide.

## Resolver — never `net.DefaultResolver`

`domain.Resolver()` returns the resolver lookups use: the external servers from
`InitResolver`, or the system resolver before that. It is an `atomic.Pointer[net.Resolver]`.
Use it wherever the target is a **name from user input**. Infrastructure — Postgres, Redis,
anything platform-internal — must keep using the system resolver. `resolver_test.go`
asserts `InitResolver` never touches the global; keep that test passing.

## SSRF — `internal/safenet`

`DialControl` rejects private, loopback, link-local, multicast, unspecified, and reserved
ranges (CGNAT, 0/8, 192.0.0.0/24, TEST-NET-1/2/3, 198.18.0.0/15, 240.0.0.0/4,
2001:db8::/32) **at dial time, after DNS resolution**. Core check is
`IsPrivateAddr(netip.Addr)`, which unmaps IPv4-mapped IPv6 first; `IsPrivateIP(net.IP)` is
the compatibility adapter. Every HTTP client in `domain` goes through
`safenet.SafeDialer()` via the shared transports in `domain/transport.go`. A new outbound
client that does not use those transports is a bug.

## Lookup-specific facts

- **Screenshot** — behind `domain.ScreenshotProvider` (`Name`, `Capture`).
  `ChromiumProvider` is the only implementation; `screenshot.provider` selects it and an
  unknown name fails startup. `DomainService.SetScreenshotProvider` wires it; the
  `lookupScreenshot` function field stays for tests.
- **Risk** — `internal/domain/risk.go`, `ComputeRiskScore`: weighted 0–100 from whatever is
  present (threat_intel 0.35, reputation 0.25, ssl / security_headers / email_security /
  domain_age 0.10 each), weights renormalized over present components. Runs as
  post-processing in `assemble()`; no network, no cache entry. `cache_hit` is true only
  when every input came from cache.
- **DNS security** — `internal/domain/dnssec.go`, raw DNS via `miekg/dns` against
  `domain.ActiveDNSServers()` because `net.Resolver` cannot query DS/DNSKEY/CAA. Truncated
  UDP retries over TCP. Tests run a local `miekg/dns` server.
- **Fingerprint** — `FingerprintEngine` holds rules behind `sync.RWMutex`; defaults are
  `go:embed`ed (~90 technologies). `FingerprintService` persists to the append-only
  `fingerprint_rules` table and loads the latest on startup. `GET/POST
  /v1/admin/fingerprints` hot-reloads rules without a redeploy. No cache key of its own —
  computed from `headers`, so rule updates take effect immediately.
- **Threat intel** — `ThreatIntelProvider` (`Name`, `Query`) fanned out by
  `LookupThreatIntel`. Providers: VirusTotal (v3, 4 req/min), URLhaus (free, always on),
  AlienVault OTX (10 req/s). Each uses `safeTransport` and `golang.org/x/time/rate`.
  `ScoreThreatIntel()` weights VT 0.5 / URLhaus 0.3 / OTX 0.2 → none/low/medium/high/
  critical. Built conditionally in `app.go`: URLhaus always, VT and OTX when
  `THREAT_INTEL_VIRUSTOTAL_API_KEY` / `THREAT_INTEL_ALIENVAULT_API_KEY` are set. Pro/admin
  only.
- **IP intelligence** — `GeoIPReader` holds MaxMind City + ASN behind `sync.RWMutex` with
  atomic `Reload()`; `DownloadAndReload()` fetches with `MAXMIND_LICENSE_KEY`. `ip_rdns.go`
  does PTR via `domain.Resolver()`; `ip_rdap.go` queries `rdap.org/ip/` for abuse contacts.
  `ip_threatintel.go` defines `IPThreatIntelProvider` and the adapters (`VTIPProvider`,
  `URLhausIPProvider`, `OTXIPProvider`) that wrap the domain providers, sharing their
  clients and limiters. `internal/app/geoip.go` opens databases at startup and downloads
  in the background when missing, unreadable, or older than `maxmind.max_age` (168h) — the
  ~80MB download must never block the listener. `planGeoIP` isolates the load/download
  decision so it is testable without network. Config: `MAXMIND_LICENSE_KEY`,
  `MAXMIND_DB_PATH`, `IP_LOOKUP_TIMEOUT`, `IP_MAX_IPS_FREE` / `_BASIC` / `_PRO`.

## Error text

`sanitizeErr()` strips internals before anything reaches a response. `safenet.BlockedError`
gets a specific friendly message; others are truncated to the final `: ` segment. The
full error chain is logged server-side for diagnosis — the error, never the request
payload, response body, or any credential it may have carried.

## Adding a lookup type

Use the `adding-features` skill. It lists every file, including the `usage.LookupColumns`
row and migration that a drift test will otherwise fail on.
