---
paths:
  - "internal/service/**"
  - "internal/cache/**"
  - "internal/notifications/**"
---

# Service layer: fan-out, caching, failure

The *why* behind each of these is in `docs/decisions.md` under "Lookups and caching" and
"Concurrency and failure". This file is what to do; read that before undoing any of it.

## Shared runner core — `internal/service/runner.go`

Both `DomainService` and `IPService` run on the same machinery: `lookupRunner`,
`fetchResult`, `runState`, the runner constructors, panic recovery, the MGET pre-flight,
and the singleflight + SET fan-out. `runState` is target-agnostic — a target string, a
field name for logs, and a `keyFor` closure — so the domain service supplies
`lookup:<domain>:<name>` keys and the IP service supplies `ip:<ip>:<name>`. Each service
keeps only what is specific to it: which lookups exist, how they are fetched, how the
response is assembled.

Per-lookup wiring is one line each: `simpleRunner` for a single result, `multiErrRunner`
for fan-out lookups (reputation, threat intel) that return partial results alongside
per-provider errors. A runner may set `uncached` to opt out of Redis entirely.

## The request path

`service.Lookup()` builds a runner per requested lookup, issues **one MGET** over all their
keys, decodes the hits, and spawns goroutines **only for the misses**, under a `sync.Mutex`
on shared state. Each goroutine writes its own result back with
`SET key json EX <per-lookup TTL>` on success. Failures are never written. Assembly happens
after `wg.Wait()`, tagging each field with where it came from. A 30-second context timeout
covers reads, lookups, and writes together.

## Singleflight

Concurrent fetches of the same lookup for the same target coalesce into one upstream call
(`golang.org/x/sync/singleflight`). Keying is **per lookup per target**, so requests with
overlapping-but-different lookup sets still share the overlap. The shared fetch runs under
`context.WithoutCancel` with `lookupTimeout` reapplied. Coalesced callers each decode the
shared payload into their own value — nobody shares a pointer. There is no whole-response
coalescing anywhere; `service/whole_response.go` is gone and must not come back.

## Failure handling

- **Panics** are recovered inside the fetch by `recoverFetch` (the IP service's `goLookup`
  helper does the same), degrading to a sanitized `internal error` on the response.
  `gin.Recovery` only covers handler goroutines. Do not move recovery to the goroutine
  boundary.
- **Lookup errors** go to `resp.Errors` with sanitized messages; the rest of the response
  still returns. Full errors are logged server-side.
- **Cache problems never reach `resp.Errors`.** MGET error → all misses. Corrupt entry →
  miss, and the live fetch overwrites it. Failed SET → still served, logged.

## Cache rules

- Keys are flat: `lookup:<domain>:<name>` / `ip:<ip>:<name>` (e.g.
  `lookup:example.net:ssl`), built by `cache.LookupKey()` with the `cache.LookupKeyPrefix`
  constant. The builder **does not normalize** — that is the handler's job.
- Redis stores the **bare payload only**. Response wrappers embed the payload type and add
  `cache_hit`, set at assembly time; only the embedded type is ever marshaled.
- TTLs come from `cache.default_ttl` + `cache.ttl.<name>` via `config.CacheTTLs()`, which
  reads each key individually so `CACHE_TTL_WHOIS` and friends work through Viper's
  `AutomaticEnv`. Pulling the subtree as a map silently drops env overrides.
- Expiry is absolute. There is no stale serving and no negative cache.
- `geo` and `asn` are `uncached`. `fingerprint` has no key of its own — it is computed
  from `headers` at assembly, and its `cache_hit` mirrors the headers entry.

## Adding a lookup

Runner in `buildRunners()`, branch in `assemble()`, function field + setter on the service.
The full multi-file checklist is the `adding-features` skill; use it rather than
reconstructing the list.

## Notifications — `internal/notifications`

`Notifier` abstracts delivery (Pushover); `ErrorRecorder` abstracts tracking (`Alerter`).
The alerter uses sliding-window counters to detect per-lookup throttling (5 failures / 5m)
and global spikes (15 errors / 5m), with a 15-minute cooldown. `DomainService` depends on
`ErrorRecorder`; with no Pushover credentials it gets `NoopRecorder`. Config:
`PUSHOVER_API_TOKEN`, `PUSHOVER_USER_KEY`, `ALERTS_THROTTLE_THRESHOLD`,
`ALERTS_THROTTLE_WINDOW`, `ALERTS_SPIKE_THRESHOLD`, `ALERTS_SPIKE_WINDOW`,
`ALERTS_COOLDOWN`.
