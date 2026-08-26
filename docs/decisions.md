# Decisions — Intelligence API

Things in this codebase that look removable and are not, with the reason attached.

The fleet's global instructions say *don't preserve complexity because it already exists*.
That rule is right, and it is dangerous on its own: some complexity is load-bearing, and
code cannot say so about itself. `domain.Resolver()` looks like a pointless wrapper around
`net.DefaultResolver` right up until you learn the global one broke every Postgres
connection the process later opened. This file is the counterweight — read it before
simplifying.

The bar for an entry: **would a competent engineer, seeing only the code, reasonably try to
undo this?** If yes, it belongs here. If the code explains itself, it does not. This is not
a design document and it is not a changelog.

<!--
  These entries were extracted from CLAUDE.md's "Key Design Decisions" section, where they
  were being loaded into every session whether or not they were relevant. Dates were not
  reconstructed — guessing them would be worse than omitting them. Entries added from here
  on carry the date they were made, newest first within their section.
-->

## Lookups and caching

### Failed lookups are never cached

**Decision.** A lookup that errors is retried on the next request. There is no negative
cache and no `redis.negative_cache_ttl` config key.

**Why.** Per-lookup TTLs removed the problem that key was compensating for. One flaky
provider can no longer shorten every other lookup's cache lifetime, because each lookup now
expires on its own schedule.

**Instead of.** Caching failures briefly to protect upstreams. That trades a real cost —
serving a stale failure to someone who would have gotten a good answer — for a saving that
per-lookup TTLs already deliver.

### `geo` and `asn` are never cached

**Decision.** Their runners set `uncached`, so they are excluded from the MGET pre-flight,
never written back, and always report `cache_hit: false`.

**Why.** They read a local MaxMind mmap. A Redis round trip costs more than recomputing
them. The old whole-document cache only stored them because they shared a key with RDAP.

**Instead of.** Caching them for consistency with every other lookup. Consistency is not
the goal; latency is, and here the cache is the slow path. This also deleted the "skip
caching when the GeoIP database is missing" special case — with geo uncached there is
nothing to skip.

### `fingerprint` has no cache key of its own

**Decision.** It is deterministic computation over `headers` data. Requesting `headers`,
`fingerprint`, or both creates exactly one headers runner, and `fingerprint.cache_hit`
mirrors the headers entry it was computed from.

**Why.** Caching `headers` already caches it. A separate entry would be a second copy of
derived data that can go stale independently.

**Instead of.** Giving it a key like every other lookup. That would also mean admin
fingerprint-rule updates sat behind a TTL instead of taking effect immediately.

### Redis stores the bare payload, never the response wrapper

**Decision.** Response types (`WhoisResult`, `DNSResult`, …) embed the payload type and add
`cache_hit`, which is set at assembly time. Only the embedded type is ever marshaled.

**Why.** `cache_hit` is a fact about *this request*. Persisting it would mean a cached
entry asserting it was a cache hit before it was ever read back.

**Instead of.** Storing the wrapper for convenience. The type embedding is what makes this
structurally impossible rather than merely avoided.

### Cache keys are flat and never re-normalized

**Decision.** `lookup:<domain>:<name>`, built by `cache.LookupKey()`. The builder does not
normalize; normalization is the handler's job.

**Why.** A missed normalization step surfaces as a distinct key — visibly wrong — rather
than being silently papered over at the cache layer.

**Instead of.** Defensive normalization in the key builder, or a composite key covering the
whole requested lookup set. The composite version meant two callers asking for overlapping
but different lookups shared nothing.

### Cache problems never fail a request

**Decision.** MGET error → treat everything as a miss. Corrupt entry → treat as a miss, and
the live fetch overwrites it. Failed SET → serve the result anyway. None of these ever reach
`resp.Errors`.

**Why.** The cache is an optimization. A request that could be served should not fail
because the optimization is unavailable. `resp.Errors` is reserved for real lookup failures,
so putting cache noise there would train callers to ignore it.

**Instead of.** Surfacing cache errors to the caller, which looks more honest and makes
Redis a hard dependency of every request. It also mixes two kinds of error in one field, and
the field callers actually act on is the one that then becomes noisy.

**Revisit if.** Cache failures ever become invisible for long enough to matter — they are
logged, and that is the only signal.

## Concurrency and failure

### Lookups use a scoped resolver, not `net.DefaultResolver`

**Decision.** `domain.Resolver()` returns an `atomic.Pointer[net.Resolver]` set by
`InitResolver`. Lookups that resolve user-supplied names use it. Infrastructure keeps using
the system resolver.

**Why.** Overriding `net.DefaultResolver` sent *every* resolution in the process to public
DNS, including the service's own connections to Postgres and Redis. Anything addressed by a
platform-internal name — a Compose service, a Kubernetes service, a Fly `.internal` address
— stopped resolving. Calling `InitResolver` after those connected only protected the initial
connections: `database/sql` recycles on `conn_max_lifetime`, and the replacements failed
with "no such host" (issue #62).

**Instead of.** Setting `net.DefaultResolver` once at startup, which is shorter and looks
equivalent. It is not — the blast radius is the entire process. `resolver_test.go` asserts
`InitResolver` installs no `Dial` hook on the global resolver, so this cannot regress
quietly.

**Revisit if.** The service stops depending on any name only the platform's resolver knows.

### Panic recovery happens inside the fetch, not at the goroutine boundary

**Decision.** Every lookup fetch runs behind `recoverFetch`, which degrades a panic to a
sanitized `internal error` on the response.

**Why.** A panic escaping into singleflight is re-raised in *every* coalesced caller.
Recovering at the goroutine boundary would let one bad lookup take down unrelated in-flight
requests.

**Instead of.** Relying on `gin.Recovery()`, which only covers the handler's own goroutine,
or recovering where the goroutine is spawned, which is too late.

### The shared singleflight fetch runs under `context.WithoutCancel`

**Decision.** The coalesced fetch detaches from the caller's context and reapplies the
service's own `lookupTimeout`.

**Why.** One caller disconnecting, or holding a tight deadline, must not cancel or truncate
work other callers are waiting on.

**Instead of.** Passing the first caller's context through. That makes the shared work
hostage to whichever request happened to arrive first.

### Coalesced callers each decode their own copy

**Decision.** Every caller unmarshals the shared payload into its own response value.

**Why.** Nobody shares a mutable pointer, so one caller mutating its result cannot corrupt
another's.

**Instead of.** Handing out the same decoded value and defending with a deep copy. This
replaced exactly that — the old `copyViaJSON` guard — by making the sharing impossible
rather than compensating for it.

### Screenshot concurrency defaults to 1

**Decision.** `screenshot.max_concurrent` defaults to **1**. The runner takes a semaphore
slot before running and reports a queue timeout if none frees up before the deadline.

**Why.** Each in-process Chromium wants roughly half a gigabyte. The previous default of 4
could exhaust a machine sized for the API and take the whole process down.

**Instead of.** A higher default for throughput. Throughput here is bounded by memory, not
by the cap — and the failure mode of getting it wrong is the process dying, not requests
being slow.

### Dependency injection: interfaces only where a second implementation is real

**Decision.** Lookups with one implementation and no state are function fields, swapped in
tests via setters. Collaborators that could plausibly have a second implementation get an
interface — `cache.Cache`, `notifications.Notifier`, `usage.Recorder`, `billing.Service`,
`domain.ThreatIntelProvider`, `domain.ScreenshotProvider`.

**Why.** The test is whether an alternative is *real*, not whether one is imaginable.
Screenshots earned an interface because a hosted provider is a live option and local
Chromium cannot serve bulk capture at any affordable machine size.

**Instead of.** Wrapping everything in interfaces for symmetry. `LookupDNS` behind an
interface buys nothing and costs a layer of indirection at every call site.

## HTTP surface and API contract

### The lookup endpoint returns `{"results": [...]}`, not a bare array

**Decision.** Every response is a JSON object.

**Why.** Consistent with `{"error": "..."}`, and response-level fields can be added later
without breaking clients.

**Instead of.** Returning the array directly, which is tidier and permanently unextendable.

### `handler.New` takes a `Deps` struct

**Decision.** One struct, every field optional, a nil service making its endpoints return
503 rather than panicking.

**Why.** Most fields are nilable and several share a type, so a misordered positional
argument list would have compiled silently. Naming them also documents which surfaces a
given Handler serves.

**Instead of.** `New(nil, nil, nil, nil, nil, nil, nil, nil, rc, nil, nil, nil)`. Adding a
dependency is now additive; every existing call site is untouched.

### SSRF is blocked at the dialer, after DNS resolution

**Decision.** `safenet.DialControl` rejects private, loopback, link-local, multicast,
unspecified, and reserved addresses at connect time. All HTTP clients in `domain` use it via
the shared transports in `domain/transport.go`.

**Why.** Checking after resolution means there is no TOCTOU window between validating a
hostname and connecting to it.

**Instead of.** Validating the URL or hostname before the request. A name that resolves to
a private address passes that check and connects anyway.

### The 404 page never echoes the requested path

**Decision.** `Handler.NotFound` renders a static page. Paths under `/v1` or `/billing` get
the JSON error envelope instead, so a mistyped endpoint lands in a caller's existing error
path.

**Why.** Reflecting caller-chosen text onto our own domain is a phishing primitive.

**Instead of.** The conventional "no such page: /foo", which is friendlier and turns the
domain into a rendering surface for arbitrary attacker-supplied strings.

## Docs pages

### `docsPages` is the canonical page set

**Decision.** One table in `docs.go`. Routes are registered by looping it, and the tests
derive their page lists from it.

**Why.** The set was previously spelled out in the router, twice in `docs_test.go`, twice
more in `docs_layout_test.go`, and in every template's topbar nav. Adding `/docs/account`
meant finding all six by hand.

**Instead of.** Listing pages where they are used. Tests that apply to only *some* pages
select rather than re-list — `docsPagesWithLanguageTabs()` — so a page that gains a Go
example gets it compiled without anyone remembering.

### Every table is wrapped in `.table-scroll`, and grid tracks use `minmax(0, 1fr)`

**Decision.** Both are pinned by tests in `docs_layout_test.go`.

**Why.** Both are invisible at a desktop viewport and made every page unreadable on a phone.
`width: 100%` on a table is a floor, not a ceiling: when the columns' min-content widths
exceed the container, the table grows past it and takes the document's scroll width with it.
A bare `1fr` track floors at the widest item's min-content — the unbreakable base URL — and
`.hero-card` clips its overflow, so hero copy was cut off mid-sentence.

**Instead of.** Trusting `width: 100%` and `1fr` to mean what they appear to mean. They do
not, and nothing on a desktop screen tells you.

### The copy button and page search are injected by `docs.js`, never written into templates

**Decision.** Pinned by `docs_controls_test.go`, which fails if either control's class names
appear in a template or diverge between script and stylesheet.

**Why.** Markup for either one is left behind when the script does not run — a dead control
on a page that is otherwise readable static HTML. A search index authored by hand drifts
from tables that are edited constantly.

**Instead of.** Putting the button in the markup. It also must live in the `.code-block`
wrapper rather than inside the `<pre>`: a `<pre>` is its own horizontal scroll container, so
a control inside one slides away with the code exactly when a 40-line payload is hardest to
select.

## Operations

### `feature_usage` counts requested lookups, not served ones

**Decision.** The usage middleware records what the caller asked for, regardless of whether
it came from cache. `cache_hits`/`cache_misses` are separate counters on `request_log`.

**Why.** A cache hit must not make a feature look less used. Those are different questions
and were previously answered by the same number.

**Instead of.** Counting upstream work, which measures cost rather than demand.

### `usage.LookupColumns` is asserted to match `domain.AllLookupNames`

**Decision.** A test fails when they diverge.

**Why.** A new lookup that nobody added a column for fails loudly in CI rather than silently
in production, where the symptom is a feature that appears unused forever.

**Instead of.** A checklist entry in the "adding a lookup" docs. Checklists are followed
until they are not, and this failure is undetectable by anyone reading the diff.

### `sactl` enforces `--allow-writes` at each mutation site

**Decision.** `requireWrites` is called at every point that changes deployed state, rather
than threading a field through commands.

**Why.** A path that forgot to check a field would be silently unguarded. There is one
function to consult instead.

**Instead of.** A `dryRun bool` on the command struct — the standard approach, and one where
the failure mode is invisible.

### `sactl` parses `.env` rather than sourcing it

**Decision.** The CLI reads and parses the file itself.

**Why.** Connection strings contain `&`, which a shell treats as a background operator,
truncating the value at the first query parameter. `scripts/status.sh` works around the same
problem by grepping individual keys out of the file.

**Instead of.** `source .env` or `set -a; . ./.env`, which is what everyone reaches for
first. It does not error — it silently hands you a connection string cut off at the first
`&`, and the failure appears later as an authentication error against the wrong database.

### The smoke test and docker reset are deliberately not in `sactl`

**Decision.** `scripts/smoke-test.sh` and `scripts/docker-reset.sh` are the single source of
truth for both.

**Why.** They existed in `sactl` briefly and were removed. Two implementations of the same
procedure drift, and the one you are not looking at is the one that is wrong.

**Instead of.** Folding them in for a single operator entry point, which is a real
convenience and the reason it was tried once already. If the CLI should run them, it should
shell out to the scripts rather than reimplement them.

### The Fly volume is chowned by the entrypoint, running as root then dropping

**Decision.** `docker-entrypoint.sh` chowns the mount as root, then execs the app as
`appuser` via `su-exec`. The container sets no `USER`.

**Why.** Fly volumes mount root-owned and Fly offers no uid/gid option. Without this step the
GeoIP download fails with permission denied on every boot — **silently**.

**Instead of.** Setting `USER appuser` in the Dockerfile, which is the correct default
everywhere else and produces a service that looks healthy while never populating its
database.

### A missing GeoIP database does not degrade `/v1/health`

**Decision.** Postgres or Redis down returns 503. Missing GeoIP does not.

**Why.** It self-bootstraps at startup and is absent for the first few seconds of a cold
start. Degrading on it would page someone for normal startup, every time.

**Instead of.** Treating every dependency uniformly, which reads as more rigorous and
produces an alert that fires on every deploy until people mute it. A missing GeoIP database
is also classified in `isExpectedError` for the same reason.
