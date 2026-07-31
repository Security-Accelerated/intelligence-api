---
name: adding-features
description: Step-by-step checklists for adding a new lookup type or a new endpoint to the Intelligence API, covering every file that must change including tests, migrations, config, and docs.
---

# Adding features to the Intelligence API

These checklists exist because both changes touch many files, and missing one
surfaces late — usually as a drift test failing in CI or a stale docs surface.

## Adding a New Lookup Type

1. Create `internal/domain/newlookup.go` with a function matching the pattern: `func LookupThing(ctx context.Context, domain string) (*ThingInfo, error)`
2. Add the payload type (`ThingInfo`) and its response wrapper (`ThingResult` — embeds `*ThingInfo`, adds `cache_hit`) to `internal/domain/model.go`, plus a `LookupThingName` constant and an entry in `AllLookupNames`
3. Add the field to `DomainResponse`
4. Add a function field to `DomainService` in `internal/service/domain.go` and wire it in `NewDomainService()`
5. Add a runner in `buildRunners()` (one `simpleRunner`/`multiErrRunner` line) and an assembly branch in `assemble()`
6. Add a row to `lookupMinPlan` in `internal/handler/domain.go` — that alone makes the name valid and sets its plan gate. There is no bool to thread through the request, options, or cache key
7. Add a TTL default: `cache.ttl.<name>` in `internal/config/config.go` and `sample-config.yml`
8. Add the column to `usage.LookupColumns` and a migration for `request_log` (the drift test will fail until you do)
9. Add a setter method for tests (`SetThingLookup`)
10. Update all test files that call `New()` or `SetLookups()`
11. Update README, docs HTML (request table, valid-lookups table, response field section with its `cache_hit` row, caching TTL table), api.http, smoke test, integration tests, changelog.yaml

## Adding a New Endpoint

1. Define request/response types in `internal/domain/model.go`
2. Create a service in `internal/service/`
3. Add a handler method in `internal/handler/`
4. Define a service interface in `internal/handler/handler.go`
5. Register the route in `RegisterProtectedRoutes()` with `RequireAdmin()` if admin-only
6. Wire the service in `internal/app/app.go`
7. Add a field to `handler.Deps` and set it in `app.go` — existing test call sites need no change, since they name only the dependencies they use
8. Add context keys to `middleware/request_logger.go` if needed
9. Update README, api.http, smoke test, integration tests, changelog.yaml
