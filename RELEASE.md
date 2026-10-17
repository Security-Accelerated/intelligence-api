# Releasing the Intelligence API

How shipping works in this repo. The fleet `releasing` skill reads this file and follows
it, so keep every section truthful — an agent trusts it over anything it could infer from
the `Makefile` or the workflows.

## Shape

**A release is a tag, and the tag is the deploy.** `make release V=vX.Y.Z` pushes the
tag; `.github/workflows/fly-deploy.yml` fires on any `v*` tag, runs the test workflow,
and then `flyctl deploy` with the tag name baked in as the version. There is no `release`
branch and no second PR.

The deploy job runs in the `production` GitHub environment, which requires a reviewer
(set 2026-10-17). After the tests pass, the run pauses at "Review deployments" in the
Actions UI until Jason approves it; nothing reaches Fly before that click. An agent
reports the waiting run and stops. It never approves a deployment, by `gh` or otherwise.

The human decisions are `make release` and that approval. Everything before the tag has
already been reviewed on its way into `main`; everything after the approval is automatic.

## Preconditions

- On `main`, clean tree, up to date with `origin/main`.
- The PR that motivated the release is **merged**, not merely approved.
- `make verify` passes (gofmt, vet, lint on new findings, unit + race, integration).

Any of these failing stops the release. Do not release around a dirty tree.

## Steps

1. **`git fetch --tags --prune`.** Local tags go stale. A release cut against a stale list
   silently reuses or skips a version — and here the tag is the deploy, so a wrong
   version is a wrong deploy. Confirm the real latest with `git tag | sort -V | tail -3`.

2. **Add the changelog entry and land it on `main` by PR** — the same way as any other
   change; there are no direct pushes to `main`. `changelog.yaml` at the root is a symlink
   to `internal/handler/changelog.yaml`; edit it from the root. Copy the shape of the
   entry above it. Every change carries an `audience`:
   - `public` — renders on `/docs/changelog`. Describe what a caller sees; no config
     keys, admin endpoints, infrastructure, or upstream feed names (say "threat
     intelligence feeds", not the provider)
   - `internal` — not rendered on the docs. It is still public: the file is in a public
     repo and `GET /v1/admin/changelog` returns everything

   When unsure which a change is, **ask**. Guessing `public` puts internal reasoning on a
   customer-facing page. Public entries are never flipped or deleted later; when a
   release reverses one, add "superseded in vX" to it.

   The entry goes in before the tag. Tag first and the deploy builds a version whose notes
   do not exist yet.

3. **`make release V=vX.Y.Z`.** Creates an annotated tag and pushes it. **This is the
   deploy.** Report the version and stop; the rest is the pipeline's.

4. **Approve the deployment.** Once the tests pass, the run waits on the `production`
   environment reviewer. Jason approves it under Actions → the run → Review deployments.
   An agent waiting on a release reports "waiting for approval" with the run URL and does
   nothing else until the run finishes.

   Branch names must not start with `release/` — git cannot hold a `release` ref and a
   `release/…` ref at once, and the old branch may still exist in some clones.

## Verify

After the tag push, in this order:

1. **The deploy run for *this tag* passed** —
   `gh run list --workflow fly-deploy.yml --branch vX.Y.Z --json databaseId,conclusion`,
   then `gh run view <id> --exit-status`. Filter by the tag; a bare `gh run list` can show
   an older green run above today's failure.
2. **The service is up** — `GET https://api.securityaccelerated.com/v1/health` returns 200
   (unauthenticated; reports Postgres, Redis, and GeoIP state).
3. **The new version is actually live** — the version pill on
   `https://api.securityaccelerated.com/docs` equals the tag just pushed.

Check 3 is the one that matters. The version is the tag name by construction, so a
mismatch here means the deploy did not happen, not that it was mislabelled.

`./scripts/status.sh` covers machine state and endpoint reachability in one command.

## Rollback

Redeploy an earlier tag: **Actions → Fly Deploy → Run workflow → tag** (or
`gh workflow run fly-deploy.yml -f tag=vX.Y.Z`). The workflow refuses anything that is not
exactly a release tag. A rollback goes through the same `production` approval as a
release. Then run the Verify section against that tag.

A rollback is a deploy, not a release: no changelog entry, no new tag. If the fix is a
code change, that is a new release.

## Never

- **Never delete or move a tag.** A tag is a deployed version; rewriting one rewrites what
  production claims to be. A bad release is a new release.
- **Never `fly deploy` or `make deploy` by hand** to route around a failed pipeline.
  Report the failure; use the rollback path if production is broken.
- **Never push a `v*` tag by any route other than `make release`.** The Makefile target is
  the one place the version is chosen.

## Not automated

These exist and are useful, and an agent runs them only when asked in the session:

- **Production smoke test** — `./scripts/smoke-test.sh https://api.securityaccelerated.com`.
  Hits every endpoint with every key/plan combination. It consumes real rate limit and
  writes usage rows, so it is never part of the default flow. Needs `SMOKE_*` keys from
  `.env`.
- **Production migrations.** Docker `initdb` only runs on first volume creation, so
  production (Neon) migrations are applied by hand with
  `psql "$NEON_CONNECTION_STRING"`. A release does not apply them; check whether a
  migration is pending *before* cutting one.
