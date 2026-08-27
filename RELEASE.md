# Releasing the Intelligence API

How shipping works in this repo. The fleet `releasing` skill reads this file and follows
it, so keep every section truthful — an agent trusts it over anything it could infer from
the `Makefile` or the workflows.

## Shape

Tag `main`, then open a PR from `main` to `release`. **Merging that PR is what deploys.**
`.github/workflows/fly-deploy.yml` runs the test workflow and then `flyctl deploy` on every
push to `release`, baking the version in via `git describe --tags --abbrev=0`.

That `git describe` is why the release PR must land as a **merge commit — never squash,
never rebase.** Both rewrite the commits onto `release`, so the tagged commit is no longer
in its history and `describe` walks back to the previous tag: the pipeline goes green and
deploys the new code labelled with the old version. That is the failure behind "I don't
see the new tag on the live page."

Nothing about a release touches production until that PR merges.

## Preconditions

- On `main`, clean tree, up to date with `origin/main`.
- The feature PR that motivated the release is **merged**, not merely approved.
- `make verify` passes (gofmt, vet, lint on new findings, unit + race, integration).

Any of these failing stops the release. Do not release around a dirty tree.

## Steps

1. **`git fetch --tags --prune`.** Local tags go stale. A release cut against a stale list
   silently reuses or skips a version, and nothing reports it — you find out when the docs
   page shows an older version than the tag you thought you pushed. Confirm the real latest
   with `git tag | sort -V | tail -3`.

2. **Add the changelog entry, then commit it to `main`.** `changelog.yaml` at the root is a
   symlink to `internal/handler/changelog.yaml`; edit it from the root. Copy the shape of
   the entry above it. Every change carries an `audience`:
   - `public` — renders in "What's New" on `/docs`, `/docs/domain`, `/docs/ip`
   - `internal` — admin endpoint only (`GET /v1/admin/changelog`)

   When unsure which a change is, **ask**. Guessing `public` puts internal reasoning on a
   customer-facing page.

   The entry goes in before the tag. Tag first and the deploy builds a version whose notes
   do not exist yet.

3. **`make release V=vX.Y.Z`.** Creates an annotated tag and pushes **the tag only**. It
   does not deploy and does not write to `release`.

4. **`gh pr create --base release --head main --title "Release vX.Y.Z"`.**

   **Stop here.** Report the PR number and wait. Conflicts on this PR are a stop, not a
   step — reconciling `main` and `release` is a decision, not a mechanical fix.

## Verify

Only after the user confirms the PR is merged; the merge is what triggers the deploy.

1. **The tag is in `release`'s history** — `git fetch --tags origin release`, then
   `git describe --tags --abbrev=0 origin/release` must print the tag just cut. If it
   prints the previous one, the merge rewrote history (see Shape) and the deploy is
   mislabelled; stop and report before anything else.
2. **The pipeline passed for *this* merge, not an earlier one** —
   `gh run list --branch release --commit $(git rev-parse origin/release) --json databaseId,conclusion`,
   then `gh run view <id> --exit-status`. A bare `gh run list` shows recent runs, and an
   older green one can sit above today's failure.
3. **The service is up** — `GET https://api.securityaccelerated.com/v1/health` returns 200
   (unauthenticated; reports Postgres, Redis, and GeoIP state)
4. **The new version is actually live** — the version pill on
   `https://api.securityaccelerated.com/docs` matches the tag just cut

Check 4 is the one that gets skipped and the one that matters. A green pipeline is not
proof the new version is serving: the deploy reads its version from `git describe`, so a
tag that did not reach the remote — or was rewritten out of `release` — produces a
successful deploy of an older version.

`./scripts/status.sh` covers machine state and endpoint reachability in one command.

## Never

- **Never push to `release`.** It is reached through a reviewed PR from `main`. A fleet
  `PreToolUse` hook blocks every spelling of this; if you are looking for one that gets
  past it, stop and ask.
- **Never merge the release PR.** Opening it is the deliverable.
- **Never `fly deploy` or `make deploy` by hand** to route around a failed pipeline. Report
  the failure.
- **Never re-tag to fix a bad release.** That is a new release, and Jason's call.

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
