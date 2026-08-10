#!/usr/bin/env bash
# DEV ONLY — tears down all containers and WIPES the database and Redis
# volumes, then rebuilds from scratch. Do not run against production data.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=$(git describe --tags --always --dirty)
export VERSION

echo "==> Deploying version: $VERSION"
echo ""
echo "==> Stopping containers..."
docker compose down

echo "==> Removing postgres and redis volumes..."
docker compose down -v

echo "==> Pruning build cache..."
docker builder prune -f

echo "==> Rebuilding and starting containers..."
docker compose up --build -d

# The wait is bounded so a container that never becomes healthy fails with the
# name of the stuck dependency instead of hanging the terminal forever.
TIMEOUT="${RESET_TIMEOUT:-300}"

# Each probe carries its own timeout as well, because wait_for only re-checks
# the deadline between calls: a probe that blocks forever never returns to the
# loop, and TIMEOUT bounds nothing.
#
# curl is the one that could actually hang. It has no read timeout by default,
# and a Go server that has bound its listener but is still starting accepts the
# connection and writes no response — measured at over 10s against a socket that
# accepts and never replies, versus 5s with this flag. pg_isready already
# defaults to a 3s connect timeout, so it is stated here for symmetry and to
# stop the bound depending on a tool default rather than on this script.
#
# The bound is per-probe rather than an outer `timeout`, which is GNU coreutils
# and absent from a stock macOS. It also stops at the readiness loop on purpose:
# a wedged Docker daemon hangs `docker compose up --build` several lines earlier,
# so bounding only these two calls against it would be a false reassurance.
PROBE_TIMEOUT=5

wait_for() {
    local name="$1"
    shift
    local deadline=$((SECONDS + TIMEOUT))
    until "$@" >/dev/null 2>&1; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "error: $name did not become ready within ${TIMEOUT}s" >&2
            echo "       check container logs with: docker compose logs $name" >&2
            exit 1
        fi
        sleep 1
    done
}

echo "==> Waiting for postgres to be ready..."
wait_for postgres docker compose exec -T postgres \
    pg_isready -U intelligence -d intelligence_api -t "$PROBE_TIMEOUT"

echo "==> Waiting for API to be ready..."
wait_for api curl -sf --max-time "$PROBE_TIMEOUT" http://localhost:8080/v1/hello