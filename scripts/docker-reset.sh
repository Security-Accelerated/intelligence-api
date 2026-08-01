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
wait_for postgres docker compose exec -T postgres pg_isready -U intelligence -d intelligence_api

echo "==> Waiting for API to be ready..."
wait_for api curl -sf http://localhost:8080/v1/hello