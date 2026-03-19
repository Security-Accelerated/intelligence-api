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

echo "==> Waiting for postgres to be ready..."
until docker compose exec -T postgres pg_isready -U intelligence -d intelligence_api >/dev/null 2>&1; do
    sleep 1
done

echo "==> Waiting for API to be ready..."
until curl -sf http://localhost:8080/v1/hello >/dev/null 2>&1; do
    sleep 1
done