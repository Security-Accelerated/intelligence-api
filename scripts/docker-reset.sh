#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Stopping containers..."
docker compose down

echo "==> Removing postgres and redis volumes..."
docker compose down -v

echo "==> Rebuilding and starting containers..."
docker compose up --build -d

echo "==> Waiting for postgres to be ready..."
until docker compose exec -T postgres pg_isready -U intelligence -d intelligence_api >/dev/null 2>&1; do
    sleep 1
done

echo "==> Waiting for API to be ready..."
until curl -sf http://localhost:8080/api/v1/hello >/dev/null 2>&1; do
    sleep 1
done