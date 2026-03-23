#!/usr/bin/env bash
# Fetch and pretty-print the /v1/info admin endpoint.
set -euo pipefail

HOST="${1:-https://api.securityaccelerated.com}"
ENV_FILE="$(dirname "$0")/../.env"

env_get() {
    local key="$1" val=""
    if [ -f "$ENV_FILE" ]; then
        val=$(grep "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true)
        val="${val#\"}" ; val="${val%\"}"
        val="${val#\'}" ; val="${val%\'}"
    fi
    echo "$val"
}

ADMIN_KEY="${SMOKE_ADMIN_KEY:-$(env_get SMOKE_ADMIN_KEY)}"

if [ -z "$ADMIN_KEY" ]; then
    echo "Error: SMOKE_ADMIN_KEY not set in environment or .env" >&2
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed" >&2
    exit 1
fi

curl -sf --max-time 10 -H "X-API-Key: $ADMIN_KEY" "$HOST/v1/info" | jq .
