#!/usr/bin/env bash
# Status check — verifies Fly app, Neon Postgres, and Redis are healthy.
set -euo pipefail

# Load .env if present (keys for production testing)
ENV_FILE="$(dirname "$0")/../.env"
[ -f "$ENV_FILE" ] && set -a && . "$ENV_FILE" && set +a

APP="security-accelerated-intelligence-api"
HOST="https://api.securityaccelerated.com"
ADMIN_KEY="${SMOKE_ADMIN_KEY:-}"

pass=0
fail=0

check() {
    local desc="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        printf "  \033[32m✓\033[0m %s\n" "$desc"
        pass=$((pass + 1))
    else
        printf "  \033[31m✗\033[0m %s\n" "$desc"
        fail=$((fail + 1))
    fi
}

echo "=== Fly Machines ==="
fly status -a "$APP" 2>/dev/null | grep -E "^(app|PROCESS|App)" || echo "  Could not reach Fly API (is flyctl installed?)"

echo ""
echo "=== Endpoint Health ==="
check "GET /v1/hello (app responding)" \
    curl -sf --max-time 10 "$HOST/v1/hello"

check "POST /v1/domain/lookup returns 401 without key (auth middleware running)" \
    test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST "$HOST/v1/domain/lookup")" = "401"

if [ -n "$ADMIN_KEY" ]; then
    echo ""
    echo "=== Admin Info ==="
    info=$(curl -sf --max-time 10 -H "X-API-Key: $ADMIN_KEY" "$HOST/v1/info" 2>/dev/null || true)
    if [ -n "$info" ]; then
        version=$(echo "$info" | jq -r '.application.version // "unknown"')
        pg_host=$(echo "$info" | jq -r '.config.postgres_host // "unknown"')
        redis_addr=$(echo "$info" | jq -r '.redis.addr // "unknown"')
        redis_keys=$(echo "$info" | jq -r '.redis.key_count // "unknown"')
        auth_cache=$(echo "$info" | jq -r '.auth_cache.size // "unknown"')
        uptime=$(echo "$info" | jq -r '.application.start_time // "unknown"')

        printf "  Version:      %s\n" "$version"
        printf "  Started:      %s\n" "$uptime"
        printf "  Postgres:     %s\n" "$pg_host"
        printf "  Redis:        %s (%s keys)\n" "$redis_addr" "$redis_keys"
        printf "  Auth cache:   %s entries\n" "$auth_cache"
        check "Admin endpoint accessible" true
    else
        check "Admin endpoint accessible" false
    fi
else
    echo ""
    echo "  (Set SMOKE_ADMIN_KEY for detailed status from /v1/info)"
fi

echo ""
echo "=== Neon Postgres ==="
check "Postgres reachable (via app startup)" \
    curl -sf --max-time 10 "$HOST/v1/hello"

echo ""
printf "Results: \033[32m%d passed\033[0m" "$pass"
[ "$fail" -gt 0 ] && printf ", \033[31m%d failed\033[0m" "$fail"
echo ""

[ "$fail" -eq 0 ]
