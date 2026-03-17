#!/usr/bin/env bash
# Status check — verifies Fly app, Neon Postgres, and Redis are healthy.
set -euo pipefail

ENV_FILE="$(dirname "$0")/../.env"

# Read specific keys from .env without sourcing (connection strings contain & which
# breaks shell sourcing). Falls back to environment variables if .env is absent.
env_get() {
    local key="$1"
    if [ -f "$ENV_FILE" ]; then
        grep "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true
    fi
}

APP="security-accelerated-intelligence-api"
HOST="https://api.securityaccelerated.com"
ADMIN_KEY="${SMOKE_ADMIN_KEY:-$(env_get SMOKE_ADMIN_KEY)}"
NEON_CONN="${NEON_CONNECTION_STRING:-$(env_get NEON_CONNECTION_STRING)}"

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

echo ""
echo "=== Neon Postgres ==="
if [ -n "$NEON_CONN" ]; then
    check "Neon reachable (SELECT 1)" \
        psql "$NEON_CONN" -c "SELECT 1" -t -A
    if psql "$NEON_CONN" -t -A -c "SELECT 1" > /dev/null 2>&1; then
        customers=$(psql "$NEON_CONN" -t -A -c "SELECT COUNT(*) FROM customers" 2>/dev/null)
        keys=$(psql "$NEON_CONN" -t -A -c "SELECT COUNT(*) FROM api_keys" 2>/dev/null)
        fp_rules=$(psql "$NEON_CONN" -t -A -c "SELECT COUNT(*) FROM fingerprint_rules" 2>/dev/null)
        requests=$(psql "$NEON_CONN" -t -A -c "SELECT COUNT(*) FROM request_log" 2>/dev/null)
        requests_24h=$(psql "$NEON_CONN" -t -A -c "SELECT COUNT(*) FROM request_log WHERE created_at > NOW() - INTERVAL '24 hours'" 2>/dev/null)
        printf "  Customers:     %s\n" "$customers"
        printf "  API keys:      %s\n" "$keys"
        printf "  FP rules:      %s\n" "$fp_rules"
        printf "  Requests:      %s total, %s last 24h\n" "$requests" "$requests_24h"
    fi
else
    echo "  (Set NEON_CONNECTION_STRING for direct Postgres checks)"
fi

if [ -n "$ADMIN_KEY" ]; then
    echo ""
    echo "=== Application (/v1/info) ==="
    info=$(curl -sf --max-time 10 -H "X-API-Key: $ADMIN_KEY" "$HOST/v1/info" 2>/dev/null || true)
    if [ -n "$info" ]; then
        check "Admin endpoint accessible" true

        version=$(echo "$info" | jq -r '.application.version // "unknown"')
        mode=$(echo "$info" | jq -r '.application.mode // "unknown"')
        uptime=$(echo "$info" | jq -r '.application.uptime // "unknown"')
        start_time=$(echo "$info" | jq -r '.application.start_time // "unknown"')
        session_id=$(echo "$info" | jq -r '.application.session_id // "unknown"')

        go_ver=$(echo "$info" | jq -r '.environment.golang_version // "unknown"')
        host=$(echo "$info" | jq -r '.environment.host // "unknown"')
        arch=$(echo "$info" | jq -r '.environment.architecture // "unknown"')
        os=$(echo "$info" | jq -r '.environment.os // "unknown"')
        kernel=$(echo "$info" | jq -r '.environment.kernel // "unknown"')

        pg_host=$(echo "$info" | jq -r '.config.postgres_host // "unknown"')
        pg_db=$(echo "$info" | jq -r '.config.postgres_dbname // "unknown"')
        pg_ssl=$(echo "$info" | jq -r '.config.postgres_sslmode // "unknown"')

        redis_addr=$(echo "$info" | jq -r '.redis.addr // "unknown"')
        redis_keys=$(echo "$info" | jq -r '.redis.key_count // "unknown"')
        redis_mem=$(echo "$info" | jq -r '.redis.memory_used // "unknown"')

        cache_ttl=$(echo "$info" | jq -r '.config.cache_ttl // "unknown"')
        auth_ttl=$(echo "$info" | jq -r '.config.auth_cache_ttl // "unknown"')
        auth_size=$(echo "$info" | jq -r '.auth_cache.size // "unknown"')

        rl_free=$(echo "$info" | jq -r '.config.rate_limit_free // "?"')
        rl_basic=$(echo "$info" | jq -r '.config.rate_limit_basic // "?"')
        rl_pro=$(echo "$info" | jq -r '.config.rate_limit_pro // "?"')

        fp_rules=$(echo "$info" | jq -r '.fingerprint.rule_count // "n/a"')

        pushover=$(echo "$info" | jq -r '.notifications.pushover_enabled // false')
        stripe=$(echo "$info" | jq -r '.billing.stripe_enabled // false')

        echo ""
        printf "  %-16s %s\n" "Version:" "$version"
        printf "  %-16s %s\n" "Mode:" "$mode"
        printf "  %-16s %s\n" "Uptime:" "$uptime"
        printf "  %-16s %s\n" "Started:" "$start_time"
        printf "  %-16s %s\n" "Session:" "$session_id"

        echo ""
        printf "  %-16s %s (%s/%s, %s)\n" "Host:" "$host" "$os" "$arch" "$kernel"
        printf "  %-16s %s\n" "Go:" "$go_ver"

        echo ""
        printf "  %-16s %s (db: %s, ssl: %s)\n" "Postgres:" "$pg_host" "$pg_db" "$pg_ssl"
        printf "  %-16s %s (%s keys, %s memory)\n" "Redis:" "$redis_addr" "$redis_keys" "$redis_mem"
        printf "  %-16s %s (TTL: %s)\n" "Cache:" "$cache_ttl" "$cache_ttl"
        printf "  %-16s %s entries (TTL: %s)\n" "Auth cache:" "$auth_size" "$auth_ttl"

        echo ""
        printf "  %-16s free=%s, basic=%s, pro=%s req/min\n" "Rate limits:" "$rl_free" "$rl_basic" "$rl_pro"
        printf "  %-16s %s rules\n" "Fingerprints:" "$fp_rules"
        printf "  %-16s %s\n" "Pushover:" "$pushover"
        printf "  %-16s %s\n" "Stripe:" "$stripe"
    else
        check "Admin endpoint accessible" false
    fi
else
    echo ""
    echo "  (Set SMOKE_ADMIN_KEY for detailed status from /v1/info)"
fi

echo ""
printf "Results: \033[32m%d passed\033[0m" "$pass"
[ "$fail" -gt 0 ] && printf ", \033[31m%d failed\033[0m" "$fail"
echo ""

[ "$fail" -eq 0 ]
