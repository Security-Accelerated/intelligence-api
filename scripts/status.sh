#!/usr/bin/env bash
# Status check — verifies Fly app, Neon Postgres, and Redis are healthy.
set -euo pipefail

ENV_FILE="$(dirname "$0")/../.env"

# Read specific keys from .env without sourcing (connection strings contain & which
# breaks shell sourcing). Falls back to environment variables if .env is absent.
env_get() {
    local key="$1" val=""
    if [ -f "$ENV_FILE" ]; then
        val=$(grep "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true)
        # Strip surrounding quotes if present
        val="${val#\"}" ; val="${val%\"}"
        val="${val#\'}" ; val="${val%\'}"
    fi
    echo "$val"
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

        version=$(echo "$info" | jq -r '.system.version // "unknown"')
        mode=$(echo "$info" | jq -r '.system.mode // "unknown"')
        uptime=$(echo "$info" | jq -r '.system.uptime // "unknown"')
        start_time=$(echo "$info" | jq -r '.system.start_time // "unknown"')
        session_id=$(echo "$info" | jq -r '.system.session_id // "unknown"')
        go_ver=$(echo "$info" | jq -r '.system.golang_version // "unknown"')
        host=$(echo "$info" | jq -r '.system.host // "unknown"')
        arch=$(echo "$info" | jq -r '.system.architecture // "unknown"')
        os=$(echo "$info" | jq -r '.system.os // "unknown"')
        kernel=$(echo "$info" | jq -r '.system.kernel // "unknown"')

        pg_host=$(echo "$info" | jq -r '.database.host // "unknown"')
        pg_db=$(echo "$info" | jq -r '.database.dbname // "unknown"')
        pg_ssl=$(echo "$info" | jq -r '.database.sslmode // "unknown"')
        pg_pool_open=$(echo "$info" | jq -r '.postgres_pool.open_connections // "?"')
        pg_pool_inuse=$(echo "$info" | jq -r '.postgres_pool.in_use // "?"')
        pg_pool_idle=$(echo "$info" | jq -r '.postgres_pool.idle // "?"')

        redis_addr=$(echo "$info" | jq -r '.cache.addr // "unknown"')
        redis_keys=$(echo "$info" | jq -r '.cache.key_count // "unknown"')
        redis_mem=$(echo "$info" | jq -r '.cache.memory_used // "unknown"')
        redis_ping=$(echo "$info" | jq -r '.cache.ping_ms // "?"')
        cache_ttl=$(echo "$info" | jq -r '.cache.default_ttl // "unknown"')
        cache_lookup_ttls=$(echo "$info" | jq -r '.cache.lookup_ttls // {} | to_entries | map("\(.key)=\(.value)") | join(", ")')
        auth_ttl=$(echo "$info" | jq -r '.cache.auth_cache_ttl // "unknown"')
        auth_size=$(echo "$info" | jq -r '.cache.auth_cache_size // "unknown"')

        rl_free=$(echo "$info" | jq -r '.lookups.rate_limit_free // "?"')
        rl_pro=$(echo "$info" | jq -r '.lookups.rate_limit_pro // "?"')

        fp_rules=$(echo "$info" | jq -r '.services.fingerprint.rule_count // "n/a"')
        fp_source=$(echo "$info" | jq -r '.services.fingerprint.source // "unknown"')
        pushover=$(echo "$info" | jq -r '.services.notifications.enabled // false')
        stripe=$(echo "$info" | jq -r '.services.billing.enabled // false')
        ti_providers=$(echo "$info" | jq -r '.services.threat_intel.providers // [] | join(", ")')

        goroutines=$(echo "$info" | jq -r '.runtime.goroutines // "?"')
        heap_mb=$(echo "$info" | jq -r '.runtime.heap_alloc_mb // "?" | if type == "number" then (. * 10 | round / 10 | tostring) else . end')

        echo ""
        printf "  %-16s %s\n" "Version:" "$version"
        printf "  %-16s %s\n" "Mode:" "$mode"
        printf "  %-16s %s\n" "Uptime:" "$uptime"
        printf "  %-16s %s\n" "Started:" "$start_time"
        printf "  %-16s %s\n" "Session:" "$session_id"

        echo ""
        printf "  %-16s %s (%s/%s, %s)\n" "Host:" "$host" "$os" "$arch" "$kernel"
        printf "  %-16s %s\n" "Go:" "$go_ver"
        printf "  %-16s %s goroutines, %s MB heap\n" "Runtime:" "$goroutines" "$heap_mb"

        echo ""
        printf "  %-16s %s (db: %s, ssl: %s)\n" "Postgres:" "$pg_host" "$pg_db" "$pg_ssl"
        printf "  %-16s open=%s, in_use=%s, idle=%s\n" "  Pool:" "$pg_pool_open" "$pg_pool_inuse" "$pg_pool_idle"
        printf "  %-16s %s (%s keys, %s memory, %sms ping)\n" "Redis:" "$redis_addr" "$redis_keys" "$redis_mem" "$redis_ping"
        printf "  %-16s default TTL %s\n" "Cache:" "$cache_ttl"
        printf "  %-16s %s\n" "  Lookup TTLs:" "$cache_lookup_ttls"
        printf "  %-16s %s entries (TTL: %s)\n" "Auth cache:" "$auth_size" "$auth_ttl"

        echo ""
        printf "  %-16s free=%s, pro=%s req/min\n" "Rate limits:" "$rl_free" "$rl_pro"
        printf "  %-16s %s rules (%s)\n" "Fingerprints:" "$fp_rules" "$fp_source"
        printf "  %-16s %s\n" "Threat intel:" "$ti_providers"
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
