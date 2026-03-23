#!/usr/bin/env bash
# Fetch and display API usage statistics from the admin endpoint.
# Usage: ./scripts/usage.sh [days] [host]
#   days  — lookback period (default: 30, max: 365)
#   host  — API base URL (default: https://api.securityaccelerated.com)
set -euo pipefail

DAYS="${1:-30}"
HOST="${2:-https://api.securityaccelerated.com}"
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

resp=$(curl -sf --max-time 10 -H "X-API-Key: $ADMIN_KEY" "$HOST/v1/admin/usage?days=$DAYS" 2>/dev/null) || {
    echo "Error: failed to fetch usage data" >&2
    exit 1
}

total=$(echo "$resp" | jq -r '.total_requests // 0')
cache_hits=$(echo "$resp" | jq -r '.cache_hits // 0')
hit_rate=$(echo "$resp" | jq -r '.cache_hit_rate // 0 | . * 10 | round / 10')
avg_latency=$(echo "$resp" | jq -r '.avg_latency_ms // 0 | . * 10 | round / 10')
total_domains=$(echo "$resp" | jq -r '.total_domains // 0')
period_start=$(echo "$resp" | jq -r '.period_start // "?" | split("T")[0]')
period_end=$(echo "$resp" | jq -r '.period_end // "?" | split("T")[0]')

echo "=== Usage Statistics ($DAYS days) ==="
echo "  Period:         $period_start → $period_end"
echo ""
printf "  %-18s %s\n" "Total requests:" "$total"
printf "  %-18s %s\n" "Total domains:" "$total_domains"
printf "  %-18s %s (%s%%)\n" "Cache hits:" "$cache_hits" "$hit_rate"
printf "  %-18s %sms\n" "Avg latency:" "$avg_latency"

echo ""
echo "  Status Codes:"
echo "$resp" | jq -r '.status_codes // {} | to_entries | sort_by(.key) | .[] | "    \(.key): \(.value)"'

echo ""
echo "  Feature Usage:"
echo "$resp" | jq -r '.feature_usage // {} | to_entries | sort_by(-.value) | .[] | "    \(.key): \(.value)"'

echo ""
echo "  Requests by Path:"
echo "$resp" | jq -r '.requests_by_path // {} | to_entries | sort_by(-.value) | .[] | "    \(.key): \(.value)"'
