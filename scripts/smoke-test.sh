#!/usr/bin/env bash
# Smoke test — hits every endpoint with every key/plan combination and checks
# expected HTTP status codes against the running API. Requires Docker containers
# to be up (make docker-reset or docker compose up).
set -euo pipefail

HOST="${1:-http://localhost:8080}"

# Only load .env for non-localhost targets (production keys)
if [[ "$HOST" != *"localhost"* && "$HOST" != *"127.0.0.1"* ]]; then
    ENV_FILE="$(dirname "$0")/../.env"
    [ -f "$ENV_FILE" ] && set -a && . "$ENV_FILE" && set +a
fi

pass=0
fail=0
errors=()

check() {
    local expect="$1"
    local desc="$2"
    shift 2
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' "$@")
    if [ "$status" = "$expect" ]; then
        printf "  \033[32m✓\033[0m %s → %s\n" "$desc" "$status"
        pass=$((pass + 1))
    else
        printf "  \033[31m✗\033[0m %s → %s (expected %s)\n" "$desc" "$status" "$expect"
        fail=$((fail + 1))
        errors+=("$desc: got $status, expected $expect")
    fi
}

post() {
    local expect="$1" desc="$2" path="$3" key="$4" body="$5"
    if [ "$key" = "" ]; then
        check "$expect" "$desc" -X POST "$HOST$path" -H "Content-Type: application/json" -d "$body"
    else
        check "$expect" "$desc" -X POST "$HOST$path" -H "Content-Type: application/json" -H "X-API-Key: $key" -d "$body"
    fi
}

# check_json — captures response body from a curl command, validates it as JSON,
# and checks for expected top-level fields. Arguments:
#   $1  description
#   $2  jq filter expression that must produce a non-empty/true result
#   $@  remaining args are passed to curl
check_json() {
    local desc="$1" filter="$2"
    shift 2
    local body
    body=$(curl -s "$@")
    if echo "$body" | jq -e "$filter" > /dev/null 2>&1; then
        printf "  \033[32m✓\033[0m %s\n" "$desc"
        pass=$((pass + 1))
    else
        printf "  \033[31m✗\033[0m %s (jq filter failed: %s)\n" "$desc" "$filter"
        fail=$((fail + 1))
        errors+=("$desc: jq filter '$filter' failed")
    fi
}

get() {
    local expect="$1" desc="$2" path="$3" key="$4"
    if [ "$key" = "" ]; then
        check "$expect" "$desc" "$HOST$path"
    else
        check "$expect" "$desc" "$HOST$path" -H "X-API-Key: $key"
    fi
}

# Keys (override via .env or env vars for production)
ADMIN="${SMOKE_ADMIN_KEY:-test-admin-key}"
BASIC="${SMOKE_BASIC_KEY:-test-basic-key}"
PRO="${SMOKE_PRO_KEY:-test-pro-key}"

DOMAIN='{"domains":["example.com"]}'

echo ""
echo "=== Health Check ==="
get 200 "GET /hello (no auth)" "/api/v1/hello" ""

echo ""
echo "=== App Info ==="
get 200 "GET /info (admin)"             "/api/v1/info" "$ADMIN"
get 403 "GET /info (pro — not admin)"   "/api/v1/info" "$PRO"
get 403 "GET /info (basic — not admin)" "/api/v1/info" "$BASIC"
get 401 "GET /info (no key)"            "/api/v1/info" ""

echo ""
echo "=== Domain Lookup — Auth ==="
post 200 "lookup (admin)"      "/api/v1/domain/lookup" "$ADMIN" "$DOMAIN"
post 200 "lookup (pro)"        "/api/v1/domain/lookup" "$PRO"   "$DOMAIN"
post 200 "lookup (basic)"      "/api/v1/domain/lookup" "$BASIC" "$DOMAIN"
post 401 "lookup (no key)"     "/api/v1/domain/lookup" ""       "$DOMAIN"
post 401 "lookup (wrong key)"  "/api/v1/domain/lookup" "totally-wrong-key" "$DOMAIN"

echo ""
echo "=== Domain Lookup — Pro Options ==="
post 200 "screenshot (admin)"            "/api/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"screenshot":true}'
post 200 "screenshot (pro)"              "/api/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"screenshot":true}'
post 403 "screenshot (basic — pro only)" "/api/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"screenshot":true}'
post 200 "reputation (admin)"            "/api/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"reputation":true}'
post 200 "reputation (pro)"              "/api/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"reputation":true}'
post 403 "reputation (basic — pro only)" "/api/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"reputation":true}'
post 200 "screenshot+reputation (admin)" "/api/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"screenshot":true,"reputation":true}'

echo ""
echo "=== Domain Lookup — All-Plan Options ==="
post 200 "email_security (admin)"  "/api/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"email_security":true}'
post 200 "email_security (pro)"    "/api/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"email_security":true}'
post 200 "email_security (basic)"  "/api/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"email_security":true}'
post 200 "subdomains (admin)"      "/api/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"subdomains":true}'
post 200 "subdomains (basic)"      "/api/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"subdomains":true}'
post 200 "ct_logs (admin)"         "/api/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"ct_logs":true}'
post 200 "ct_logs (basic)"         "/api/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"ct_logs":true}'
post 200 "bgp (admin)"             "/api/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"bgp":true}'
post 200 "bgp (basic)"             "/api/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"bgp":true}'
post 200 "fingerprint (admin)"     "/api/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"fingerprint":true}'
post 200 "fingerprint (basic)"     "/api/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"fingerprint":true}'

echo ""
echo "=== Domain Lookup — Validation ==="
post 400 "empty domains"       "/api/v1/domain/lookup" "$ADMIN" '{"domains":[]}'
post 400 "missing domains"     "/api/v1/domain/lookup" "$ADMIN" '{}'
post 400 "invalid domain"      "/api/v1/domain/lookup" "$ADMIN" '{"domains":["notadomain"]}'
post 400 "raw IP"              "/api/v1/domain/lookup" "$ADMIN" '{"domains":["1.2.3.4"]}'

echo ""
echo "=== Admin ==="
post 200 "cache invalidate (admin)"             "/api/v1/admin/auth/cache/invalidate" "$ADMIN" ""
post 403 "cache invalidate (basic — not admin)" "/api/v1/admin/auth/cache/invalidate" "$BASIC" ""
post 401 "cache invalidate (no key)"            "/api/v1/admin/auth/cache/invalidate" ""       ""

echo ""
echo "=== Admin — Fingerprint Rules ==="
get  200 "GET fingerprints (admin)"             "/api/v1/admin/fingerprints" "$ADMIN"
get  403 "GET fingerprints (basic — not admin)" "/api/v1/admin/fingerprints" "$BASIC"
get  401 "GET fingerprints (no key)"            "/api/v1/admin/fingerprints" ""
post 403 "POST fingerprints (basic — not admin)" "/api/v1/admin/fingerprints" "$BASIC" '[{"name":"TestTech","category":"web-server","headers":{"Server":"test"}}]'
post 401 "POST fingerprints (no key)"           "/api/v1/admin/fingerprints" ""       '[{"name":"TestTech","category":"web-server","headers":{"Server":"test"}}]'

echo ""
echo "=== Response Body Validation ==="
check_json "GET /hello returns {message: hello world}" \
    '.message == "hello world"' \
    "$HOST/api/v1/hello"

check_json "lookup response is JSON array with domain field" \
    '.[0].domain' \
    -X POST "$HOST/api/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

echo ""
echo "=== Rate Limiting ==="
# Basic plan limit is 30/min. Send 31 requests and verify the last gets 429.
rate_ok=true
for i in $(seq 1 31); do
    rl_status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/api/v1/domain/lookup" \
        -H "Content-Type: application/json" -H "X-API-Key: $BASIC" \
        -d "$DOMAIN")
    if [ "$i" -eq 31 ]; then
        if [ "$rl_status" = "429" ]; then
            printf "  \033[32m✓\033[0m request 31 got 429 (rate limited)\n"
            pass=$((pass + 1))
        else
            printf "  \033[31m✗\033[0m request 31 got %s (expected 429)\n" "$rl_status"
            fail=$((fail + 1))
            errors+=("rate limit: request 31 got $rl_status, expected 429")
            rate_ok=false
        fi
    fi
done

echo ""
echo "=== Body Size Limit ==="
# Send a >1MB payload. MaxBytesReader surfaces through Gin's binding layer as 400.
# Written to a temp file because the shell can't pass >1MB as a CLI argument.
big_body_file=$(mktemp)
python3 -c "print('{\"domains\":[\"' + 'x'*1048577 + '\"]}')" > "$big_body_file"
check 400 "oversized body (>1MB) rejected" \
    -X POST "$HOST/api/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d @"$big_body_file"
rm -f "$big_body_file"

echo ""
echo "=== Client Request ID ==="
# Verify the header is echoed back
rid_echo=$(curl -s -D - -o /dev/null -X POST "$HOST/api/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -H "X-Client-Request-ID: smoke-test-456" \
    -d "$DOMAIN" 2>&1 | grep -i "X-Client-Request-ID" | tr -d '\r')
if echo "$rid_echo" | grep -q "smoke-test-456"; then
    printf "  \033[32m✓\033[0m X-Client-Request-ID echoed back\n"
    pass=$((pass + 1))
else
    printf "  \033[31m✗\033[0m X-Client-Request-ID not echoed (got: %s)\n" "$rid_echo"
    fail=$((fail + 1))
    errors+=("X-Client-Request-ID echo failed")
fi

# Summary
echo ""
echo "================================"
printf "  \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n" "$pass" "$fail"
if [ ${#errors[@]} -gt 0 ]; then
    echo ""
    echo "  Failures:"
    for e in "${errors[@]}"; do
        printf "    \033[31m✗\033[0m %s\n" "$e"
    done
fi
echo "================================"
echo ""

[ "$fail" -eq 0 ]
