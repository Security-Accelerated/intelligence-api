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
FREE="${SMOKE_FREE_KEY:-test-free-key}"

DOMAIN='{"domains":["example.com"]}'

echo ""
echo "=== Docs ==="
check 200 "GET / (API docs)" "$HOST/"

echo ""
echo "=== Health Check ==="
get 200 "GET /hello (no auth)" "/v1/hello" ""

echo ""
echo "=== App Info ==="
get 200 "GET /info (admin)"             "/v1/info" "$ADMIN"
get 403 "GET /info (pro — not admin)"   "/v1/info" "$PRO"
get 403 "GET /info (basic — not admin)" "/v1/info" "$BASIC"
get 401 "GET /info (no key)"            "/v1/info" ""

echo ""
echo "=== Domain Lookup — Auth ==="
post 200 "lookup (admin)"      "/v1/domain/lookup" "$ADMIN" "$DOMAIN"
post 200 "lookup (pro)"        "/v1/domain/lookup" "$PRO"   "$DOMAIN"
post 200 "lookup (basic)"      "/v1/domain/lookup" "$BASIC" "$DOMAIN"
post 200 "lookup (free)"       "/v1/domain/lookup" "$FREE"  "$DOMAIN"
post 401 "lookup (no key)"     "/v1/domain/lookup" ""       "$DOMAIN"
post 401 "lookup (wrong key)"  "/v1/domain/lookup" "totally-wrong-key" "$DOMAIN"

echo ""
echo "=== Domain Lookup — Pro Options ==="
post 200 "screenshot (admin)"            "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"screenshot":true}'
post 200 "screenshot (pro)"              "/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"screenshot":true}'
post 403 "screenshot (basic — pro only)" "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"screenshot":true}'
post 403 "screenshot (free — pro only)"  "/v1/domain/lookup" "$FREE"  '{"domains":["example.com"],"screenshot":true}'
post 200 "reputation (admin)"            "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"reputation":true}'
post 200 "reputation (pro)"              "/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"reputation":true}'
post 403 "reputation (basic — pro only)" "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"reputation":true}'
post 403 "reputation (free — pro only)"  "/v1/domain/lookup" "$FREE"  '{"domains":["example.com"],"reputation":true}'
post 200 "screenshot+reputation (admin)" "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"screenshot":true,"reputation":true}'

echo ""
echo "=== Domain Lookup — All-Plan Options ==="
post 200 "email_security (admin)"  "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"email_security":true}'
post 200 "email_security (pro)"    "/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"email_security":true}'
post 200 "email_security (basic)"  "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"email_security":true}'
post 200 "email_security (free)"   "/v1/domain/lookup" "$FREE"  '{"domains":["example.com"],"email_security":true}'
post 200 "subdomains (admin)"      "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"subdomains":true}'
post 200 "subdomains (basic)"      "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"subdomains":true}'
post 200 "ct_logs (admin)"         "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"ct_logs":true}'
post 200 "ct_logs (basic)"         "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"ct_logs":true}'
post 200 "bgp (admin)"             "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"bgp":true}'
post 200 "bgp (basic)"             "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"bgp":true}'
post 200 "fingerprint (admin)"     "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"fingerprint":true}'
post 200 "fingerprint (basic)"     "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"fingerprint":true}'

echo ""
echo "=== Domain Lookup — Validation ==="
post 400 "empty domains"       "/v1/domain/lookup" "$ADMIN" '{"domains":[]}'
post 400 "missing domains"     "/v1/domain/lookup" "$ADMIN" '{}'
post 400 "invalid domain"      "/v1/domain/lookup" "$ADMIN" '{"domains":["notadomain"]}'
post 400 "raw IP"              "/v1/domain/lookup" "$ADMIN" '{"domains":["1.2.3.4"]}'
post 400 "free plan max domains" "/v1/domain/lookup" "$FREE" '{"domains":["a.com","b.com"]}'

echo ""
echo "=== Admin ==="
post 200 "cache invalidate (admin)"             "/v1/admin/auth/cache/invalidate" "$ADMIN" ""
post 403 "cache invalidate (basic — not admin)" "/v1/admin/auth/cache/invalidate" "$BASIC" ""
post 401 "cache invalidate (no key)"            "/v1/admin/auth/cache/invalidate" ""       ""

echo ""
echo "=== Admin — Fingerprint Rules ==="
get  200 "GET fingerprints (admin)"             "/v1/admin/fingerprints" "$ADMIN"
get  403 "GET fingerprints (basic — not admin)" "/v1/admin/fingerprints" "$BASIC"
get  401 "GET fingerprints (no key)"            "/v1/admin/fingerprints" ""
post 403 "POST fingerprints (basic — not admin)" "/v1/admin/fingerprints" "$BASIC" '[{"name":"TestTech","category":"web-server","headers":{"Server":"test"}}]'
post 401 "POST fingerprints (no key)"           "/v1/admin/fingerprints" ""       '[{"name":"TestTech","category":"web-server","headers":{"Server":"test"}}]'

echo ""
echo "=== Admin — Usage ==="
get  200 "GET usage (admin)"             "/v1/admin/usage" "$ADMIN"
get  200 "GET usage ?days=7 (admin)"     "/v1/admin/usage?days=7" "$ADMIN"
get  403 "GET usage (basic — not admin)" "/v1/admin/usage" "$BASIC"
get  401 "GET usage (no key)"            "/v1/admin/usage" ""

echo ""
echo "=== Billing ==="
check 200 "GET /billing/success (no session_id — renders error page)" "$HOST/billing/success"
check 200 "GET /billing/success (invalid session_id — renders error page)" "$HOST/billing/success?session_id=invalid"
check 400 "POST /billing/webhook (no signature)" -X POST "$HOST/billing/webhook" -H "Content-Type: application/json" -d '{}'
check 400 "POST /billing/webhook (bad signature)" -X POST "$HOST/billing/webhook" -H "Content-Type: application/json" -H "Stripe-Signature: t=123,v1=bad" -d '{}'

echo ""
echo "=== Response Body Validation ==="
check_json "GET /hello returns {message: hello world}" \
    '.message == "hello world"' \
    "$HOST/v1/hello"

check_json "lookup response is JSON array with domain field" \
    '.[0].domain' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

echo ""
echo "=== Body Size Limit ==="
# Send a >1MB payload. MaxBytesReader surfaces through Gin's binding layer as 400.
# Written to a temp file because the shell can't pass >1MB as a CLI argument.
big_body_file=$(mktemp)
python3 -c "print('{\"domains\":[\"' + 'x'*1048577 + '\"]}')" > "$big_body_file"
check 400 "oversized body (>1MB) rejected" \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d @"$big_body_file"
rm -f "$big_body_file"

echo ""
echo "=== Client Request ID ==="
# Verify the header is echoed back
rid_echo=$(curl -s -D - -o /dev/null -X POST "$HOST/v1/domain/lookup" \
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
