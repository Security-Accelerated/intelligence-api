#!/usr/bin/env bash
# Smoke test — hits every endpoint with every key/tier combination and checks
# expected HTTP status codes against the running API. Requires Docker containers
# to be up (make docker-reset or docker compose up).
set -euo pipefail

HOST="${1:-http://localhost:8080}"

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

# Keys
ADMIN="test-admin-key"
LOOKUP="test-lookup-key"
TYPO="test-typosquatting-key"
ENTERPRISE="test-enterprise-key"

DOMAIN='{"domains":["example.com"]}'

echo ""
echo "=== Health Check ==="
get 200 "GET /hello (no auth)" "/api/v1/hello" ""

echo ""
echo "=== App Info ==="
get 200 "GET /info (admin)"               "/api/v1/info" "$ADMIN"
get 403 "GET /info (lookup — no admin)"    "/api/v1/info" "$LOOKUP"
get 403 "GET /info (typosquatting — no admin)" "/api/v1/info" "$TYPO"
get 403 "GET /info (enterprise — no admin)" "/api/v1/info" "$ENTERPRISE"
get 401 "GET /info (no key)"               "/api/v1/info" ""

echo ""
echo "=== Domain Lookup — Auth & Features ==="
post 200 "lookup (admin)"       "/api/v1/domain/lookup" "$ADMIN"      "$DOMAIN"
post 200 "lookup (lookup)"      "/api/v1/domain/lookup" "$LOOKUP"     "$DOMAIN"
post 200 "lookup (enterprise)"  "/api/v1/domain/lookup" "$ENTERPRISE" "$DOMAIN"
post 403 "lookup (typosquatting — no lookup feature)" "/api/v1/domain/lookup" "$TYPO" "$DOMAIN"
post 401 "lookup (no key)"      "/api/v1/domain/lookup" ""            "$DOMAIN"
post 401 "lookup (wrong key)"  "/api/v1/domain/lookup" "totally-wrong-key" "$DOMAIN"

echo ""
echo "=== Domain Lookup — Premium Options ==="
post 200 "screenshot (admin — premium)"         "/api/v1/domain/lookup" "$ADMIN"      '{"domains":["example.com"],"screenshot":true}'
post 200 "screenshot (enterprise — premium)"    "/api/v1/domain/lookup" "$ENTERPRISE" '{"domains":["example.com"],"screenshot":true}'
post 403 "screenshot (lookup — basic tier)"     "/api/v1/domain/lookup" "$LOOKUP"     '{"domains":["example.com"],"screenshot":true}'
post 200 "reputation (admin — premium)"         "/api/v1/domain/lookup" "$ADMIN"      '{"domains":["example.com"],"reputation":true}'
post 200 "reputation (enterprise — premium)"    "/api/v1/domain/lookup" "$ENTERPRISE" '{"domains":["example.com"],"reputation":true}'
post 403 "reputation (lookup — basic tier)"     "/api/v1/domain/lookup" "$LOOKUP"     '{"domains":["example.com"],"reputation":true}'
post 200 "screenshot+reputation (admin)"        "/api/v1/domain/lookup" "$ADMIN"      '{"domains":["example.com"],"screenshot":true,"reputation":true}'

echo ""
echo "=== Domain Lookup — All-Tier Options ==="
post 200 "email_security (admin)"      "/api/v1/domain/lookup" "$ADMIN"      '{"domains":["example.com"],"email_security":true}'
post 200 "email_security (lookup)"     "/api/v1/domain/lookup" "$LOOKUP"     '{"domains":["example.com"],"email_security":true}'
post 200 "email_security (enterprise)" "/api/v1/domain/lookup" "$ENTERPRISE" '{"domains":["example.com"],"email_security":true}'
post 200 "subdomains (admin)"          "/api/v1/domain/lookup" "$ADMIN"      '{"domains":["example.com"],"subdomains":true}'
post 200 "subdomains (lookup)"         "/api/v1/domain/lookup" "$LOOKUP"     '{"domains":["example.com"],"subdomains":true}'
post 200 "subdomains (enterprise)"     "/api/v1/domain/lookup" "$ENTERPRISE" '{"domains":["example.com"],"subdomains":true}'
post 200 "ct_logs (admin)"             "/api/v1/domain/lookup" "$ADMIN"      '{"domains":["example.com"],"ct_logs":true}'
post 200 "ct_logs (lookup)"            "/api/v1/domain/lookup" "$LOOKUP"     '{"domains":["example.com"],"ct_logs":true}'
post 200 "bgp (admin)"                 "/api/v1/domain/lookup" "$ADMIN"      '{"domains":["example.com"],"bgp":true}'
post 200 "bgp (lookup)"               "/api/v1/domain/lookup" "$LOOKUP"     '{"domains":["example.com"],"bgp":true}'
post 200 "fingerprint (admin)"         "/api/v1/domain/lookup" "$ADMIN"      '{"domains":["example.com"],"fingerprint":true}'
post 200 "fingerprint (lookup)"        "/api/v1/domain/lookup" "$LOOKUP"     '{"domains":["example.com"],"fingerprint":true}'

echo ""
echo "=== Domain Lookup — Validation ==="
post 400 "empty domains"       "/api/v1/domain/lookup" "$ADMIN" '{"domains":[]}'
post 400 "missing domains"     "/api/v1/domain/lookup" "$ADMIN" '{}'
post 400 "invalid domain"      "/api/v1/domain/lookup" "$ADMIN" '{"domains":["notadomain"]}'
post 400 "raw IP"              "/api/v1/domain/lookup" "$ADMIN" '{"domains":["1.2.3.4"]}'

echo ""
echo "=== Typosquatting — Auth & Features ==="
post 200 "typosquatting (admin)"               "/api/v1/domain/typosquatting" "$ADMIN"      "$DOMAIN"
post 200 "typosquatting (typosquatting key)"    "/api/v1/domain/typosquatting" "$TYPO"       "$DOMAIN"
post 200 "typosquatting (enterprise)"           "/api/v1/domain/typosquatting" "$ENTERPRISE" "$DOMAIN"
post 403 "typosquatting (lookup — no feature)"  "/api/v1/domain/typosquatting" "$LOOKUP"     "$DOMAIN"
post 401 "typosquatting (no key)"               "/api/v1/domain/typosquatting" ""            "$DOMAIN"

echo ""
echo "=== Typosquatting — Options ==="
post 200 "typosquatting depth=shallow"  "/api/v1/domain/typosquatting" "$ADMIN" '{"domains":["example.com"],"depth":"shallow"}'
post 200 "typosquatting depth=deep"     "/api/v1/domain/typosquatting" "$ADMIN" '{"domains":["example.com"],"depth":"deep"}'
post 200 "typosquatting check_live"     "/api/v1/domain/typosquatting" "$ADMIN" '{"domains":["example.com"],"check_live":true}'
post 400 "typosquatting invalid depth"  "/api/v1/domain/typosquatting" "$ADMIN" '{"domains":["example.com"],"depth":"invalid"}'

echo ""
echo "=== Admin ==="
post 200 "cache invalidate (admin)"            "/api/v1/admin/auth/cache/invalidate" "$ADMIN"  ""
post 403 "cache invalidate (lookup — no admin)" "/api/v1/admin/auth/cache/invalidate" "$LOOKUP" ""
post 401 "cache invalidate (no key)"           "/api/v1/admin/auth/cache/invalidate" ""        ""

echo ""
echo "=== Admin — Fingerprint Rules ==="
get  200 "GET fingerprints (admin)"            "/api/v1/admin/fingerprints" "$ADMIN"
get  403 "GET fingerprints (lookup — no admin)" "/api/v1/admin/fingerprints" "$LOOKUP"
get  401 "GET fingerprints (no key)"           "/api/v1/admin/fingerprints" ""
post 200 "POST fingerprints (admin)"           "/api/v1/admin/fingerprints" "$ADMIN" '[{"name":"TestTech","category":"web-server","headers":{"Server":"test"}}]'
post 403 "POST fingerprints (lookup — no admin)" "/api/v1/admin/fingerprints" "$LOOKUP" '[{"name":"TestTech","category":"web-server","headers":{"Server":"test"}}]'
post 401 "POST fingerprints (no key)"          "/api/v1/admin/fingerprints" ""       '[{"name":"TestTech","category":"web-server","headers":{"Server":"test"}}]'

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

check_json "typosquatting response has domain and permutations" \
    '.[0] | (.domain and .permutations)' \
    -X POST "$HOST/api/v1/domain/typosquatting" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

echo ""
echo "=== Rate Limiting ==="
# Basic tier limit is 30/min. Send 31 requests and verify the last gets 429.
rate_ok=true
for i in $(seq 1 31); do
    rl_status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/api/v1/domain/lookup" \
        -H "Content-Type: application/json" -H "X-API-Key: $LOOKUP" \
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
rid_status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/api/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -H "X-Client-Request-ID: smoke-test-123" \
    -d "$DOMAIN")
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
