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
warn=0
errors=()
warnings=()

check() {
    local expect="$1"
    local desc="$2"
    shift 2
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' "$@") || true
    if [ "$status" = "$expect" ]; then
        printf "  \033[32m✓\033[0m %s → %s\n" "$desc" "$status"
        pass=$((pass + 1))
    else
        printf "  \033[31m✗\033[0m %s → %s (expected %s)\n" "$desc" "$status" "$expect"
        fail=$((fail + 1))
        errors+=("$desc: got $status, expected $expect")
    fi
}

# assert_json — applies a jq filter to an already-captured response body.
# Failure is fatal. Split out from check_json so one response can carry several
# assertions without re-issuing the request.
#   $1  description
#   $2  jq filter that must produce a non-empty/true result
#   $3  response body
assert_json() {
    local desc="$1" filter="$2" body="$3"
    if echo "$body" | jq -e "$filter" > /dev/null 2>&1; then
        printf "  \033[32m✓\033[0m %s\n" "$desc"
        pass=$((pass + 1))
    else
        printf "  \033[31m✗\033[0m %s (jq filter failed: %s)\n" "$desc" "$filter"
        fail=$((fail + 1))
        errors+=("$desc: jq filter '$filter' failed")
    fi
}

# assert_json_upstream — assert_json, but a failure is a warning rather than
# counting against the exit status. For assertions that depend on a third-party
# service we do not control: crt.sh in particular returns 502s and rate-limits
# wildcard queries, and a release check that goes red because somebody else had
# a bad minute is a check people learn to ignore.
#
# Use this ONLY for the part of a response the third party supplies. Whether our
# own API answered at all is never in this category — assert that with
# assert_json first, or a 5xx from us reads as somebody else's outage.
assert_json_upstream() {
    local desc="$1" filter="$2" body="$3"
    if echo "$body" | jq -e "$filter" > /dev/null 2>&1; then
        printf "  \033[32m✓\033[0m %s\n" "$desc"
        pass=$((pass + 1))
    else
        printf "  \033[33m!\033[0m %s (upstream unavailable, not fatal)\n" "$desc"
        warn=$((warn + 1))
        warnings+=("$desc: upstream did not return the expected data")
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
    body=$(curl -s "$@") || true
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

# check_header — verifies a response header is present and optionally matches a value.
#   $1  description
#   $2  header name
#   $3  expected value (empty string = just check presence)
#   $@  remaining args are passed to curl
check_header() {
    local desc="$1" header="$2" expected="$3"
    shift 3
    local value
    value=$(curl -s -D - -o /dev/null "$@" 2>&1 | grep -i "^$header:" | head -1 | sed "s/^[^:]*: //" | tr -d '\r') || true
    if [ -z "$value" ]; then
        printf "  \033[31m✗\033[0m %s (header %s not found)\n" "$desc" "$header"
        fail=$((fail + 1))
        errors+=("$desc: header $header not found")
    elif [ -n "$expected" ] && [ "$value" != "$expected" ]; then
        printf "  \033[31m✗\033[0m %s (%s = %s, expected %s)\n" "$desc" "$header" "$value" "$expected"
        fail=$((fail + 1))
        errors+=("$desc: $header = $value, expected $expected")
    else
        printf "  \033[32m✓\033[0m %s (%s: %s)\n" "$desc" "$header" "$value"
        pass=$((pass + 1))
    fi
}

# Keys (override via .env or env vars for production)
ADMIN="${SMOKE_ADMIN_KEY:-test-admin-key}"
BASIC="${SMOKE_BASIC_KEY:-test-basic-key}"
PRO="${SMOKE_PRO_KEY:-test-pro-key}"

# Free-plan keys are pooled and rotated: the rate limiter is per key per minute
# and free allows 5, so one key alone makes a full run spend minutes waiting out
# windows. SMOKE_FREE_KEYS (comma-separated) or numbered siblings
# (SMOKE_FREE_KEY_2, _3, ...) are picked up automatically.
FREE_POOL=()
if [ -n "${SMOKE_FREE_KEYS:-}" ]; then
    IFS=',' read -r -a FREE_POOL <<< "$SMOKE_FREE_KEYS"
else
    FREE_POOL=("${SMOKE_FREE_KEY:-test-free-key}")
    n=2
    while true; do
        var="SMOKE_FREE_KEY_$n"
        [ -z "${!var:-}" ] && break
        FREE_POOL+=("${!var}")
        n=$((n + 1))
    done
    # No configured siblings means the local stack: seed.sql provides three.
    if [ ${#FREE_POOL[@]} -eq 1 ] && [ "${FREE_POOL[0]}" = "test-free-key" ]; then
        FREE_POOL+=("test-free-key-2" "test-free-key-3")
    fi
fi

# SMOKE_RATELIMIT_KEY is a free key RESERVED for the rate limit check and held
# out of the pool. That check has to exhaust one key's window, which is the
# opposite of what the pool is for: rotating would spread the load and never
# reach the limit, and reusing a pooled key would stall whichever later check
# drew it. Without one the check is skipped rather than run wrongly.
RATELIMIT_KEY="${SMOKE_RATELIMIT_KEY:-}"
if [ -z "$RATELIMIT_KEY" ] && [[ "$HOST" == *"localhost"* || "$HOST" == *"127.0.0.1"* ]]; then
    RATELIMIT_KEY="test-free-key-4"  # seeded by migrations/seed.sql
fi
if [ -n "$RATELIMIT_KEY" ]; then
    filtered=()
    for k in "${FREE_POOL[@]}"; do [ "$k" != "$RATELIMIT_KEY" ] && filtered+=("$k"); done
    [ ${#filtered[@]} -gt 0 ] && FREE_POOL=("${filtered[@]}")
fi

# free_key rotates the pool, setting FK to the next key.
free_i=0
free_key() {
    FK="${FREE_POOL[free_i % ${#FREE_POOL[@]}]}"
    free_i=$((free_i + 1))
}

DOMAIN='{"domains":["example.com"],"lookups":["whois","dns","ssl","headers"]}'

echo ""
echo "=== Docs ==="
check 301 "GET / (redirect to /docs)" "$HOST/"
check 200 "GET /docs (landing page)" "$HOST/docs"
check 200 "GET /docs/domain (domain docs)" "$HOST/docs/domain"
check 200 "GET /docs/ip (IP docs)" "$HOST/docs/ip"
check 200 "GET /docs/changelog (release notes)" "$HOST/docs/changelog"
check 200 "GET /docs/openapi.yaml (OpenAPI spec)" "$HOST/docs/openapi.yaml"
check 404 "GET /nope (unknown page)" "$HOST/nope"
check 404 "GET /v1/nope (unknown API path)" "$HOST/v1/nope"

echo ""
echo "=== Health Check ==="
get 200 "GET /hello (no auth)" "/v1/hello" ""
get 200 "GET /health (no auth)" "/v1/health" ""

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
free_key; post 200 "lookup (free)"       "/v1/domain/lookup" "$FK"  "$DOMAIN"
free_key; post 400 "free plan max domains" "/v1/domain/lookup" "$FK" '{"domains":["a.com","b.com"],"lookups":["dns"]}'
post 401 "lookup (no key)"     "/v1/domain/lookup" ""       "$DOMAIN"
post 401 "lookup (wrong key)"  "/v1/domain/lookup" "totally-wrong-key" "$DOMAIN"

echo ""
echo "=== Domain Lookup — Pro Options ==="
post 200 "screenshot (admin)"            "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["screenshot"]}'
post 200 "screenshot (pro)"              "/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"lookups":["screenshot"]}'
post 403 "screenshot (basic — pro only)" "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["screenshot"]}'
free_key; post 403 "screenshot (free — pro only)"  "/v1/domain/lookup" "$FK"  '{"domains":["example.com"],"lookups":["screenshot"]}'
post 200 "reputation (admin)"            "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["reputation"]}'
post 200 "reputation (pro)"              "/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"lookups":["reputation"]}'
post 403 "reputation (basic — pro only)" "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["reputation"]}'
free_key; post 403 "reputation (free — pro only)"  "/v1/domain/lookup" "$FK" '{"domains":["example.com"],"lookups":["reputation"]}'
post 200 "screenshot+reputation (admin)" "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["screenshot","reputation"]}'
post 200 "threat_intel (admin)"            "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["threat_intel"]}'
post 200 "threat_intel (pro)"              "/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"lookups":["threat_intel"]}'
post 403 "threat_intel (basic — pro only)" "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["threat_intel"]}'
free_key; post 403 "threat_intel (free — pro only)"  "/v1/domain/lookup" "$FK" '{"domains":["example.com"],"lookups":["threat_intel"]}'

echo ""
echo "=== Domain Lookup — All-Plan Options ==="
post 200 "email_security (admin)"  "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["email_security"]}'
post 200 "email_security (pro)"    "/v1/domain/lookup" "$PRO"   '{"domains":["example.com"],"lookups":["email_security"]}'
post 200 "email_security (basic)"  "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["email_security"]}'
free_key; post 200 "email_security (free)"   "/v1/domain/lookup" "$FK" '{"domains":["example.com"],"lookups":["email_security"]}'
post 200 "subdomains (admin)"      "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["subdomains"]}'
post 200 "subdomains (basic)"      "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["subdomains"]}'
post 200 "ct_logs (admin)"         "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["ct_logs"]}'
post 200 "ct_logs (basic)"         "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["ct_logs"]}'
post 200 "bgp (admin)"             "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["bgp"]}'
post 200 "bgp (basic)"             "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["bgp"]}'
post 200 "fingerprint (admin)"     "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["fingerprint"]}'
post 200 "fingerprint (basic)"     "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["fingerprint"]}'
post 200 "dns_security (admin)"    "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["dns_security"]}'
post 200 "dns_security (basic)"    "/v1/domain/lookup" "$BASIC" '{"domains":["example.com"],"lookups":["dns_security"]}'
free_key; post 200 "dns_security (free)"     "/v1/domain/lookup" "$FK" '{"domains":["example.com"],"lookups":["dns_security"]}'
post 200 "risk (admin)"            "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["ssl","headers","risk"]}'
free_key; post 200 "risk (free)"             "/v1/domain/lookup" "$FK" '{"domains":["example.com"],"lookups":["ssl","headers","risk"]}'

echo ""
echo "=== Domain Lookup — Validation ==="
post 400 "empty domains"       "/v1/domain/lookup" "$ADMIN" '{"domains":[],"lookups":["dns"]}'
post 400 "missing domains"     "/v1/domain/lookup" "$ADMIN" '{}'
post 400 "invalid domain"      "/v1/domain/lookup" "$ADMIN" '{"domains":["notadomain"],"lookups":["dns"]}'
post 400 "raw IP"              "/v1/domain/lookup" "$ADMIN" '{"domains":["1.2.3.4"],"lookups":["dns"]}'
post 400 "missing lookups"     "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"]}'
post 400 "empty lookups"       "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":[]}'
post 400 "blank lookups"       "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["  "]}'
post 400 "unknown lookup"      "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":["dns","banana"]}'
post 200 "lookup names normalized" "/v1/domain/lookup" "$ADMIN" '{"domains":["example.com"],"lookups":[" DNS ","dns"]}'

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
echo "=== My Usage ==="
get  200 "GET /v1/usage (pro)"        "/v1/usage" "$PRO"
get  200 "GET /v1/usage ?days=7 (basic)" "/v1/usage?days=7" "$BASIC"
get  401 "GET /v1/usage (no key)"     "/v1/usage" ""

echo ""
echo "=== Key Rotation ==="
# Positive rotation is deliberately NOT exercised here: rotating would mint a
# new key and grace-expire the configured smoke keys, breaking later runs.
post 401 "rotate key (no key)" "/v1/keys/rotate" "" ""

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

check_json "lookup response is a results envelope with domain field" \
    '.results[0].domain == "example.com"' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

check_json "lookup response has whois populated" \
    '.results[0].whois.domain_name' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

check_json "lookup response has dns populated" \
    '.results[0].dns' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

check_json "lookup response has ssl populated" \
    '.results[0].ssl.subject' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

check_json "lookup response has headers populated" \
    '.results[0].headers.status_code' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

check_json "dns_security response has dnssec field" \
    '.results[0].dns_security.dnssec' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"domains":["example.com"],"lookups":["dns_security"]}'

check_json "risk scores over the other requested lookups" \
    '.results[0].risk | .score >= 0 and (.components | length) > 0' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"domains":["example.com"],"lookups":["ssl","headers","risk"]}'

echo ""
echo "=== Multi-Domain Batch ==="
post 200 "basic 3 domains" "/v1/domain/lookup" "$BASIC" '{"domains":["example.com","example.org","example.net"],"lookups":["dns"]}'
check_json "basic batch returns 3 results" \
    '.results | length == 3' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $BASIC" \
    -d '{"domains":["example.com","example.org","example.net"],"lookups":["dns"]}'
post 200 "pro 3 domains" "/v1/domain/lookup" "$PRO" '{"domains":["example.com","example.org","example.net"],"lookups":["dns"]}'

echo ""
echo "=== All Features Combined ==="
# One request, two assertions with different severities. Our own lookups must
# populate their fields or the release is broken; ct_logs and subdomains both
# come from crt.sh, so those degrade to a warning.
all_features_body=$(curl -s -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"domains":["example.com"],"lookups":["email_security","subdomains","ct_logs","bgp","fingerprint"]}') || true

assert_json "all features: our own lookups return populated fields" \
    '.results[0] | .email_security and .bgp and .fingerprint' \
    "$all_features_body"

assert_json_upstream "all features: ct_logs and subdomains populated (crt.sh dependent)" \
    '.results[0] | .ct_logs and .subdomains' \
    "$all_features_body"

echo ""
echo "=== Selectable Lookups ==="
check_json "response contains only requested lookups" \
    '.results[0] | has("dns") and has("bgp") and (has("whois") | not) and (has("ssl") | not)' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"domains":["example.com"],"lookups":["dns","bgp"]}'

check_json "each lookup carries its own cache_hit" \
    '.results[0] | (.dns.cache_hit | type == "boolean") and (.ssl.cache_hit | type == "boolean")' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"domains":["example.com"],"lookups":["dns","ssl"]}'

check_json "no top-level cache_hit" \
    '.results[0] | has("cache_hit") | not' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"domains":["example.com"],"lookups":["dns"]}'

check_json "duplicate domains dedupe and report inputs verbatim" \
    '.results | length == 1 and (.[0].domain == "example.com") and (.[0].inputs | length == 2)' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"domains":["HTTPS://Example.COM/","example.com"],"lookups":["dns"]}'

check_json "fingerprint-only omits headers from the response" \
    '.results[0] | has("fingerprint") and (has("headers") | not)' \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"domains":["example.com"],"lookups":["fingerprint"]}'

echo ""
echo "=== Security Headers ==="
check_header "X-Content-Type-Options present" "X-Content-Type-Options" "nosniff" "$HOST/v1/hello"
check_header "X-Frame-Options present"        "X-Frame-Options"        "DENY"    "$HOST/v1/hello"
check_header "Cache-Control: no-store"         "Cache-Control"          "no-store" "$HOST/v1/hello"

echo ""
echo "=== X-Request-ID ==="
check_header "X-Request-ID on unauthenticated request" "X-Request-ID" "" "$HOST/v1/hello"
check_header "X-Request-ID on authenticated request"   "X-Request-ID" "" \
    -X POST "$HOST/v1/domain/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d "$DOMAIN"

echo ""
echo "=== Rate Limit Headers ==="
check_header "X-RateLimit-Limit on basic request"     "X-RateLimit-Limit"     "" "$HOST/v1/domain/lookup" -X POST -H "Content-Type: application/json" -H "X-API-Key: $BASIC" -d "$DOMAIN"
check_header "X-RateLimit-Remaining on basic request" "X-RateLimit-Remaining" "" "$HOST/v1/domain/lookup" -X POST -H "Content-Type: application/json" -H "X-API-Key: $BASIC" -d "$DOMAIN"

echo ""
echo "=== Rate Limit Enforcement ==="
# Exhausts the reserved key's window: free allows 5/min, so within 7 rapid
# requests one must come back 429 carrying Retry-After. Uses GET /v1/usage —
# authenticated and rate-limited, but no lookup cost. The key stays exhausted
# for up to a minute afterwards, which is why it must not be in the pool.
if [ -z "$RATELIMIT_KEY" ]; then
    printf "  \033[33m!\033[0m skipped — set SMOKE_RATELIMIT_KEY to a free key reserved for this check\n"
    warn=$((warn + 1))
    warnings+=("rate limit enforcement skipped: no SMOKE_RATELIMIT_KEY configured")
else
    rl_headers=""
    rl_status=""
    for _ in 1 2 3 4 5 6 7; do
        rl_headers=$(curl -s -D - -o /dev/null "$HOST/v1/usage" -H "X-API-Key: $RATELIMIT_KEY") || true
        rl_status=$(echo "$rl_headers" | head -1 | awk '{print $2}')
        [ "$rl_status" = "429" ] && break
    done
    if [ "$rl_status" = "429" ]; then
        printf "  \033[32m✓\033[0m free plan rate limit enforced → 429\n"
        pass=$((pass + 1))
        if echo "$rl_headers" | grep -qi '^Retry-After:'; then
            printf "  \033[32m✓\033[0m 429 carries Retry-After\n"
            pass=$((pass + 1))
        else
            printf "  \033[31m✗\033[0m 429 without Retry-After header\n"
            fail=$((fail + 1))
            errors+=("429 response missing Retry-After header")
        fi
    else
        printf "  \033[31m✗\033[0m rate limit never triggered (last status %s)\n" "$rl_status"
        fail=$((fail + 1))
        errors+=("free plan rate limit not enforced: 7 rapid requests, no 429")
    fi
fi

echo ""
echo "=== Body Size Limit ==="
# Send a >1MB payload. MaxBytesReader surfaces through Gin's binding layer as 400.
# Written to a temp file because the shell can't pass >1MB as a CLI argument.
big_body_file=$(mktemp)
python3 -c "print('{\"lookups\":[\"dns\"],\"domains\":[\"' + 'x'*1048577 + '\"]}')" > "$big_body_file"
check 413 "oversized body (>1MB) rejected" \
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
    -d "$DOMAIN" 2>&1 | grep -i "X-Client-Request-ID" | tr -d '\r') || true
if echo "$rid_echo" | grep -q "smoke-test-456"; then
    printf "  \033[32m✓\033[0m X-Client-Request-ID echoed back\n"
    pass=$((pass + 1))
else
    printf "  \033[31m✗\033[0m X-Client-Request-ID not echoed (got: %s)\n" "$rid_echo"
    fail=$((fail + 1))
    errors+=("X-Client-Request-ID echo failed")
fi

echo "=== IP Lookup — Auth ==="

# Several checks below assert on geo/asn content, which needs the MaxMind
# databases. When they are absent every one of those checks fails as an opaque
# "jq filter failed", which says nothing about the cause. Ask /v1/health once and
# say so plainly instead.
#
# Still a failure, not a warning: geo being unavailable is a real problem
# wherever this runs, and downgrading it would hide exactly the regression the
# checks exist to catch. The message just makes the cause obvious.
# The `|| true` matters: under `set -euo pipefail` an unreachable host makes
# curl exit non-zero, and the failing command substitution would abort the
# entire smoke run here rather than reporting anything.
geoip_state=$(curl -s -m 10 "$HOST/v1/health" 2>/dev/null | jq -r '.components.geoip // "unknown"' 2>/dev/null || true)
# jq's // fallback only fires for parseable JSON. An unreachable host or a
# non-JSON error page makes jq fail with no output at all, which would print as
# "geoip=" — the one thing this whole check exists to avoid.
geoip_state=${geoip_state:-unreachable}

if [ "$geoip_state" != "ok" ]; then
    printf "  \033[31m✗\033[0m GeoIP databases are not loaded (/v1/health geoip=%s)\n" "$geoip_state"
    printf "      The geo/asn content checks below will fail as a result.\n"
    printf "      Locally: set MAXMIND_LICENSE_KEY in .env and restart — the app downloads on boot.\n"
    printf "      Deployed: check startup logs, or POST %s/v1/admin/geoip/refresh to force it.\n" "$HOST"
    fail=$((fail + 1))
    errors+=("GeoIP databases not loaded (geoip=$geoip_state) — geo/asn checks cannot pass")
fi

IP='{"ips":["8.8.8.8"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}'
post 200 "admin key" /v1/ip/lookup "$ADMIN" "$IP"
post 200 "basic key" /v1/ip/lookup "$BASIC" "$IP"
post 200 "pro key" /v1/ip/lookup "$PRO" "$IP"
free_key; post 200 "free key" /v1/ip/lookup "$FK" "$IP"
post 401 "no key" /v1/ip/lookup "" "$IP"
post 401 "bad key" /v1/ip/lookup "invalid-key" "$IP"

echo "=== IP Lookup — Pro Options ==="
post 200 "threat_intel (admin)" /v1/ip/lookup "$ADMIN" '{"ips":["8.8.8.8"],"lookups":["threat_intel"]}'
post 200 "threat_intel (pro)" /v1/ip/lookup "$PRO" '{"ips":["8.8.8.8"],"lookups":["threat_intel"]}'
post 403 "threat_intel (basic)" /v1/ip/lookup "$BASIC" '{"ips":["8.8.8.8"],"lookups":["threat_intel"]}'
free_key; post 403 "threat_intel (free)" /v1/ip/lookup "$FK" '{"ips":["8.8.8.8"],"lookups":["threat_intel"]}'

echo "=== IP Lookup — Validation ==="
post 400 "invalid IP" /v1/ip/lookup "$ADMIN" '{"ips":["not-an-ip"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}'
post 400 "private IP" /v1/ip/lookup "$ADMIN" '{"ips":["127.0.0.1"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}'
post 400 "metadata IP" /v1/ip/lookup "$ADMIN" '{"ips":["169.254.169.254"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}'
post 400 "empty array" /v1/ip/lookup "$ADMIN" '{"ips":[],"lookups":["geo","asn","reverse_dns","abuse_contact"]}'
post 400 "missing lookups"    /v1/ip/lookup "$ADMIN" '{"ips":["8.8.8.8"]}'
post 400 "empty lookups"      /v1/ip/lookup "$ADMIN" '{"ips":["8.8.8.8"],"lookups":[]}'
post 400 "unknown lookup"     /v1/ip/lookup "$ADMIN" '{"ips":["8.8.8.8"],"lookups":["geo","banana"]}'
post 400 "domain-only lookup" /v1/ip/lookup "$ADMIN" '{"ips":["8.8.8.8"],"lookups":["whois"]}'

check_json "IP response contains only requested lookups" \
    '.results[0] | has("geo") and (has("asn") | not) and (has("reverse_dns") | not)' \
    -X POST "$HOST/v1/ip/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"ips":["8.8.8.8"],"lookups":["geo"]}'

check_json "IP lookups carry their own cache_hit" \
    '.results[0] | (.geo.cache_hit | type == "boolean") and (.reverse_dns.cache_hit | type == "boolean")' \
    -X POST "$HOST/v1/ip/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"ips":["8.8.8.8"],"lookups":["geo","reverse_dns"]}'

check_json "IP addresses dedupe and report inputs verbatim" \
    '.results | length == 1 and (.[0].inputs | length == 2)' \
    -X POST "$HOST/v1/ip/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"ips":[" 8.8.8.8 ","8.8.8.8"],"lookups":["geo"]}'
post 400 "missing field" /v1/ip/lookup "$ADMIN" '{}'

echo "=== IP Lookup — Response Validation ==="
check_json "IP response has ip field" '.results[0].ip == "8.8.8.8"' \
    -X POST "$HOST/v1/ip/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"ips":["8.8.8.8"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}'
check_json "IP response has reverse_dns" '.results[0].reverse_dns != null' \
    -X POST "$HOST/v1/ip/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"ips":["8.8.8.8"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}'
check_json "IP response has abuse_contact" '.results[0].abuse_contact != null' \
    -X POST "$HOST/v1/ip/lookup" \
    -H "Content-Type: application/json" -H "X-API-Key: $ADMIN" \
    -d '{"ips":["8.8.8.8"],"lookups":["geo","asn","reverse_dns","abuse_contact"]}'

echo "=== GeoIP Admin ==="
# Note: admin success test omitted — refresh downloads from MaxMind (requires real license key)
post 403 "refresh (basic, forbidden)" /v1/admin/geoip/refresh "$BASIC" '{}'
post 401 "refresh (no key)" /v1/admin/geoip/refresh "" '{}'

# Summary
echo ""
echo "================================"
printf "  \033[32m%d passed\033[0m, \033[31m%d failed\033[0m, \033[33m%d warned\033[0m\n" "$pass" "$fail" "$warn"
if [ ${#errors[@]} -gt 0 ]; then
    echo ""
    echo "  Failures:"
    for e in "${errors[@]}"; do
        printf "    \033[31m✗\033[0m %s\n" "$e"
    done
fi
if [ ${#warnings[@]} -gt 0 ]; then
    echo ""
    echo "  Warnings (third-party services, not release blockers):"
    for w in "${warnings[@]}"; do
        printf "    \033[33m!\033[0m %s\n" "$w"
    done
fi
echo "================================"
echo ""

[ "$fail" -eq 0 ]
