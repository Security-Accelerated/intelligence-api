#!/usr/bin/env bash
# Load test — hits domain and IP endpoints concurrently with enough unique
# targets to avoid cache hits. Measures response times and error rates.
#
# With ~500 domains and ~1500 IPs running concurrently, this runs 30-60 minutes.
#
# Usage:
#   ./scripts/load-test.sh                          # localhost
#   ./scripts/load-test.sh https://api.securityaccelerated.com   # production
#
# Requires: curl
set -euo pipefail

HOST="${1:-http://localhost:8080}"

# Load .env for non-localhost targets
if [[ "$HOST" != *"localhost"* && "$HOST" != *"127.0.0.1"* ]]; then
    ENV_FILE="$(dirname "$0")/../.env"
    [ -f "$ENV_FILE" ] && set -a && . "$ENV_FILE" && set +a
    if [ -z "${SMOKE_ADMIN_KEY:-}" ]; then
        echo "ERROR: SMOKE_ADMIN_KEY is required for non-localhost targets. Set it in .env or environment." >&2
        exit 1
    fi
fi

KEY="${SMOKE_ADMIN_KEY:-test-admin-key}"

# Shared counters via temp files (for cross-process aggregation)
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
DOMAIN_LOG="$TMPDIR/domain.log"
IP_LOG="$TMPDIR/ip.log"
touch "$DOMAIN_LOG" "$IP_LOG"

# --- ~500 unique domains ---
DOMAINS=(
    # Big tech
    "google.com" "youtube.com" "facebook.com" "instagram.com" "twitter.com"
    "linkedin.com" "microsoft.com" "apple.com" "amazon.com" "netflix.com"
    "tiktok.com" "snapchat.com" "pinterest.com" "whatsapp.com" "telegram.org"
    "discord.com" "signal.org" "slack.com" "zoom.us" "teams.microsoft.com"
    # Dev platforms
    "github.com" "gitlab.com" "bitbucket.org" "sourceforge.net" "codeberg.org"
    "stackoverflow.com" "stackexchange.com" "dev.to" "hashnode.com" "medium.com"
    "hackernews.com" "lobste.rs" "slashdot.org" "techmeme.com" "arstechnica.com"
    # Cloud / infra
    "aws.amazon.com" "cloud.google.com" "azure.microsoft.com" "digitalocean.com" "linode.com"
    "vultr.com" "hetzner.com" "ovhcloud.com" "scaleway.com" "upcloud.com"
    "fly.io" "railway.app" "render.com" "vercel.com" "netlify.com"
    "heroku.com" "platformsh.com" "dokku.com" "coolify.io" "caprover.com"
    # CDN / edge
    "cloudflare.com" "akamai.com" "fastly.com" "bunny.net" "cdn77.com"
    "keycdn.com" "stackpath.com" "limelight.com" "edgecast.com" "imperva.com"
    # Security
    "crowdstrike.com" "paloaltonetworks.com" "fortinet.com" "checkpoint.com" "zscaler.com"
    "sentinelone.com" "trellix.com" "sophos.com" "trendmicro.com" "kaspersky.com"
    "malwarebytes.com" "bitdefender.com" "avast.com" "norton.com" "mcafee.com"
    "okta.com" "auth0.com" "duo.com" "onelogin.com" "jumpcloud.com"
    "1password.com" "lastpass.com" "bitwarden.com" "dashlane.com" "keeper.io"
    "snyk.io" "sonarqube.org" "veracode.com" "checkmarx.com" "synopsys.com"
    "hackerone.com" "bugcrowd.com" "intigriti.com" "yeswehack.com" "cobalt.io"
    # Observability
    "datadog.com" "grafana.com" "elastic.co" "splunk.com" "dynatrace.com"
    "newrelic.com" "honeycomb.io" "lightstep.com" "sentry.io" "rollbar.com"
    "pagerduty.com" "opsgenie.com" "victorops.com" "betteruptime.com" "statuspage.io"
    # Databases
    "mongodb.com" "postgresql.org" "mysql.com" "mariadb.org" "cockroachlabs.com"
    "planetscale.com" "neon.tech" "supabase.com" "fauna.com" "dgraph.io"
    "redis.io" "memcached.org" "couchbase.com" "arangodb.com" "neo4j.com"
    "influxdata.com" "timescale.com" "questdb.io" "clickhouse.com" "duckdb.org"
    # Languages / runtimes
    "golang.org" "rust-lang.org" "python.org" "nodejs.org" "ruby-lang.org"
    "php.net" "swift.org" "kotlinlang.org" "typescriptlang.org" "dart.dev"
    "elixir-lang.org" "erlang.org" "haskell.org" "scala-lang.org" "clojure.org"
    "zig-lang.org" "vlang.io" "nim-lang.org" "crystal-lang.org" "julia-lang.org"
    # Package registries
    "npmjs.com" "pypi.org" "crates.io" "rubygems.org" "packagist.org"
    "nuget.org" "pkg.go.dev" "hex.pm" "pub.dev" "maven.org"
    # DNS / domain
    "godaddy.com" "namecheap.com" "cloudns.net" "dnsimple.com" "route53.amazonaws.com"
    "dynu.com" "afraid.org" "noip.com" "duckdns.org" "freedns.afraid.org"
    # Email
    "gmail.com" "outlook.com" "protonmail.com" "tutanota.com" "fastmail.com"
    "zoho.com" "mailgun.com" "sendgrid.com" "postmark.com" "mailchimp.com"
    "constantcontact.com" "brevo.com" "sparkpost.com" "amazonses.com" "mailjet.com"
    # Payments / fintech
    "stripe.com" "paypal.com" "square.com" "adyen.com" "braintreepayments.com"
    "wise.com" "revolut.com" "plaid.com" "coinbase.com" "binance.com"
    "kraken.com" "gemini.com" "blockchain.com" "ledger.com" "trezor.io"
    # SaaS
    "salesforce.com" "hubspot.com" "zendesk.com" "freshworks.com" "intercom.com"
    "atlassian.com" "asana.com" "monday.com" "clickup.com" "notion.so"
    "airtable.com" "basecamp.com" "trello.com" "todoist.com" "linear.app"
    "figma.com" "canva.com" "miro.com" "sketch.com" "invisionapp.com"
    "loom.com" "calendly.com" "typeform.com" "surveymonkey.com" "jotform.com"
    # Media / entertainment
    "spotify.com" "soundcloud.com" "bandcamp.com" "deezer.com" "tidal.com"
    "twitch.tv" "kick.com" "rumble.com" "vimeo.com" "dailymotion.com"
    "hulu.com" "disneyplus.com" "hbomax.com" "peacocktv.com" "paramountplus.com"
    "crunchyroll.com" "funimation.com" "imdb.com" "rottentomatoes.com" "metacritic.com"
    # News / media
    "bbc.com" "cnn.com" "nytimes.com" "washingtonpost.com" "theguardian.com"
    "reuters.com" "apnews.com" "bloomberg.com" "wsj.com" "ft.com"
    "wired.com" "theverge.com" "engadget.com" "gizmodo.com" "techcrunch.com"
    "zdnet.com" "cnet.com" "tomshardware.com" "anandtech.com" "extremetech.com"
    # Education
    "mit.edu" "stanford.edu" "harvard.edu" "oxford.ac.uk" "cambridge.org"
    "coursera.org" "edx.org" "udemy.com" "khanacademy.org" "codecademy.com"
    "freecodecamp.org" "leetcode.com" "hackerrank.com" "codewars.com" "exercism.org"
    # E-commerce
    "shopify.com" "bigcommerce.com" "woocommerce.com" "magento.com" "squarespace.com"
    "wix.com" "weebly.com" "godaddy.com" "etsy.com" "ebay.com"
    # Reference / tools
    "wikipedia.org" "wikimedia.org" "archive.org" "wolframalpha.com" "mathworld.wolfram.com"
    "who.is" "whois.com" "domaintools.com" "securitytrails.com" "shodan.io"
    "censys.io" "zoomeye.org" "greynoise.io" "urlscan.io" "virustotal.com"
    "abuseipdb.com" "ipinfo.io" "maxmind.com" "ipgeolocation.io" "ip-api.com"
    # Government / org
    "usa.gov" "gov.uk" "europa.eu" "un.org" "who.int"
    "eff.org" "fsf.org" "apache.org" "linuxfoundation.org" "cncf.io"
    "letsencrypt.org" "mozilla.org" "torproject.org" "privacytools.io" "protonvpn.com"
    # Gaming
    "steampowered.com" "epicgames.com" "gog.com" "ea.com" "ubisoft.com"
    "riotgames.com" "blizzard.com" "minecraft.net" "roblox.com" "unity.com"
    # Telecom
    "att.com" "verizon.com" "t-mobile.com" "vodafone.com" "orange.com"
    "bt.com" "telekom.com" "ntt.com" "singtel.com" "rogers.com"
    # Misc popular
    "reddit.com" "quora.com" "tumblr.com" "blogger.com" "wordpress.com"
    "ghost.org" "substack.com" "patreon.com" "gofundme.com" "kickstarter.com"
    "uber.com" "lyft.com" "airbnb.com" "booking.com" "tripadvisor.com"
    "zillow.com" "realtor.com" "redfin.com" "trulia.com" "apartments.com"
    "yelp.com" "doordash.com" "grubhub.com" "ubereats.com" "instacart.com"
)

# --- Curated IPs + generated from public ranges (~1500 unique) ---
IPS=(
    # DNS resolvers (curated)
    "8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1" "9.9.9.9" "9.9.9.10"
    "208.67.222.222" "208.67.220.220" "4.2.2.1" "4.2.2.2" "64.6.64.6" "64.6.65.6"
    "77.88.8.8" "77.88.8.1" "156.154.70.1" "156.154.71.1" "94.140.14.14" "94.140.15.15"
    "185.228.168.9" "185.228.169.9" "45.90.28.0" "45.90.30.0" "76.76.19.19"
    "8.26.56.26" "8.20.247.20" "195.46.39.39" "80.80.80.80" "91.239.100.100" "89.233.43.71"
    "149.112.112.112" "76.223.122.150"
    # Well-known services (curated)
    "13.107.4.50" "13.107.42.14" "52.96.165.130" "151.101.1.140" "151.101.65.140"
    "104.16.100.52" "172.67.182.31" "199.232.69.194" "185.199.108.153" "140.82.112.4"
    "192.0.78.24" "198.185.159.144" "76.76.21.21" "75.2.60.5" "34.102.136.180"
    "20.205.243.166" "157.240.1.35" "142.250.80.46" "54.230.226.99" "23.185.0.2"
    "104.244.42.65" "192.229.211.108" "23.67.75.179" "205.251.242.103" "93.184.216.34"
)

# Generate IPs from well-known public ranges to pad to ~1500
generate_ips() {
    # Cloudflare (104.16.0.0/12)
    for i in $(seq 0 99); do printf "104.16.%d.%d\n" "$((i / 10))" "$((i % 10 + 1))"; done
    # AWS (52.0.0.0/8 subset)
    for i in $(seq 1 100); do printf "52.%d.%d.1\n" "$((i % 256))" "$(((i * 7) % 256))"; done
    # Google (142.250.0.0/16 subset)
    for i in $(seq 1 100); do printf "142.250.%d.%d\n" "$((i % 256))" "$(((i * 3) % 256 + 1))"; done
    # Azure (20.0.0.0/8 subset)
    for i in $(seq 1 100); do printf "20.%d.%d.%d\n" "$((i % 256))" "$(((i * 11) % 256))" "$(((i * 5) % 256 + 1))"; done
    # Fastly (151.101.0.0/16)
    for i in $(seq 1 100); do printf "151.101.%d.%d\n" "$((i % 256))" "$(((i * 9) % 256 + 1))"; done
    # Akamai (23.0.0.0/8 subset)
    for i in $(seq 1 100); do printf "23.%d.%d.%d\n" "$((i % 256))" "$(((i * 13) % 256))" "$(((i * 7) % 256 + 1))"; done
    # DigitalOcean (159.89.0.0/16, 165.22.0.0/16)
    for i in $(seq 1 50); do printf "159.89.%d.%d\n" "$((i % 256))" "$(((i * 3) % 256 + 1))"; done
    for i in $(seq 1 50); do printf "165.22.%d.%d\n" "$((i % 256))" "$(((i * 7) % 256 + 1))"; done
    # Hetzner (95.216.0.0/16)
    for i in $(seq 1 100); do printf "95.216.%d.%d\n" "$((i % 256))" "$(((i * 11) % 256 + 1))"; done
    # OVH (51.0.0.0/8 subset)
    for i in $(seq 1 100); do printf "51.%d.%d.%d\n" "$((i % 256))" "$(((i * 17) % 256))" "$(((i * 3) % 256 + 1))"; done
    # Meta (157.240.0.0/16)
    for i in $(seq 1 100); do printf "157.240.%d.%d\n" "$((i % 256))" "$(((i * 7) % 256 + 1))"; done
    # GitHub (140.82.112.0/20)
    for i in $(seq 1 50); do printf "140.82.%d.%d\n" "$((112 + i % 16))" "$(((i * 5) % 256 + 1))"; done
    # Linode (45.33.0.0/16)
    for i in $(seq 1 50); do printf "45.33.%d.%d\n" "$((i % 256))" "$(((i * 9) % 256 + 1))"; done
    # Vultr (45.76.0.0/16, 45.77.0.0/16)
    for i in $(seq 1 50); do printf "45.76.%d.%d\n" "$((i % 256))" "$(((i * 3) % 256 + 1))"; done
    for i in $(seq 1 50); do printf "45.77.%d.%d\n" "$((i % 256))" "$(((i * 7) % 256 + 1))"; done
    # Scaleway (51.15.0.0/16)
    for i in $(seq 1 50); do printf "51.15.%d.%d\n" "$((i % 256))" "$(((i * 11) % 256 + 1))"; done
    # Oracle Cloud (132.145.0.0/16)
    for i in $(seq 1 50); do printf "132.145.%d.%d\n" "$((i % 256))" "$(((i * 13) % 256 + 1))"; done
    # Alibaba Cloud (47.88.0.0/16)
    for i in $(seq 1 50); do printf "47.88.%d.%d\n" "$((i % 256))" "$(((i * 5) % 256 + 1))"; done
}

# Append generated IPs (deduplicated)
while IFS= read -r ip; do
    IPS+=("$ip")
done < <(generate_ips | sort -u)

# --- Worker function ---
run_worker() {
    local type="$1" logfile="$2"
    shift 2
    local targets=("$@")
    local endpoint="/v1/domain/lookup"
    local field="domains"
    [ "$type" = "ip" ] && endpoint="/v1/ip/lookup" && field="ips"

    # Singles
    for target in "${targets[@]}"; do
        local req_start elapsed status
        req_start=$(date +%s%N)
        status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 45 \
            -X POST "$HOST$endpoint" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $KEY" \
            -d "{\"$field\":[\"$target\"]}") || status="000"
        elapsed=$(( ($(date +%s%N) - req_start) / 1000000 ))

        if [ "$status" = "200" ]; then
            printf "  \033[32m✓\033[0m %-6s %-30s %s  %5dms\n" "$type" "$target" "$status" "$elapsed"
            echo "pass $elapsed" >> "$logfile"
        else
            printf "  \033[31m✗\033[0m %-6s %-30s %s  %5dms\n" "$type" "$target" "$status" "$elapsed"
            echo "fail $elapsed $type:$target=$status" >> "$logfile"
        fi
    done

    # Batches (5 per request)
    for (( i=0; i<${#targets[@]}-4; i+=5 )); do
        local batch_label="${targets[$i]}+4"
        local body="{\"$field\":[\"${targets[$i]}\",\"${targets[$((i+1))]}\",\"${targets[$((i+2))]}\",\"${targets[$((i+3))]}\",\"${targets[$((i+4))]}\"]}"

        local req_start elapsed status
        req_start=$(date +%s%N)
        status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
            -X POST "$HOST$endpoint" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $KEY" \
            -d "$body") || status="000"
        elapsed=$(( ($(date +%s%N) - req_start) / 1000000 ))

        if [ "$status" = "200" ]; then
            printf "  \033[32m✓\033[0m %-6s %-30s %s  %5dms\n" "batch" "$batch_label" "$status" "$elapsed"
            echo "pass $elapsed" >> "$logfile"
        else
            printf "  \033[31m✗\033[0m %-6s %-30s %s  %5dms\n" "batch" "$batch_label" "$status" "$elapsed"
            echo "fail $elapsed batch:$batch_label=$status" >> "$logfile"
        fi
    done
}

# Header
start_time=$(date +%s)
echo ""
echo "============================================"
echo "  Load Test — $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Host: $HOST"
echo "  Domains: ${#DOMAINS[@]} | IPs: ${#IPS[@]}"
echo "  Running domain + IP workers concurrently"
echo "============================================"
echo ""

# Launch both workers concurrently
run_worker "domain" "$DOMAIN_LOG" "${DOMAINS[@]}" &
DOMAIN_PID=$!

run_worker "ip" "$IP_LOG" "${IPS[@]}" &
IP_PID=$!

# Wait for both
wait "$DOMAIN_PID" 2>/dev/null || true
wait "$IP_PID" 2>/dev/null || true

# --- Aggregate results ---
end_time=$(date +%s)
wall_time=$((end_time - start_time))
wall_min=$((wall_time / 60))
wall_sec=$((wall_time % 60))

pass=0
fail=0
total_time=0
request_count=0
errors=()

for logfile in "$DOMAIN_LOG" "$IP_LOG"; do
    while IFS= read -r line; do
        status=$(echo "$line" | cut -d' ' -f1)
        elapsed=$(echo "$line" | cut -d' ' -f2)
        total_time=$((total_time + elapsed))
        request_count=$((request_count + 1))
        if [ "$status" = "pass" ]; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
            errors+=("$(echo "$line" | cut -d' ' -f3-)")
        fi
    done < "$logfile"
done

avg=$((total_time / (request_count > 0 ? request_count : 1)))

echo ""
echo "============================================"
printf "  \033[32m%d passed\033[0m, \033[31m%d failed\033[0m out of %d requests\n" "$pass" "$fail" "$request_count"
printf "  Wall time:   %dm %ds\n" "$wall_min" "$wall_sec"
printf "  Avg latency: %dms/request\n" "$avg"
printf "  Throughput:   %.1f req/s\n" "$(echo "scale=1; $request_count / ($wall_time + 1)" | bc)"
if [ ${#errors[@]} -gt 0 ]; then
    echo ""
    echo "  Failures (${#errors[@]}):"
    for e in "${errors[@]}"; do
        printf "    \033[31m✗\033[0m %s\n" "$e"
    done
fi
echo "============================================"
echo ""

[ "$fail" -eq 0 ]
