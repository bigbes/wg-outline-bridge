#!/usr/bin/env bash
set -euo pipefail

# ─── DNS Integration Test Script ────────────────────────────────────
#
# Tests the bridge's DNS server by reading the YAML config and
# verifying static records, block rules (patterns + blocklists),
# upstream routing rules, and default upstream forwarding.
#
# Usage:
#   ./scripts/test-dns.sh -config configs/bridge.yaml
#   ./scripts/test-dns.sh -config configs/bridge.yaml -addr 10.100.0.1 -port 53
#   ./scripts/test-dns.sh -config configs/bridge.yaml -blocklist-samples 5
#
# Prerequisites: dig, yq (https://github.com/mikefarah/yq)

# ─── Defaults ───────────────────────────────────────────────────────
CONFIG=""
ADDR=""
PORT=""
BLOCKLIST_SAMPLES=3   # how many domains to sample from each blocklist URL
TIMEOUT=2             # dig timeout in seconds

# ─── Parse arguments ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -config)  CONFIG="$2"; shift 2;;
        -addr)    ADDR="$2";   shift 2;;
        -port)    PORT="$2";   shift 2;;
        -blocklist-samples) BLOCKLIST_SAMPLES="$2"; shift 2;;
        -timeout) TIMEOUT="$2"; shift 2;;
        -h|--help)
            echo "Usage: $0 -config <path> [-addr <ip>] [-port <port>] [-blocklist-samples <n>]"
            exit 0;;
        *) echo "Unknown argument: $1"; exit 1;;
    esac
done

if [[ -z "$CONFIG" ]]; then
    echo "ERROR: -config is required"
    echo "Usage: $0 -config <path> [-addr <ip>] [-port <port>]"
    exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: config file not found: $CONFIG"
    exit 1
fi

# ─── Check prerequisites ────────────────────────────────────────────
for cmd in dig yq curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' is not installed."
        exit 1
    fi
done

# ─── Read config ────────────────────────────────────────────────────
DNS_ENABLED=$(yq '.dns.enabled // false' "$CONFIG")
if [[ "$DNS_ENABLED" != "true" ]]; then
    echo "ERROR: dns.enabled is not true in $CONFIG"
    exit 1
fi

DNS_LISTEN=$(yq '.dns.listen // ""' "$CONFIG")
DNS_UPSTREAM=$(yq '.dns.upstream // ""' "$CONFIG")

# Derive listen addr/port from config if not overridden
if [[ -z "$ADDR" || -z "$PORT" ]]; then
    if [[ -n "$DNS_LISTEN" ]]; then
        CONF_ADDR="${DNS_LISTEN%%:*}"
        CONF_PORT="${DNS_LISTEN##*:}"
        [[ -z "$ADDR" ]] && ADDR="$CONF_ADDR"
        [[ -z "$PORT" ]] && PORT="$CONF_PORT"
    else
        # Derive from wireguard address
        WG_ADDR=$(yq '.wireguard.address // ""' "$CONFIG")
        WG_ADDR="${WG_ADDR%%/*}"  # strip CIDR
        [[ -z "$ADDR" ]] && ADDR="${WG_ADDR:-127.0.0.1}"
        [[ -z "$PORT" ]] && PORT="53"
    fi
fi

if [[ -z "$DNS_UPSTREAM" ]]; then
    DNS_UPSTREAM=$(yq '.wireguard.dns // "1.1.1.1"' "$CONFIG")
    [[ "$DNS_UPSTREAM" != *:* ]] && DNS_UPSTREAM="${DNS_UPSTREAM}:53"
fi

# ─── Colors & helpers ───────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

pass() {
    PASSED=$((PASSED + 1))
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
}

fail() {
    FAILED=$((FAILED + 1))
    echo -e "  ${RED}✗ FAIL${NC}: $1"
}

skip() {
    SKIPPED=$((SKIPPED + 1))
    echo -e "  ${YELLOW}⊘ SKIP${NC}: $1"
}

info() {
    echo -e "${CYAN}▸${NC} $1"
}

DIG="dig @$ADDR -p $PORT +noall +answer +comments +timeout=$TIMEOUT +tries=1"

check_contains() {
    local test_name="$1" output="$2" expected="$3"
    if echo "$output" | grep -qF "$expected"; then
        pass "$test_name"
    else
        fail "$test_name (expected '$expected')"
    fi
}

check_not_contains() {
    local test_name="$1" output="$2" unexpected="$3"
    if echo "$output" | grep -qF "$unexpected"; then
        fail "$test_name (unexpected '$unexpected' found)"
    else
        pass "$test_name"
    fi
}

check_blocked_a() {
    local test_name="$1" domain="$2"
    local output
    output=$($DIG "$domain" A 2>/dev/null) || true
    if echo "$output" | grep -q $'\t'"A"$'\t' && echo "$output" | grep -qF "0.0.0.0"; then
        pass "$test_name"
    else
        fail "$test_name — expected 0.0.0.0 for $domain"
    fi
}

check_not_blocked_a() {
    local test_name="$1" domain="$2"
    local output
    output=$($DIG "$domain" A 2>/dev/null) || true
    if echo "$output" | grep -qF "0.0.0.0"; then
        fail "$test_name — got 0.0.0.0 for $domain (should not be blocked)"
    else
        pass "$test_name"
    fi
}

check_resolves() {
    local test_name="$1" domain="$2" qtype="${3:-A}"
    local output
    output=$($DIG "$domain" "$qtype" 2>/dev/null) || true
    if echo "$output" | grep -q "status: NOERROR"; then
        pass "$test_name"
    else
        fail "$test_name — expected NOERROR for $domain $qtype"
    fi
}

# ─── Connectivity check ────────────────────────────────────────────
info "Testing DNS server at $ADDR:$PORT (upstream: $DNS_UPSTREAM)"
echo ""

output=$($DIG example.com A 2>/dev/null) || true
if ! echo "$output" | grep -q "status:"; then
    echo -e "${RED}ERROR${NC}: Cannot reach DNS server at $ADDR:$PORT"
    echo "  Make sure the bridge is running with: ./main run -config $CONFIG"
    exit 1
fi
info "DNS server is reachable"
echo ""

# ═══════════════════════════════════════════════════════════════════
# Test Group 1: Static Records
# ═══════════════════════════════════════════════════════════════════
RECORD_COUNT=$(yq '.dns.records | length // 0' "$CONFIG")

if [[ "$RECORD_COUNT" -gt 0 ]]; then
    info "Test Group 1: Static Records ($RECORD_COUNT configured)"

    yq -o json '.dns.records // {}' "$CONFIG" | while IFS= read -r name; do
        # yq outputs keys
        :
    done

    # Iterate over each record
    for name in $(yq '.dns.records | keys | .[]' "$CONFIG"); do
        a_addrs=$(yq ".dns.records.\"$name\".a // [] | .[]" "$CONFIG" 2>/dev/null) || true
        aaaa_addrs=$(yq ".dns.records.\"$name\".aaaa // [] | .[]" "$CONFIG" 2>/dev/null) || true
        ttl=$(yq ".dns.records.\"$name\".ttl // 60" "$CONFIG")

        if [[ -n "$a_addrs" ]]; then
            output=$($DIG "$name" A 2>/dev/null) || true
            for ip in $a_addrs; do
                check_contains "Static A: $name → $ip" "$output" "$ip"
            done
            check_contains "Static TTL: $name → $ttl" "$output" "$ttl"
        fi

        if [[ -n "$aaaa_addrs" ]]; then
            output=$($DIG "$name" AAAA 2>/dev/null) || true
            for ip in $aaaa_addrs; do
                check_contains "Static AAAA: $name → $ip" "$output" "$ip"
            done
        fi
    done

    # Edge case: case insensitivity — pick first record name and uppercase it
    first_name=$(yq '.dns.records | keys | .[0]' "$CONFIG")
    first_a=$(yq ".dns.records.\"$first_name\".a[0] // \"\"" "$CONFIG")
    if [[ -n "$first_a" ]]; then
        upper_name=$(echo "$first_name" | tr '[:lower:]' '[:upper:]')
        output=$($DIG "$upper_name" A 2>/dev/null) || true
        check_contains "Case insensitive: $upper_name → $first_a" "$output" "$first_a"
    fi

    echo ""
else
    info "Test Group 1: Static Records — none configured, skipping"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════
# Test Group 2: DNS Rules (block + upstream patterns)
# ═══════════════════════════════════════════════════════════════════
RULE_COUNT=$(yq '.dns.rules | length // 0' "$CONFIG")

if [[ "$RULE_COUNT" -gt 0 ]]; then
    info "Test Group 2: DNS Rules ($RULE_COUNT configured)"

    for i in $(seq 0 $((RULE_COUNT - 1))); do
        rule_name=$(yq ".dns.rules[$i].name // \"rule-$i\"" "$CONFIG")
        rule_action=$(yq ".dns.rules[$i].action" "$CONFIG")
        rule_upstream=$(yq ".dns.rules[$i].upstream // \"\"" "$CONFIG")
        domains_count=$(yq ".dns.rules[$i].domains | length // 0" "$CONFIG")

        echo ""
        info "  Rule: \"$rule_name\" (action=$rule_action)"

        # Test domain patterns
        if [[ "$domains_count" -gt 0 ]]; then
            for j in $(seq 0 $((domains_count - 1))); do
                pattern=$(yq ".dns.rules[$i].domains[$j]" "$CONFIG")

                if [[ "$pattern" == \*.* ]]; then
                    # Wildcard pattern — generate a test subdomain
                    base="${pattern#\*.}"
                    test_domain="dns-test-sub.${base}"

                    if [[ "$rule_action" == "block" ]]; then
                        check_blocked_a "Block wildcard $pattern → $test_domain" "$test_domain"
                    elif [[ "$rule_action" == "upstream" ]]; then
                        check_resolves "Upstream $pattern → $test_domain (via $rule_upstream)" "$test_domain"
                    fi

                    # Verify wildcard does NOT match the parent domain itself
                    check_not_blocked_a "Wildcard $pattern does not match parent $base" "$base"
                else
                    # Exact domain
                    if [[ "$rule_action" == "block" ]]; then
                        check_blocked_a "Block exact $pattern" "$pattern"
                    elif [[ "$rule_action" == "upstream" ]]; then
                        check_resolves "Upstream exact $pattern (via $rule_upstream)" "$pattern"
                    fi
                fi
            done
        fi
    done

    echo ""
else
    info "Test Group 2: DNS Rules — none configured, skipping"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════
# Test Group 3: Blocklists
# ═══════════════════════════════════════════════════════════════════
# Find rules that have lists[] entries, fetch a few domains from each
# list, and verify they are blocked.

HAS_BLOCKLISTS=false
for i in $(seq 0 $((RULE_COUNT - 1))); do
    list_count=$(yq ".dns.rules[$i].lists | length // 0" "$CONFIG")
    if [[ "$list_count" -gt 0 ]]; then
        HAS_BLOCKLISTS=true
        break
    fi
done

if [[ "$HAS_BLOCKLISTS" == "true" ]]; then
    info "Test Group 3: Blocklists (sampling $BLOCKLIST_SAMPLES domains per list)"

    for i in $(seq 0 $((RULE_COUNT - 1))); do
        rule_name=$(yq ".dns.rules[$i].name // \"rule-$i\"" "$CONFIG")
        rule_action=$(yq ".dns.rules[$i].action" "$CONFIG")
        list_count=$(yq ".dns.rules[$i].lists | length // 0" "$CONFIG")

        [[ "$list_count" -eq 0 ]] && continue

        for k in $(seq 0 $((list_count - 1))); do
            list_url=$(yq ".dns.rules[$i].lists[$k].url" "$CONFIG")
            list_format=$(yq ".dns.rules[$i].lists[$k].format // \"domains\"" "$CONFIG")

            echo ""
            info "  Rule \"$rule_name\": $list_url (format=$list_format)"

            # Fetch the list and extract sample domains
            raw=$(curl -fsSL --max-time 10 "$list_url" 2>/dev/null | head -5000) || true
            if [[ -z "$raw" ]]; then
                skip "Could not fetch blocklist: $list_url"
                continue
            fi

            sample_domains=()
            if [[ "$list_format" == "hosts" ]]; then
                # hosts format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
                while IFS= read -r domain; do
                    [[ -n "$domain" ]] && sample_domains+=("$domain")
                done < <(echo "$raw" \
                    | grep -v '^[[:space:]]*#' \
                    | grep -v '^[[:space:]]*!' \
                    | grep -v '^[[:space:]]*$' \
                    | awk '{print $2}' \
                    | grep -v -E '^(localhost|localhost\.localdomain|local|broadcasthost|ip6-|0\.0\.0\.0|ff\.)' \
                    | grep '\.' \
                    | shuf -n "$BLOCKLIST_SAMPLES" 2>/dev/null || head -n "$BLOCKLIST_SAMPLES")
            else
                # domains format: one domain per line, optional *. prefix
                while IFS= read -r domain; do
                    [[ -n "$domain" ]] && sample_domains+=("$domain")
                done < <(echo "$raw" \
                    | grep -v '^[[:space:]]*#' \
                    | grep -v '^[[:space:]]*!' \
                    | grep -v '^[[:space:]]*$' \
                    | sed 's/^\*\.//' \
                    | grep '\.' \
                    | shuf -n "$BLOCKLIST_SAMPLES" 2>/dev/null || head -n "$BLOCKLIST_SAMPLES")
            fi

            if [[ ${#sample_domains[@]} -eq 0 ]]; then
                skip "No valid domains extracted from $list_url"
                continue
            fi

            for domain in "${sample_domains[@]}"; do
                if [[ "$rule_action" == "block" ]]; then
                    check_blocked_a "Blocklist ($rule_name): $domain" "$domain"
                fi
            done
        done
    done

    # Negative test: a domain that should NOT be blocked
    echo ""
    info "  Blocklist negative tests"
    check_not_blocked_a "Known-good domain not blocked: google.com" "google.com"
    check_not_blocked_a "Known-good domain not blocked: github.com" "github.com"

    echo ""
else
    info "Test Group 3: Blocklists — none configured, skipping"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════
# Test Group 4: Upstream Routing (smart DNS)
# ═══════════════════════════════════════════════════════════════════
# Find rules with action=upstream and verify they resolve via the
# specified upstream (we can't easily verify WHICH upstream was used,
# but we can verify the query succeeds).

HAS_UPSTREAM_RULES=false
for i in $(seq 0 $((RULE_COUNT - 1))); do
    action=$(yq ".dns.rules[$i].action" "$CONFIG")
    if [[ "$action" == "upstream" ]]; then
        HAS_UPSTREAM_RULES=true
        break
    fi
done

if [[ "$HAS_UPSTREAM_RULES" == "true" ]]; then
    info "Test Group 4: Upstream Routing (Smart DNS)"

    for i in $(seq 0 $((RULE_COUNT - 1))); do
        action=$(yq ".dns.rules[$i].action" "$CONFIG")
        [[ "$action" != "upstream" ]] && continue

        rule_name=$(yq ".dns.rules[$i].name // \"rule-$i\"" "$CONFIG")
        rule_upstream=$(yq ".dns.rules[$i].upstream // \"\"" "$CONFIG")
        domains_count=$(yq ".dns.rules[$i].domains | length // 0" "$CONFIG")

        [[ "$domains_count" -eq 0 ]] && continue

        echo ""
        info "  Rule \"$rule_name\" → upstream $rule_upstream"

        for j in $(seq 0 $((domains_count - 1))); do
            pattern=$(yq ".dns.rules[$i].domains[$j]" "$CONFIG")

            if [[ "$pattern" == \*.* ]]; then
                # For wildcard, test with "www." prefix on the base domain
                base="${pattern#\*.}"
                test_domain="www.${base}"
            else
                test_domain="$pattern"
            fi

            # Resolve via our DNS server
            our_output=$($DIG "$test_domain" A 2>/dev/null) || true
            # Resolve via the specified upstream directly for comparison
            upstream_host="${rule_upstream%%:*}"
            upstream_port="${rule_upstream##*:}"
            [[ "$upstream_port" == "$upstream_host" ]] && upstream_port=53
            direct_output=$(dig "@$upstream_host" -p "$upstream_port" +noall +answer +timeout=$TIMEOUT +tries=1 "$test_domain" A 2>/dev/null) || true

            # Both should resolve
            check_resolves "Smart DNS: $test_domain resolves via our server" "$test_domain"

            # Compare: our answer should match the upstream's answer
            our_ips=$(echo "$our_output" | awk '/\tA\t/{print $NF}' | sort)
            direct_ips=$(echo "$direct_output" | awk '/\tA\t/{print $NF}' | sort)

            if [[ -n "$our_ips" && -n "$direct_ips" ]]; then
                if [[ "$our_ips" == "$direct_ips" ]]; then
                    pass "Smart DNS: $test_domain IPs match upstream $rule_upstream"
                else
                    # Some domains have rotating IPs; just warn, don't fail
                    skip "Smart DNS: $test_domain IPs differ (CDN/rotation?) — ours: $(echo $our_ips | tr '\n' ',') vs direct: $(echo $direct_ips | tr '\n' ',')"
                fi
            elif [[ -z "$our_ips" && -z "$direct_ips" ]]; then
                pass "Smart DNS: $test_domain — both returned no A records (OK)"
            fi
        done
    done

    echo ""
else
    info "Test Group 4: Upstream Routing — no upstream rules configured, skipping"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════
# Test Group 5: Default Upstream
# ═══════════════════════════════════════════════════════════════════
info "Test Group 5: Default Upstream ($DNS_UPSTREAM)"

check_resolves "Default upstream: example.com A" "example.com" "A"
check_resolves "Default upstream: example.com AAAA" "example.com" "AAAA"

# Verify we get actual content, not a block response
output=$($DIG example.com A 2>/dev/null) || true
check_not_contains "Default upstream: example.com not blocked" "$output" "0.0.0.0"

echo ""

# ═══════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════
TOTAL=$((PASSED + FAILED + SKIPPED))
echo "═══════════════════════════════════════════════"
echo -e "Total: $TOTAL  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}  ${YELLOW}Skipped: $SKIPPED${NC}"
echo "═══════════════════════════════════════════════"

if [[ "$FAILED" -gt 0 ]]; then
    exit 1
fi
