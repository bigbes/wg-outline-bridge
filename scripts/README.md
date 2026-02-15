# Scripts

## test-dns.sh

Integration test for the bridge's built-in DNS server. Reads your `bridge.yaml` config to auto-generate and run tests against a **running** bridge instance.

### Prerequisites

- `dig` — from `bind-tools` (Arch) or `dnsutils` (Debian/Ubuntu)
- `yq` — [mikefarah/yq](https://github.com/mikefarah/yq) (YAML processor)
- `curl` — for fetching blocklist samples

### Usage

```bash
# Basic — reads listen address and port from config
./scripts/test-dns.sh -config configs/bridge.yaml

# Override address/port (e.g. testing remotely)
./scripts/test-dns.sh -config configs/bridge.yaml -addr 10.100.0.1 -port 53

# Sample more domains from each blocklist URL
./scripts/test-dns.sh -config configs/bridge.yaml -blocklist-samples 10

# Increase dig timeout for slow upstreams
./scripts/test-dns.sh -config configs/bridge.yaml -timeout 5
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | *(required)* | Path to the bridge YAML config file |
| `-addr` | from config | DNS server IP to query |
| `-port` | from config | DNS server port to query |
| `-blocklist-samples` | `3` | Number of domains to sample per blocklist URL |
| `-timeout` | `2` | `dig` query timeout in seconds |

### What it tests

The script parses your config and generates tests dynamically:

1. **Static Records** — Verifies every `dns.records` entry: A/AAAA addresses, TTL values, case-insensitive lookups.

2. **Block/Upstream Rules** — For each `dns.rules` entry with `domains`:
   - `action: block` — wildcard and exact patterns return `0.0.0.0` / `::`
   - `action: upstream` — queries resolve successfully via the specified upstream
   - Verifies wildcards (`*.example.com`) don't match the parent (`example.com`)

3. **Blocklists** — For each `dns.rules` entry with `lists`:
   - Fetches the blocklist URL, extracts sample domains
   - Verifies sampled domains are blocked (`0.0.0.0`)
   - Negative tests: confirms known-good domains (google.com, github.com) are not blocked

4. **Smart DNS (Upstream Routing)** — For `action: upstream` rules, resolves domains through both the bridge and the target upstream directly, then compares results.

5. **Default Upstream** — Verifies fallback resolution works and doesn't false-positive as blocked.

### Exit codes

- `0` — all tests passed
- `1` — one or more tests failed (or config/prerequisite error)

### Example output

```
▸ Testing DNS server at 10.100.0.1:53 (upstream: 1.1.1.1:53)

▸ Test Group 1: Static Records (2 configured)
  ✓ PASS: Static A: myhost.internal → 10.100.0.10
  ✓ PASS: Static TTL: myhost.internal → 60
  ✓ PASS: Case insensitive: MYHOST.INTERNAL → 10.100.0.10

▸ Test Group 2: DNS Rules (3 configured)
  ▸   Rule: "ads" (action=block)
  ▸   Rule: "ru-direct-dns" (action=upstream)
  ✓ PASS: Upstream *.ru → dns-test-sub.ru (via 77.88.8.8:53)
  ✓ PASS: Wildcard *.ru does not match parent ru

▸ Test Group 3: Blocklists (sampling 3 domains per list)
  ✓ PASS: Blocklist (ads): tracking.example.com
  ✓ PASS: Known-good domain not blocked: google.com

▸ Test Group 4: Upstream Routing (Smart DNS)
  ✓ PASS: Smart DNS: www.ru resolves via our server

▸ Test Group 5: Default Upstream (1.1.1.1:53)
  ✓ PASS: Default upstream: example.com A
  ✓ PASS: Default upstream: example.com not blocked

═══════════════════════════════════════════════
Total: 11  Passed: 11  Failed: 0  Skipped: 0
═══════════════════════════════════════════════
```
