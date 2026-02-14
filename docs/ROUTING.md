# Routing Design: SNI-based and IP-based Traffic Routing

## Goal

Support multiple routing policies so that traffic can be:

1. **Direct** — bypass all proxies (e.g., Russian IPs)
2. **Outline A** (default) — proxy through the primary Outline server
3. **Outline B** — proxy through a secondary Outline server (e.g., for specific domains)

## Decision Point

Routing decisions happen inside the TCP/UDP forwarder handlers (`proxy/tcp.go`, `proxy/udp.go`) at connection time, **before** dialing the upstream. Currently the forwarders unconditionally use a single `StreamDialer`/`PacketDialer`. A router component would select which dialer (or direct) to use per connection.

## Technique 1: IP-based Routing

### How It Works

When the TCP/UDP forwarder receives a new connection, it inspects the **destination IP** and matches it against a set of CIDR prefix rules to decide which dialer to use.

### IP List Sources for Russian IPs

| Source | Format | Update Frequency |
|--------|--------|-----------------|
| [RIPE DB](https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest) | Delegated stats (CSV-like) | Daily |
| [antifilter.download](https://antifilter.download/) | CIDR lists, ready to use | Frequently |
| [bgp.tools](https://bgp.tools/) | BGP-based country prefix lists | Real-time |
| MaxMind GeoLite2 | MMDB binary format | Weekly |
| Static CIDR list in config | YAML array | Manual |

### Matching

Use a prefix trie (radix tree) or `netip.Prefix` table for O(1) longest-prefix-match lookups. Go's `net/netip` makes prefix containment checks cheap:

```go
// Pseudocode
for _, prefix := range russianPrefixes {
    if prefix.Contains(destIP) {
        return directDialer
    }
}
return defaultOutlineDialer
```

### Pros/Cons

- ✅ Simple, fast, works for all protocols (TCP, UDP)
- ✅ No packet inspection needed
- ❌ Requires maintaining/updating IP lists
- ❌ CDN IPs (Cloudflare, Google) serve multiple countries — can't distinguish by IP alone

## Technique 2: SNI-based Routing (TLS ClientHello Inspection)

### How It Works

For TLS connections (typically port 443), the **first packet** from the client contains a TLS ClientHello message with the **Server Name Indication (SNI)** extension in plaintext. The TCP forwarder can peek at this to extract the target domain.

### Flow

```
Client → WireGuard → gVisor TCP Forwarder
                          │
                          ├── Read first bytes (TLS ClientHello)
                          ├── Parse SNI extension
                          ├── Match domain against routing rules
                          ├── Select dialer (direct / outline-a / outline-b)
                          ├── Dial upstream with selected dialer
                          └── Replay buffered bytes + relay
```

### Implementation Considerations

1. **Buffering**: Must `Read()` the initial bytes from the gVisor TCP connection, parse SNI, then prepend those bytes when relaying to upstream. Use `io.MultiReader(bytes.NewReader(buffered), clientConn)` for the client→upstream copy.

2. **TLS ClientHello parsing**: The SNI is in the `server_name` extension (type 0x0000) of the ClientHello. Parsing requires:
   - Verify record type = 0x16 (Handshake)
   - Verify handshake type = 0x01 (ClientHello)
   - Skip past: version, random, session ID, cipher suites, compression methods
   - Iterate extensions to find type 0x0000
   - Go stdlib has no public SNI parser; need ~50 lines of custom parsing or use a library

3. **Non-TLS traffic**: Falls back to IP-based routing (no SNI available for plain HTTP, UDP, etc.)

4. **ECH (Encrypted Client Hello)**: Future TLS versions may encrypt SNI. This technique won't work for ECH-enabled clients. Not widely deployed yet.

5. **QUIC (UDP)**: QUIC also carries SNI in its Initial packet's ClientHello. Parsing is more complex (need to decrypt QUIC Initial packet headers). Could be supported but significantly harder.

### Matching

Domain matching strategies:
- **Exact match**: `example.com`
- **Suffix/wildcard**: `*.example.com` or domain suffix `.example.com`
- **Domain lists**: load from file, one domain per line
- **Regex**: powerful but slower

```go
// Pseudocode
sni := extractSNI(firstBytes)
switch {
case matchesList(sni, outlineBDomains):
    return outlineBDialer
case matchesList(sni, directDomains):
    return directDialer
default:
    return defaultOutlineDialer
}
```

### Pros/Cons

- ✅ Fine-grained per-domain control
- ✅ Handles CDN/shared-IP cases that IP routing can't
- ❌ Only works for TLS (port 443)
- ❌ Adds latency (must read first packet before dialing)
- ❌ Won't work with Encrypted Client Hello (ECH)
- ❌ QUIC/UDP SNI parsing is complex

## Technique 3: Combined IP + SNI Routing

The most practical approach combines both:

```
New connection arrives
    │
    ├── Check destination IP against CIDR rules
    │   └── If matched → use that route (direct/outline-b)
    │
    ├── If port 443 (TLS) and no IP match
    │   ├── Peek at ClientHello, extract SNI
    │   └── Match domain against rules → select dialer
    │
    └── Default → primary Outline
```

Priority order: IP rules first (cheap, no buffering), then SNI rules (only for TLS), then default.

## Possible Config Structure

```yaml
routing:
  routes:
    - name: "direct-russia"
      action: direct
      match:
        ip_lists:
          - "https://antifilter.download/download/ipsum.lst"
          - "configs/russian-ips.txt"
        update_interval: 86400  # seconds

    - name: "outline-secondary"
      action: outline
      transport: "ss://secondary-server..."
      match:
        domains:
          - "*.youtube.com"
          - "*.googlevideo.com"
        domain_lists:
          - "configs/video-domains.txt"

    - name: "direct-local"
      action: direct
      match:
        cidrs:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"

  default: outline  # primary outline for everything else
```

## Architecture Changes Required

1. **Router component** (`internal/routing/router.go`): Takes destination IP + optional SNI, returns a dialer. Holds the rule table and IP prefix trie.

2. **SNI parser** (`internal/routing/sni.go`): Parses TLS ClientHello to extract SNI from buffered bytes.

3. **Multi-dialer registry**: Map of named dialers (direct, outline-a, outline-b). Direct dialer uses `net.Dialer{}` without any proxy.

4. **TCP proxy changes**: Before dialing, consult the router. For TLS ports, buffer first bytes for SNI extraction. Prepend buffered bytes to the relay.

5. **UDP proxy changes**: IP-based routing only (no practical SNI extraction for UDP, except QUIC which is very complex).

6. **IP list updater**: Background goroutine that periodically fetches/refreshes IP lists from URLs.
