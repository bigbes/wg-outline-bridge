# WireGuard-Outline Bridge

A userspace WireGuard server that proxies all client traffic through [Outline](https://getoutline.org/) (Shadowsocks) servers. Built with [gVisor netstack](https://gvisor.dev/) for in-process TCP/UDP handling — no TUN device or root access required on the host.

## How It Works

```
WireGuard Client ──► WireGuard (userspace) ──► gVisor netstack ──► Outline proxy ──► Internet
                         UDP                    TCP/UDP forwarders     Shadowsocks
```

1. Clients connect via standard WireGuard protocol
2. Decrypted packets are injected into a gVisor network stack
3. TCP and UDP flows are intercepted by transport-layer forwarders
4. Each flow is routed through an Outline (Shadowsocks) proxy — or sent directly — based on configurable IP and SNI rules

## Quick Start

### Install

An installation script is provided in `scripts/install.sh`. It builds the binary, creates the directory layout, generates server keys and config, and installs the systemd unit. Requires `sudo` and Go installed.

```bash
sudo ./scripts/install.sh "ss://..."               # default prefix /data
sudo ./scripts/install.sh /opt/bridge "ss://..."    # custom prefix
```

This creates the following layout under the prefix:

```
<prefix>/
  bin/bridge          # binary
  etc/bridge.conf     # config (with generated server keys)
  etc/peers/          # peer configs
  var/log/bridge.log  # log file
  var/lib/bridge/     # data directory (sqlite, etc.)
```

If the config file already exists, key generation is skipped.

### Build (manual)

```bash
go build -o main ./cmd/bridge/main.go
# or
just build
```

### Initialize Config

```bash
./main init -transport "ss://..." -config configs/bridge.yaml
```

This generates a server keypair and writes a config file. The output shows the server public key to share with clients.

### Add a Peer

```bash
./main genconf -name alice -config configs/bridge.yaml
```

This generates a client keypair, assigns the next available IP, adds the peer to the config, and prints a ready-to-use WireGuard client config.

### Run

```bash
./main run -config configs/bridge.yaml
```

The bridge listens on the configured WireGuard UDP port and proxies traffic through Outline.

### Run with Auto-Restart

```bash
./main watch -config configs/bridge.yaml -log output.log
```

The `watch` command runs the bridge as a subprocess and automatically restarts it when the binary is updated. Useful for deployments where you `scp` a new binary to the server.

## Configuration

```yaml
log_level: "info"  # debug, info, warn, error

wireguard:
  private_key: "base64-encoded-key"
  listen_port: 51820
  address: "10.100.0.1/24"
  public_address: "203.0.113.1"   # server's public IP (for client config generation)
  mtu: 1420
  dns: "1.1.1.1"
outlines:
  - name: "default"
    transport: "ss://..."
    default: true                  # exactly one must be default
    health_check:
      enabled: true
      interval: 30
      target: "1.1.1.1:80"
  - name: "alt"
    transport: "ss://..."
database:
  path: "/var/lib/wg-outline-bridge/bridge.sqlite"  # empty or omitted = disabled
  flush_interval: 30                                 # seconds (default: 30)
proxies:
  - name: "socks-main"
    type: socks5
    listen: "0.0.0.0:1080"
  - name: "http-auth"
    type: http
    listen: "0.0.0.0:8080"
    username: "user"
    password: "pass"
```

### Outline Entries

All Outline (Shadowsocks) endpoints are defined in a single `outlines` array. Each entry has:

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Identifier used in routing rules |
| `transport` | yes | Shadowsocks URI (`ss://...`) |
| `default` | no | Set `true` on exactly one entry — used when no routing rule matches |
| `health_check` | no | Periodic TCP probe to verify the proxy is reachable |

## Routing

Traffic routing is decided per-connection with three levels:

| Level | Scope | Description |
|-------|-------|-------------|
| **CIDR rules** | Client-side | Traffic never enters the WireGuard tunnel (handled via `AllowedIPs` in client config) |
| **IP rules** | Server-side | Match destination IP against CIDR lists → `direct`, `outline`, or `default` |
| **SNI rules** | Server-side | Match TLS SNI (port 443 only) against domain patterns → `direct`, `outline`, or `default` |

Evaluation order: IP rules → SNI rules (TLS only) → default outline.

### CIDR Rules (Client AllowedIPs)

The `routing.cidrs` list controls which CIDRs end up in the client's WireGuard `AllowedIPs`. Each entry is a rule with an action prefix:

| Format | Description |
|--------|-------------|
| `allow:<range>` or `a:<range>` | Include CIDR in AllowedIPs |
| `disallow:<range>` or `d:<range>` | Exclude CIDR from AllowedIPs |
| `a:*` | Allow all (base 0.0.0.0/0) |
| `d:*` | Disallow all |
| bare CIDR (e.g. `192.168.0.0/16`) | Treated as disallow (backward compat) |

When no explicit allow rules are given, the base is `0.0.0.0/0`. The server's `public_address` is automatically excluded.

```yaml
wireguard:
  public_address: "203.0.113.1"

routing:
  cidrs:
    - "d:192.168.0.0/16"   # local network goes direct
```

### IP Rules

Match destination IP against inline CIDRs, downloaded lists, or ASN prefixes. Lists and ASN data are fetched through the default Outline proxy and refreshed periodically.

```yaml
routing:
  ip_rules:
    - name: "private-networks"
      action: direct
      cidrs:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"

    - name: "country-bypass"
      action: direct
      lists:
        - url: "https://example.com/country-cidrs.txt"
          refresh: 86400   # seconds (default: 24h)

    - name: "cloudflare-direct"
      action: direct
      asns:
        - 13335            # Cloudflare
        - 32934            # Facebook
```

IP list format: one CIDR per line, `#` comments and blank lines are ignored.

ASN prefixes are resolved via the [RIPE Stat API](https://stat.ripe.net/) and refreshed every 24 hours. A single rule can combine `cidrs`, `lists`, and `asns` — a match on any source triggers the rule.

### SNI Rules

Match the TLS Server Name Indication from the ClientHello on port 443. Supports exact domains and `*.suffix` wildcards.

```yaml
routing:
  sni_rules:
    - name: "video-via-alt"
      action: outline
      outline: "alt"          # route to named outline
      domains:
        - "*.youtube.com"
        - "*.googlevideo.com"

    - name: "direct-domains"
      action: direct
      domains:
        - "*.example.com"
```

### Routing Actions

| Action | Description |
|--------|-------------|
| `direct` | Connect to destination directly, bypassing all proxies |
| `outline` | Route through a named outline (specify `outline: "name"`) |
| `default` | Use the default outline (same as no rule matching) |

## Proxy Servers

The bridge can expose SOCKS5, HTTP, and HTTPS forward proxy servers that route traffic through Outline. Multiple instances of each type can run simultaneously.

```yaml
proxies:
  - name: "socks-main"
    type: socks5              # socks5, http, or https
    listen: "0.0.0.0:1080"
    outline: ""               # optional: named outline (default = default)
    username: "user"          # optional: enables SOCKS5 user/pass auth
    password: "pass"

  - name: "http-main"
    type: http
    listen: "0.0.0.0:8080"
    username: "user"          # optional: enables HTTP Basic auth
    password: "pass"

  - name: "https-secure"
    type: https
    listen: "0.0.0.0:8443"
    username: "user"
    password: "pass"
    tls:
      cert_file: "/path/to/cert.pem"   # manual TLS cert
      key_file: "/path/to/key.pem"
      # OR automatic Let's Encrypt:
      # domain: "proxy.example.com"
      # acme_email: "admin@example.com"
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique identifier for the proxy instance |
| `type` | yes | `socks5`, `http`, or `https` |
| `listen` | yes | Listen address (e.g. `0.0.0.0:1080`) |
| `outline` | no | Named outline to use (default = default outline) |
| `username` | no | Enable authentication (SOCKS5 user/pass or HTTP Basic) |
| `password` | no | Password for authentication |
| `tls` | https only | TLS configuration (cert files or ACME domain) |

- **HTTP** proxy handles both plain HTTP forwarding and HTTPS via `CONNECT` tunneling
- **HTTPS** proxy is an HTTP proxy with TLS on the listener (client↔proxy connection is encrypted)
- **SOCKS5** proxy supports the `CONNECT` command

## Telegram Bot

The bridge can be monitored via a Telegram bot. It supports two modes that can be used independently or together:

- **Interactive commands** — send commands directly to the bot from any chat
- **Push notifications** — periodic status updates sent to a configured chat (requires `chat_id`)

### Setup

1. Create a bot via [@BotFather](https://t.me/BotFather) and copy the API token
2. Add to your config:

```yaml
telegram:
  enabled: true
  token: "123456:ABC-DEF..."
  # chat_id: -1001234567890   # optional: enables periodic push notifications
  # interval: 300             # push interval in seconds (default: 300)
  # allowed_users:            # optional: restrict private-chat access to these user IDs
  #   - 123456789
```

If `chat_id` is omitted, the bot only responds to direct commands — no push notifications are sent.

If `allowed_users` is set, the bot ignores private messages from users not in the list. Group/channel messages are not affected. When omitted, anyone can use the bot in private chats.

### Commands

| Command | Description |
|---------|-------------|
| `/status` | Show peer status, traffic, and active connections |
| `/proxy` | Show Telegram proxy links (MTProxy) |
| `/listconf` | List all configured peers |
| `/showconf <name>` | Show WireGuard client config for a peer |
| `/addpeer <name>` | Add a new WireGuard peer (requires database) |
| `/delpeer <name>` | Delete a WireGuard peer (requires database) |
| `/addsecret [type] [comment]` | Add a new MTProxy secret (requires database) |
| `/delsecret <hex>` | Delete an MTProxy secret (requires database) |
| `/help` | List available commands |

The management commands (`/addpeer`, `/delpeer`, `/addsecret`, `/delsecret`) require `database.path` to be configured. Peer changes are applied immediately to the running WireGuard device. MTProxy secret changes require a restart to take effect.

### Status Output

```
📊 Bridge Status
⏱ Uptime: 2d 5h 30m

🟢 alice
  Handshake: 45s ago
  Traffic: ↓12.3 MB ↑1.2 MB
  Total: ↓1.5 GB ↑256.0 MB
  Connections: 3 active, 42 total

🟡 bob
  Handshake: 5m30s ago
  Traffic: ↓45.6 MB ↑8.9 MB
  Total: ↓3.2 GB ↑512.0 MB
  Connections: 0 active, 15 total

📡 MTProxy
  Connections: 2 active, 18 session, 204 total
  Traffic: ↑5.3 MB ↓12.1 MB
  Total: ↑1.2 GB ↓3.4 GB
  Errors: 3 handshake, 1 dial (1 dial total)
  TLS: 16 session

  Secrets:
  • a1b2c3d4… — last 2m ago
    Conns: 12 session, 150 total | Traffic: ↑3.1 MB ↓8.0 MB (↑900.0 MB ↓2.5 GB)
  • e5f6a7b8… — last 1h 15m ago
    Conns: 6 session, 54 total | Traffic: ↑2.2 MB ↓4.1 MB (↑300.0 MB ↓900.0 MB)
```

Indicators: 🟢 active (handshake < 3 min), 🟡 stale, ⚪ never connected.

## Database

Enable SQLite-backed storage for persistent stats and peer/secret management:

```yaml
database:
  path: /var/lib/wg-outline-bridge/bridge.sqlite  # empty or omitted = disabled
  flush_interval: 30  # seconds (default: 30)
```

When the database is enabled:
- **Peers and MTProxy secrets** are stored in SQLite, enabling management via Telegram bot commands (`/addpeer`, `/delpeer`, `/addsecret`, `/delsecret`) and CLI commands. On first run, existing file-based peers and secrets are automatically imported into the database.
- **Persistent stats** track cumulative traffic, handshakes, and connections across daemon restarts.

Tracked stats:
- **WireGuard peers**: cumulative rx/tx bytes, last handshake time, handshake event count
- **MTProxy secrets**: cumulative connections, bytes relayed, handshake/dial errors
- **Daemon**: start time

Counters survive daemon restarts via delta-accumulation (UAPI/atomic counters that reset are reconciled with stored baselines).

## Live Reload

Send `SIGHUP` to reload configuration without restarting:

```bash
kill -HUP <pid>
```

This reloads peers (add/remove) and swaps the default Outline client if its transport URI changed.

## Systemd Service

A systemd unit file is provided in `configs/bridge.service`. Install it with:

```bash
sudo cp configs/bridge.service /etc/systemd/system/bridge.service
sudo systemctl daemon-reload
sudo systemctl enable --now bridge   # start and enable on boot
```

Manage the service:

```bash
sudo systemctl status bridge        # check status
sudo systemctl reload bridge        # reload config (sends SIGHUP)
sudo systemctl stop bridge          # stop the bridge
```

Logs are written to `/data/var/log/bridge.log`. Make sure the directory exists before starting:

```bash
sudo mkdir -p /data/var/log
```

## Commands

| Command | Description |
|---------|-------------|
| `run` | Start the bridge |
| `watch` | Run with auto-restart on binary update |
| `init` | Generate a new server config with fresh keys |
| `genconf` | Generate a client keypair and add to config |
| `listconf` | List all configured peers |
| `showconf` | Print WireGuard client config for a peer |
| `gensecret` | Generate a new MTProxy secret and save to database (or secrets file) |
| `showproxy` | Print Telegram proxy links for all MTProxy secrets |

### MTProxy Secrets File

MTProxy secrets can be stored in an external file (default: `mtproxy.secrets` next to your config). Generate new secrets with `gensecret`:

```bash
./main gensecret -config configs/bridge.yaml       # standard secret
./main gensecret -config configs/bridge.yaml -dd   # dd-prefix (padding mode)
```

The file supports two comment styles:

```
# Line comment — everything from # to end of line
dd0123456789abcdef0123456789abcdef  # inline comment after a secret

#~ Block comment:
   everything between #~ and ~# is ignored,
   can span multiple lines ~#

ee0123456789abcdef0123456789abcdef
```

Secrets from the file are merged with any inline `secrets:` in the YAML config. The file path can be customized with `mtproxy.secrets_file` in the config.

## Project Structure

```
cmd/bridge/
  main.go              CLI dispatch
  commands/             Subcommand implementations
internal/
  bridge/               Core bridge orchestration
  config/               YAML config loading, validation, CIDR utilities
  dns/                  Built-in DNS proxy server with blocklists
  geoip/                GeoIP database management for country-based routing
  mtproxy/              MTProxy (Telegram proxy) server implementation
  proxyserver/          SOCKS5, HTTP, and HTTPS forward proxy servers
  observer/             Telegram bot observer (status push & command handling)
  outline/              Outline SDK client wrapper
  proxy/                TCP/UDP proxy with gVisor, SNI parser, routing integration
  routing/              IP/SNI routing engine, IP list downloader
  statsdb/              SQLite-backed persistent stats and peer/secret storage
  telegram/             Telegram Bot API client
  wireguard/            gVisor netstack TUN device
configs/                Example configuration files
```

## Requirements

- Go 1.21+
- An Outline/Shadowsocks server (obtain a `ss://` transport URI)
