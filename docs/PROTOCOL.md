# MTProxy Protocol Specification

Complete technical documentation for reimplementing MTProxy in Golang.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Project Structure](#2-project-structure)
3. [MTProto Protocol](#3-mtproto-protocol)
4. [Connection Types & Handshake](#4-connection-types--handshake)
5. [TLS Fake Handshake](#5-tls-fake-handshake)
6. [Encryption & Cryptography](#6-encryption--cryptography)
7. [Connection Forwarding](#7-connection-forwarding)
8. [Configuration](#8-configuration)
9. [Network Architecture](#9-network-architecture)
10. [HTTP Interface](#10-http-interface)
11. [Security Features](#11-security-features)
12. [Data Structures](#12-data-structures)
13. [Constants & Limits](#13-constants--limits)
14. [Go Implementation Guide](#14-go-implementation-guide)

---

## 1. Overview

### 1.1 Purpose

MTProxy is an MT-Proto proxy server that forwards Telegram client traffic to Telegram servers. It acts as a middleman supporting:

- **Obfuscated protocols**: Compact and medium packet formats
- **TLS-transport mode**: Fake TLS handshake for censorship resistance
- **HTTP fallback**: Stats and query interface
- **Multi-worker architecture**: Process-based parallelism

### 1.2 Key Features

| Feature | Description |
|---------|-------------|
| Protocol detection | Auto-detects compact/medium/TLS/HTTP |
| End-to-end encryption | Preserves Telegram's encryption |
| TLS obfuscation | Appears as HTTPS traffic |
| Connection pooling | Maintains persistent backend connections |
| Stats interface | HTTP endpoint for monitoring |
| Multi-secret support | Multiple proxy secrets |

---

## 2. Project Structure

```
MTProxy/
├── mtproto/
│   ├── mtproto-proxy.c      # Entry point, connection handling, forwarding
│   ├── mtproto-config.c     # Config parsing, cluster management
│   ├── mtproto-config.h     # Config structures
│   └── mtproto-common.h     # Protocol constants, packet structures
├── net/
│   ├── net-connections.c    # Connection management, epoll handling
│   ├── net-tcp-rpc-ext-server.c  # RPC server, TLS handshake
│   ├── net-tcp-rpc-common.c      # RPC packet handling
│   ├── net-crypto-aes.c     # AES encryption/decryption
│   ├── net-crypto-dh.c      # Diffie-Hellman key exchange
│   └── net-http-server.c    # HTTP stats interface
├── crypto/
│   └── aesni256.c           # AES-256 via OpenSSL EVP
├── common/
│   ├── crc32.c, crc32.h     # CRC32 computation
│   ├── sha1.c, sha1.h       # SHA-1 hashing
│   ├── sha256.c, sha256.h   # SHA-256 hashing
│   └── md5.c, md5.h         # MD5 hashing
├── engine/
│   └── engine.c             # Main loop, signals, cron jobs
├── jobs/
│   └── jobs.h               # Async job system, thread pool
└── vv/
    └── tree.h               # Tree structures, I/O utilities
```

---

## 3. MTProto Protocol

### 3.1 Packet Format

#### Unencrypted Packet

Used during initial DH handshake. `auth_key_id` is 0.

```
Offset  Size  Field
------  ----  -----
0       8     auth_key_id (0 for unencrypted)
8       16    msg_key (message key)
24      8     server_salt (for encrypted)
32      8     session_id
40      8     msg_id
48      4     seq_no
52      4     msg_len (divisible by 4)
56      N     message (up to MAX_MESSAGE_INTS * 4 bytes)
```

**Reference**: `mtproto/mtproto-common.h:59-71`

```c
struct encrypted_message {
    long long auth_key_id;    // 0 for unencrypted
    char msg_key[16];         // Message key
    // For encrypted:
    long long server_salt;
    long long session_id;
    long long msg_id;
    int seq_no;
    int msg_len;              // Divisible by 4
    int message[];            // Up to MAX_MESSAGE_INTS (1048576)
};
```

### 3.2 RPC Packet Types

**Reference**: `mtproto/mtproto-common.h:46-51`

| Constant | Value | Description |
|----------|-------|-------------|
| `RPC_PROXY_REQ` | `0x36cef1ee` | Request from client to proxy |
| `RPC_PROXY_ANS` | `0x4403da0d` | Answer from proxy to client |
| `RPC_CLOSE_CONN` | `0x1fcf425d` | Close connection notification |
| `RPC_CLOSE_EXT` | `0x5eb634a2` | Close external connection |
| `RPC_SIMPLE_ACK` | `0x3bac409b` | Simple acknowledgment |

### 3.3 RPC_PROXY_REQ Structure

Wraps client data forwarded to Telegram backend.

**Reference**: `mtproto/mtproto-common.h:75-90`

```c
struct rpc_proxy_req {
    int type;                  // RPC_PROXY_REQ (0x36cef1ee)
    int flags;
    long long ext_conn_id;     // Connection identifier
    unsigned char remote_ipv6[16];  // Client IPv6 or IPv4-mapped
    int remote_port;           // Client port
    unsigned char our_ipv6[16];     // Proxy IP
    int our_port;              // Proxy port
    int extra_bytes;
    int extra[];               // Proxy tag, HTTP headers if flags set
};
```

### 3.4 Packet Length Encoding

#### Compact Mode
- If `len <= 0x7e * 4` (504 bytes): Single byte `len / 4`
- If `len > 0x7e * 4`: 4 bytes `(len << 6) | 0x7f`

#### Medium Mode
- Direct 4-byte little-endian length

---

## 4. Connection Types & Handshake

### 4.1 Protocol Detection

**Reference**: `net/net-tcp-rpc-ext-server.c:1039-1366`

The proxy auto-detects connection type from initial bytes:

| Pattern | Type | Flag |
|---------|------|------|
| First byte = `0xef` | Compact | `RPC_F_COMPACT` |
| First 4 bytes = `0xeeeeeeee` | Medium | `RPC_F_MEDIUM` |
| First 4 bytes = `0xdddddddd` | Medium + Padding | `RPC_F_MEDIUM \| RPC_F_PAD` |
| `HEAD`, `POST`, `GET `, `OPTI` | HTTP | - |
| `\x16\x03\x01...` | TLS | - |
| 64-byte obfuscated header | Obfuscated | - |

### 4.2 64-byte Obfuscated Header

**Reference**: `net/net-tcp-rpc-ext-server.c:1271-1367`

```
Offset  Size  Description
------  ----  -----------
0       8     Random bytes
8       32    Read key (or derived via SHA256)
40      16    Read IV
56      4     Tag (decrypts to 0xdddddddd, 0xeeeeeeee, or 0xefefefef)
60      2     Target DC ID (signed short)
62      2     Padding
```

#### Tag Decryption
The encrypted tag at offset 56-59 must decrypt to one of:
- `0xdddddddd` → Medium with padding
- `0xeeeeeeee` → Medium
- `0xefefefef` → Compact

#### DC ID Extraction
```c
short dc_id = *(short*)(header + 60);  // Signed 16-bit
```

---

## 5. TLS Fake Handshake

### 5.1 Overview

The TLS mode makes traffic appear as legitimate HTTPS to bypass censorship. It performs a fake TLS 1.2/1.3 handshake before tunneling MTProto.

**Reference**: `net/net-tcp-rpc-ext-server.c:204-741`

### 5.2 ClientHello Detection

1. Check first 3 bytes: `\x16\x03\x01` (TLS 1.2 record layer)
2. Extract SNI (Server Name Indication) from extensions
3. Validate domain against allowed list (configured via `-D` flag)

### 5.3 Client Random Validation

```
ClientHello structure:
[11:43] = zeros(28) + client_random[32:44] (12 bytes with timestamp)

Validation:
SHA256HMAC(secret, zeros(28) + timestamp(4) + random(8)) == expected_random
```

- First 28 bytes of client_random must match HMAC output
- Timestamp must be within 10 minutes of server time
- Prevents replay attacks via client_random caching (48 hours)

### 5.4 ServerHello Generation

```c
// Generate fake server random using HMAC
server_random = SHA256HMAC(secret, client_random)

// Generate X25519 ephemeral key pair
x25519_public_key = X25519(private_key, base_point)

// Extensions order may be reversed depending on upstream server
// Encrypted application data size varies (server-dependent)
```

### 5.5 TLS Packet Framing

After handshake completion, all data is framed as TLS Application Data:

```
Byte 0:    0x17 (Application Data)
Bytes 1-2: 0x03 0x03 (TLS 1.2 legacy version)
Bytes 3-4: Length (big-endian, 16-bit)
Bytes 5+:  Encrypted MTProto data
```

**Maximum packet size**: 1425 bytes (`MAX_PACKET_LENGTH`)

### 5.6 Allowed Domains

Domains are configured via `-D <domain>` flag. The proxy validates:
1. ClientHello SNI matches configured domain
2. Domain resolves and can establish upstream connection

---

## 6. Encryption & Cryptography

### 6.1 AES-256-CTR (External Connections)

**Reference**: `net/net-crypto-aes.c:95-108`

Used for encrypting traffic between proxy and Telegram servers.

```c
struct aes_key_data {
    unsigned char read_key[32];
    unsigned char read_iv[16];
    unsigned char write_key[32];
    unsigned char write_iv[16];
};

// Initialize with EVP_aes_256_ctr()
// For TLS mode: wrap each packet with 5-byte TLS header
```

### 6.2 Key Derivation

**Reference**: `net/net-crypto-aes.c:232-310`

The key derivation string is constructed as:

```
nonce_server(16) + nonce_client(16) + client_timestamp(4) +
server_ip(4) + client_port(2) + "SERVER"/"CLIENT"(6) +
client_ip(4) + server_port(2) + secret + nonce_server(16) +
[ipv6 addresses if no ipv4] + nonce_client(16) + temp_key
```

Key derivation formula:
```c
// str = derivation string above
write_key = MD5(str + 1)[0:12] + SHA1(str)[0:8]  // 20 bytes
write_iv  = MD5(str + 2)                          // 16 bytes

// For read keys, swap "SERVER" <-> "CLIENT" in string
```

### 6.3 AES-256-CBC (Internal RPC)

**Reference**: `net/net-crypto-aes.c:80-93`

Used for internal client-to-server RPC with standard PKCS#7 padding.

### 6.4 Diffie-Hellman Key Exchange

**Reference**: `net/net-crypto-dh.c`

```c
// Prime: rpc_dh_prime_bin (2048-bit, little-endian)
// Generator: 3

// Process:
1. Generate random 'a' (256+ bytes)
2. Compute g_a = pow(3, a) mod p
3. Receive g_b from server
4. Compute shared: g_ab = pow(g_b, a) mod p
5. Shared secret = SHA1(g_ab)
```

### 6.5 Hashing Functions

| Function | Usage |
|----------|-------|
| SHA-1 | DH shared secret, msg_key derivation |
| SHA-256 | TLS client_random validation, obfuscated header |
| MD5 | Key derivation |
| HMAC-SHA256 | TLS replay protection |

---

## 7. Connection Forwarding

### 7.1 External Connection Table

**Reference**: `mtproto/mtproto-proxy.c:174-366`

```c
struct ext_connection {
    int in_fd, in_gen;       // Client connection fd + generation
    int out_fd, out_gen;     // Backend connection fd + generation
    long long in_conn_id;    // Client connection ID
    long long out_conn_id;   // Unique ID for routing responses
    long long auth_key_id;   // Telegram auth key
    // LRU list pointers for memory management
};

// Hash function: ext_conn_hash(in_fd, in_conn_id)
// Lookup by out_conn_id: OutExtConnections[hash % TABLE_SIZE]
```

### 7.2 Query Forwarding Flow

**Reference**: `mtproto/mtproto-proxy.c:1688-1853`

```
┌─────────┐      ┌──────────┐      ┌─────────────────┐
│ Client  │─────▶│  Proxy   │─────▶│ Telegram Server │
└─────────┘      └──────────┘      └─────────────────┘
     │                │                      │
     │ 1. MTProto     │ 2. RPC_PROXY_REQ     │
     │    packet      │    wrapped           │
     │                │                      │
     │                │ 3. Response          │
     │ 4. Forwarded   │    RPC_PROXY_ANS     │
     │    to client   │                      │
     └────────────────┘──────────────────────┘
```

#### Encrypted Packets
1. Extract `auth_key_id` from header
2. Find or create `ext_connection` linking client ↔ backend
3. Wrap in `RPC_PROXY_REQ` with client IP/port metadata
4. Forward to Telegram backend via existing connection

#### Unencrypted (DH handshake)
- Types: `req_pq`, `req_pq_multi`, `req_DH_params`, `set_client_DH_params`
- Forward directly without wrapping
- Function handlers: `CODE_req_pq`, `CODE_req_pq_multi`, etc.

### 7.3 Response Handling

**Reference**: `mtproto/mtproto-proxy.c:838-908`

| RPC Type | Action |
|----------|--------|
| `RPC_PROXY_ANS` | Lookup `ext_connection` by `out_conn_id`, forward to client |
| `RPC_SIMPLE_ACK` | Forward acknowledgment to client |
| `RPC_CLOSE_EXT` | Close external connection |

---

## 8. Configuration

### 8.1 Proxy Config File

**Reference**: `mtproto/mtproto-config.c:247-352`

```
# Telegram server endpoints
proxy <ip>:<port>;
proxy_for <dc_id> <ip>:<port>;

# Connection limits
min_connections <n>;
max_connections <n>;

# Timeouts
timeout <ms>;

# Default DC
default <dc_id>;
```

### 8.2 Command-Line Arguments

**Reference**: `mtproto/mtproto-proxy.c:2127-2248`

| Flag | Description | Default |
|------|-------------|---------|
| `-H <ports>` | Comma-separated client ports | none |
| `-p <port>` | Stats HTTP port | none |
| `-S <secret>` | 16-byte hex secret (can repeat) | none |
| `-P <tag>` | 16-byte hex proxy tag | none |
| `-D <domain>` | TLS domain (enables TLS-only) | none |
| `-C <max>` | Max client connections per worker | 1000000 |
| `-W <bytes>` | TCP window clamp | 131072 |
| `-M <workers>` | Number of worker processes | 1 |
| `-T <seconds>` | Ping interval | 0 |
| `--http-stats` | Enable stats via HTTP | false |
| `-u <user>` | Drop privileges to user | none |
| Positional 1 | AES password file | required |
| Positional 2 | Config file | required |

### 8.3 AES Password File (`proxy-secret`)

- 32-256 bytes of binary secret
- MD5 hash used for key derivation
- Fetched from `https://core.telegram.org/getProxySecret`
- Enables communication with Telegram backend

### 8.4 Proxy Secret (`-S` flag)

- 16-byte hex string (32 characters)
- Can specify multiple secrets
- If prefixed with `dd`, enables random padding
- Used for client-to-proxy obfuscation

---

## 9. Network Architecture

### 9.1 Thread Model

**Reference**: `jobs/jobs.h`, `engine/engine.c`

```
┌─────────────────────────────────────────────────┐
│                    Main Process                  │
├─────────────────────────────────────────────────┤
│  JC_MAIN (epoll)     - Main event loop          │
│  JC_IO               - I/O read/write threads   │
│  JC_CPU              - Packet processing        │
│  JC_CONNECTION       - State machine            │
│  JC_ENGINE           - Cron jobs                │
└─────────────────────────────────────────────────┘
```

For Go: Replace with goroutines and channels.

### 9.2 Connection State Machine

**Reference**: `net/net-connections.h:90-98`

```c
enum conn_state {
    conn_none,         // Closed/uninitialized
    conn_connecting,   // Outbound connecting
    conn_working,      // Active
    conn_error,        // Error state
    conn_listen,       // Listening socket
    conn_write_close   // Flush and close
};
```

### 9.3 Connection Flags

**Reference**: `net/net-connections.h:57-87`

| Flag | Value | Description |
|------|-------|-------------|
| `C_WANTRD` | `0x00000001` | Want read events |
| `C_WANTWR` | `0x00000002` | Want write events |
| `C_ERROR` | `0x00000008` | Connection error |
| `C_CONNECTED` | `0x02000000` | Connected |
| `C_IS_TLS` | `0x08000000` | TLS transport mode |
| `C_IPV6` | `0x00004000` | IPv6 connection |
| `C_SPECIAL` | `0x00010000` | Counted against max_special |

### 9.4 RPC Data Flags

**Reference**: `net/net-tcp-rpc-common.h:107-116`

| Flag | Value | Description |
|------|-------|-------------|
| `RPC_F_PAD` | `0x08000000` | Random padding enabled |
| `RPC_F_DROPPED` | `0x10000000` | Packet was dropped |
| `RPC_F_MEDIUM` | `0x20000000` | Medium packet format |
| `RPC_F_COMPACT` | `0x40000000` | Compact packet format |
| `RPC_F_QUICKACK` | `0x80000000` | Quick ack flag |

---

## 10. HTTP Interface

### 10.1 Stats Endpoint (`/stats`)

**Reference**: `mtproto/mtproto-proxy.c:594-714`

- Accessible only from localhost (127.0.0.1)
- Returns plaintext key-value statistics

### 10.2 Stats Fields

| Field | Description |
|-------|-------------|
| `config_filename` | Config file path |
| `config_loaded_at` | Config load timestamp |
| `config_size` | Config file size |
| `config_md5` | Config MD5 hash |
| `workers` | Worker process count |
| `queries_get` | Total queries received |
| `qps_get` | Queries per second |
| `tot_forwarded_queries` | Total forwarded queries |
| `expired_forwarded_queries` | Expired queries |
| `dropped_queries` | Dropped client queries |
| `tot_forwarded_responses` | Total responses forwarded |
| `dropped_responses` | Dropped responses |
| `active_rpcs` | Active RPC calls |
| `window_clamp` | TCP window clamp |
| `total_ready_targets` | Ready backend targets |
| `total_connections` | Total connections |
| `total_encrypted_connections` | Encrypted connections |
| `total_dh_connections` | DH handshake connections |
| `ext_connections` | External connections |
| `ext_connections_created` | External connections created |
| `total_network_buffers_*` | Network buffer stats |
| `mtproto_proxy_errors` | Error count |
| `connections_failed_*` | Failed connection counts |
| `http_connections` | HTTP connection count |
| `http_queries` | HTTP query count |
| `proxy_mode` | Proxy mode flag |
| `proxy_tag_set` | Proxy tag configured |
| `version` | Proxy version |

### 10.3 API Endpoint (`/api`, `/apiw`)

- POST with MTProto binary payload
- CORS headers supported
- `X-Real-IP` / `X-Real-Port` for proxied connections

---

## 11. Security Features

### 11.1 Replay Attack Prevention

**Reference**: `net/net-tcp-rpc-ext-server.c:854-937`

- Client random cached for 48 hours
- Timestamps must be within ±10 minutes
- Duplicate `client_random` values rejected

### 11.2 Rate Limiting

| Limit | Function |
|-------|----------|
| DH accept rate | `tcp_set_max_dh_accept_rate()` |
| Connection accept rate | `tcp_set_max_accept_rate()` |
| Max special connections | `max_special_connections` |

### 11.3 Memory Management

**Reference**: `mtproto/mtproto-proxy.c:1909-1938`

- LRU eviction when buffer memory exceeds limit
- Per-connection buffer limit: `MAX_CONNECTION_BUFFER_SPACE` (32MB)
- Global buffer limit triggers connection closure

### 11.4 Flood Protection

- Overloaded connections flagged as `RPC_F_DROPPED`
- Subsequent packets on dropped connections trigger close
- Prevents resource exhaustion

---

## 12. Data Structures

### 12.1 Cluster/Target Management

**Reference**: `mtproto/mtproto-config.h:31-57`

```c
#define MAX_CFG_CLUSTERS 16
#define MAX_CFG_TARGETS  64

struct mf_cluster {
    int targets_num;           // Number of targets in cluster
    int write_targets_num;     // Number of write targets
    int cluster_id;            // DC ID
    conn_target_job_t *cluster_targets;
};

struct mf_config {
    int auth_clusters;
    struct mf_cluster auth_cluster[MAX_CFG_CLUSTERS];
    conn_target_job_t targets[MAX_CFG_TARGETS];
};
```

### 12.2 Connection Info

**Reference**: `net/net-connections.h:216-264`

```c
struct connection_info {
    int fd;                    // Socket file descriptor
    int generation;            // Connection generation
    int flags;                 // Connection flags
    int status;                // State machine status
    
    unsigned our_ip;           // Local IPv4
    unsigned remote_ip;        // Remote IPv4
    unsigned our_port;         // Local port
    unsigned remote_port;      // Remote port
    
    unsigned char our_ipv6[16];   // Local IPv6
    unsigned char remote_ipv6[16]; // Remote IPv6
    
    struct raw_message in;     // Input buffer
    struct raw_message in_u;   // Unencrypted buffer
    struct raw_message out;    // Output buffer
    struct raw_message out_p;  // Priority output
    
    struct mp_queue *in_queue;  // Input queue
    struct mp_queue *out_queue; // Output queue
    
    void *crypto;              // struct aes_crypto*
    
    int window_clamp;          // TCP window clamp
    int left_tls_packet_length; // TLS packet reassembly
};
```

---

## 13. Constants & Limits

### 13.1 Core Constants

```c
#define MAX_CONNECTIONS          65536
#define MAX_MESSAGE_INTS         1048576    // Max message size in ints
#define MAX_POST_SIZE            262144 * 4 - 4096
#define MAX_HTTP_WAIT_TIMEOUT    960.0      // seconds
#define DEFAULT_WINDOW_CLAMP     131072
#define MAX_PACKET_LENGTH        1425       // TLS mode max packet
#define TLS_REQUEST_LENGTH       517        // Expected ClientHello size
#define MAX_CLIENT_RANDOM_TIME   48 * 3600  // 48 hours in seconds
#define MAX_CONNECTION_BUFFER_SPACE  (32 << 20)  // 32MB
```

### 13.2 Protocol Constants

```c
// RPC Types
#define RPC_PROXY_REQ    0x36cef1ee
#define RPC_PROXY_ANS    0x4403da0d
#define RPC_CLOSE_CONN   0x1fcf425d
#define RPC_CLOSE_EXT    0x5eb634a2
#define RPC_SIMPLE_ACK   0x3bac409b

// Packet markers
#define COMPACT_MARKER   0xef
#define MEDIUM_MARKER    0xeeeeeeee
#define PADDED_MARKER    0xdddddddd

// TLS
#define TLS_RECORD_APP_DATA  0x17
#define TLS_VERSION_1_2      0x0303
```

---

## 14. Go Implementation Guide

### 14.1 Recommended Project Structure

```
mtproxy-go/
├── cmd/
│   └── mtproxy/
│       └── main.go           # Entry point, flag parsing
├── internal/
│   ├── config/
│   │   ├── config.go         # Config parsing
│   │   └── cluster.go        # Cluster/target management
│   ├── protocol/
│   │   ├── packet.go         # MTProto packet structures
│   │   ├── handshake.go      # TLS fake handshake
│   │   ├── obfuscated.go     # 64-byte header handling
│   │   └── rpc.go            # RPC_PROXY_* types
│   ├── crypto/
│   │   ├── aes.go            # AES-256-CTR/CBC
│   │   ├── dh.go             # Diffie-Hellman
│   │   └── keys.go           # Key derivation
│   ├── proxy/
│   │   ├── connection.go     # Connection tracking
│   │   ├── forwarder.go      # Query forwarding
│   │   └── backend.go        # Telegram server connections
│   ├── server/
│   │   ├── listener.go       # TCP listener
│   │   ├── handler.go        # Connection handler
│   │   └── http.go           # Stats HTTP server
│   └── stats/
│       ├── metrics.go        # Metrics collection
│       └── stats.go          # Stats formatting
├── go.mod
└── go.sum
```

### 14.2 Key Go Packages

```go
import (
    // Cryptography
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/md5"
    "crypto/hmac"
    
    // X25519 for TLS handshake
    "golang.org/x/crypto/curve25519"
    
    // Networking
    "net"
    "net/http"
    
    // Concurrency
    "sync"
    "sync/atomic"
)
```

### 14.3 Core Types

```go
// Packet types
const (
    RPCProxyReq   uint32 = 0x36cef1ee
    RPCProxyAns   uint32 = 0x4403da0d
    RPCCloseConn  uint32 = 0x1fcf425d
    RPCCloseExt   uint32 = 0x5eb634a2
    RPCSimpleAck  uint32 = 0x3bac409b
)

// Connection state
type ConnState int

const (
    ConnNone ConnState = iota
    ConnConnecting
    ConnWorking
    ConnError
    ConnListen
    ConnWriteClose
)

// Packet format flags
const (
    FlagPad      uint32 = 0x08000000
    FlagDropped  uint32 = 0x10000000
    FlagMedium   uint32 = 0x20000000
    FlagCompact  uint32 = 0x40000000
    FlagQuickAck uint32 = 0x80000000
)

// AES key data
type AESKeyData struct {
    ReadKey  [32]byte
    ReadIV   [16]byte
    WriteKey [32]byte
    WriteIV  [16]byte
}

// External connection
type ExtConnection struct {
    InFD       int
    OutFD      int
    InConnID   int64
    OutConnID  int64
    AuthKeyID  int64
    CreatedAt  time.Time
}

// RPC Proxy Request
type RPCProxyReq struct {
    Type        uint32
    Flags       uint32
    ExtConnID   int64
    RemoteIPv6  [16]byte
    RemotePort  uint32
    OurIPv6     [16]byte
    OurPort     uint32
    ExtraBytes  uint32
    Extra       []byte
}
```

### 14.4 Key Functions to Implement

#### Protocol Detection
```go
func DetectProtocol(data []byte) ProtocolType {
    if len(data) < 4 {
        return ProtocolUnknown
    }
    
    switch {
    case data[0] == 0xef:
        return ProtocolCompact
    case binary.LittleEndian.Uint32(data[0:4]) == 0xeeeeeeee:
        return ProtocolMedium
    case binary.LittleEndian.Uint32(data[0:4]) == 0xdddddddd:
        return ProtocolMediumPadded
    case bytes.HasPrefix(data, []byte{0x16, 0x03, 0x01}):
        return ProtocolTLS
    case bytes.HasPrefix(data, []byte("HEAD")) ||
         bytes.HasPrefix(data, []byte("POST")) ||
         bytes.HasPrefix(data, []byte("GET ")):
        return ProtocolHTTP
    case len(data) >= 64:
        return ProtocolObfuscated
    default:
        return ProtocolUnknown
    }
}
```

#### Key Derivation
```go
func DeriveKeys(nonceServer, nonceClient []byte, timestamp uint32,
    serverIP, clientIP net.IP, serverPort, clientPort uint16,
    secret []byte, isServer bool) *AESKeyData {
    
    var buf bytes.Buffer
    buf.Write(nonceServer)
    buf.Write(nonceClient)
    binary.Write(&buf, binary.LittleEndian, timestamp)
    
    // Add IPs and ports based on IPv4 or IPv6
    if serverIP.To4() != nil {
        buf.Write(serverIP.To4())
        binary.Write(&buf, binary.LittleEndian, clientPort)
        if isServer {
            buf.WriteString("SERVER")
        } else {
            buf.WriteString("CLIENT")
        }
        buf.Write(clientIP.To4())
        binary.Write(&buf, binary.LittleEndian, serverPort)
    } else {
        // IPv6 handling
    }
    
    buf.Write(secret)
    buf.Write(nonceServer)
    // ... continue per spec
    
    // Derive keys
    str := buf.Bytes()
    writeKey := make([]byte, 32)
    copy(writeKey[:12], md5Hash(append([]byte{1}, str...)))
    copy(writeKey[12:], sha1Hash(str)[:8])
    
    writeIV := md5Hash(append([]byte{2}, str...))
    
    // ... return keys
}
```

#### TLS Packet Framing
```go
func WrapTLSPacket(data []byte) []byte {
    if len(data) > MaxPacketLength {
        // Fragment
    }
    
    pkt := make([]byte, 5+len(data))
    pkt[0] = 0x17  // Application Data
    pkt[1] = 0x03  // TLS 1.2 legacy
    pkt[2] = 0x03
    binary.BigEndian.PutUint16(pkt[3:5], uint16(len(data)))
    copy(pkt[5:], data)
    return pkt
}
```

### 14.5 Critical Implementation Notes

1. **TLS Mode**: Must accurately emulate real TLS 1.2/1.3 ClientHello/ServerHello
2. **Obfuscation**: The 64-byte header is decrypted with key derived from secret
3. **Padding**: `dd` prefix in secret enables random padding mode
4. **Connection Mapping**: Use `out_conn_id` (int64) for routing responses
5. **Buffer Management**: Implement backpressure to prevent memory exhaustion
6. **Stats**: Must be accessible only from localhost
7. **Concurrency**: Use Go's goroutines instead of process-based workers
8. **Graceful Shutdown**: Handle SIGTERM/SIGINT for clean shutdown

### 14.6 Testing Checklist

- [ ] Compact protocol detection and handling
- [ ] Medium protocol detection and handling  
- [ ] Medium with padding protocol
- [ ] TLS handshake (ClientHello parsing, ServerHello generation)
- [ ] Obfuscated 64-byte header decryption
- [ ] AES-256-CTR encryption/decryption
- [ ] Key derivation matches reference implementation
- [ ] Connection forwarding (client ↔ proxy ↔ Telegram)
- [ ] Response routing via out_conn_id
- [ ] HTTP stats endpoint (localhost only)
- [ ] Multiple proxy secrets
- [ ] Random padding with `dd` prefix
- [ ] Memory limits and LRU eviction
- [ ] Graceful shutdown

---

## References

- Original C Implementation: https://github.com/TelegramMessenger/MTProxy
- MTProto Protocol: https://core.telegram.org/mtproto
- Telegram API: https://core.telegram.org/api
- TLS 1.2 RFC: https://tools.ietf.org/html/rfc5246
- TLS 1.3 RFC: https://tools.ietf.org/html/rfc8446
