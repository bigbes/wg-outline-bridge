#!/bin/sh
set -e

CONFIG_FILE="${CONFIG_FILE:-/app/configs/bridge.yaml}"
PASSWORD_FILE="${PASSWORD_FILE:-/app/.socks5_password}"

log() {
    echo "[entrypoint] $1"
}

error() {
    echo "[entrypoint] ERROR: $1" >&2
    exit 1
}

generate_password() {
    tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16 || \
    openssl rand -hex 8 2>/dev/null
}

generate_wireguard_key() {
    openssl rand -base64 32 2>/dev/null | tr -d '\n' || \
    head -c 32 /dev/urandom | base64 | tr -d '\n'
}

validate_upstreams() {
    if [ -z "$UPSTREAMS" ]; then
        error "UPSTREAMS is required (format: name=ss://...,name2=ss://...)"
    fi
    
    first_upstream=$(echo "$UPSTREAMS" | cut -d',' -f1)
    transport=$(echo "$first_upstream" | cut -d'=' -f2-)
    if [ -z "$transport" ]; then
        error "UPSTREAMS format invalid. Expected: name=ss://..."
    fi
    case "$transport" in
        ss://*|sss://*) ;;
        *) error "UPSTREAMS transport must start with ss:// or sss:// (got: ${transport%%@*}@...)" ;;
    esac
}

if [ -f "$CONFIG_FILE" ]; then
    log "Config file exists at $CONFIG_FILE, skipping generation"
else
    log "Config file not found, generating from environment variables..."

    if [ -z "$DOMAIN_NAME" ]; then
        error "DOMAIN_NAME is required"
    fi

    if [ -z "$DOMAIN_NAME_ACME_EMAIL" ]; then
        error "DOMAIN_NAME_ACME_EMAIL is required"
    fi

    validate_upstreams

    LOG_LEVEL="${LOG_LEVEL:-info}"

    OBSERVABILITY_HTTP_ADDR="${OBSERVABILITY_HTTP_ADDR:-:6060}"
    OBSERVABILITY_HTTP_PPROF="${OBSERVABILITY_HTTP_PPROF:-true}"
    OBSERVABILITY_HTTP_METRICS="${OBSERVABILITY_HTTP_METRICS:-true}"

    DNS_ENABLED="${DNS_ENABLED:-true}"
    DNS_LISTEN="${DNS_LISTEN:-127.0.0.1:15353}"
    DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1:53}"

    MTPROXY_ENABLED="${MTPROXY_ENABLED:-false}"
    MTPROXY_LISTEN="${MTPROXY_LISTEN:-:443}"
    MTPROXY_FAKE_TLS_ENABLED="${MTPROXY_FAKE_TLS_ENABLED:-true}"
    MTPROXY_FAKE_TLS_SNI="${MTPROXY_FAKE_TLS_SNI:-$DOMAIN_NAME}"

    PROXIES_SOCKS5_ENABLED="${PROXIES_SOCKS5_ENABLED:-true}"
    PROXIES_SOCKS5_LISTEN="${PROXIES_SOCKS5_LISTEN:-:1080}"
    PROXIES_SOCKS5_USERNAME="${PROXIES_SOCKS5_USERNAME:-admin}"

    if [ -f "$PASSWORD_FILE" ]; then
        PROXIES_SOCKS5_PASSWORD=$(cat "$PASSWORD_FILE")
    else
        PROXIES_SOCKS5_PASSWORD="${PROXIES_SOCKS5_PASSWORD:-$(generate_password)}"
        echo -n "$PROXIES_SOCKS5_PASSWORD" > "$PASSWORD_FILE"
        log "Generated SOCKS5 password: $PROXIES_SOCKS5_PASSWORD"
    fi

    MINIAPP_ENABLED="${MINIAPP_ENABLED:-true}"
    MINIAPP_LISTEN="${MINIAPP_LISTEN:-:8443}"
    MINIAPP_DOMAIN="${MINIAPP_DOMAIN:-$DOMAIN_NAME}"
    MINIAPP_ACME_EMAIL="${MINIAPP_ACME_EMAIL:-$DOMAIN_NAME_ACME_EMAIL}"

    GEOIP="${GEOIP:-rf-country=https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/Country.mmdb,gl2-asn=https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb,gl2-country=https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb}"

    WG_PRIVATE_KEY=$(generate_wireguard_key)

    mkdir -p "$(dirname "$CONFIG_FILE")"

    UPSTREAMS_YAML=""
    first_name=$(echo "$UPSTREAMS" | cut -d',' -f1 | cut -d'=' -f1)
    for upstream in $(echo "$UPSTREAMS" | tr ',' ' '); do
        name=$(echo "$upstream" | cut -d'=' -f1)
        transport=$(echo "$upstream" | cut -d'=' -f2-)
        if [ "$name" = "$first_name" ]; then
            is_default="true"
        else
            is_default="false"
        fi
        UPSTREAMS_YAML="${UPSTREAMS_YAML}  - name: \"${name}\"
    type: \"outline\"
    transport: \"${transport}\"
    default: ${is_default}
"
    done

    GEOIP_YAML=""
    for geo in $(echo "$GEOIP" | tr ',' ' '); do
        name=$(echo "$geo" | cut -d'=' -f1)
        path=$(echo "$geo" | cut -d'=' -f2-)
        GEOIP_YAML="${GEOIP_YAML}  - name: \"${name}\"
    path: \"${path}\"
    refresh: 86400
"
    done

    MTPROXY_YAML="mtproxy:
  enabled: false"
    if [ "$MTPROXY_ENABLED" = "true" ]; then
        SNI_YAML=""
        for sni in $(echo "$MTPROXY_FAKE_TLS_SNI" | tr ',' ' '); do
            SNI_YAML="${SNI_YAML}      - \"${sni}\"
"
        done
        MTPROXY_YAML="mtproxy:
  enabled: true
  listen:
    - \"${MTPROXY_LISTEN}\"
  fake_tls:
    enabled: ${MTPROXY_FAKE_TLS_ENABLED}
    sni:
${SNI_YAML}"
    fi

    PROXIES_YAML="proxies: []"
    if [ "$PROXIES_SOCKS5_ENABLED" = "true" ]; then
        PROXIES_YAML="proxies:
  - name: \"socks5\"
    type: \"socks5\"
    listen: \"${PROXIES_SOCKS5_LISTEN}\"
    upstream_group: \"\"
    username: \"${PROXIES_SOCKS5_USERNAME}\"
    password: \"${PROXIES_SOCKS5_PASSWORD}\""
    fi

    MINIAPP_YAML="miniapp:
  enabled: false"
    if [ "$MINIAPP_ENABLED" = "true" ]; then
        MINIAPP_YAML="miniapp:
  enabled: true
  listen: \"${MINIAPP_LISTEN}\"
  domain: \"${MINIAPP_DOMAIN}\"
  acme_email: \"${MINIAPP_ACME_EMAIL}\""
    fi

    cat > "$CONFIG_FILE" << EOF
log_level: "${LOG_LEVEL}"
cache_dir: "/app/cache"

observability_http:
  addr: "${OBSERVABILITY_HTTP_ADDR}"
  pprof: ${OBSERVABILITY_HTTP_PPROF}
  metrics: ${OBSERVABILITY_HTTP_METRICS}

wireguard:
  private_key: "${WG_PRIVATE_KEY}"
  listen_port: 51820
  address: "10.100.0.1/24"
  mtu: 1420
  dns: "1.1.1.1"

dns:
  enabled: ${DNS_ENABLED}
  listen: "${DNS_LISTEN}"
  upstream: "${DNS_UPSTREAM}"
  records: {}
  rules: []

upstreams:
${UPSTREAMS_YAML}
routing:
  enabled: false
  cidrs: []
  ip_rules: []
  sni_rules: []
  port_rules: []
  protocol_rules: []

geoip:
${GEOIP_YAML}
${MTPROXY_YAML}

${PROXIES_YAML}

${MINIAPP_YAML}

database:
  path: "/app/data/bridge.db"
  flush_interval: 30
EOF

    log "Config file generated at $CONFIG_FILE"
fi

if [ -n "$PROXIES_SOCKS5_PASSWORD" ] && [ "$PROXIES_SOCKS5_ENABLED" = "true" ]; then
    log "SOCKS5 proxy credentials - username: ${PROXIES_SOCKS5_USERNAME}, password: ${PROXIES_SOCKS5_PASSWORD}"
fi

exec "$@"
