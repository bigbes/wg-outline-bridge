#!/usr/bin/env bash
set -euo pipefail

PREFIX="${1:-/data}"
TRANSPORT="${2:-}"

if [[ -z "$TRANSPORT" ]]; then
    echo "Usage: sudo $0 [prefix] <transport-uri>"
    echo "  prefix         installation prefix (default: /data)"
    echo "  transport-uri  Outline transport URI (ss://...)"
    echo ""
    echo "Examples:"
    echo "  sudo $0 'ss://...'"
    echo "  sudo $0 /data 'ss://...'"
    exit 1
fi

# When only one arg is given, it's the transport URI
if [[ $# -eq 1 ]]; then
    TRANSPORT="$1"
    PREFIX="/data"
fi

BIN_DIR="$PREFIX/bin"
ETC_DIR="$PREFIX/etc"
LOG_DIR="$PREFIX/var/log"
LIB_DIR="$PREFIX/var/lib/bridge"
CONFIG="$ETC_DIR/bridge.yaml"
PEERS_DIR="$ETC_DIR/peers"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Installing WireGuard-Outline Bridge ==="
echo "  Prefix:    $PREFIX"
echo "  Binary:    $BIN_DIR/bridge"
echo "  Config:    $CONFIG"
echo ""

# Build
echo "Building binary..."
VERSION="$(cd "$SRCDIR" && git describe --tags --long --always 2>/dev/null || echo "dev")"
DIRTY="$(cd "$SRCDIR" && git diff --quiet 2>/dev/null && git diff --cached --quiet 2>/dev/null && echo false || echo true)"
(cd "$SRCDIR" && go build -ldflags "-X main.Version=$VERSION -X main.Dirty=$DIRTY" -o bridge ./cmd/bridge/main.go)

# Create directories
echo "Creating directories..."
mkdir -p "$BIN_DIR" "$ETC_DIR" "$PEERS_DIR" "$LOG_DIR" "$LIB_DIR"

# Install binary
echo "Installing binary..."
install -m 0755 "$SRCDIR/bridge" "$BIN_DIR/bridge"
rm -f "$SRCDIR/bridge"

# Generate config with server keys (only if config doesn't exist)
if [[ -f "$CONFIG" ]]; then
    echo "Config already exists at $CONFIG, skipping key generation."
else
    echo "Generating server keys and config..."
    "$BIN_DIR/bridge" init -transport "$TRANSPORT" -config "$CONFIG"
    chmod 600 "$CONFIG"
fi

# Install systemd unit with correct prefix
echo "Installing systemd unit..."
sed \
    -e "s|/data/bin/bridge|$BIN_DIR/bridge|g" \
    -e "s|/data/etc/bridge.yaml|$CONFIG|g" \
    -e "s|/data/var/log/bridge.log|$LOG_DIR/bridge.log|g" \
    -e "s|ReadWritePaths=/data|ReadWritePaths=$PREFIX|g" \
    "$SRCDIR/configs/bridge.service" > /etc/systemd/system/bridge.service

systemctl daemon-reload
systemctl enable bridge

echo ""
echo "=== Installation complete ==="
echo "Start with: systemctl start bridge"
