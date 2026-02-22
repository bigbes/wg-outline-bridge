package bridge

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	wg "github.com/bigbes/wireguard-outline-bridge/internal/wireguard"
)

const peerMonitorInterval = 10 * time.Second

// peerStatus holds parsed UAPI status for a single peer.
type peerStatus struct {
	publicKeyHex      string
	lastHandshakeSec  int64
	lastHandshakeNsec int64
	rxBytes           int64
	txBytes           int64
}

type peerMonitor struct {
	dev    wg.Device
	peers  map[string]config.PeerConfig
	logger *slog.Logger

	// lastGoodHandshake tracks when each peer (by public key) last had a valid handshake.
	lastGoodHandshake map[string]time.Time
}

func newPeerMonitor(dev wg.Device, peers map[string]config.PeerConfig, logger *slog.Logger) *peerMonitor {
	return &peerMonitor{
		dev:               dev,
		peers:             peers,
		logger:            logger,
		lastGoodHandshake: make(map[string]time.Time),
	}
}

func (m *peerMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(peerMonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check()
		}
	}
}

func (m *peerMonitor) check() {
	statuses := m.getPeerStatuses()

	for _, st := range statuses {
		pubB64 := hexToBase64(st.publicKeyHex)

		hsTime := time.Unix(st.lastHandshakeSec, st.lastHandshakeNsec)
		if st.lastHandshakeSec == 0 && st.lastHandshakeNsec == 0 {
			hsTime = time.Time{}
		}

		prev, known := m.lastGoodHandshake[pubB64]

		if !hsTime.IsZero() {
			m.lastGoodHandshake[pubB64] = hsTime
		}

		// Log when a peer completes its first handshake or reconnects after being stale.
		if !hsTime.IsZero() && (!known || hsTime.After(prev)) {
			name := m.peerName(pubB64)
			m.logger.Info("peer monitor: handshake",
				"name", name,
				"public_key", pubB64,
				"last_handshake", hsTime.Format(time.RFC3339),
			)
		}
	}
}

func (m *peerMonitor) getPeerStatuses() []peerStatus {
	ipcStr, err := m.dev.IpcGet()
	if err != nil {
		m.logger.Error("peer monitor: failed to get IPC status", "err", err)
		return nil
	}

	var statuses []peerStatus
	var current *peerStatus

	scanner := bufio.NewScanner(strings.NewReader(ipcStr))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			if current != nil {
				statuses = append(statuses, *current)
			}
			current = &peerStatus{publicKeyHex: value}
		case "last_handshake_time_sec":
			if current != nil {
				current.lastHandshakeSec, _ = strconv.ParseInt(value, 10, 64)
			}
		case "last_handshake_time_nsec":
			if current != nil {
				current.lastHandshakeNsec, _ = strconv.ParseInt(value, 10, 64)
			}
		case "rx_bytes":
			if current != nil {
				current.rxBytes, _ = strconv.ParseInt(value, 10, 64)
			}
		case "tx_bytes":
			if current != nil {
				current.txBytes, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	}
	if current != nil {
		statuses = append(statuses, *current)
	}
	return statuses
}

func (m *peerMonitor) peerName(pubB64 string) string {
	for name, peer := range m.peers {
		if peer.PublicKey == pubB64 {
			return name
		}
	}
	return pubB64[:8] + "..."
}

func (m *peerMonitor) updatePeers(peers map[string]config.PeerConfig) {
	m.peers = peers
}

func hexToBase64(hexStr string) string {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return hexStr
	}
	return base64.StdEncoding.EncodeToString(raw)
}
