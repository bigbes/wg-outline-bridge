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

	"golang.zx2c4.com/wireguard/device"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

const (
	peerMonitorInterval   = 10 * time.Second
	peerHandshakeTimeout  = 30 * time.Second // remove peer after no handshake for this long
)

type peerMonitor struct {
	dev    *device.Device
	peers  map[string]config.PeerConfig
	logger *slog.Logger

	// lastGoodHandshake tracks when each peer (by public key) last had a valid handshake.
	// Zero time means the peer has never completed a handshake.
	lastGoodHandshake map[string]time.Time
	// removed tracks peers that have been removed due to stale handshakes.
	removed map[string]bool
}

func newPeerMonitor(dev *device.Device, peers map[string]config.PeerConfig, logger *slog.Logger) *peerMonitor {
	return &peerMonitor{
		dev:               dev,
		peers:             peers,
		logger:            logger,
		lastGoodHandshake: make(map[string]time.Time),
		removed:           make(map[string]bool),
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

// peerStatus holds parsed UAPI status for a single peer.
type peerStatus struct {
	publicKeyHex      string
	lastHandshakeSec  int64
	lastHandshakeNsec int64
}

func (m *peerMonitor) check() {
	statuses := m.getPeerStatuses()
	now := time.Now()

	for _, st := range statuses {
		pubB64 := hexToBase64(st.publicKeyHex)

		hsTime := time.Unix(st.lastHandshakeSec, st.lastHandshakeNsec)
		if st.lastHandshakeSec == 0 && st.lastHandshakeNsec == 0 {
			hsTime = time.Time{}
		}

		// Update lastGoodHandshake if we see a valid (non-zero) handshake time.
		if !hsTime.IsZero() {
			m.lastGoodHandshake[pubB64] = hsTime
		}

		lastGood, known := m.lastGoodHandshake[pubB64]
		if !known {
			// Peer has never completed a handshake; nothing to reap yet.
			continue
		}

		staleDuration := now.Sub(lastGood)
		if staleDuration > peerHandshakeTimeout && !m.removed[pubB64] {
			m.logger.Info("peer monitor: removing stale peer",
				"public_key", pubB64,
				"last_handshake", lastGood.Format(time.RFC3339),
				"stale_for", staleDuration.Round(time.Second).String(),
			)
			m.removePeer(pubB64)
			m.removed[pubB64] = true
		}
	}

	// Re-add removed peers so they can accept incoming handshakes.
	// This is done on every tick: the peer is re-added with no endpoint,
	// so WireGuard won't initiate outgoing handshakes but will respond
	// to incoming ones from the client.
	for pubB64 := range m.removed {
		m.readdPeer(pubB64)
		delete(m.removed, pubB64)
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
		}
	}
	if current != nil {
		statuses = append(statuses, *current)
	}
	return statuses
}

func (m *peerMonitor) removePeer(pubB64 string) {
	uapi, err := config.PeerUAPIRemove(pubB64)
	if err != nil {
		m.logger.Error("peer monitor: failed to generate remove UAPI", "public_key", pubB64, "err", err)
		return
	}
	if err := m.dev.IpcSet(uapi); err != nil {
		m.logger.Error("peer monitor: failed to remove peer", "public_key", pubB64, "err", err)
	}
}

func (m *peerMonitor) readdPeer(pubB64 string) {
	for name, peer := range m.peers {
		if peer.PublicKey == pubB64 {
			uapi, err := config.PeerUAPIAdd(peer)
			if err != nil {
				m.logger.Error("peer monitor: failed to generate add UAPI", "name", name, "err", err)
				return
			}
			if err := m.dev.IpcSet(uapi); err != nil {
				m.logger.Error("peer monitor: failed to re-add peer", "name", name, "err", err)
			}
			m.logger.Info("peer monitor: re-added stale peer (will accept incoming handshakes)",
				"name", name,
			)
			return
		}
	}
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
