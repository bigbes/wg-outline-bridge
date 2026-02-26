package routing

import (
	"encoding/binary"
	"strings"
)

// ProtocolBitTorrent is the identifier for the BitTorrent protocol family.
const ProtocolBitTorrent = "bittorrent"

// DetectTCPProtocol inspects the beginning of a TCP payload and returns
// the detected application protocol name, or "" if unknown.
func DetectTCPProtocol(data []byte) string {
	if isBitTorrentHandshake(data) {
		return ProtocolBitTorrent
	}
	return ""
}

// DetectUDPProtocol inspects a UDP packet payload and returns the detected
// application protocol name, or "" if unknown.
func DetectUDPProtocol(data []byte) string {
	if isBitTorrentTracker(data) || isBitTorrentDHT(data) {
		return ProtocolBitTorrent
	}
	return ""
}

// isBitTorrentHandshake checks for the BitTorrent peer wire protocol handshake.
// Format: pstrlen(1) + pstr(19) = "\x13BitTorrent protocol"
func isBitTorrentHandshake(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	return data[0] == 19 && string(data[1:20]) == "BitTorrent protocol"
}

// isBitTorrentDHT checks for BitTorrent DHT (BEP 5) messages.
// DHT messages are bencoded dictionaries containing a "y" key (message type).
func isBitTorrentDHT(data []byte) bool {
	if len(data) < 10 {
		return false
	}
	if data[0] != 'd' {
		return false
	}
	s := string(data)
	// DHT messages always contain "1:y" (message type key) and either
	// "1:q" (query), "1:r" (response), or "1:e" (error).
	return strings.Contains(s, "1:y") &&
		(strings.Contains(s, "1:q") || strings.Contains(s, "1:r") || strings.Contains(s, "1:e"))
}

// isBitTorrentTracker checks for the UDP tracker protocol (BEP 15).
// Connect requests start with the magic constant 0x41727101980.
func isBitTorrentTracker(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	protocolID := binary.BigEndian.Uint64(data[0:8])
	return protocolID == 0x41727101980
}
