package frontend

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

// QUIC version constants for packet classification.
const (
	quicVersionV1 uint32 = 0x00000001
	quicVersionV2 uint32 = 0x6b3343cf
)

// UDPMux demultiplexes UDP packets on a shared socket between QUIC and AWG.
// QUIC packets are identified by their long-header format (Initial packets)
// or by tracking known QUIC remote addresses (short-header packets).
type UDPMux struct {
	conn    net.PacketConn
	quicCh  chan udpPacket
	awgCh   chan udpPacket
	logger  *slog.Logger
	closeCh chan struct{}

	// Track active QUIC remote addresses for short-header routing.
	quicAddrsMu sync.RWMutex
	quicAddrs   map[string]struct{}
}

type udpPacket struct {
	data []byte
	addr net.Addr
	n    int
}

// NewUDPMux creates a new UDP multiplexer on the given packet connection.
func NewUDPMux(conn net.PacketConn, logger *slog.Logger) *UDPMux {
	return &UDPMux{
		conn:      conn,
		quicCh:    make(chan udpPacket, 256),
		awgCh:     make(chan udpPacket, 256),
		logger:    logger.With("component", "udp-mux"),
		closeCh:   make(chan struct{}),
		quicAddrs: make(map[string]struct{}),
	}
}

// Run reads packets from the shared socket and routes them to either
// the QUIC or AWG channel. Blocks until the socket is closed.
func (m *UDPMux) Run() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-m.closeCh:
				return
			default:
			}
			m.logger.Debug("udp read error", "err", err)
			return
		}
		if n == 0 {
			continue
		}

		// Make a copy for the channel.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		if m.isQUICPacket(pkt, addr) {
			select {
			case m.quicCh <- udpPacket{data: pkt, addr: addr, n: n}:
			default:
				m.logger.Debug("quic channel full, dropping packet")
			}
		} else {
			select {
			case m.awgCh <- udpPacket{data: pkt, addr: addr, n: n}:
			default:
				m.logger.Debug("awg channel full, dropping packet")
			}
		}
	}
}

// Close signals the mux to stop.
func (m *UDPMux) Close() {
	close(m.closeCh)
}

// QUICChannel returns the channel for QUIC packets.
func (m *UDPMux) QUICChannel() <-chan udpPacket {
	return m.quicCh
}

// AWGChannel returns the channel for AWG packets.
func (m *UDPMux) AWGChannel() <-chan udpPacket {
	return m.awgCh
}

// TrackQUICAddr adds a remote address to the known QUIC connections set.
func (m *UDPMux) TrackQUICAddr(addr string) {
	m.quicAddrsMu.Lock()
	m.quicAddrs[addr] = struct{}{}
	m.quicAddrsMu.Unlock()
}

// UntrackQUICAddr removes a remote address from the known QUIC connections set.
func (m *UDPMux) UntrackQUICAddr(addr string) {
	m.quicAddrsMu.Lock()
	delete(m.quicAddrs, addr)
	m.quicAddrsMu.Unlock()
}

// isQUICPacket determines whether a UDP packet belongs to QUIC.
//
// Detection logic:
//  1. Long header (byte 0 & 0xC0 == 0xC0) with known QUIC version (v1/v2)
//     and DCID length ≤ 20 → QUIC Initial packet.
//  2. Remote addr in active QUIC connections set → short-header packet.
//  3. Otherwise → AWG.
func (m *UDPMux) isQUICPacket(data []byte, addr net.Addr) bool {
	if len(data) < 5 {
		return false
	}

	// Check for QUIC long header: form bit set (bit 7) + fixed bit (bit 6).
	if data[0]&0xC0 == 0xC0 {
		// Long header: version at bytes 1-4, DCID length at byte 5.
		if len(data) >= 6 {
			version := uint32(data[1])<<24 | uint32(data[2])<<16 | uint32(data[3])<<8 | uint32(data[4])
			if version == quicVersionV1 || version == quicVersionV2 {
				dcidLen := data[5]
				if dcidLen <= 20 {
					// Valid QUIC Initial — track this address.
					m.TrackQUICAddr(addr.String())
					return true
				}
			}
		}
	}

	// Check if this is a known QUIC address (for short-header packets).
	m.quicAddrsMu.RLock()
	_, known := m.quicAddrs[addr.String()]
	m.quicAddrsMu.RUnlock()
	return known
}

// MuxedPacketConn is a virtual net.PacketConn that reads from a channel
// and writes to the shared UDP socket. Used by quic-go as its transport.
type MuxedPacketConn struct {
	ch     <-chan udpPacket
	conn   net.PacketConn
	closed chan struct{}
	once   sync.Once
}

// NewMuxedPacketConn creates a virtual PacketConn for QUIC.
func NewMuxedPacketConn(ch <-chan udpPacket, conn net.PacketConn) *MuxedPacketConn {
	return &MuxedPacketConn{
		ch:     ch,
		conn:   conn,
		closed: make(chan struct{}),
	}
}

func (c *MuxedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-c.ch:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *MuxedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.conn.WriteTo(p, addr)
}

func (c *MuxedPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *MuxedPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *MuxedPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *MuxedPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *MuxedPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
