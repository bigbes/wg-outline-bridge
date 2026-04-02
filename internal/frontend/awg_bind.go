package frontend

import (
	"net"
	"net/netip"
	"sync"

	awgconn "github.com/amnezia-vpn/amneziawg-go/conn"
)

// AWGBind implements awgconn.Bind (and is structurally compatible with
// conn.Bind from wireguard-go). It reads packets from the UDP mux's AWG
// channel and writes to the shared UDP socket.
type AWGBind struct {
	awgCh   <-chan udpPacket
	conn    net.PacketConn
	closeCh chan struct{}
	once    sync.Once
}

// NewAWGBind creates a Bind that reads from the AWG channel and writes
// to the shared UDP socket.
func NewAWGBind(awgCh <-chan udpPacket, conn net.PacketConn) *AWGBind {
	return &AWGBind{
		awgCh:   awgCh,
		conn:    conn,
		closeCh: make(chan struct{}),
	}
}

// Open puts the Bind into a listening state. The port parameter is ignored
// since the shared socket is already bound. Returns port 443.
func (b *AWGBind) Open(port uint16) ([]awgconn.ReceiveFunc, uint16, error) {
	fn := func(packets [][]byte, sizes []int, eps []awgconn.Endpoint) (int, error) {
		select {
		case pkt, ok := <-b.awgCh:
			if !ok {
				return 0, net.ErrClosed
			}
			n := copy(packets[0], pkt.data)
			sizes[0] = n
			eps[0] = &AWGEndpoint{addr: pkt.addr}
			return 1, nil
		case <-b.closeCh:
			return 0, net.ErrClosed
		}
	}
	return []awgconn.ReceiveFunc{fn}, 443, nil
}

// Close closes the bind. All ReceiveFuncs will return net.ErrClosed.
func (b *AWGBind) Close() error {
	b.once.Do(func() { close(b.closeCh) })
	return nil
}

// SetMark is a no-op (SO_MARK is not needed for the muxed socket).
func (b *AWGBind) SetMark(_ uint32) error { return nil }

// Send writes packets to the shared UDP socket.
func (b *AWGBind) Send(bufs [][]byte, ep awgconn.Endpoint) error {
	awgEp, ok := ep.(*AWGEndpoint)
	if !ok {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := b.conn.WriteTo(buf, awgEp.addr); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint creates an AWGEndpoint from a "host:port" string.
func (b *AWGBind) ParseEndpoint(s string) (awgconn.Endpoint, error) {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	return &AWGEndpoint{addr: addr}, nil
}

// BatchSize returns 1 — we process one packet at a time from the mux.
func (b *AWGBind) BatchSize() int { return 1 }

// AWGEndpoint implements awgconn.Endpoint (and conn.Endpoint).
type AWGEndpoint struct {
	addr net.Addr
}

func (e *AWGEndpoint) ClearSrc() {}

func (e *AWGEndpoint) SrcToString() string { return "" }

func (e *AWGEndpoint) DstToString() string {
	return e.addr.String()
}

func (e *AWGEndpoint) DstToBytes() []byte {
	udpAddr, ok := e.addr.(*net.UDPAddr)
	if !ok {
		return nil
	}
	addrPort := udpAddr.AddrPort()
	b, _ := addrPort.MarshalBinary()
	return b
}

func (e *AWGEndpoint) DstIP() netip.Addr {
	udpAddr, ok := e.addr.(*net.UDPAddr)
	if !ok {
		return netip.Addr{}
	}
	return udpAddr.AddrPort().Addr()
}

func (e *AWGEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
