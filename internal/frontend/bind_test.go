package frontend

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// mockPacketConn records WriteTo calls and provides a LocalAddr.
type mockPacketConn struct {
	mu      sync.Mutex
	written []writtenPacket
	closed  bool
}

type writtenPacket struct {
	data []byte
	addr net.Addr
}

func (c *mockPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	select {} // block forever
}

func (c *mockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	c.written = append(c.written, writtenPacket{data: cp, addr: addr})
	return len(p), nil
}

func (c *mockPacketConn) Close() error                       { c.closed = true; return nil }
func (c *mockPacketConn) LocalAddr() net.Addr                { return fakeAddr("0.0.0.0:443") }
func (c *mockPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *mockPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *mockPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *mockPacketConn) getWritten() []writtenPacket {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]writtenPacket, len(c.written))
	copy(out, c.written)
	return out
}

// --- AWGBind ---

func TestAWGBind_Open(t *testing.T) {
	bind := NewAWGBind(make(chan udpPacket), &mockPacketConn{})
	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if port != 443 {
		t.Fatalf("port = %d, want 443", port)
	}
	if len(fns) != 1 {
		t.Fatalf("ReceiveFuncs = %d, want 1", len(fns))
	}
}

func TestAWGBind_Send(t *testing.T) {
	conn := &mockPacketConn{}
	bind := NewAWGBind(make(chan udpPacket), conn)

	ep := &AWGEndpoint{addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5678}}
	data := [][]byte{{0x01, 0x02}, {0x03, 0x04, 0x05}}

	if err := bind.Send(data, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	w := conn.getWritten()
	if len(w) != 2 {
		t.Fatalf("written = %d, want 2", len(w))
	}
	if string(w[0].data) != "\x01\x02" {
		t.Fatalf("first packet: %x", w[0].data)
	}
	if string(w[1].data) != "\x03\x04\x05" {
		t.Fatalf("second packet: %x", w[1].data)
	}
	if w[0].addr.String() != "1.2.3.4:5678" {
		t.Fatalf("addr = %s", w[0].addr)
	}
}

func TestAWGBind_SendWrongEndpointType(t *testing.T) {
	bind := NewAWGBind(make(chan udpPacket), &mockPacketConn{})
	// A non-*AWGEndpoint should return error.
	err := bind.Send([][]byte{{0x01}}, badEndpoint{})
	if err == nil {
		t.Fatal("expected error for wrong endpoint type")
	}
}

// badEndpoint implements awgconn.Endpoint but is not *AWGEndpoint.
type badEndpoint struct{}

func (badEndpoint) ClearSrc()           {}
func (badEndpoint) SrcToString() string { return "" }
func (badEndpoint) DstToString() string { return "" }
func (badEndpoint) DstToBytes() []byte  { return nil }
func (badEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (badEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func TestAWGBind_Close_SignalsReceive(t *testing.T) {
	bind := NewAWGBind(make(chan udpPacket), &mockPacketConn{})
	bind.Close()

	// closeCh should be closed.
	select {
	case <-bind.closeCh:
	default:
		t.Fatal("closeCh not signalled")
	}

	// Double close should not panic.
	bind.Close()
}

func TestAWGBind_ParseEndpoint(t *testing.T) {
	bind := NewAWGBind(nil, nil)
	ep, err := bind.ParseEndpoint("1.2.3.4:5678")
	if err != nil {
		t.Fatal(err)
	}
	if ep.DstToString() != "1.2.3.4:5678" {
		t.Fatalf("DstToString = %q", ep.DstToString())
	}
	if ep.SrcToString() != "" {
		t.Fatalf("SrcToString = %q, want empty", ep.SrcToString())
	}
}

func TestAWGBind_BatchSize(t *testing.T) {
	if NewAWGBind(nil, nil).BatchSize() != 1 {
		t.Fatal("BatchSize != 1")
	}
}

func TestAWGBind_SetMark(t *testing.T) {
	if err := NewAWGBind(nil, nil).SetMark(42); err != nil {
		t.Fatal(err)
	}
}

// --- AWGEndpoint ---

func TestAWGEndpoint_DstIP(t *testing.T) {
	ep := &AWGEndpoint{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}}
	got := ep.DstIP()
	// net.ParseIP("10.0.0.1") returns a 16-byte (v4-in-v6) slice, so
	// AddrPort().Addr() yields ::ffff:10.0.0.1. Unmap to compare as v4.
	want := netip.MustParseAddr("10.0.0.1")
	if got.Unmap() != want {
		t.Fatalf("DstIP = %s, want %s", got, want)
	}
}

func TestAWGEndpoint_SrcIP(t *testing.T) {
	ep := &AWGEndpoint{addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5678}}
	if ep.SrcIP().IsValid() {
		t.Fatal("SrcIP should be zero/invalid")
	}
}

func TestAWGEndpoint_DstToBytes(t *testing.T) {
	ep := &AWGEndpoint{addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5678}}
	b := ep.DstToBytes()
	if len(b) == 0 {
		t.Fatal("DstToBytes should be non-empty")
	}
}

func TestAWGEndpoint_ClearSrc(t *testing.T) {
	ep := &AWGEndpoint{addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5678}}
	ep.ClearSrc() // should not panic
}
