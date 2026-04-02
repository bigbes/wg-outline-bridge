package frontend

import (
	"encoding/binary"
	"log/slog"
	"net"
	"testing"
	"time"
)

// fakeAddr implements net.Addr for testing.
type fakeAddr string

func (a fakeAddr) Network() string { return "udp" }
func (a fakeAddr) String() string  { return string(a) }

func newTestUDPMux() *UDPMux {
	return &UDPMux{
		quicCh:    make(chan udpPacket, 256),
		awgCh:     make(chan udpPacket, 256),
		logger:    slog.Default(),
		closeCh:   make(chan struct{}),
		quicAddrs: make(map[string]struct{}),
	}
}

// makeQUICInitial builds a minimal QUIC long-header Initial packet.
func makeQUICInitial(version uint32, dcidLen byte) []byte {
	pkt := make([]byte, 6+int(dcidLen))
	pkt[0] = 0xC0 | 0x01 // long header form bit + fixed bit + Initial type
	binary.BigEndian.PutUint32(pkt[1:5], version)
	pkt[5] = dcidLen
	return pkt
}

func TestIsQUICPacket_V1Initial(t *testing.T) {
	m := newTestUDPMux()
	addr := fakeAddr("1.2.3.4:5678")

	pkt := makeQUICInitial(0x00000001, 8)
	if !m.isQUICPacket(pkt, addr) {
		t.Fatal("expected QUIC v1 Initial to be classified as QUIC")
	}

	// Should also have tracked the address.
	m.quicAddrsMu.RLock()
	_, tracked := m.quicAddrs[addr.String()]
	m.quicAddrsMu.RUnlock()
	if !tracked {
		t.Fatal("expected address to be tracked after QUIC Initial")
	}
}

func TestIsQUICPacket_V2Initial(t *testing.T) {
	m := newTestUDPMux()
	addr := fakeAddr("1.2.3.4:5678")

	pkt := makeQUICInitial(0x6b3343cf, 16)
	if !m.isQUICPacket(pkt, addr) {
		t.Fatal("expected QUIC v2 Initial to be classified as QUIC")
	}
}

func TestIsQUICPacket_DCIDZero(t *testing.T) {
	m := newTestUDPMux()
	pkt := makeQUICInitial(0x00000001, 0)
	if !m.isQUICPacket(pkt, fakeAddr("1.2.3.4:1234")) {
		t.Fatal("expected QUIC Initial with DCID=0 to be classified as QUIC")
	}
}

func TestIsQUICPacket_DCID20(t *testing.T) {
	m := newTestUDPMux()
	pkt := makeQUICInitial(0x00000001, 20)
	if !m.isQUICPacket(pkt, fakeAddr("1.2.3.4:1234")) {
		t.Fatal("expected QUIC Initial with DCID=20 to be classified as QUIC")
	}
}

func TestIsQUICPacket_DCIDTooLarge(t *testing.T) {
	m := newTestUDPMux()
	// DCID=21 is not valid for QUIC → should fall through to AWG.
	pkt := makeQUICInitial(0x00000001, 21)
	if m.isQUICPacket(pkt, fakeAddr("1.2.3.4:1234")) {
		t.Fatal("DCID=21 should NOT be classified as QUIC")
	}
}

func TestIsQUICPacket_AWGJunk(t *testing.T) {
	m := newTestUDPMux()
	// AWG CPS junk: first byte 0xC7 (long header bits set), fake version,
	// byte 5 from <rc 8> = random alphanumeric (ASCII 48-122, always > 20).
	pkt := make([]byte, 100)
	pkt[0] = 0xC7 // looks like long header
	// Version bytes that are NOT 0x00000001 or 0x6b3343cf.
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	pkt[4] = 0x01 // version = 0x00000001
	pkt[5] = 48   // ASCII '0' = 48, which is > 20

	if m.isQUICPacket(pkt, fakeAddr("5.6.7.8:9999")) {
		t.Fatal("AWG junk with DCID byte=48 should NOT be classified as QUIC")
	}
}

func TestIsQUICPacket_AWGJunkAllASCIIValues(t *testing.T) {
	m := newTestUDPMux()
	// Verify that ALL possible <rc N> outputs (ASCII 48-122) produce DCID > 20.
	for b := byte(48); b <= 122; b++ {
		pkt := makeQUICInitial(0x00000001, 0) // will overwrite byte 5
		pkt[5] = b
		if m.isQUICPacket(pkt, fakeAddr("5.6.7.8:9999")) {
			t.Fatalf("AWG <rc> byte %d (0x%02x) was incorrectly classified as QUIC", b, b)
		}
	}
}

func TestIsQUICPacket_UnknownVersion(t *testing.T) {
	m := newTestUDPMux()
	pkt := makeQUICInitial(0xDEADBEEF, 8)
	if m.isQUICPacket(pkt, fakeAddr("1.2.3.4:1234")) {
		t.Fatal("unknown QUIC version should NOT be classified as QUIC")
	}
}

func TestIsQUICPacket_RuntPacket(t *testing.T) {
	m := newTestUDPMux()
	// Packets shorter than 5 bytes are always AWG.
	for _, size := range []int{0, 1, 2, 3, 4} {
		pkt := make([]byte, size)
		if size > 0 {
			pkt[0] = 0xC0 // would look like long header
		}
		if m.isQUICPacket(pkt, fakeAddr("1.2.3.4:1234")) {
			t.Fatalf("runt packet (%d bytes) should not be classified as QUIC", size)
		}
	}
}

func TestIsQUICPacket_ExactlyFiveBytes(t *testing.T) {
	m := newTestUDPMux()
	// 5 bytes: long header check passes (byte 0), version matches,
	// but byte 5 (DCID len) is missing → len(data) < 6, falls through.
	pkt := make([]byte, 5)
	pkt[0] = 0xC0
	binary.BigEndian.PutUint32(pkt[1:5], 0x00000001)
	if m.isQUICPacket(pkt, fakeAddr("1.2.3.4:1234")) {
		t.Fatal("5-byte packet should not be classified as QUIC (no DCID byte)")
	}
}

func TestIsQUICPacket_ShortHeaderKnownAddr(t *testing.T) {
	m := newTestUDPMux()
	addr := fakeAddr("10.0.0.1:443")
	m.TrackQUICAddr(addr.String())

	// Short header: bit 7 clear (0x40 = fixed bit set, form bit clear).
	pkt := []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05}
	if !m.isQUICPacket(pkt, addr) {
		t.Fatal("short-header packet from known QUIC addr should be classified as QUIC")
	}
}

func TestIsQUICPacket_ShortHeaderUnknownAddr(t *testing.T) {
	m := newTestUDPMux()
	// No addresses tracked.
	pkt := []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05}
	if m.isQUICPacket(pkt, fakeAddr("10.0.0.2:443")) {
		t.Fatal("short-header packet from unknown addr should NOT be classified as QUIC")
	}
}

func TestIsQUICPacket_NonLongHeader(t *testing.T) {
	m := newTestUDPMux()
	// Byte 0 with only bit 7 set (no bit 6) → not a long header.
	pkt := make([]byte, 10)
	pkt[0] = 0x80 // bit 7 set, bit 6 clear
	binary.BigEndian.PutUint32(pkt[1:5], 0x00000001)
	pkt[5] = 8
	if m.isQUICPacket(pkt, fakeAddr("1.2.3.4:1234")) {
		t.Fatal("packet with only bit 7 set should NOT be classified as QUIC long header")
	}
}

func TestIsQUICPacket_TrackAndUntrack(t *testing.T) {
	m := newTestUDPMux()
	addr := fakeAddr("10.0.0.1:443")

	// Initially unknown.
	pkt := []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05}
	if m.isQUICPacket(pkt, addr) {
		t.Fatal("should not be QUIC before tracking")
	}

	// Track via Initial.
	initial := makeQUICInitial(0x00000001, 8)
	if !m.isQUICPacket(initial, addr) {
		t.Fatal("QUIC Initial should be QUIC")
	}

	// Now short header from same addr should be QUIC.
	if !m.isQUICPacket(pkt, addr) {
		t.Fatal("should be QUIC after tracking")
	}

	// Untrack.
	m.UntrackQUICAddr(addr.String())
	if m.isQUICPacket(pkt, addr) {
		t.Fatal("should not be QUIC after untracking")
	}
}

// TestUDPMuxRouting verifies that Run() routes packets to the correct channels.
func TestUDPMuxRouting(t *testing.T) {
	// Create a real UDP socket pair for testing.
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	mux := NewUDPMux(serverConn, slog.Default())
	go mux.Run()
	defer mux.Close()

	serverAddr := serverConn.LocalAddr()

	// Use TWO different sender sockets so that the QUIC address tracking
	// from the Initial doesn't cause the AWG packet to be misrouted.
	quicSender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer quicSender.Close()

	awgSender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer awgSender.Close()

	// Send a QUIC v1 Initial packet from quicSender.
	quicPkt := makeQUICInitial(0x00000001, 8)
	if _, err := quicSender.WriteTo(quicPkt, serverAddr); err != nil {
		t.Fatal(err)
	}

	// Send an AWG-like packet from awgSender (different source port).
	awgPkt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if _, err := awgSender.WriteTo(awgPkt, serverAddr); err != nil {
		t.Fatal(err)
	}

	// Read from QUIC channel.
	select {
	case pkt := <-mux.QUICChannel():
		if len(pkt.data) != len(quicPkt) {
			t.Fatalf("QUIC packet size mismatch: got %d, want %d", len(pkt.data), len(quicPkt))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for QUIC packet")
	}

	// Read from AWG channel.
	select {
	case pkt := <-mux.AWGChannel():
		if len(pkt.data) != len(awgPkt) {
			t.Fatalf("AWG packet size mismatch: got %d, want %d", len(pkt.data), len(awgPkt))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for AWG packet")
	}
}
