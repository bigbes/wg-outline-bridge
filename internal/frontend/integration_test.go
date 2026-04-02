package frontend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	mpcrypto "github.com/bigbes/wireguard-outline-bridge/internal/proxy/mtproxy/crypto"
)

// selfSignedTLS generates a self-signed TLS certificate and returns a tls.Config.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

// TestTCPMux_Integration_TLS verifies that a real TLS client connecting to the
// TCP mux gets served the static HTTP handler via HTTP/1.1 over TLS.
func TestTCPMux_Integration_TLS(t *testing.T) {
	// Create a static file to serve.
	tmpDir := t.TempDir()
	indexContent := "hello from frontend"
	if err := os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(indexContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Set up listener, TLS config, HTTP handler.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	tlsCfg := selfSignedTLS(t)
	handler := http.FileServer(http.Dir(tmpDir))

	mux := NewTCPMux(ln, tlsCfg, handler, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go mux.Serve(ctx)

	// Connect with a real TLS client.
	clientTLS := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer conn.Close()

	// Send HTTP/1.1 request (use "/" — FileServer redirects /index.html to /).
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if len(resp) == 0 {
		t.Fatal("empty response")
	}

	body := string(resp)
	if !containsSubstring(body, indexContent) {
		t.Fatalf("response does not contain %q:\n%s", indexContent, body)
	}
}

// TestTCPMux_Integration_MTProxy verifies that an MTProxy-signed ClientHello
// gets routed to the MTProxy handler instead of the TLS handler.
func TestTCPMux_Integration_MTProxy(t *testing.T) {
	// Set up MTProxy secret.
	var secretBytes [16]byte
	rand.Read(secretBytes[:])
	secret := mpcrypto.Secret{Raw: secretBytes}

	// Track whether the MTProxy handler was called.
	var mtCalled sync.WaitGroup
	mtCalled.Add(1)
	var receivedData []byte
	mtHandler := &captureMTHandler{
		onConn: func(conn net.Conn) {
			defer mtCalled.Done()
			// Read whatever the connection sends (the replayed TLS record).
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			receivedData = buf[:n]
			conn.Close()
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	tlsCfg := selfSignedTLS(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP handler should NOT be called for MTProxy connection")
	})

	mux := NewTCPMux(ln, tlsCfg, handler, slog.Default())
	mux.SetMTProxy(mtHandler, func() ([]mpcrypto.Secret, []string) {
		return []mpcrypto.Secret{secret}, []string{"test"}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go mux.Serve(ctx)

	// Build a fake TLS ClientHello with MTProxy HMAC in client_random.
	record := buildMTProxyClientHello(t, secret)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write(record); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	// Wait for the MTProxy handler to be called.
	done := make(chan struct{})
	go func() {
		mtCalled.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for MTProxy handler")
	}

	// The handler should have received the full TLS record (replayed via prefixConn).
	if len(receivedData) == 0 {
		t.Fatal("MTProxy handler received no data")
	}
	// First byte should be 0x16 (TLS handshake).
	if receivedData[0] != 0x16 {
		t.Fatalf("first byte = 0x%02x, want 0x16 (TLS handshake)", receivedData[0])
	}
}

// TestTCPMux_Integration_NonTLS verifies that a non-TLS connection is rejected.
func TestTCPMux_Integration_NonTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	tlsCfg := selfSignedTLS(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP handler should NOT be called for non-TLS connection")
	})

	mux := NewTCPMux(ln, tlsCfg, handler, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mux.Serve(ctx)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Send non-TLS data.
	conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))

	// Connection should be closed by the mux.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed for non-TLS data")
	}
	conn.Close()
}

// TestUDPMux_Integration_MixedTraffic sends interleaved QUIC and AWG packets
// from multiple sources and verifies correct demultiplexing.
func TestUDPMux_Integration_MixedTraffic(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	mux := NewUDPMux(serverConn, slog.Default())
	go mux.Run()
	defer mux.Close()

	serverAddr := serverConn.LocalAddr()

	// Create 3 senders: 2 QUIC clients, 1 AWG client.
	quicClient1, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer quicClient1.Close()
	quicClient2, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer quicClient2.Close()
	awgClient, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer awgClient.Close()

	// Send: QUIC Initial from client1, AWG from awgClient, QUIC Initial from client2,
	// then short-header from client1 (should route to QUIC due to tracking).
	pkt1 := makeQUICInitial(0x00000001, 8) // QUIC v1 from client1
	quicClient1.WriteTo(pkt1, serverAddr)

	pkt2 := []byte{0x01, 0x02, 0x03, 0x04, 0x05} // AWG
	awgClient.WriteTo(pkt2, serverAddr)

	pkt3 := makeQUICInitial(0x6b3343cf, 4) // QUIC v2 from client2
	quicClient2.WriteTo(pkt3, serverAddr)

	pkt4 := []byte{0x40, 0xAA, 0xBB, 0xCC, 0xDD} // short header from client1
	quicClient1.WriteTo(pkt4, serverAddr)

	// Collect: expect 3 QUIC packets and 1 AWG packet.
	quicCount := 0
	awgCount := 0
	timeout := time.After(3 * time.Second)

	for quicCount < 3 || awgCount < 1 {
		select {
		case <-mux.QUICChannel():
			quicCount++
		case <-mux.AWGChannel():
			awgCount++
		case <-timeout:
			t.Fatalf("timeout: got %d QUIC + %d AWG, want 3+1", quicCount, awgCount)
		}
	}

	if quicCount != 3 {
		t.Fatalf("QUIC count = %d, want 3", quicCount)
	}
	if awgCount != 1 {
		t.Fatalf("AWG count = %d, want 1", awgCount)
	}
}

// --- helpers ---

type captureMTHandler struct {
	onConn func(net.Conn)
}

func (h *captureMTHandler) HandleConn(_ context.Context, conn net.Conn) {
	h.onConn(conn)
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findSubstring(s, sub))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// buildMTProxyClientHello builds a TLS ClientHello with an MTProxy-signed client_random.
func buildMTProxyClientHello(t *testing.T, secret mpcrypto.Secret) []byte {
	t.Helper()
	record := buildFakeClientHello()

	// Zero client_random for HMAC.
	forHMAC := make([]byte, len(record))
	copy(forHMAC, record)
	for i := range 32 {
		forHMAC[11+i] = 0
	}

	mac := hmac.New(sha256.New, secret.Raw[:])
	mac.Write(forHMAC)
	computed := mac.Sum(nil)

	// Write HMAC into client_random (bytes 11-42 of record).
	copy(record[11:39], computed[:28])

	// Last 4 bytes: timestamp XOR.
	now := uint32(time.Now().Unix())
	var tsBytes [4]byte
	binary.LittleEndian.PutUint32(tsBytes[:], now^binary.LittleEndian.Uint32(computed[28:32]))
	copy(record[39:43], tsBytes[:])

	return record
}
