package mtproxy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	mpcrypto "github.com/blikh/wireguard-outline-bridge/internal/mtproxy/crypto"
	"github.com/blikh/wireguard-outline-bridge/internal/mtproxy/telegram"
)

// directDialer dials TCP directly (no proxy).
type directDialer struct{}

func (d *directDialer) DialStream(ctx context.Context, addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 5*time.Second)
}

// TestMTProxyIntegration_ReqPQ starts a local MTProxy, connects as a client
// with obfuscated2, sends req_pq_multi to a real Telegram DC, and checks for
// a response. Requires network access.
func TestMTProxyIntegration_ReqPQ(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Generate a random 16-byte secret
	var secretBytes [16]byte
	rand.Read(secretBytes[:])
	secret := mpcrypto.Secret{Raw: secretBytes}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	logger := slog.Default()
	endpoints := telegram.NewEndpointManager(nil)
	srv := NewServer(ServerConfig{
		ListenAddrs: []string{"127.0.0.1:0"},
		Secrets:     []mpcrypto.Secret{secret},
	}, &directDialer{}, endpoints, logger)

	// Bind to a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	t.Logf("MTProxy listening on %s", addr)

	// Run accept loop in background
	go srv.acceptLoop(ctx, ln)

	// Verify our client header building works with DecryptHeader
	dcID := int16(2)
	tag := mpcrypto.TagMedium
	testHeader, _, _ := buildClientHeader(t, secret, tag, dcID)
	parsed, secretIdx, err := mpcrypto.DecryptHeader(testHeader, []mpcrypto.Secret{secret})
	if err != nil {
		t.Fatalf("header roundtrip check failed: %v", err)
	}
	t.Logf("header roundtrip OK: tag=0x%08x dc=%d secret_idx=%d", parsed.Tag, parsed.DCID, secretIdx)

	// --- Client side: connect with obfuscated2 ---
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial mtproxy: %v", err)
	}
	defer conn.Close()

	// Build the 64-byte obfuscated2 header for the client side
	clientHeader, encStream, decStream := buildClientHeader(t, secret, tag, dcID)

	// Send the header
	if _, err := conn.Write(clientHeader[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	// Build req_pq_multi MTProto message (unencrypted)
	// Format: auth_key_id(8) + message_id(8) + length(4) + constructor(4) + nonce(16) = 40 bytes
	var nonce [16]byte
	rand.Read(nonce[:])

	var mtprotoMsg [40]byte
	// auth_key_id = 0 (unencrypted)
	// message_id = timestamp-based
	msgID := uint64(time.Now().Unix()) << 32
	binary.LittleEndian.PutUint64(mtprotoMsg[8:16], msgID)
	// message_data_length = 20 (constructor + nonce)
	binary.LittleEndian.PutUint32(mtprotoMsg[16:20], 20)
	// req_pq_multi constructor = 0xbe7e8ef1
	binary.LittleEndian.PutUint32(mtprotoMsg[20:24], 0xbe7e8ef1)
	copy(mtprotoMsg[24:40], nonce[:])

	// Wrap in intermediate transport: 4-byte length prefix
	var transportMsg [44]byte
	binary.LittleEndian.PutUint32(transportMsg[0:4], 40)
	copy(transportMsg[4:], mtprotoMsg[:])

	// Encrypt and send
	var encryptedMsg [44]byte
	encStream.XORKeyStream(encryptedMsg[:], transportMsg[:])
	if _, err := conn.Write(encryptedMsg[:]); err != nil {
		t.Fatalf("write req_pq_multi: %v", err)
	}

	// Wait a bit for relay to start
	time.Sleep(100 * time.Millisecond)

	// Read response (should be resPQ)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	responseBuf := make([]byte, 1024)
	n, err := conn.Read(responseBuf)
	if err != nil {
		t.Fatalf("read response: %v (n=%d)", err, n)
	}

	// Decrypt response
	plainResponse := make([]byte, n)
	decStream.XORKeyStream(plainResponse, responseBuf[:n])

	// Parse: first 4 bytes = length (intermediate transport)
	if n < 4 {
		t.Fatalf("response too short: %d bytes", n)
	}
	respLen := binary.LittleEndian.Uint32(plainResponse[0:4])
	t.Logf("response: %d bytes total, transport length=%d", n, respLen)

	// The inner message should have auth_key_id=0 and contain resPQ constructor (0x05162463)
	if n < 24 {
		t.Fatalf("response too short for MTProto: %d bytes", n)
	}
	authKeyID := binary.LittleEndian.Uint64(plainResponse[4:12])
	if authKeyID != 0 {
		t.Fatalf("expected auth_key_id=0, got %d", authKeyID)
	}

	constructor := binary.LittleEndian.Uint32(plainResponse[24:28])
	t.Logf("response constructor: 0x%08x", constructor)
	if constructor != 0x05162463 {
		t.Fatalf("expected resPQ constructor 0x05162463, got 0x%08x", constructor)
	}

	// Verify the nonce matches
	var responseNonce [16]byte
	copy(responseNonce[:], plainResponse[28:44])
	if responseNonce != nonce {
		t.Fatal("response nonce doesn't match request nonce")
	}

	t.Log("SUCCESS: received valid resPQ from Telegram DC")
}

// buildClientHeader creates a 64-byte obfuscated2 header from the client's perspective.
// The key derivation uses the WIRE bytes (same as DecryptHeader on the server side).
// Returns the header to send, the encrypt stream (client->proxy) and decrypt stream (proxy->client).
func buildClientHeader(t *testing.T, secret mpcrypto.Secret, tag uint32, dcID int16) (header [64]byte, encrypt cipher.Stream, decrypt cipher.Stream) {
	t.Helper()

	// Generate random wire bytes for header[0:56]
	for {
		if _, err := io.ReadFull(rand.Reader, header[:56]); err != nil {
			t.Fatal(err)
		}

		first := header[0]
		if first == 0xef || first == 0x48 || first == 0x44 ||
			first == 0x50 || first == 0x47 || first == 0x16 || first == 0x14 {
			continue
		}
		first4 := binary.LittleEndian.Uint32(header[:4])
		if first4 == 0 || first4 == mpcrypto.TagCompact || first4 == mpcrypto.TagMedium || first4 == mpcrypto.TagMediumPadded {
			continue
		}
		break
	}

	// Derive encrypt key from wire bytes: SHA256(header[8:40] + secret)
	var encKeyInput [48]byte
	copy(encKeyInput[:32], header[8:40])
	copy(encKeyInput[32:], secret.Raw[:])
	encKey := sha256.Sum256(encKeyInput[:])
	var encIV [16]byte
	copy(encIV[:], header[40:56])

	encBlock, _ := aes.NewCipher(encKey[:])
	encStream := cipher.NewCTR(encBlock, encIV[:])

	// Advance encrypt stream by 56 bytes to reach tag position
	var skip [56]byte
	encStream.XORKeyStream(skip[:], skip[:])

	// Construct plaintext for positions 56-63: tag(4) + dcID(2) + padding(2)
	var plain [8]byte
	binary.LittleEndian.PutUint32(plain[0:4], tag)
	binary.LittleEndian.PutUint16(plain[4:6], uint16(dcID))
	encStream.XORKeyStream(header[56:], plain[:])
	// encStream is now at position 64, ready for payload

	// Derive decrypt key from wire bytes: SHA256(reverse(header[24:56]) + secret)
	var decKeyInput [48]byte
	for i := 0; i < 32; i++ {
		decKeyInput[i] = header[55-i]
	}
	copy(decKeyInput[32:], secret.Raw[:])
	decKey := sha256.Sum256(decKeyInput[:])
	var decIV [16]byte
	for i := 0; i < 16; i++ {
		decIV[i] = header[23-i]
	}

	decBlock, _ := aes.NewCipher(decKey[:])
	decStream := cipher.NewCTR(decBlock, decIV[:])

	return header, encStream, decStream
}

// TestMTProxyIntegration_Compact tests with TagCompact (abridged transport).
func TestMTProxyIntegration_Compact(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	var secretBytes [16]byte
	rand.Read(secretBytes[:])
	secret := mpcrypto.Secret{Raw: secretBytes}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	endpoints := telegram.NewEndpointManager(nil)
	srv := NewServer(ServerConfig{
		ListenAddrs: []string{"127.0.0.1:0"},
		Secrets:     []mpcrypto.Secret{secret},
	}, &directDialer{}, endpoints, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	t.Logf("MTProxy listening on %s", addr)

	go srv.acceptLoop(ctx, ln)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial mtproxy: %v", err)
	}
	defer conn.Close()

	dcID := int16(2)
	tag := mpcrypto.TagCompact
	clientHeader, encStream, decStream := buildClientHeader(t, secret, tag, dcID)

	if _, err := conn.Write(clientHeader[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	// req_pq_multi = 40 bytes
	var nonce [16]byte
	rand.Read(nonce[:])
	var mtprotoMsg [40]byte
	msgID := uint64(time.Now().Unix()) << 32
	binary.LittleEndian.PutUint64(mtprotoMsg[8:16], msgID)
	binary.LittleEndian.PutUint32(mtprotoMsg[16:20], 20)
	binary.LittleEndian.PutUint32(mtprotoMsg[20:24], 0xbe7e8ef1)
	copy(mtprotoMsg[24:40], nonce[:])

	// Abridged transport: length / 4, if < 0x7f use 1 byte
	wordLen := len(mtprotoMsg) / 4 // 10
	var transportMsg []byte
	if wordLen < 0x7f {
		transportMsg = make([]byte, 1+len(mtprotoMsg))
		transportMsg[0] = byte(wordLen)
		copy(transportMsg[1:], mtprotoMsg[:])
	} else {
		t.Fatal("message too long for simple abridged test")
	}

	encrypted := make([]byte, len(transportMsg))
	encStream.XORKeyStream(encrypted, transportMsg)
	if _, err := conn.Write(encrypted); err != nil {
		t.Fatalf("write req_pq_multi: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	responseBuf := make([]byte, 1024)
	n, err := conn.Read(responseBuf)
	if err != nil {
		t.Fatalf("read response: %v (n=%d)", err, n)
	}

	plainResponse := make([]byte, n)
	decStream.XORKeyStream(plainResponse, responseBuf[:n])

	// Abridged: first byte = word count, then message
	if n < 1 {
		t.Fatal("empty response")
	}
	respWordLen := int(plainResponse[0])
	t.Logf("response: %d bytes, abridged word_len=%d", n, respWordLen)

	// Find constructor in the response
	if n < 25 {
		t.Fatalf("response too short: %d", n)
	}
	// After 1-byte length: auth_key_id(8) + message_id(8) + length(4) + constructor(4)
	constructor := binary.LittleEndian.Uint32(plainResponse[21:25])
	t.Logf("response constructor: 0x%08x", constructor)

	if constructor != 0x05162463 {
		// Dump first bytes for debugging
		t.Logf("response hex: %x", plainResponse[:min(n, 60)])
		t.Fatalf("expected resPQ constructor 0x05162463, got 0x%08x", constructor)
	}

	t.Log("SUCCESS: received valid resPQ via compact transport")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Verify that a wrong secret is rejected.
func TestMTProxyIntegration_WrongSecret(t *testing.T) {
	var secretBytes [16]byte
	rand.Read(secretBytes[:])
	secret := mpcrypto.Secret{Raw: secretBytes}

	var wrongSecretBytes [16]byte
	rand.Read(wrongSecretBytes[:])
	wrongSecret := mpcrypto.Secret{Raw: wrongSecretBytes}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	endpoints := telegram.NewEndpointManager(nil)
	srv := NewServer(ServerConfig{
		ListenAddrs: []string{"127.0.0.1:0"},
		Secrets:     []mpcrypto.Secret{secret},
	}, &directDialer{}, endpoints, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	go srv.acceptLoop(ctx, ln)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Connect with wrong secret
	clientHeader, _, _ := buildClientHeader(t, wrongSecret, mpcrypto.TagMedium, 2)
	if _, err := conn.Write(clientHeader[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	// Server should close the connection (wrong secret = header decryption fails)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed for wrong secret")
	}
	t.Logf("correctly rejected: %v", err)
}
