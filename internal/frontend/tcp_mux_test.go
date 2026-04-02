package frontend

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"

	mpcrypto "github.com/bigbes/wireguard-outline-bridge/internal/proxy/mtproxy/crypto"
)

// buildFakeClientHello builds a minimal TLS ClientHello record.
// The client_random field is 32 zero bytes by default.
func buildFakeClientHello() []byte {
	// ClientHello body:
	//   handshake_type(1) = 0x01
	//   length(3)
	//   client_version(2) = 0x03 0x03
	//   client_random(32)
	//   session_id_length(1) = 0
	//   cipher_suites_length(2) = 2
	//   cipher_suite(2) = 0x13 0x01
	//   compression_methods_length(1) = 1
	//   compression_method(1) = 0
	body := make([]byte, 45)
	body[0] = 0x01 // handshake type: ClientHello
	// length = 41 (body[1:4])
	body[1] = 0
	body[2] = 0
	body[3] = 41
	// version
	body[4] = 0x03
	body[5] = 0x03
	// client_random at body[6:38] — leave as zeros for now
	// session_id_length = 0
	body[38] = 0
	// cipher suites length = 2
	body[39] = 0
	body[40] = 2
	// cipher suite TLS_AES_128_GCM_SHA256
	body[41] = 0x13
	body[42] = 0x01
	// compression methods length = 1, null compression
	body[43] = 1
	body[44] = 0x00

	// Wrap in TLS record header.
	record := make([]byte, 5+len(body))
	record[0] = 0x16 // handshake
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(body)))
	copy(record[5:], body)
	return record
}

// signClientHello creates an MTProxy-style HMAC in the client_random.
func signClientHello(record []byte, secret mpcrypto.Secret) []byte {
	signed := make([]byte, len(record))
	copy(signed, record)

	// Zero client_random for HMAC input.
	forHMAC := make([]byte, len(signed))
	copy(forHMAC, signed)
	for i := range 32 {
		forHMAC[11+i] = 0
	}

	mac := hmac.New(sha256.New, secret.Raw[:])
	mac.Write(forHMAC)
	computed := mac.Sum(nil)

	// Write first 28 bytes of HMAC into client_random (bytes 11-42 of record).
	copy(signed[11:39], computed[:28])
	// Last 4 bytes of client_random would be timestamp XOR, leave as-is for detection.
	return signed
}

func newTestTCPMux(secret *mpcrypto.Secret) *TCPMux {
	m := &TCPMux{
		logger:    slog.Default(),
		tlsConnCh: make(chan net.Conn, 64),
	}
	if secret != nil {
		secrets := []mpcrypto.Secret{*secret}
		m.secretGet = func() ([]mpcrypto.Secret, []string) {
			return secrets, []string{"aabbccdd"}
		}
		m.mtHandler = &noopMTHandler{}
	}
	return m
}

type noopMTHandler struct{}

func (h *noopMTHandler) HandleConn(_ context.Context, _ net.Conn) {}

func TestIsMTProxyClientHello_ValidHMAC(t *testing.T) {
	var secretBytes [16]byte
	rand.Read(secretBytes[:])
	secret := mpcrypto.Secret{Raw: secretBytes}

	m := newTestTCPMux(&secret)

	record := buildFakeClientHello()
	signed := signClientHello(record, secret)

	clientHello := signed[5:]
	if !m.isMTProxyClientHello(signed, clientHello) {
		t.Fatal("expected valid HMAC to be detected as MTProxy")
	}
}

func TestIsMTProxyClientHello_WrongSecret(t *testing.T) {
	var secretBytes [16]byte
	rand.Read(secretBytes[:])
	secret := mpcrypto.Secret{Raw: secretBytes}

	var wrongBytes [16]byte
	rand.Read(wrongBytes[:])
	wrongSecret := mpcrypto.Secret{Raw: wrongBytes}

	m := newTestTCPMux(&secret)

	record := buildFakeClientHello()
	signed := signClientHello(record, wrongSecret)

	clientHello := signed[5:]
	if m.isMTProxyClientHello(signed, clientHello) {
		t.Fatal("wrong secret should NOT be detected as MTProxy")
	}
}

func TestIsMTProxyClientHello_NormalBrowserClientHello(t *testing.T) {
	var secretBytes [16]byte
	rand.Read(secretBytes[:])
	secret := mpcrypto.Secret{Raw: secretBytes}

	m := newTestTCPMux(&secret)

	// A normal browser ClientHello has random bytes in client_random — no HMAC.
	record := buildFakeClientHello()
	rand.Read(record[11:43]) // randomize client_random

	clientHello := record[5:]
	if m.isMTProxyClientHello(record, clientHello) {
		t.Fatal("random client_random should NOT match MTProxy HMAC")
	}
}

func TestIsMTProxyClientHello_TruncatedClientHello(t *testing.T) {
	var secretBytes [16]byte
	rand.Read(secretBytes[:])
	secret := mpcrypto.Secret{Raw: secretBytes}

	m := newTestTCPMux(&secret)

	// ClientHello body shorter than 38 bytes.
	shortBody := make([]byte, 20)
	shortBody[0] = 0x01
	record := make([]byte, 5+len(shortBody))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(shortBody)))
	copy(record[5:], shortBody)

	if m.isMTProxyClientHello(record, shortBody) {
		t.Fatal("truncated ClientHello should not match")
	}
}

func TestIsMTProxyClientHello_NoSecrets(t *testing.T) {
	m := newTestTCPMux(nil) // no secrets configured
	m.secretGet = func() ([]mpcrypto.Secret, []string) {
		return nil, nil
	}

	record := buildFakeClientHello()
	clientHello := record[5:]
	if m.isMTProxyClientHello(record, clientHello) {
		t.Fatal("no secrets should never match")
	}
}

func TestIsMTProxyClientHello_MultipleSecrets(t *testing.T) {
	var s1Bytes, s2Bytes, s3Bytes [16]byte
	rand.Read(s1Bytes[:])
	rand.Read(s2Bytes[:])
	rand.Read(s3Bytes[:])
	s1 := mpcrypto.Secret{Raw: s1Bytes}
	s2 := mpcrypto.Secret{Raw: s2Bytes}
	s3 := mpcrypto.Secret{Raw: s3Bytes}

	m := &TCPMux{
		logger:    slog.Default(),
		tlsConnCh: make(chan net.Conn, 64),
		secretGet: func() ([]mpcrypto.Secret, []string) {
			return []mpcrypto.Secret{s1, s2, s3}, []string{"s1", "s2", "s3"}
		},
	}

	// Sign with s2 (second secret).
	record := buildFakeClientHello()
	signed := signClientHello(record, s2)

	if !m.isMTProxyClientHello(signed, signed[5:]) {
		t.Fatal("should match second secret")
	}

	// Sign with s3 (third secret).
	signed3 := signClientHello(record, s3)
	if !m.isMTProxyClientHello(signed3, signed3[5:]) {
		t.Fatal("should match third secret")
	}
}

func TestPrefixConn_Read(t *testing.T) {
	// Create a pipe to simulate a connection.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	prefix := []byte("hello, ")
	pc := newPrefixConn(serverConn, prefix)

	// Write the rest from the client side.
	go func() {
		clientConn.Write([]byte("world!"))
		clientConn.Close()
	}()

	// Read everything from the prefixed connection.
	all, err := io.ReadAll(pc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(all, []byte("hello, world!")) {
		t.Fatalf("got %q, want %q", all, "hello, world!")
	}
}

func TestPrefixConn_SmallReads(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	prefix := []byte("abcdef")
	pc := newPrefixConn(serverConn, prefix)

	go func() {
		clientConn.Write([]byte("ghij"))
		clientConn.Close()
	}()

	// Read 3 bytes at a time.
	var result []byte
	buf := make([]byte, 3)
	for {
		n, err := pc.Read(buf)
		result = append(result, buf[:n]...)
		if err != nil {
			break
		}
	}
	if !bytes.Equal(result, []byte("abcdefghij")) {
		t.Fatalf("got %q, want %q", result, "abcdefghij")
	}
}
