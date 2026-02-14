package mtproxy

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	mpcrypto "github.com/blikh/wireguard-outline-bridge/internal/mtproxy/crypto"
	"github.com/blikh/wireguard-outline-bridge/internal/mtproxy/telegram"
)

const (
	handshakeTimeout = 10 * time.Second
	maxTLSRecordLen  = 16384
)

// StreamDialer dials a TCP connection (typically through Outline proxy).
type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

// ServerConfig holds MTProxy server configuration.
type ServerConfig struct {
	ListenAddrs []string
	Secrets     []mpcrypto.Secret
	FakeTLS     *FakeTLSConfig
}

// FakeTLSConfig holds fake TLS settings.
type FakeTLSConfig struct {
	AllowedSNIs         []string
	MaxClockSkewSec     int
	ReplayCacheTTLHours int
}

// Stats holds atomic counters for the MTProxy server.
type Stats struct {
	Connections          atomic.Int64 // total connections accepted
	ActiveConnections    atomic.Int64 // currently active connections
	TLSConnections       atomic.Int64 // connections using fake TLS
	HandshakeErrors      atomic.Int64 // failed handshakes (TLS, header, secret mismatch)
	BackendDialErrors    atomic.Int64 // failed backend dials
	BytesClientToBackend atomic.Int64 // bytes relayed client -> backend
	BytesBackendToClient atomic.Int64 // bytes relayed backend -> client
}

// Server is the MTProxy server.
type Server struct {
	config    ServerConfig
	dialer    StreamDialer
	endpoints *telegram.EndpointManager
	logger    *slog.Logger

	listeners []net.Listener
	wg        sync.WaitGroup

	// Stats counters
	stats Stats

	// Replay cache for fake TLS (client_random dedup)
	replayMu    sync.Mutex
	replayCache map[[32]byte]time.Time
}

// NewServer creates a new MTProxy server.
func NewServer(config ServerConfig, dialer StreamDialer, endpoints *telegram.EndpointManager, logger *slog.Logger) *Server {
	return &Server{
		config:      config,
		dialer:      dialer,
		endpoints:   endpoints,
		logger:      logger.With("component", "mtproxy"),
		replayCache: make(map[[32]byte]time.Time),
	}
}

// Start begins listening on all configured addresses. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	for _, addr := range s.config.ListenAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("listening on %s: %w", addr, err)
		}
		s.listeners = append(s.listeners, ln)
		s.logger.Info("listening", "addr", addr)

		s.wg.Add(1)
		go func(ln net.Listener) {
			defer s.wg.Done()
			s.acceptLoop(ctx, ln)
		}(ln)
	}

	if s.config.FakeTLS != nil {
		go s.cleanupReplayCache(ctx)
	}

	<-ctx.Done()
	s.closeListeners()
	s.wg.Wait()
	return nil
}

func (s *Server) closeListeners() {
	for _, ln := range s.listeners {
		ln.Close()
	}
}

// ReplayCacheSize returns the current number of entries in the replay cache.
func (s *Server) ReplayCacheSize() int {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	return len(s.replayCache)
}

// StatsSnapshot returns a point-in-time snapshot of the server stats.
func (s *Server) StatsSnapshot() *Stats {
	snap := &Stats{}
	snap.Connections.Store(s.stats.Connections.Load())
	snap.ActiveConnections.Store(s.stats.ActiveConnections.Load())
	snap.TLSConnections.Store(s.stats.TLSConnections.Load())
	snap.HandshakeErrors.Store(s.stats.HandshakeErrors.Load())
	snap.BackendDialErrors.Store(s.stats.BackendDialErrors.Load())
	snap.BytesClientToBackend.Store(s.stats.BytesClientToBackend.Load())
	snap.BytesBackendToClient.Store(s.stats.BytesBackendToClient.Load())
	return snap
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Error("accept error", "err", err)
				continue
			}
		}
		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	s.stats.Connections.Add(1)
	s.stats.ActiveConnections.Add(1)
	defer s.stats.ActiveConnections.Add(-1)

	remoteAddr := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	// Read initial bytes to detect protocol
	var peekBuf [3]byte
	if _, err := io.ReadFull(conn, peekBuf[:]); err != nil {
		s.stats.HandshakeErrors.Add(1)
		s.logger.Debug("handshake: failed to read initial bytes", "remote", remoteAddr, "err", err)
		return
	}

	var innerConn io.ReadWriter = conn
	var isTLS bool

	// Check for TLS ClientHello: 0x16 0x03 0x01
	if peekBuf[0] == 0x16 && peekBuf[1] == 0x03 && peekBuf[2] == 0x01 {
		if s.config.FakeTLS == nil {
			s.stats.HandshakeErrors.Add(1)
			s.logger.Debug("handshake: TLS not configured, dropping", "remote", remoteAddr)
			return
		}

		// Handle fake TLS handshake
		tlsConn, err := s.handleFakeTLSHandshake(conn, peekBuf[:])
		if err != nil {
			s.stats.HandshakeErrors.Add(1)
			s.logger.Debug("handshake: fake TLS failed", "remote", remoteAddr, "err", err)
			return
		}
		innerConn = tlsConn
		isTLS = true
		s.stats.TLSConnections.Add(1)
	}

	// Read the 64-byte obfuscated header
	var fullHeader [64]byte
	var headerReader io.Reader
	if isTLS {
		headerReader = innerConn
	} else {
		// We already read 3 bytes, prepend them
		copy(fullHeader[:3], peekBuf[:])
		if _, err := io.ReadFull(conn, fullHeader[3:]); err != nil {
			s.stats.HandshakeErrors.Add(1)
			s.logger.Debug("handshake: failed to read obfuscated header", "remote", remoteAddr, "err", err)
			return
		}
		headerReader = nil // already have the full header
	}

	if headerReader != nil {
		if _, err := io.ReadFull(headerReader, fullHeader[:]); err != nil {
			s.stats.HandshakeErrors.Add(1)
			s.logger.Debug("handshake: failed to read obfuscated header from TLS", "remote", remoteAddr, "err", err)
			return
		}
	}

	// Decrypt header with configured secrets
	parsed, err := mpcrypto.DecryptHeader(fullHeader, s.config.Secrets)
	if err != nil {
		s.stats.HandshakeErrors.Add(1)
		s.logger.Debug("handshake: header decryption failed", "remote", remoteAddr, "err", err)
		return
	}

	conn.SetDeadline(time.Time{}) // clear handshake deadline

	dcID := int(parsed.DCID)
	backendAddr, err := s.endpoints.Resolve(dcID)
	if err != nil {
		s.stats.HandshakeErrors.Add(1)
		s.logger.Warn("no backend for DC", "dc_id", dcID, "remote", remoteAddr)
		return
	}

	s.logger.Debug("connection established",
		"remote", remoteAddr,
		"dc_id", dcID,
		"tag", fmt.Sprintf("%08x", parsed.Tag),
		"backend", backendAddr,
		"tls", isTLS,
	)

	// Dial backend via Outline
	backendConn, err := s.dialer.DialStream(ctx, backendAddr)
	if err != nil {
		s.stats.BackendDialErrors.Add(1)
		s.logger.Error("failed to dial backend", "backend", backendAddr, "dc_id", dcID, "err", err)
		return
	}
	defer backendConn.Close()

	// Bidirectional relay with AES-CTR encryption/decryption
	// Client -> Backend: decrypt with parsed.Decrypt
	// Backend -> Client: encrypt with parsed.Encrypt
	var relayWg sync.WaitGroup
	relayWg.Add(2)

	// Determine the actual reader/writer for the client side
	var clientReader io.Reader
	var clientWriter io.Writer
	if isTLS {
		clientReader = innerConn
		clientWriter = innerConn
	} else {
		clientReader = conn
		clientWriter = conn
	}

	// Client -> Backend (decrypt incoming)
	go func() {
		defer relayWg.Done()
		sr := &cipher.StreamReader{S: parsed.Decrypt, R: clientReader}
		n, err := io.Copy(backendConn, sr)
		s.stats.BytesClientToBackend.Add(n)
		if err != nil {
			s.logger.Debug("relay: client->backend done", "remote", remoteAddr, "err", err)
		}
	}()

	// Backend -> Client (encrypt outgoing)
	go func() {
		defer relayWg.Done()
		sw := &cipher.StreamWriter{S: parsed.Encrypt, W: clientWriter}
		n, err := io.Copy(sw, backendConn)
		s.stats.BytesBackendToClient.Add(n)
		if err != nil {
			s.logger.Debug("relay: backend->client done", "remote", remoteAddr, "err", err)
		}
	}()

	relayWg.Wait()
	s.logger.Debug("connection closed", "remote", remoteAddr, "dc_id", dcID)
}

// handleFakeTLSHandshake processes the TLS ClientHello and sends ServerHello.
// Returns a wrapper that handles TLS record framing for the inner connection.
// The peeked bytes (first 3 bytes of the record header) are passed in.
func (s *Server) handleFakeTLSHandshake(conn net.Conn, peeked []byte) (*tlsFramedConn, error) {
	// Read remaining 2 bytes of TLS record header (length)
	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return nil, fmt.Errorf("reading TLS record length: %w", err)
	}
	recordLen := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if recordLen < 39 || recordLen > maxTLSRecordLen {
		return nil, fmt.Errorf("invalid ClientHello length: %d", recordLen)
	}

	// Read the full ClientHello
	clientHello := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, clientHello); err != nil {
		return nil, fmt.Errorf("reading ClientHello: %w", err)
	}

	// Full record for HMAC validation: 5-byte header + body
	fullRecord := make([]byte, 5+recordLen)
	copy(fullRecord[:3], peeked)
	copy(fullRecord[3:5], lengthBuf[:])
	copy(fullRecord[5:], clientHello)

	// Extract client_random from ClientHello
	// In clientHello: handshake_type(1) + length(3) + version(2) + random(32) starts at offset 6
	if len(clientHello) < 38 {
		return nil, fmt.Errorf("ClientHello too short")
	}
	var clientRandom [32]byte
	copy(clientRandom[:], clientHello[6:38])

	// Zero out client_random in the full record for HMAC validation
	fullRecordForHMAC := make([]byte, len(fullRecord))
	copy(fullRecordForHMAC, fullRecord)
	for i := 0; i < 32; i++ {
		fullRecordForHMAC[11+i] = 0
	}

	// Try each secret for HMAC validation
	matchedSecretIdx := -1
	var expectedRandom [32]byte
	for i, secret := range s.config.Secrets {
		mac := hmac.New(sha256.New, secret.Raw[:])
		mac.Write(fullRecordForHMAC)
		computed := mac.Sum(nil)
		copy(expectedRandom[:], computed[:32])

		if hmac.Equal(expectedRandom[:28], clientRandom[:28]) {
			matchedSecretIdx = i
			break
		}
	}

	if matchedSecretIdx < 0 {
		return nil, fmt.Errorf("no secret matched client_random HMAC")
	}

	// Check replay
	if s.hasClientRandom(clientRandom) {
		return nil, fmt.Errorf("replayed client_random")
	}
	s.addClientRandom(clientRandom)

	// Validate timestamp: XOR of expected_random[28:32] with client_random[28:32]
	timestampBytes := binary.LittleEndian.Uint32(expectedRandom[28:32]) ^ binary.LittleEndian.Uint32(clientRandom[28:32])
	timestamp := int64(timestampBytes)
	nowUnix := time.Now().Unix()
	maxSkew := int64(600) // 10 minutes default
	if s.config.FakeTLS != nil && s.config.FakeTLS.MaxClockSkewSec > 0 {
		maxSkew = int64(s.config.FakeTLS.MaxClockSkewSec)
	}
	if timestamp > nowUnix+3 || timestamp < nowUnix-maxSkew {
		return nil, fmt.Errorf("timestamp out of range: %d (now: %d)", timestamp, nowUnix)
	}

	// Extract cipher suite ID from ClientHello for ServerHello
	cipherSuiteID := byte(0x01) // default TLS_AES_128_GCM_SHA256
	if len(clientHello) > 43 {
		offset := 38 // after handshake header(4) + version(2) + random(32)
		if offset < len(clientHello) {
			sessionIDLen := int(clientHello[offset])
			offset += 1 + sessionIDLen
			if offset+2 <= len(clientHello) {
				csLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
				offset += 2
				for i := 0; i+1 < csLen && offset+i+1 < len(clientHello); i += 2 {
					if clientHello[offset+i] == 0x13 && clientHello[offset+i+1] >= 0x01 && clientHello[offset+i+1] <= 0x03 {
						cipherSuiteID = clientHello[offset+i+1]
						break
					}
				}
			}
		}
	}

	// Copy session ID from ClientHello
	var sessionID [32]byte
	if len(clientHello) >= 71 {
		copy(sessionID[:], clientHello[39:71])
	}

	encryptedSize := 2500 + int(randByte())%200
	responseSize := 127 + 6 + 5 + encryptedSize

	// Build response buffer: 32 bytes client_random prefix + response
	buffer := make([]byte, 32+responseSize)
	copy(buffer[:32], clientRandom[:])

	resp := buffer[32:]
	// ServerHello record header
	copy(resp, []byte{0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03})
	// Server random at resp[11:43] will be filled by HMAC below
	resp[43] = 0x20 // session ID length
	copy(resp[44:76], sessionID[:])
	copy(resp[76:81], []byte{0x13, cipherSuiteID, 0x00, 0x00, 0x2e})

	// Extensions: key_share (0x33) and supported_versions (0x2b)
	pos := 81
	copy(resp[pos:], []byte{0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20})
	pos += 8
	rand.Read(resp[pos : pos+32])
	pos += 32
	copy(resp[pos:], []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	pos += 6

	// Change Cipher Spec + encrypted data header
	copy(resp[pos:], []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03})
	pos += 9
	resp[pos] = byte(encryptedSize >> 8)
	resp[pos+1] = byte(encryptedSize & 0xFF)
	pos += 2
	rand.Read(resp[pos : pos+encryptedSize])

	// Compute server_random via HMAC-SHA256(secret, client_random + entire response)
	secret := s.config.Secrets[matchedSecretIdx]
	mac := hmac.New(sha256.New, secret.Raw[:])
	mac.Write(buffer[:32+responseSize])
	serverRandom := mac.Sum(nil)
	copy(resp[11:43], serverRandom[:32])

	// Send ServerHello
	if _, err := conn.Write(resp[:responseSize]); err != nil {
		return nil, fmt.Errorf("writing ServerHello: %w", err)
	}

	// Read client's dummy ChangeCipherSpec + first Application Data header
	var ccsBuf [11]byte
	if _, err := io.ReadFull(conn, ccsBuf[:]); err != nil {
		return nil, fmt.Errorf("reading ChangeCipherSpec: %w", err)
	}
	if string(ccsBuf[:9]) != "\x14\x03\x03\x00\x01\x01\x17\x03\x03" {
		return nil, fmt.Errorf("invalid ChangeCipherSpec")
	}

	firstRecordLen := int(ccsBuf[9])<<8 | int(ccsBuf[10])
	if firstRecordLen < 64 {
		return nil, fmt.Errorf("first TLS record too short: %d", firstRecordLen)
	}

	return newTLSFramedConn(conn, firstRecordLen), nil
}

func randByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

// tlsFramedConn wraps a net.Conn with TLS Application Data record framing.
// Reads unwrap TLS records, writes wrap in TLS records.
type tlsFramedConn struct {
	conn           net.Conn
	readBuf        []byte
	firstRecordLen int
	firstRecord    bool
}

func newTLSFramedConn(conn net.Conn, firstRecordLen int) *tlsFramedConn {
	return &tlsFramedConn{
		conn:           conn,
		firstRecordLen: firstRecordLen,
		firstRecord:    true,
	}
}

func (t *tlsFramedConn) Read(p []byte) (int, error) {
	for {
		// Return buffered data
		if len(t.readBuf) > 0 {
			n := copy(p, t.readBuf)
			t.readBuf = t.readBuf[n:]
			return n, nil
		}

		// Read next TLS record
		var recordLen int
		if t.firstRecord {
			recordLen = t.firstRecordLen
			t.firstRecord = false
		} else {
			var header [5]byte
			if _, err := io.ReadFull(t.conn, header[:]); err != nil {
				return 0, err
			}
			if header[0] != 0x17 {
				return 0, fmt.Errorf("unexpected TLS record type: %d", header[0])
			}
			recordLen = int(binary.BigEndian.Uint16(header[3:5]))
		}

		if recordLen <= 0 || recordLen > maxTLSRecordLen+256 {
			return 0, fmt.Errorf("invalid TLS record length: %d", recordLen)
		}

		buf := make([]byte, recordLen)
		if _, err := io.ReadFull(t.conn, buf); err != nil {
			return 0, err
		}
		t.readBuf = buf
	}
}

func (t *tlsFramedConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxTLSRecordLen {
			chunk = p[:maxTLSRecordLen]
		}
		p = p[len(chunk):]

		var header [5]byte
		header[0] = 0x17 // Application Data
		header[1] = 0x03
		header[2] = 0x03
		binary.BigEndian.PutUint16(header[3:5], uint16(len(chunk)))

		if _, err := t.conn.Write(header[:]); err != nil {
			return total, err
		}
		n, err := t.conn.Write(chunk)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Replay cache methods
func (s *Server) hasClientRandom(random [32]byte) bool {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	_, exists := s.replayCache[random]
	return exists
}

func (s *Server) addClientRandom(random [32]byte) {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	s.replayCache[random] = time.Now()
}

func (s *Server) cleanupReplayCache(ctx context.Context) {
	ttl := 48 * time.Hour
	if s.config.FakeTLS != nil && s.config.FakeTLS.ReplayCacheTTLHours > 0 {
		ttl = time.Duration(s.config.FakeTLS.ReplayCacheTTLHours) * time.Hour
	}
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.replayMu.Lock()
			cutoff := time.Now().Add(-ttl)
			for k, t := range s.replayCache {
				if t.Before(cutoff) {
					delete(s.replayCache, k)
				}
			}
			s.replayMu.Unlock()
		}
	}
}
