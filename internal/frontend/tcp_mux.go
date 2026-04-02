package frontend

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

	mpcrypto "github.com/bigbes/wireguard-outline-bridge/internal/proxy/mtproxy/crypto"
)

// MTProxyHandler handles connections routed to the MTProxy server.
type MTProxyHandler interface {
	HandleConn(ctx context.Context, conn net.Conn)
}

// SecretGetter returns the current MTProxy secrets.
type SecretGetter func() ([]mpcrypto.Secret, []string)

// TCPMux multiplexes TCP connections on a shared listener.
// It peeks at the TLS ClientHello to detect MTProxy fake-TLS connections
// (via HMAC in client_random) and routes them accordingly. All other TLS
// connections are terminated with a real TLS stack and served as HTTP/2.
type TCPMux struct {
	listener    net.Listener
	tlsConfig   *tls.Config
	httpHandler http.Handler
	mtHandler   MTProxyHandler
	secretGet   SecretGetter
	logger      *slog.Logger
	wg          sync.WaitGroup
	tlsConnCh   chan net.Conn
}

// NewTCPMux creates a new TCP multiplexer.
func NewTCPMux(ln net.Listener, tlsCfg *tls.Config, httpHandler http.Handler, logger *slog.Logger) *TCPMux {
	return &TCPMux{
		listener:    ln,
		tlsConfig:   tlsCfg,
		httpHandler: httpHandler,
		logger:      logger.With("component", "tcp-mux"),
		tlsConnCh:   make(chan net.Conn, 64),
	}
}

// SetMTProxy configures MTProxy routing.
func (m *TCPMux) SetMTProxy(handler MTProxyHandler, secretGet SecretGetter) {
	m.mtHandler = handler
	m.secretGet = secretGet
}

// Serve accepts connections and routes them. Blocks until ctx is cancelled.
func (m *TCPMux) Serve(ctx context.Context) {
	// The HTTP server reads from a channel-based listener that receives
	// connections after TLS termination for non-MTProxy traffic.
	chListener := &chanListener{ch: m.tlsConnCh, addr: m.listener.Addr()}
	httpSrv := &http.Server{
		Handler:  m.httpHandler,
		ErrorLog: slog.NewLogLogger(m.logger.Handler(), slog.LevelDebug),
	}

	go func() {
		if err := httpSrv.Serve(chListener); err != nil && err != http.ErrServerClosed {
			m.logger.Error("http server error", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		m.listener.Close()
		close(m.tlsConnCh)
		httpSrv.Close()
	}()

	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			m.logger.Error("accept error", "err", err)
			continue
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handleConn(ctx, conn)
		}()
	}

	m.wg.Wait()
}

// Close closes the underlying listener.
func (m *TCPMux) Close() error {
	return m.listener.Close()
}

func (m *TCPMux) handleConn(ctx context.Context, conn net.Conn) {
	// Peek at initial bytes to detect TLS ClientHello.
	// We need the full ClientHello to check the HMAC in client_random.
	// TLS record header: type(1) + version(2) + length(2) = 5 bytes.
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		conn.Close()
		return
	}

	// Check for TLS ClientHello: 0x16 (handshake), 0x03 0x01 (TLS 1.0 compat)
	isTLS := header[0] == 0x16 && header[1] == 0x03 && header[2] == 0x01
	if !isTLS {
		// Not TLS — close immediately. We only serve TLS on port 443.
		conn.Close()
		return
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen < 39 || recordLen > 16384 {
		conn.Close()
		return
	}

	// Read the full ClientHello body.
	clientHello := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, clientHello); err != nil {
		conn.Close()
		return
	}

	// Build full record for HMAC validation.
	fullRecord := make([]byte, 5+recordLen)
	copy(fullRecord[:5], header[:])
	copy(fullRecord[5:], clientHello)

	// Check if this is an MTProxy connection by verifying the HMAC in client_random.
	if m.mtHandler != nil && m.secretGet != nil && m.isMTProxyClientHello(fullRecord, clientHello) {
		// This is MTProxy — hand the connection (with peeked bytes replayed) to the MTProxy server.
		pc := newPrefixConn(conn, fullRecord)
		m.mtHandler.HandleConn(ctx, pc)
		return
	}

	// Normal TLS — wrap with prefix, hand to the HTTP server via the channel listener.
	pc := newPrefixConn(conn, fullRecord)
	tlsConn := tls.Server(pc, m.tlsConfig)
	m.tlsConnCh <- tlsConn
}

// isMTProxyClientHello checks whether the ClientHello's client_random contains
// a valid HMAC for any of the configured MTProxy secrets.
func (m *TCPMux) isMTProxyClientHello(fullRecord, clientHello []byte) bool {
	// client_random is at offset 6 in the ClientHello body (handshake_type(1) + length(3) + version(2)).
	if len(clientHello) < 38 {
		return false
	}
	var clientRandom [32]byte
	copy(clientRandom[:], clientHello[6:38])

	// Zero out client_random in copy for HMAC computation.
	fullRecordForHMAC := make([]byte, len(fullRecord))
	copy(fullRecordForHMAC, fullRecord)
	for i := range 32 {
		fullRecordForHMAC[11+i] = 0 // offset 5 (header) + 6 (to random)
	}

	secrets, _ := m.secretGet()
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, secret.Raw[:])
		mac.Write(fullRecordForHMAC)
		computed := mac.Sum(nil)

		// Compare first 28 bytes (last 4 are timestamp XOR).
		if hmac.Equal(computed[:28], clientRandom[:28]) {
			return true
		}
	}
	return false
}

// prefixConn replays peeked bytes before reading from the real connection.
type prefixConn struct {
	net.Conn
	prefix []byte
	offset int
}

func newPrefixConn(conn net.Conn, prefix []byte) *prefixConn {
	return &prefixConn{Conn: conn, prefix: prefix}
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.offset < len(c.prefix) {
		n := copy(p, c.prefix[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// chanListener is a net.Listener backed by a channel of connections.
type chanListener struct {
	ch   <-chan net.Conn
	addr net.Addr
}

func (l *chanListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }
