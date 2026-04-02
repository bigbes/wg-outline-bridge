package frontend

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/quic-go/quic-go/http3"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

// Frontend is the all-in-one port-443 multiplexer that consolidates
// AWG (UDP), MTProxy fake-TLS (TCP), real TLS/HTTP2 (TCP), and
// QUIC/HTTP3 (UDP) behind a single IP:port pair.
type Frontend struct {
	cfg     config.FrontendConfig
	acmeDir string
	logger  *slog.Logger

	// Set before Init.
	mtHandler MTProxyHandler
	secretGet SecretGetter

	// Set before Serve.
	miniAppHandler http.Handler

	// Created during Init.
	udpMux  *UDPMux
	tcpMux  *TCPMux
	udpConn net.PacketConn
	tcpLn   net.Listener
}

// New creates a new Frontend.
func New(cfg config.FrontendConfig, acmeDir string, logger *slog.Logger) *Frontend {
	return &Frontend{
		cfg:     cfg,
		acmeDir: acmeDir,
		logger:  logger.With("component", "frontend"),
	}
}

// SetMTProxy configures MTProxy connection handling.
func (f *Frontend) SetMTProxy(handler MTProxyHandler, secretGet SecretGetter) {
	f.mtHandler = handler
	f.secretGet = secretGet
}

// Init binds the TCP and UDP sockets and creates the multiplexers.
// After Init, Bind() can be called to get the WireGuard bind.
// Call Serve to start accepting connections.
func (f *Frontend) Init() error {
	// Bind TCP listener.
	tcpLn, err := net.Listen("tcp", f.cfg.Listen)
	if err != nil {
		return fmt.Errorf("frontend tcp listen: %w", err)
	}
	f.tcpLn = tcpLn

	// Bind UDP socket.
	udpAddr, err := net.ResolveUDPAddr("udp", f.cfg.Listen)
	if err != nil {
		tcpLn.Close()
		return fmt.Errorf("frontend udp resolve: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tcpLn.Close()
		return fmt.Errorf("frontend udp listen: %w", err)
	}
	f.udpConn = udpConn

	// Create UDP mux (doesn't start reading yet — Run does that).
	f.udpMux = NewUDPMux(udpConn, f.logger)

	f.logger.Info("frontend initialized", "listen", f.cfg.Listen)
	return nil
}

// SetMiniApp sets the handler for the mini app, mounted at /app/.
// Must be called before Serve.
func (f *Frontend) SetMiniApp(handler http.Handler) {
	f.miniAppHandler = handler
}

// Bind returns an AmneziaWG Bind that reads from the UDP mux's
// AWG channel and writes to the shared UDP socket.
// Must be called after Init.
func (f *Frontend) Bind() any {
	return NewAWGBind(f.udpMux.AWGChannel(), f.udpConn)
}

// Serve starts the multiplexers and servers. Blocks until ctx is cancelled.
// Init must be called first.
func (f *Frontend) Serve(ctx context.Context) error {
	tlsCfg, err := buildTLSConfig(f.cfg, f.acmeDir)
	if err != nil {
		return fmt.Errorf("frontend tls: %w", err)
	}

	// Compose handler: miniapp at /app/, static files as fallback.
	mux := http.NewServeMux()
	if f.miniAppHandler != nil {
		mux.Handle("/app/", http.StripPrefix("/app", f.miniAppHandler))
	}
	mux.Handle("/", newHTTPHandler(f.cfg.StaticDir))
	httpHandler := http.Handler(mux)

	// Start UDP mux read loop.
	go f.udpMux.Run()

	// Start QUIC/HTTP3 server on the muxed QUIC channel.
	quicConn := NewMuxedPacketConn(f.udpMux.QUICChannel(), f.udpConn)
	h3TLSCfg := http3.ConfigureTLSConfig(tlsCfg.Clone())
	h3Server := &http3.Server{
		TLSConfig: h3TLSCfg,
		Handler:   httpHandler,
	}
	go func() {
		if err := h3Server.Serve(quicConn); err != nil && ctx.Err() == nil {
			f.logger.Error("http3 server error", "err", err)
		}
	}()

	// Add Alt-Svc header so browsers discover HTTP/3.
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3="%s"; ma=86400`, f.cfg.Listen))
		httpHandler.ServeHTTP(w, r)
	})

	// Start TCP mux with real TLS for non-MTProxy connections.
	tcpTLSCfg := tlsCfg.Clone()
	f.tcpMux = NewTCPMux(f.tcpLn, tcpTLSCfg, wrappedHandler, f.logger)
	if f.mtHandler != nil && f.secretGet != nil {
		f.tcpMux.SetMTProxy(f.mtHandler, f.secretGet)
	}

	f.logger.Info("frontend serving",
		"listen", f.cfg.Listen,
		"domain", f.cfg.Domain,
		"static_dir", f.cfg.StaticDir,
	)

	go func() {
		<-ctx.Done()
		f.udpMux.Close()
		quicConn.Close()
		h3Server.Close()
		f.tcpLn.Close()
		f.udpConn.Close()
	}()

	// Serve TCP mux (blocks until ctx done).
	f.tcpMux.Serve(ctx)
	return nil
}
