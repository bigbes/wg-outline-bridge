// Package proxyserver implements SOCKS5, HTTP, and HTTPS forward proxy servers
// that route outbound connections through an Outline (Shadowsocks) proxy.
package proxyserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	httpproxy "github.com/bigbes/wireguard-outline-bridge/internal/proxy/http"
	socks6 "github.com/bigbes/wireguard-outline-bridge/internal/proxy/socks5"
)

// StreamDialer dials a TCP connection (typically through an Outline proxy).
type StreamDialer = httpproxy.StreamDialer

// ServerConfig holds the configuration for a single proxy server instance.
type ServerConfig struct {
	Name     string
	Type     string // "socks5", "http", "https"
	Listen   string
	Username string
	Password string

	// DNSAddr, when set, makes the SOCKS5 resolver use the onboard DNS
	// proxy instead of the system resolver. Format: "host:port".
	DNSAddr string

	// TLS settings (https only)
	CertFile  string
	KeyFile   string
	Domain    string
	ACMEEmail string
	ACMEDir   string // cache directory for ACME certs
}

// Server is a proxy server instance (SOCKS5, HTTP, or HTTPS).
type Server struct {
	config   ServerConfig
	dialer   StreamDialer
	logger   *slog.Logger
	listener net.Listener
	wg       sync.WaitGroup
}

// NewServer creates a new proxy server.
func NewServer(config ServerConfig, dialer StreamDialer, logger *slog.Logger) *Server {
	return &Server{
		config: config,
		dialer: dialer,
		logger: logger.With("component", "proxyserver", "name", config.Name, "type", config.Type),
	}
}

// Listen binds the server to its configured address.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.config.Listen, err)
	}

	if s.config.Type == "https" {
		tlsCfg, err := s.buildTLSConfig()
		if err != nil {
			ln.Close()
			return fmt.Errorf("configuring TLS: %w", err)
		}
		ln = tls.NewListener(ln, tlsCfg)
	}

	s.listener = ln
	s.logger.Info("listening", "addr", s.config.Listen)
	return nil
}

// Serve starts accepting connections. Blocks until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) {
	switch s.config.Type {
	case "socks5":
		s.serveSOCKS5(ctx)
	case "http", "https":
		s.serveHTTP(ctx)
	}
}

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if s.config.Domain != "" {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.config.Domain),
			Email:      s.config.ACMEEmail,
		}
		if s.config.ACMEDir != "" {
			m.Cache = autocert.DirCache(s.config.ACMEDir)
		}
		return m.TLSConfig(), nil
	}

	if s.config.CertFile != "" && s.config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert/key: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	}

	return nil, fmt.Errorf("https proxy requires either domain (ACME) or cert_file+key_file")
}

// --- SOCKS5 ---

func (s *Server) serveSOCKS5(ctx context.Context) {
	conf := &socks6.Config{
		Dial:   s.dialForSOCKS5,
		Logger: log.New(io.Discard, "", 0),
	}

	if s.config.DNSAddr != "" {
		conf.Resolver = &onboardDNSResolver{addr: s.config.DNSAddr}
	}

	if s.config.Username != "" {
		conf.Credentials = socks6.StaticCredentials{
			s.config.Username: s.config.Password,
		}
	}

	srv, err := socks6.New(conf)
	if err != nil {
		s.logger.Error("failed to create socks5 server", "err", err)
		return
	}

	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	s.logger.Info("serving socks5")
	if err := srv.Serve(s.listener); err != nil && ctx.Err() == nil {
		if !errors.Is(err, net.ErrClosed) {
			s.logger.Error("socks5 serve error", "err", err)
		}
	}
}

func (s *Server) dialForSOCKS5(ctx context.Context, network, addr string) (net.Conn, error) {
	s.logger.Debug("socks5: dialing", "addr", addr)
	return s.dialer.DialStream(ctx, addr)
}

// --- HTTP/HTTPS forward proxy ---

func (s *Server) serveHTTP(ctx context.Context) {
	handler := httpproxy.NewHandler(s.dialer, s.config.Username, s.config.Password, s.logger)

	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutCtx)
	}()

	s.logger.Info("serving http proxy")
	if err := httpSrv.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("http proxy serve error", "err", err)
	}
}

// onboardDNSResolver resolves names via the built-in DNS proxy server.
type onboardDNSResolver struct {
	addr string // "host:port" of the onboard DNS server
}

func (r *onboardDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", r.addr)
		},
	}
	addrs, err := resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	if len(addrs) == 0 {
		return ctx, nil, fmt.Errorf("no addresses found for %s", name)
	}
	return ctx, addrs[0].IP, nil
}
