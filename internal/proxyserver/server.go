// Package proxyserver implements SOCKS5, HTTP, and HTTPS forward proxy servers
// that route outbound connections through an Outline (Shadowsocks) proxy.
package proxyserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/bigbes/wireguard-outline-bridge/internal/socks5"
)

const connectIdleTimeout = 5 * time.Minute

// StreamDialer dials a TCP connection (typically through an Outline proxy).
type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

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
	conf := &socks5.Config{
		Dial:   s.dialForSOCKS5,
		Logger: log.New(io.Discard, "", 0),
	}

	if s.config.DNSAddr != "" {
		conf.Resolver = &onboardDNSResolver{addr: s.config.DNSAddr}
	}

	if s.config.Username != "" {
		conf.Credentials = socks5.StaticCredentials{
			s.config.Username: s.config.Password,
		}
	}

	srv, err := socks5.New(conf)
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
	handler := &httpProxyHandler{
		dialer:   s.dialer,
		logger:   s.logger,
		username: s.config.Username,
		password: s.config.Password,
	}

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

type httpProxyHandler struct {
	dialer   StreamDialer
	logger   *slog.Logger
	username string
	password string
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.username != "" {
		if !h.checkAuth(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

func (h *httpProxyHandler) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}

	user, pass, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}

	return user == h.username && pass == h.password
}

// handleConnect implements the HTTP CONNECT method for HTTPS tunneling.
func (h *httpProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("http: CONNECT", "dest", r.Host)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	upstream, err := h.dialer.DialStream(ctx, r.Host)
	if err != nil {
		h.logger.Debug("http: CONNECT dial failed", "dest", r.Host, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	client, _, err := hijacker.Hijack()
	if err != nil {
		h.logger.Debug("http: hijack failed", "err", err)
		return
	}
	defer client.Close()

	idle := &idleTimer{timeout: connectIdleTimeout, a: client, b: upstream}
	idle.touch()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstream, &activityReader{r: client, idle: idle})
		upstream.Close() // unblock upstream -> client read
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, &activityReader{r: upstream, idle: idle})
		client.Close() // unblock client -> upstream read
	}()
	wg.Wait()
}

// handleHTTP forwards plain HTTP requests through the Outline proxy.
func (h *httpProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	h.logger.Debug("http: forward", "method", r.Method, "dest", host)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	upstream, err := h.dialer.DialStream(ctx, host)
	if err != nil {
		h.logger.Debug("http: dial failed", "dest", host, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// Rewrite request to relative URL for upstream server
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.RequestURI = r.URL.RequestURI()

	// Remove hop-by-hop headers
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")

	if err := r.Write(upstream); err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Hijack the client connection to relay the raw response
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	io.Copy(client, upstream)
}

// idleTimer tracks bidirectional activity and sets read deadlines on both
// connections. Activity on either side extends the deadline for both.
type idleTimer struct {
	timeout time.Duration
	a, b    interface{ SetReadDeadline(time.Time) error }
}

func (t *idleTimer) touch() {
	deadline := time.Now().Add(t.timeout)
	t.a.SetReadDeadline(deadline)
	t.b.SetReadDeadline(deadline)
}

type activityReader struct {
	r    io.Reader
	idle *idleTimer
}

func (r *activityReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.idle.touch()
	}
	return n, err
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
