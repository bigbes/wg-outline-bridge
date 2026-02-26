// Package httpproxy implements an HTTP/HTTPS forward proxy handler.
package httpproxy

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const connectIdleTimeout = 5 * time.Minute

// StreamDialer dials a TCP connection (typically through a proxy).
type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

// Handler is an http.Handler that implements HTTP/HTTPS forward proxying.
type Handler struct {
	dialer   StreamDialer
	logger   *slog.Logger
	username string
	password string
}

// NewHandler creates a new HTTP proxy handler.
func NewHandler(dialer StreamDialer, username, password string, logger *slog.Logger) *Handler {
	return &Handler{
		dialer:   dialer,
		logger:   logger,
		username: username,
		password: password,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) checkAuth(r *http.Request) bool {
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
func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
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
		upstream.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, &activityReader{r: upstream, idle: idle})
		client.Close()
	}()
	wg.Wait()
}

// handleHTTP forwards plain HTTP requests through the proxy.
func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":80"
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
