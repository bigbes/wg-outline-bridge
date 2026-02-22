package mtproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// StatsServer serves MTProxy stats via HTTP, similar to the original C MTProxy.
// Only responds to requests from localhost.
type StatsServer struct {
	server    *Server
	httpSrv   *http.Server
	startTime time.Time
	logger    *slog.Logger
}

// NewStatsServer creates a stats HTTP server bound to the given address.
func NewStatsServer(addr string, srv *Server, logger *slog.Logger) *StatsServer {
	ss := &StatsServer{
		server:    srv,
		startTime: time.Now(),
		logger:    logger.With("component", "mtproxy-stats"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", ss.handleStats)

	ss.httpSrv = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return ss
}

// Start begins serving stats. Blocks until ctx is cancelled.
func (ss *StatsServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", ss.httpSrv.Addr)
	if err != nil {
		return fmt.Errorf("stats server listen: %w", err)
	}

	ss.logger.Info("stats server listening", "addr", ss.httpSrv.Addr)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ss.httpSrv.Shutdown(shutCtx)
	}()

	if err := ss.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("stats server: %w", err)
	}
	return nil
}

func (ss *StatsServer) handleStats(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := ss.server.StatsSnapshot()
	uptime := int64(time.Since(ss.startTime).Seconds())

	var b strings.Builder
	fmt.Fprintf(&b, "uptime\t%d\n", uptime)
	fmt.Fprintf(&b, "connections\t%d\n", stats.Connections.Load())
	fmt.Fprintf(&b, "active_connections\t%d\n", stats.ActiveConnections.Load())
	fmt.Fprintf(&b, "unique_users\t%d\n", stats.UniqueUsers.Load())
	fmt.Fprintf(&b, "tls_connections\t%d\n", stats.TLSConnections.Load())
	fmt.Fprintf(&b, "handshake_errors\t%d\n", stats.HandshakeErrors.Load())
	fmt.Fprintf(&b, "backend_dial_errors\t%d\n", stats.BackendDialErrors.Load())
	fmt.Fprintf(&b, "bytes_client_to_backend\t%d\n", stats.BytesClientToBackend.Load())
	fmt.Fprintf(&b, "bytes_backend_to_client\t%d\n", stats.BytesBackendToClient.Load())
	fmt.Fprintf(&b, "replay_cache_size\t%d\n", ss.server.ReplayCacheSize())

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(b.String()))
}
