package miniapp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/blikh/wireguard-outline-bridge/internal/observer"
)

// Server serves the Telegram Mini App web interface and JSON API.
type Server struct {
	provider     observer.StatusProvider
	cfgProv      observer.ConfigProvider
	manager      observer.Manager
	botToken     string
	allowedUsers []int64
	listen       string
	domain       string
	logger       *slog.Logger
}

// New creates a new Mini App server.
func New(
	provider observer.StatusProvider,
	cfgProv observer.ConfigProvider,
	manager observer.Manager,
	botToken string,
	allowedUsers []int64,
	listen string,
	domain string,
	logger *slog.Logger,
) *Server {
	return &Server{
		provider:     provider,
		cfgProv:      cfgProv,
		manager:      manager,
		botToken:     botToken,
		allowedUsers: allowedUsers,
		listen:       listen,
		domain:       domain,
		logger:       logger,
	}
}

// URL returns the public URL of the Mini App.
func (s *Server) URL() string {
	return fmt.Sprintf("https://%s/", s.domain)
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	// API routes (authenticated).
	mux.HandleFunc("/api/status", s.authMiddleware(s.handleStatus))
	mux.HandleFunc("/api/peers", s.authMiddleware(s.handleAddPeer))
	mux.HandleFunc("/api/peers/", s.authMiddleware(s.handlePeersRoute))
	mux.HandleFunc("/api/secrets", s.authMiddleware(s.handleAddSecret))
	mux.HandleFunc("/api/secrets/", s.authMiddleware(s.handleDeleteSecret))
	mux.HandleFunc("/api/proxies", s.authMiddleware(s.handleAddProxy))
	mux.HandleFunc("/api/proxies/", s.authMiddleware(s.handleDeleteProxy))

	// Static files (SPA).
	mux.HandleFunc("/", s.handleStatic)

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("miniapp: listen %s: %w", s.listen, err)
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	s.logger.Info("miniapp server started", "listen", s.listen, "domain", s.domain)
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("miniapp: serve: %w", err)
	}
	return nil
}

// handlePeersRoute dispatches DELETE /api/peers/<name>.
func (s *Server) handlePeersRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.handleDeletePeer(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		initData := r.Header.Get("X-Telegram-Init-Data")
		if initData == "" {
			// Also support Authorization: tma <initData>
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "tma ") {
				initData = strings.TrimPrefix(auth, "tma ")
			}
		}

		if initData == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing init data"})
			return
		}

		userID, err := ValidateInitData(initData, s.botToken)
		if err != nil {
			s.logger.Debug("miniapp: auth failed", "err", err)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid init data"})
			return
		}

		if len(s.allowedUsers) > 0 {
			allowed := false
			for _, uid := range s.allowedUsers {
				if uid == userID {
					allowed = true
					break
				}
			}
			if !allowed {
				s.logger.Debug("miniapp: unauthorized user", "user_id", userID)
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized"})
				return
			}
		}

		next.ServeHTTP(w, r)
	}
}
