package miniapp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/bigbes/wireguard-outline-bridge/internal/observer"
	"github.com/bigbes/wireguard-outline-bridge/internal/statsdb"
	tgbot "github.com/bigbes/wireguard-outline-bridge/internal/telegram"
)

type contextKey int

const (
	ctxKeyUserID contextKey = iota
	ctxKeyUserRole
)

// Server serves the Telegram Mini App web interface and JSON API.
type Server struct {
	provider     observer.StatusProvider
	cfgProv      observer.ConfigProvider
	manager      observer.Manager
	bot          *tgbot.Bot
	store        *statsdb.Store
	botToken     string
	allowedUsers []int64
	listen       string
	domain       string
	acmeEmail    string
	acmeDir      string
	logger       *slog.Logger
}

// New creates a new Mini App server.
func New(
	provider observer.StatusProvider,
	cfgProv observer.ConfigProvider,
	manager observer.Manager,
	bot *tgbot.Bot,
	store *statsdb.Store,
	botToken string,
	allowedUsers []int64,
	listen string,
	domain string,
	acmeEmail string,
	acmeDir string,
	logger *slog.Logger,
) *Server {
	return &Server{
		provider:     provider,
		cfgProv:      cfgProv,
		manager:      manager,
		bot:          bot,
		store:        store,
		botToken:     botToken,
		allowedUsers: allowedUsers,
		listen:       listen,
		domain:       domain,
		acmeEmail:    acmeEmail,
		acmeDir:      acmeDir,
		logger:       logger,
	}
}

// URL returns the public URL of the Mini App.
func (s *Server) URL() string {
	_, port, _ := strings.Cut(s.listen, ":")
	if port == "" || port == "443" {
		return fmt.Sprintf("https://%s/", s.domain)
	}
	return fmt.Sprintf("https://%s:%s/", s.domain, port)
}

// Run starts the HTTPS server with Let's Encrypt and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	// adminOnly wraps a handler to reject non-admin users.
	adminOnly := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !isAdminRequest(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
				return
			}
			next.ServeHTTP(w, r)
		}
	}

	// API routes (authenticated).
	mux.HandleFunc("/api/me", s.authMiddleware(s.handleMe))
	mux.HandleFunc("/api/status", s.authMiddleware(s.handleStatus))
	mux.HandleFunc("/api/peers", s.authMiddleware(s.handleAddPeer))
	mux.HandleFunc("/api/peers/", s.authMiddleware(s.handlePeersRoute))
	mux.HandleFunc("/api/secrets", s.authMiddleware(s.handleAddSecret))
	mux.HandleFunc("/api/secrets/", s.authMiddleware(s.handleSecretsRoute))
	mux.HandleFunc("/api/proxies", s.authMiddleware(adminOnly(s.handleAddProxy)))
	mux.HandleFunc("/api/proxies/", s.authMiddleware(adminOnly(s.handleDeleteProxy)))
	mux.HandleFunc("/api/upstreams", s.authMiddleware(adminOnly(s.handleAddUpstream)))
	mux.HandleFunc("/api/upstreams/", s.authMiddleware(adminOnly(s.handleUpstreamsRoute)))
	mux.HandleFunc("/api/groups", s.authMiddleware(adminOnly(s.handleGroupsRoute)))
	mux.HandleFunc("/api/groups/", s.authMiddleware(adminOnly(s.handleGroupsItemRoute)))
	mux.HandleFunc("/api/dns", s.authMiddleware(adminOnly(s.handleDNSRoute)))
	mux.HandleFunc("/api/dns/records", s.authMiddleware(adminOnly(s.handleDNSRecordsRoute)))
	mux.HandleFunc("/api/dns/records/", s.authMiddleware(adminOnly(s.handleDNSRecordsRoute)))
	mux.HandleFunc("/api/dns/rules/", s.authMiddleware(adminOnly(s.handleDeleteDNSRule)))
	mux.HandleFunc("/api/users", s.authMiddleware(adminOnly(s.handleUsers)))
	mux.HandleFunc("/api/users/", s.authMiddleware(adminOnly(s.handleUserRoute)))

	// Health check (unauthenticated).
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Static files (SPA).
	mux.HandleFunc("/", s.handleStatic)

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.domain),
		Email:      s.acmeEmail,
	}
	if s.acmeDir != "" {
		m.Cache = autocert.DirCache(s.acmeDir)
	}

	tlsCfg := m.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12

	srv := &http.Server{
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("miniapp: listen %s: %w", s.listen, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	// Start HTTP-01 challenge server on :80 if the main listener is not :80.
	go func() {
		httpSrv := &http.Server{
			Handler:      m.HTTPHandler(nil),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		httpLn, err := net.Listen("tcp", ":80")
		if err != nil {
			s.logger.Warn("miniapp: could not listen on :80 for ACME HTTP-01 challenge, using TLS-ALPN-01 only", "err", err)
			return
		}
		s.logger.Info("miniapp: ACME HTTP-01 challenge server started", "listen", ":80")
		go func() {
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			httpSrv.Shutdown(shutCtx)
		}()
		if err := httpSrv.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			s.logger.Warn("miniapp: ACME HTTP-01 server error", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	s.logger.Info("miniapp server started", "listen", s.listen, "domain", s.domain, "tls", true)
	if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("miniapp: serve: %w", err)
	}
	return nil
}

// handlePeersRoute dispatches GET /api/peers/<name>/conf, PUT /api/peers/<name>, and DELETE /api/peers/<name>.
func (s *Server) handlePeersRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/conf") {
		s.handlePeerConf(w, r)
		return
	}
	if r.Method == http.MethodPut {
		s.handleUpdatePeer(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		s.handleDeletePeer(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func requestUserID(r *http.Request) int64 {
	if v, ok := r.Context().Value(ctxKeyUserID).(int64); ok {
		return v
	}
	return 0
}

func requestUserRole(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyUserRole).(string); ok {
		return v
	}
	return ""
}

func isAdminRequest(r *http.Request) bool {
	return requestUserRole(r) == statsdb.RoleAdmin
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		initData := r.Header.Get("X-Telegram-Init-Data")
		if initData == "" {
			// Also support Authorization: tma <initData>
			auth := r.Header.Get("Authorization")
			if after, ok := strings.CutPrefix(auth, "tma "); ok {
				initData = after
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

		// Determine role: config admins are always admin.
		role := ""
		if slices.Contains(s.allowedUsers, userID) {
			role = statsdb.RoleAdmin
		}
		if role == "" && s.store != nil {
			if r, err := s.store.GetUserRole(userID); err == nil && r != "" {
				role = r
			}
		}
		if role == "" {
			s.logger.Debug("miniapp: unauthorized user", "user_id", userID)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized"})
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
		ctx = context.WithValue(ctx, ctxKeyUserRole, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
