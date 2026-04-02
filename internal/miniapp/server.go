package miniapp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/geoip"
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
	geoMgr       *geoip.Manager
	bot          *tgbot.Bot
	store        *statsdb.Store
	botToken     string
	allowedUsers []int64
	domain       string
	logger       *slog.Logger
	botUsername  string
	botMu        sync.Mutex
}

// New creates a new Mini App server.
func New(
	provider observer.StatusProvider,
	cfgProv observer.ConfigProvider,
	manager observer.Manager,
	geoMgr *geoip.Manager,
	bot *tgbot.Bot,
	store *statsdb.Store,
	botToken string,
	allowedUsers []int64,
	domain string,
	logger *slog.Logger,
) *Server {
	return &Server{
		provider:     provider,
		cfgProv:      cfgProv,
		manager:      manager,
		geoMgr:       geoMgr,
		bot:          bot,
		store:        store,
		botToken:     botToken,
		allowedUsers: allowedUsers,
		domain:       domain,
		logger:       logger,
	}
}

// URL returns the public URL of the Mini App.
func (s *Server) URL() string {
	return fmt.Sprintf("https://%s/app/", s.domain)
}

// getBotUsername returns the cached bot username, fetching it lazily on first call.
// Retries on failure so a transient error doesn't permanently break invite links.
func (s *Server) getBotUsername() string {
	s.botMu.Lock()
	defer s.botMu.Unlock()

	if s.botUsername != "" {
		return s.botUsername
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info, err := s.bot.GetMe(ctx)
	if err != nil {
		s.logger.Error("miniapp: failed to get bot username", "err", err)
		return ""
	}
	s.botUsername = info.Username
	return s.botUsername
}

// inviteDeepLink returns a Telegram deep link for the given invite token.
func (s *Server) inviteDeepLink(token string) string {
	username := s.getBotUsername()
	if username == "" {
		return ""
	}
	return fmt.Sprintf("https://t.me/%s?start=inv_%s", username, token)
}

// Handler returns the HTTP handler (mux) for the Mini App.
// The returned handler can be mounted on the frontend at /app/.
func (s *Server) Handler() http.Handler {
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
	mux.HandleFunc("/api/proxies/", s.authMiddleware(adminOnly(s.handleProxiesRoute)))
	mux.HandleFunc("/api/upstreams", s.authMiddleware(adminOnly(s.handleAddUpstream)))
	mux.HandleFunc("/api/upstreams/", s.authMiddleware(adminOnly(s.handleUpstreamsRoute)))
	mux.HandleFunc("/api/groups", s.authMiddleware(adminOnly(s.handleGroupsRoute)))
	mux.HandleFunc("/api/groups/", s.authMiddleware(adminOnly(s.handleGroupsItemRoute)))
	mux.HandleFunc("/api/dns", s.authMiddleware(adminOnly(s.handleDNSRoute)))
	mux.HandleFunc("/api/dns/records", s.authMiddleware(adminOnly(s.handleDNSRecordsRoute)))
	mux.HandleFunc("/api/dns/records/", s.authMiddleware(adminOnly(s.handleDNSRecordsRoute)))
	mux.HandleFunc("/api/dns/rules/", s.authMiddleware(adminOnly(s.handleDNSRulesItem)))
	mux.HandleFunc("/api/dns/blocklists", s.authMiddleware(adminOnly(s.handleKnownBlocklists)))
	mux.HandleFunc("/api/routing", s.authMiddleware(adminOnly(s.handleRoutingRoute)))
	mux.HandleFunc("/api/routing/cidrs", s.authMiddleware(adminOnly(s.handleAddRoutingCIDR)))
	mux.HandleFunc("/api/routing/cidrs/", s.authMiddleware(adminOnly(s.handleRoutingCIDRsItem)))
	mux.HandleFunc("/api/routing/ip-rules", s.authMiddleware(adminOnly(s.handleAddIPRule)))
	mux.HandleFunc("/api/routing/ip-rules/", s.authMiddleware(adminOnly(s.handleIPRulesItem)))
	mux.HandleFunc("/api/routing/sni-rules", s.authMiddleware(adminOnly(s.handleAddSNIRule)))
	mux.HandleFunc("/api/routing/sni-rules/", s.authMiddleware(adminOnly(s.handleSNIRulesItem)))
	mux.HandleFunc("/api/routing/port-rules", s.authMiddleware(adminOnly(s.handleAddPortRule)))
	mux.HandleFunc("/api/routing/port-rules/", s.authMiddleware(adminOnly(s.handlePortRulesItem)))
	mux.HandleFunc("/api/routing/protocol-rules", s.authMiddleware(adminOnly(s.handleAddProtocolRule)))
	mux.HandleFunc("/api/routing/protocol-rules/", s.authMiddleware(adminOnly(s.handleProtocolRulesItem)))
	mux.HandleFunc("/api/routing/cidrs/order", s.authMiddleware(adminOnly(s.handleReorderRoutingCIDRs)))
	mux.HandleFunc("/api/routing/ip-rules/order", s.authMiddleware(adminOnly(s.handleReorderIPRules)))
	mux.HandleFunc("/api/users", s.authMiddleware(adminOnly(s.handleUsers)))
	mux.HandleFunc("/api/users/", s.authMiddleware(adminOnly(s.handleUserRoute)))
	mux.HandleFunc("/api/invites", s.authMiddleware(adminOnly(s.handleInvites)))
	mux.HandleFunc("/api/invites/", s.authMiddleware(adminOnly(s.handleInviteItem)))
	mux.HandleFunc("/api/backup", s.authMiddleware(adminOnly(s.handleBackupDB)))
	mux.HandleFunc("/api/restore", s.authMiddleware(adminOnly(s.handleRestoreDB)))
	mux.HandleFunc("/api/restart", s.authMiddleware(adminOnly(s.handleRestart)))
	mux.HandleFunc("/api/reset", s.authMiddleware(adminOnly(s.handleResetDB)))

	// Invite redemption (validates Telegram init data but doesn't require authorization).
	mux.HandleFunc("/api/invite", s.handleRedeemInvite)

	// Health check (unauthenticated).
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Static files (SPA).
	mux.HandleFunc("/", s.handleStatic)

	return mux
}

// handlePeersRoute dispatches GET /api/peers/<name>/conf, PUT /api/peers/<name>, and DELETE /api/peers/<name>.
func (s *Server) handlePeersRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/conf") {
		s.handlePeerConf(w, r)
		return
	}
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/qr") {
		s.handlePeerQR(w, r)
		return
	}
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/send") {
		s.handlePeerSendConfig(w, r)
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

		// Also support _auth query parameter (for tg.downloadFile which can't set headers).
		if initData == "" {
			initData = r.URL.Query().Get("_auth")
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
