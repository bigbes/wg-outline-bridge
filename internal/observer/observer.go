package observer

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/telegram"
)

// PeerStatus holds the current status of a WireGuard peer.
type PeerStatus struct {
	ID                int
	Name              string
	PublicKey         string
	LastHandshake     time.Time
	RxBytes           int64
	TxBytes           int64
	ActiveConnections int

	// Cumulative stats from SQLite (zero when stats DB is disabled).
	RxTotal          int64
	TxTotal          int64
	ConnectionsTotal int64
}

// DaemonStatus holds daemon-level information.
type DaemonStatus struct {
	StartTime time.Time
	Version   string
	Dirty     bool
}

// MTProxyStatus holds MTProxy server stats.
type MTProxyStatus struct {
	Enabled bool

	// Session (since last restart).
	Connections       int64
	ActiveConnections int64
	UniqueUsers       int64
	TLSConnections    int64
	HandshakeErrors   int64
	BackendDialErrors int64
	BytesC2B          int64
	BytesB2C          int64

	// Cumulative from SQLite (zero when stats DB is disabled).
	ConnectionsTotal       int64
	BytesC2BTotal          int64
	BytesB2CTotal          int64
	BackendDialErrorsTotal int64

	Clients []MTProxyClient
}

// MTProxyClient holds per-secret MTProxy stats.
type MTProxyClient struct {
	Secret            string // hex secret string
	LastConnection    time.Time
	Connections       int64
	ActiveConnections int64
	UniqueUsers       int64
	BytesC2B          int64
	BytesB2C          int64

	// Cumulative from SQLite.
	ConnectionsTotal int64
	BytesC2BTotal    int64
	BytesB2CTotal    int64
}

// UpstreamStatus holds per-upstream endpoint stats (new format).
type UpstreamStatus struct {
	Name              string
	Type              string
	Enabled           bool
	Default           bool
	State             string // "healthy", "degraded", "disabled"
	Groups            []string
	RxBytes           int64
	TxBytes           int64
	ActiveConnections int64
	LastError         string
}

// StatusProvider supplies bridge status data to the observer.
type StatusProvider interface {
	PeerStatuses() []PeerStatus
	DaemonStatus() DaemonStatus
	MTProxyStatus() MTProxyStatus
	UpstreamStatuses() []UpstreamStatus
}

// ConfigProvider supplies the current config to the observer.
type ConfigProvider interface {
	CurrentConfig() *config.Config
}

// RoleChecker resolves the role of a Telegram user.
type RoleChecker interface {
	GetUserRole(userID int64) (string, error)
}

// InviteRedeemer handles invite token redemption.
type InviteRedeemer interface {
	RedeemInvite(token string, userID int64, username, firstName, lastName string) (role string, err error)
}

// Manager provides runtime peer and secret management operations.
type Manager interface {
	AddPeer(name string) (int, config.PeerConfig, error)
	DeletePeer(id int) error
	AddSecret(secretType, comment string) (int, string, error)
	DeleteSecret(id int) error
	DeleteUser(userID int64) error
	AddProxy(p config.ProxyServerConfig) error
	DeleteProxy(name string) error
	AddUpstream(u config.UpstreamConfig) error
	UpdateUpstream(u config.UpstreamConfig) error
	DeleteUpstream(name string) error
	SetPeerDisabled(id int, disabled bool) error
	SetPeerExcludePrivate(id int, excludePrivate bool) error
	SetPeerExcludeServer(id int, excludeServer bool) error
	SetPeerUpstreamGroup(id int, group string) error
	SetProxyUpstreamGroup(name, group string) error
	SetProxyAuth(name, username, password string) error
	SetSecretUpstreamGroup(id int, group string) error
	RenamePeer(id int, newName string) error
	RenameSecret(id int, name string) error
	AddDNSRecord(name string, rec config.DNSRecordConfig) error
	UpdateDNSRecord(name string, rec config.DNSRecordConfig) error
	DeleteDNSRecord(name string) error
	SetDNSEnabled(enabled bool) error
	AddDNSRule(r config.DNSRuleConfig) error
	DeleteDNSRule(name string) error
	UpdateDNSRule(r config.DNSRuleConfig) error
	AddRoutingCIDR(entry config.CIDREntry) error
	DeleteRoutingCIDR(cidr string) error
	AddIPRule(r config.IPRuleConfig) error
	DeleteIPRule(name string) error
	AddSNIRule(r config.SNIRuleConfig) error
	DeleteSNIRule(name string) error
	UpdateSNIRule(r config.SNIRuleConfig) error
	AddPortRule(r config.PortRuleConfig) error
	DeletePortRule(name string) error
	UpdatePortRule(r config.PortRuleConfig) error
	AddProtocolRule(r config.ProtocolRuleConfig) error
	DeleteProtocolRule(name string) error
	UpdateProtocolRule(r config.ProtocolRuleConfig) error
	ReorderRoutingCIDRs(cidrs []string) error
	ReorderIPRules(names []string) error
	UpdateRoutingCIDR(oldCIDR string, entry config.CIDREntry) error
	UpdateIPRule(r config.IPRuleConfig) error
	SetRoutingEnabled(enabled bool) error
	CreateGroup(name string) error
	DeleteGroup(name string) error
	ResetConfig() error
}

// Observer sends periodic status updates and handles bot commands via Telegram.
type Observer struct {
	bot            *telegram.Bot
	provider       StatusProvider
	cfgProv        ConfigProvider
	roleChecker    RoleChecker
	inviteRedeemer InviteRedeemer
	interval       time.Duration
	chatID         int64
	logger         *slog.Logger
}

// New creates a new Observer. If chatID is 0, periodic push notifications
// are disabled but the bot still responds to incoming commands.
// roleChecker and inviteRedeemer may be nil when no database is configured.
func New(bot *telegram.Bot, provider StatusProvider, cfgProv ConfigProvider, roleChecker RoleChecker, inviteRedeemer InviteRedeemer, interval time.Duration, chatID int64, logger *slog.Logger) *Observer {
	return &Observer{
		bot:            bot,
		provider:       provider,
		cfgProv:        cfgProv,
		roleChecker:    roleChecker,
		inviteRedeemer: inviteRedeemer,
		interval:       interval,
		chatID:         chatID,
		logger:         logger,
	}
}

// Run starts the observer. It launches the command polling loop and,
// if a chat_id is configured, the periodic status push loop.
func (o *Observer) Run(ctx context.Context) {
	o.registerCommands(ctx)
	if o.chatID != 0 {
		go o.pushLoop(ctx)
	}
	o.pollLoop(ctx)
}

func (o *Observer) registerCommands(ctx context.Context) {
	commands := []telegram.BotCommand{
		{Command: "help", Description: "Show available commands"},
	}
	if err := o.bot.SetMyCommands(ctx, commands); err != nil {
		o.logger.Error("observer: failed to register bot commands", "err", err)
	}
}

func (o *Observer) pushLoop(ctx context.Context) {
	o.send(ctx, "🟢 Bridge started")

	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			o.send(shutCtx, "🔴 Bridge stopped")
			cancel()
			return
		case <-ticker.C:
			o.sendStatus(ctx)
		}
	}
}

func (o *Observer) pollLoop(ctx context.Context) {
	var offset int64
	for {
		if ctx.Err() != nil {
			return
		}

		updates, err := o.bot.GetUpdates(ctx, offset, 30)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			o.logger.Error("observer: failed to poll updates", "err", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for _, u := range updates {
			offset = u.UpdateID + 1
			if u.Message == nil || u.Message.Text == "" {
				continue
			}
			o.handleCommand(ctx, u.Message)
		}
	}
}

func (o *Observer) isAllowed(msg *telegram.Message) bool {
	allowedUsers := o.cfgProv.CurrentConfig().Telegram.AllowedUsers
	if len(allowedUsers) == 0 && o.roleChecker == nil {
		return true
	}
	// Group/channel messages are allowed (filtered by chat_id if needed)
	if msg.Chat.Type != "private" {
		return true
	}
	if msg.From == nil {
		return false
	}
	if slices.Contains(allowedUsers, msg.From.ID) {
		return true
	}
	// Check DB-stored users.
	if o.roleChecker != nil {
		if role, err := o.roleChecker.GetUserRole(msg.From.ID); err == nil && role != "" {
			return true
		}
	}
	return false
}

func (o *Observer) handleCommand(ctx context.Context, msg *telegram.Message) {
	text := strings.TrimSpace(msg.Text)
	cmd, args, _ := strings.Cut(text, " ")
	args = strings.TrimSpace(args)
	// Strip @botname suffix from commands (e.g., /status@mybot)
	if at := strings.Index(cmd, "@"); at > 0 {
		cmd = cmd[:at]
	}

	// Handle invite redemption before auth check (user is not yet authorized).
	if cmd == "/start" && strings.HasPrefix(args, "inv_") {
		o.handleInviteRedemption(ctx, msg, strings.TrimPrefix(args, "inv_"))
		return
	}

	if !o.isAllowed(msg) {
		o.logger.Debug("observer: ignoring message from unauthorized user",
			"user_id", msg.From.ID, "chat_id", msg.Chat.ID)
		return
	}

	var reply string
	switch cmd {
	case "/help", "/start":
		reply = "Available commands:\n" +
			"/help — show this message"
	default:
		return
	}

	if err := o.bot.SendMessageTo(ctx, msg.Chat.ID, reply); err != nil {
		o.logger.Error("observer: failed to reply", "chat_id", msg.Chat.ID, "err", err)
	}
}

func (o *Observer) sendStatus(ctx context.Context) {
	peers := o.provider.PeerStatuses()
	daemon := o.provider.DaemonStatus()
	mt := o.provider.MTProxyStatus()
	upstreams := o.provider.UpstreamStatuses()
	msg := formatStatus(peers, daemon, mt, upstreams)
	o.send(ctx, msg)
}

func (o *Observer) send(ctx context.Context, text string) {
	if err := o.bot.SendMessage(ctx, text); err != nil {
		o.logger.Error("observer: failed to send telegram message", "err", err)
	}
}

func (o *Observer) handleInviteRedemption(ctx context.Context, msg *telegram.Message, token string) {
	if o.inviteRedeemer == nil {
		o.bot.SendMessageTo(ctx, msg.Chat.ID, "⚠️ Invite system not available")
		return
	}
	if msg.From == nil {
		return
	}

	role, err := o.inviteRedeemer.RedeemInvite(token, msg.From.ID, msg.From.Username, msg.From.FirstName, msg.From.LastName)
	if err != nil {
		o.logger.Error("observer: invite redemption failed", "user_id", msg.From.ID, "err", err)
		o.bot.SendMessageTo(ctx, msg.Chat.ID, fmt.Sprintf("❌ %s", err))
		return
	}

	o.logger.Info("observer: invite redeemed", "user_id", msg.From.ID, "role", role)

	text := fmt.Sprintf("✅ Welcome! You've been granted <b>%s</b> access.", role)
	cfg := o.cfgProv.CurrentConfig()
	if cfg.MiniApp.Enabled && cfg.MiniApp.Domain != "" {
		miniAppURL := miniAppURL(cfg)
		if err := o.bot.SendMessageWithWebApp(ctx, msg.Chat.ID, text, "HTML", "Open Panel", miniAppURL); err != nil {
			o.logger.Error("observer: failed to send welcome message", "err", err)
		}
	} else {
		o.bot.SendMessageHTML(ctx, msg.Chat.ID, text)
	}
}

func miniAppURL(cfg *config.Config) string {
	_, port, _ := strings.Cut(cfg.MiniApp.Listen, ":")
	if port == "" || port == "443" {
		return fmt.Sprintf("https://%s/", cfg.MiniApp.Domain)
	}
	return fmt.Sprintf("https://%s:%s/", cfg.MiniApp.Domain, port)
}

func formatStatus(peers []PeerStatus, daemon DaemonStatus, mt MTProxyStatus, upstreams []UpstreamStatus) string {
	var b strings.Builder
	b.WriteString("📊 Bridge Status\n")

	if !daemon.StartTime.IsZero() {
		uptime := time.Since(daemon.StartTime).Truncate(time.Second)
		fmt.Fprintf(&b, "⏱ Uptime: %s\n", formatDuration(uptime))
	}
	b.WriteString("\n")

	if len(peers) == 0 {
		b.WriteString("No peers configured\n")
	} else {
		for _, p := range peers {
			status := "⚪"
			handshake := "never"
			if !p.LastHandshake.IsZero() {
				ago := time.Since(p.LastHandshake).Truncate(time.Second)
				handshake = fmt.Sprintf("%s ago", ago)
				if ago < 3*time.Minute {
					status = "🟢"
				} else {
					status = "🟡"
				}
			}

			name := p.Name
			if name == "" {
				name = p.PublicKey[:8] + "..."
			}

			fmt.Fprintf(&b, "%s %s\n", status, name)
			fmt.Fprintf(&b, "  Handshake: %s\n", handshake)
			fmt.Fprintf(&b, "  Traffic: ↓%s ↑%s\n", formatBytes(p.RxBytes), formatBytes(p.TxBytes))
			if p.RxTotal > 0 || p.TxTotal > 0 {
				fmt.Fprintf(&b, "  Total: ↓%s ↑%s\n", formatBytes(p.RxTotal), formatBytes(p.TxTotal))
			}
			fmt.Fprintf(&b, "  Connections: %d active", p.ActiveConnections)
			if p.ConnectionsTotal > 0 {
				fmt.Fprintf(&b, ", %d total", p.ConnectionsTotal)
			}
			b.WriteString("\n\n")
		}
	}

	if mt.Enabled {
		b.WriteString("📡 MTProxy\n")
		fmt.Fprintf(&b, "  Connections: %d active", mt.ActiveConnections)
		if mt.ConnectionsTotal > 0 {
			fmt.Fprintf(&b, ", %d total", mt.ConnectionsTotal)
		}
		b.WriteString("\n")
		if mt.UniqueUsers > 0 {
			fmt.Fprintf(&b, "  Unique users: %d\n", mt.UniqueUsers)
		}
		fmt.Fprintf(&b, "  Traffic: ↑%s ↓%s\n", formatBytes(mt.BytesC2B), formatBytes(mt.BytesB2C))
		if mt.BytesC2BTotal > 0 || mt.BytesB2CTotal > 0 {
			fmt.Fprintf(&b, "  Total: ↑%s ↓%s\n", formatBytes(mt.BytesC2BTotal), formatBytes(mt.BytesB2CTotal))
		}
		if mt.HandshakeErrors > 0 || mt.BackendDialErrors > 0 {
			fmt.Fprintf(&b, "  Errors: %d handshake, %d dial", mt.HandshakeErrors, mt.BackendDialErrors)
			if mt.BackendDialErrorsTotal > 0 {
				fmt.Fprintf(&b, " (%d dial total)", mt.BackendDialErrorsTotal)
			}
			b.WriteString("\n")
		}
		if mt.TLSConnections > 0 {
			fmt.Fprintf(&b, "  TLS: %d session\n", mt.TLSConnections)
		}

		if len(mt.Clients) > 0 {
			b.WriteString("\n  Secrets:\n")
			for _, c := range mt.Clients {
				label := truncateSecret(c.Secret)
				lastConn := "never"
				if !c.LastConnection.IsZero() {
					lastConn = fmt.Sprintf("%s ago", formatDuration(time.Since(c.LastConnection).Truncate(time.Second)))
				}
				fmt.Fprintf(&b, "  • %s — last %s\n", label, lastConn)
				if c.UniqueUsers > 0 {
					fmt.Fprintf(&b, "    Users: %d | ", c.UniqueUsers)
				} else {
					fmt.Fprintf(&b, "    ")
				}
				fmt.Fprintf(&b, "Conns: %d active", c.ActiveConnections)
				if c.ConnectionsTotal > 0 {
					fmt.Fprintf(&b, ", %d total", c.ConnectionsTotal)
				}
				fmt.Fprintf(&b, " | Traffic: ↑%s ↓%s", formatBytes(c.BytesC2B), formatBytes(c.BytesB2C))
				if c.BytesC2BTotal > 0 || c.BytesB2CTotal > 0 {
					fmt.Fprintf(&b, " (↑%s ↓%s)", formatBytes(c.BytesC2BTotal), formatBytes(c.BytesB2CTotal))
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}

	if len(upstreams) > 0 {
		b.WriteString("🔗 Upstreams\n")
		for _, u := range upstreams {
			stateIcon := "⚪"
			switch u.State {
			case "healthy":
				stateIcon = "🟢"
			case "degraded":
				stateIcon = "🟡"
			case "disabled":
				stateIcon = "🔴"
			}

			label := u.Name
			if u.Type != "" {
				label += " (" + u.Type + ")"
			}
			if u.Default {
				label += " [default]"
			}

			fmt.Fprintf(&b, "%s %s — %s\n", stateIcon, label, u.State)
			fmt.Fprintf(&b, "  Traffic: ↓%s ↑%s | Conns: %d\n", formatBytes(u.RxBytes), formatBytes(u.TxBytes), u.ActiveConnections)
			if len(u.Groups) > 0 {
				fmt.Fprintf(&b, "  Groups: %s\n", strings.Join(u.Groups, ", "))
			}
			if u.LastError != "" {
				fmt.Fprintf(&b, "  Last error: %s\n", u.LastError)
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

func truncateSecret(hex string) string {
	s := hex
	// Strip known prefixes for display.
	if len(s) == 34 && (s[:2] == "dd" || s[:2] == "ee") {
		s = s[2:]
	}
	if len(s) > 8 {
		return s[:8] + "…"
	}
	return s
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
