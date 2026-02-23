package observer

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/telegram"
)

// PeerStatus holds the current status of a WireGuard peer.
type PeerStatus struct {
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
	Secret         string // hex secret string
	LastConnection time.Time
	Connections    int64
	UniqueUsers    int64
	BytesC2B       int64
	BytesB2C       int64

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

// Manager provides runtime peer and secret management operations.
type Manager interface {
	AddPeer(name string) (config.PeerConfig, error)
	DeletePeer(name string) error
	AddSecret(secretType, comment string) (string, error)
	DeleteSecret(secretHex string) error
	AddProxy(p config.ProxyServerConfig) error
	DeleteProxy(name string) error
	AddUpstream(u config.UpstreamConfig) error
	UpdateUpstream(u config.UpstreamConfig) error
	DeleteUpstream(name string) error
	SetPeerDisabled(name string, disabled bool) error
	RenamePeer(oldName, newName string) error
	AddDNSRecord(name string, rec config.DNSRecordConfig) error
	UpdateDNSRecord(name string, rec config.DNSRecordConfig) error
	DeleteDNSRecord(name string) error
	SetDNSEnabled(enabled bool) error
	AddDNSRule(r config.DNSRuleConfig) error
	DeleteDNSRule(name string) error
	CreateGroup(name string) error
	DeleteGroup(name string) error
}

// Observer sends periodic status updates and handles bot commands via Telegram.
type Observer struct {
	bot         *telegram.Bot
	provider    StatusProvider
	cfgProv     ConfigProvider
	manager     Manager
	roleChecker RoleChecker
	interval    time.Duration
	chatID      int64
	logger      *slog.Logger
}

// New creates a new Observer. If chatID is 0, periodic push notifications
// are disabled but the bot still responds to incoming commands.
// roleChecker may be nil when no database is configured.
func New(bot *telegram.Bot, provider StatusProvider, cfgProv ConfigProvider, manager Manager, roleChecker RoleChecker, interval time.Duration, chatID int64, logger *slog.Logger) *Observer {
	return &Observer{
		bot:         bot,
		provider:    provider,
		cfgProv:     cfgProv,
		manager:     manager,
		roleChecker: roleChecker,
		interval:    interval,
		chatID:      chatID,
		logger:      logger,
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
		{Command: "status", Description: "Show peer status, traffic, and connections"},
		{Command: "proxy", Description: "Show Telegram proxy links"},
		{Command: "listconf", Description: "List all peers"},
		{Command: "showconf", Description: "Show WireGuard client config for a peer"},
		{Command: "addpeer", Description: "Add a new WireGuard peer"},
		{Command: "delpeer", Description: "Delete a WireGuard peer"},
		{Command: "addsecret", Description: "Add a new MTProxy secret"},
		{Command: "delsecret", Description: "Delete an MTProxy secret"},
		{Command: "addproxy", Description: "Add a proxy server (socks5/http/https)"},
		{Command: "delproxy", Description: "Delete a proxy server"},
		{Command: "listproxy", Description: "List proxy servers and connection links"},
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

func (o *Observer) isAdmin(userID int64) bool {
	// Config admins are always admin.
	if slices.Contains(o.cfgProv.CurrentConfig().Telegram.AllowedUsers, userID) {
		return true
	}
	// Check DB role.
	if o.roleChecker != nil {
		if role, err := o.roleChecker.GetUserRole(userID); err == nil {
			return role == "admin"
		}
	}
	return false
}

func (o *Observer) handleCommand(ctx context.Context, msg *telegram.Message) {
	if !o.isAllowed(msg) {
		o.logger.Debug("observer: ignoring message from unauthorized user",
			"user_id", msg.From.ID, "chat_id", msg.Chat.ID)
		return
	}

	text := strings.TrimSpace(msg.Text)
	cmd, args, _ := strings.Cut(text, " ")
	args = strings.TrimSpace(args)
	// Strip @botname suffix from commands (e.g., /status@mybot)
	if at := strings.Index(cmd, "@"); at > 0 {
		cmd = cmd[:at]
	}

	var reply string
	var html bool
	switch cmd {
	case "/status":
		peers := o.provider.PeerStatuses()
		daemon := o.provider.DaemonStatus()
		mt := o.provider.MTProxyStatus()
		upstreams := o.provider.UpstreamStatuses()
		reply = formatStatus(peers, daemon, mt, upstreams)
	case "/proxy":
		links := config.ProxyLinks(o.cfgProv.CurrentConfig(), nil)
		if len(links) == 0 {
			reply = "No proxy links available (MTProxy not configured or no secrets)"
		} else {
			var b strings.Builder
			b.WriteString("🔗 Telegram Proxy Links:\n\n")
			for _, link := range links {
				fmt.Fprintf(&b, "[%s] %s\n", link.Name, link.URL)
			}
			reply = b.String()
		}
	case "/listconf":
		reply = o.formatPeerList()
		html = true
	case "/showconf":
		if args == "" {
			reply = "Usage: /showconf &lt;peer-name&gt;"
		} else {
			reply = o.formatShowConf(args)
			html = true
		}
	case "/addpeer":
		if !o.isAdmin(msg.From.ID) {
			reply = "⛔ Admin access required"
		} else if o.manager == nil {
			reply = "⚠️ Management not available (database not configured)"
		} else if args == "" {
			reply = "Usage: /addpeer &lt;peer-name&gt;"
			html = true
		} else {
			reply = o.handleAddPeer(args)
			html = true
		}
	case "/delpeer":
		if !o.isAdmin(msg.From.ID) {
			reply = "⛔ Admin access required"
		} else if o.manager == nil {
			reply = "⚠️ Management not available (database not configured)"
		} else if args == "" {
			reply = "Usage: /delpeer &lt;peer-name&gt;"
			html = true
		} else {
			reply = o.handleDelPeer(args)
		}
	case "/addsecret":
		if !o.isAdmin(msg.From.ID) {
			reply = "⛔ Admin access required"
		} else if o.manager == nil {
			reply = "⚠️ Management not available (database not configured)"
		} else {
			reply = o.handleAddSecret(args)
			html = true
		}
	case "/delsecret":
		if !o.isAdmin(msg.From.ID) {
			reply = "⛔ Admin access required"
		} else if o.manager == nil {
			reply = "⚠️ Management not available (database not configured)"
		} else if args == "" {
			reply = "Usage: /delsecret &lt;secret-hex&gt;"
			html = true
		} else {
			reply = o.handleDelSecret(args)
		}
	case "/addproxy":
		if !o.isAdmin(msg.From.ID) {
			reply = "⛔ Admin access required"
		} else if o.manager == nil {
			reply = "⚠️ Management not available (database not configured)"
		} else if args == "" {
			reply = "Usage: /addproxy &lt;type&gt; &lt;listen&gt; [name] [outline] [user:pass]\n\nExamples:\n/addproxy socks5 0.0.0.0:1080\n/addproxy http 0.0.0.0:8080 my-http default user:pass\n/addproxy socks5 0.0.0.0:1080 my-socks default user:pass"
			html = true
		} else {
			reply = o.handleAddProxy(args)
			html = true
		}
	case "/delproxy":
		if !o.isAdmin(msg.From.ID) {
			reply = "⛔ Admin access required"
		} else if o.manager == nil {
			reply = "⚠️ Management not available (database not configured)"
		} else if args == "" {
			reply = "Usage: /delproxy &lt;name&gt;"
			html = true
		} else {
			reply = o.handleDelProxy(args)
		}
	case "/listproxy":
		reply = o.handleListProxy()
		html = true
	case "/help", "/start":
		reply = "Available commands:\n" +
			"/status — show peer status, traffic, and connections\n" +
			"/proxy — show Telegram proxy links\n" +
			"/listconf — list all peers\n" +
			"/showconf <name> — show WireGuard client config for a peer\n" +
			"/addpeer <name> — add a new WireGuard peer\n" +
			"/delpeer <name> — delete a WireGuard peer\n" +
			"/addsecret [type] [comment] — add a new MTProxy secret\n" +
			"/delsecret <hex> — delete an MTProxy secret\n" +
			"/addproxy <type> <listen> [name] [outline] [user:pass] — add a proxy server\n" +
			"/delproxy <name> — delete a proxy server\n" +
			"/listproxy — list proxy servers and connection links\n" +
			"/help — show this message"
	default:
		return
	}

	var err error
	if html {
		err = o.bot.SendMessageHTML(ctx, msg.Chat.ID, reply)
	} else {
		err = o.bot.SendMessageTo(ctx, msg.Chat.ID, reply)
	}
	if err != nil {
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
		fmt.Fprintf(&b, "  Connections: %d active, %d session", mt.ActiveConnections, mt.Connections)
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
				fmt.Fprintf(&b, "Conns: %d session", c.Connections)
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

func (o *Observer) formatPeerList() string {
	peers := o.cfgProv.CurrentConfig().Peers
	if len(peers) == 0 {
		return "No peers configured"
	}

	names := make([]string, 0, len(peers))
	for name := range peers {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("📋 Peers:\n\n")
	for _, name := range names {
		fmt.Fprintf(&b, "• <code>%s</code>\n", name)
	}
	return b.String()
}

func (o *Observer) formatShowConf(name string) string {
	cfg := o.cfgProv.CurrentConfig()

	peer, ok := cfg.Peers[name]
	if !ok {
		return fmt.Sprintf("Peer %q not found", name)
	}

	clientIP := strings.Split(peer.AllowedIPs, "/")[0]

	serverIP := cfg.ServerPublicIP()
	endpoint := fmt.Sprintf("<SERVER_IP>:%d", cfg.WireGuard.ListenPort)
	if serverIP != "" {
		endpoint = fmt.Sprintf("%s:%d", serverIP, cfg.WireGuard.ListenPort)
	}

	allowedIPs := "0.0.0.0/0"
	cidrVars := map[string]string{"server_ip": serverIP}
	cidrRules, err := config.ParseCIDRRules(config.ExpandCIDRRuleVars(cfg.Routing.CIDRs, cidrVars))
	if err == nil {
		if computed := config.ComputeAllowedIPs(cidrRules, serverIP); computed != "" {
			allowedIPs = computed
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "<pre>")
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peer.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/24\n", clientIP)
	fmt.Fprintf(&b, "DNS = %s\n", cfg.WireGuard.DNS)
	fmt.Fprintf(&b, "\n[Peer]\n")

	if serverPublicKey, err := config.DerivePublicKey(cfg.WireGuard.PrivateKey); err == nil {
		fmt.Fprintf(&b, "PublicKey = %s\n", serverPublicKey)
	} else {
		fmt.Fprintf(&b, "PublicKey = &lt;failed to derive&gt;\n")
	}
	if peer.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowedIPs)
	fmt.Fprintf(&b, "PersistentKeepalive = 25\n")
	fmt.Fprintf(&b, "</pre>")

	return b.String()
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

func (o *Observer) handleAddPeer(name string) string {
	peer, err := o.manager.AddPeer(name)
	if err != nil {
		return fmt.Sprintf("❌ Failed to add peer: %s", err)
	}

	cfg := o.cfgProv.CurrentConfig()
	clientIP := strings.Split(peer.AllowedIPs, "/")[0]

	serverIP := cfg.ServerPublicIP()
	endpoint := fmt.Sprintf("&lt;SERVER_IP&gt;:%d", cfg.WireGuard.ListenPort)
	if serverIP != "" {
		endpoint = fmt.Sprintf("%s:%d", serverIP, cfg.WireGuard.ListenPort)
	}

	allowedIPs := "0.0.0.0/0"
	cidrVars := map[string]string{"server_ip": serverIP}
	cidrRules, err := config.ParseCIDRRules(config.ExpandCIDRRuleVars(cfg.Routing.CIDRs, cidrVars))
	if err == nil {
		if computed := config.ComputeAllowedIPs(cidrRules, serverIP); computed != "" {
			allowedIPs = computed
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "✅ Peer <code>%s</code> added (IP: %s)\n\n", name, clientIP)
	fmt.Fprintf(&b, "<pre>")
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peer.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/24\n", clientIP)
	fmt.Fprintf(&b, "DNS = %s\n", cfg.WireGuard.DNS)
	fmt.Fprintf(&b, "\n[Peer]\n")
	if serverPublicKey, err := config.DerivePublicKey(cfg.WireGuard.PrivateKey); err == nil {
		fmt.Fprintf(&b, "PublicKey = %s\n", serverPublicKey)
	} else {
		fmt.Fprintf(&b, "PublicKey = &lt;failed to derive&gt;\n")
	}
	if peer.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowedIPs)
	fmt.Fprintf(&b, "PersistentKeepalive = 25\n")
	fmt.Fprintf(&b, "</pre>")

	return b.String()
}

func (o *Observer) handleDelPeer(name string) string {
	if err := o.manager.DeletePeer(name); err != nil {
		return fmt.Sprintf("❌ Failed to delete peer: %s", err)
	}
	return fmt.Sprintf("✅ Peer %q deleted", name)
}

func (o *Observer) handleAddSecret(args string) string {
	secretType := "faketls"
	comment := ""
	if args != "" {
		parts := strings.SplitN(args, " ", 2)
		secretType = parts[0]
		if len(parts) > 1 {
			comment = parts[1]
		}
	}

	secretHex, err := o.manager.AddSecret(secretType, comment)
	if err != nil {
		return fmt.Sprintf("❌ Failed to add secret: %s", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "✅ Secret added\n\n")
	fmt.Fprintf(&b, "Secret: <code>%s</code>\n", secretHex)

	cfg := o.cfgProv.CurrentConfig()
	links := config.ProxyLinks(cfg, nil)
	if len(links) > 0 {
		fmt.Fprintf(&b, "\n🔗 %s", links[len(links)-1].URL)
	}
	fmt.Fprintf(&b, "\n\n💡 Send SIGHUP to reload secrets without restart")

	return b.String()
}

func (o *Observer) handleDelSecret(secretHex string) string {
	if err := o.manager.DeleteSecret(secretHex); err != nil {
		return fmt.Sprintf("❌ Failed to delete secret: %s", err)
	}
	return fmt.Sprintf("✅ Secret deleted\n\n💡 Send SIGHUP to reload secrets without restart")
}

func (o *Observer) handleAddProxy(args string) string {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "Usage: /addproxy &lt;type&gt; &lt;listen&gt; [name] [outline] [user:pass]"
	}

	p := config.ProxyServerConfig{
		Type:   parts[0],
		Listen: parts[1],
	}

	switch p.Type {
	case "socks5", "http":
	default:
		return fmt.Sprintf("❌ Unsupported type %q (use socks5 or http)", p.Type)
	}

	if len(parts) >= 3 {
		p.Name = parts[2]
	} else {
		p.Name = fmt.Sprintf("%s-%s", p.Type, strings.ReplaceAll(p.Listen, ":", "-"))
	}

	if len(parts) >= 4 {
		p.UpstreamGroup = "upstream:" + parts[3]
	}

	if len(parts) >= 5 {
		if user, pass, ok := strings.Cut(parts[4], ":"); ok {
			p.Username = user
			p.Password = pass
		}
	}

	if err := o.manager.AddProxy(p); err != nil {
		return fmt.Sprintf("❌ Failed to add proxy: %s", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "✅ Proxy <code>%s</code> added\n\n", p.Name)
	fmt.Fprintf(&b, "Type: %s\nListen: %s\n", p.Type, p.Listen)
	if p.Username != "" {
		fmt.Fprintf(&b, "Auth: %s:***\n", p.Username)
	}
	b.WriteString("\n⚠️ Restart required for the proxy to start")
	return b.String()
}

func (o *Observer) handleDelProxy(name string) string {
	if err := o.manager.DeleteProxy(name); err != nil {
		return fmt.Sprintf("❌ Failed to delete proxy: %s", err)
	}
	return fmt.Sprintf("✅ Proxy %q deleted\n\n⚠️ Restart required to stop the proxy", name)
}

func (o *Observer) handleListProxy() string {
	cfg := o.cfgProv.CurrentConfig()
	if len(cfg.Proxies) == 0 {
		return "No proxy servers configured"
	}

	serverIP := cfg.ServerPublicIP()
	if serverIP == "" {
		serverIP = "<SERVER_IP>"
	}

	var b strings.Builder
	b.WriteString("🔌 Proxy Servers:\n\n")
	for _, p := range cfg.Proxies {
		fmt.Fprintf(&b, "• <b>%s</b> (%s)\n", p.Name, p.Type)
		fmt.Fprintf(&b, "  Listen: %s\n", p.Listen)

		_, port, _ := strings.Cut(p.Listen, ":")
		if port == "" {
			port = p.Listen
		}
		// Handle addresses like 0.0.0.0:port or :port
		if strings.HasPrefix(p.Listen, "0.0.0.0:") || strings.HasPrefix(p.Listen, ":") {
			// Use public IP
		}

		switch p.Type {
		case "socks5":
			if p.Username != "" {
				fmt.Fprintf(&b, "  Link: <code>socks5://%s:%s@%s:%s</code>\n", p.Username, p.Password, serverIP, port)
			} else {
				fmt.Fprintf(&b, "  Link: <code>socks5://%s:%s</code>\n", serverIP, port)
			}
		case "http":
			if p.Username != "" {
				fmt.Fprintf(&b, "  Link: <code>http://%s:%s@%s:%s</code>\n", p.Username, p.Password, serverIP, port)
			} else {
				fmt.Fprintf(&b, "  Link: <code>http://%s:%s</code>\n", serverIP, port)
			}
		case "https":
			host := serverIP
			if p.TLS.Domain != "" {
				host = p.TLS.Domain
			}
			if p.Username != "" {
				fmt.Fprintf(&b, "  Link: <code>https://%s:%s@%s:%s</code>\n", p.Username, p.Password, host, port)
			} else {
				fmt.Fprintf(&b, "  Link: <code>https://%s:%s</code>\n", host, port)
			}
		}

		if p.UpstreamGroup != "" && p.UpstreamGroup != "default" {
			fmt.Fprintf(&b, "  Upstream: %s\n", p.UpstreamGroup)
		}
		b.WriteString("\n")
	}
	return b.String()
}
