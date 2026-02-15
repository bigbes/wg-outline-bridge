package observer

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
	"github.com/blikh/wireguard-outline-bridge/internal/telegram"
)

// PeerStatus holds the current status of a WireGuard peer.
type PeerStatus struct {
	Name              string
	PublicKey         string
	LastHandshake     time.Time
	RxBytes           int64
	TxBytes           int64
	ActiveConnections int
}

// StatusProvider supplies bridge status data to the observer.
type StatusProvider interface {
	PeerStatuses() []PeerStatus
}

// Observer sends periodic status updates and handles bot commands via Telegram.
type Observer struct {
	bot      *telegram.Bot
	provider StatusProvider
	cfg      *config.Config
	interval time.Duration
	chatID   int64
	logger   *slog.Logger
}

// New creates a new Observer. If chatID is 0, periodic push notifications
// are disabled but the bot still responds to incoming commands.
func New(bot *telegram.Bot, provider StatusProvider, cfg *config.Config, interval time.Duration, chatID int64, logger *slog.Logger) *Observer {
	return &Observer{
		bot:      bot,
		provider: provider,
		cfg:      cfg,
		interval: interval,
		chatID:   chatID,
		logger:   logger,
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
	allowedUsers := o.cfg.Telegram.AllowedUsers
	if len(allowedUsers) == 0 {
		return true
	}
	// Group/channel messages are allowed (filtered by chat_id if needed)
	if msg.Chat.Type != "private" {
		return true
	}
	if msg.From == nil {
		return false
	}
	for _, uid := range allowedUsers {
		if uid == msg.From.ID {
			return true
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
		reply = formatStatus(peers)
	case "/proxy":
		links := config.ProxyLinks(o.cfg)
		if len(links) == 0 {
			reply = "No proxy links available (MTProxy not configured or no secrets)"
		} else {
			var b strings.Builder
			b.WriteString("🔗 Telegram Proxy Links:\n\n")
			for i, link := range links {
				fmt.Fprintf(&b, "[%d] %s\n", i+1, link)
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
	case "/help", "/start":
		reply = "Available commands:\n" +
			"/status — show peer status, traffic, and connections\n" +
			"/proxy — show Telegram proxy links\n" +
			"/listconf — list all peers\n" +
			"/showconf <name> — show WireGuard client config for a peer\n" +
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
	msg := formatStatus(peers)
	o.send(ctx, msg)
}

func (o *Observer) send(ctx context.Context, text string) {
	if err := o.bot.SendMessage(ctx, text); err != nil {
		o.logger.Error("observer: failed to send telegram message", "err", err)
	}
}

func formatStatus(peers []PeerStatus) string {
	var b strings.Builder
	b.WriteString("📊 Bridge Status\n\n")

	if len(peers) == 0 {
		b.WriteString("No peers configured\n")
		return b.String()
	}

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
		fmt.Fprintf(&b, "  Connections: %d\n", p.ActiveConnections)
		b.WriteString("\n")
	}

	return b.String()
}

func (o *Observer) formatPeerList() string {
	peers := o.cfg.Peers
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
	peer, ok := o.cfg.Peers[name]
	if !ok {
		return fmt.Sprintf("Peer %q not found", name)
	}

	clientIP := strings.Split(peer.AllowedIPs, "/")[0]

	serverIP := o.cfg.ServerPublicIP()
	endpoint := fmt.Sprintf("<SERVER_IP>:%d", o.cfg.WireGuard.ListenPort)
	if serverIP != "" {
		endpoint = fmt.Sprintf("%s:%d", serverIP, o.cfg.WireGuard.ListenPort)
	}

	allowedIPs := "0.0.0.0/0"
	cidrRules, err := config.ParseCIDRRules(o.cfg.Routing.CIDRs)
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
	fmt.Fprintf(&b, "DNS = %s\n", o.cfg.WireGuard.DNS)
	fmt.Fprintf(&b, "\n[Peer]\n")

	if serverPublicKey, err := derivePublicKey(o.cfg.WireGuard.PrivateKey); err == nil {
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

func derivePublicKey(privateKeyB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("invalid private key length: %d", len(raw))
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
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
