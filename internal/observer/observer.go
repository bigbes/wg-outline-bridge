package observer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

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
	if o.chatID != 0 {
		go o.pushLoop(ctx)
	}
	o.pollLoop(ctx)
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

	cmd := strings.TrimSpace(msg.Text)
	// Strip @botname suffix from commands (e.g., /status@mybot)
	if at := strings.Index(cmd, "@"); at > 0 {
		cmd = cmd[:at]
	}

	var reply string
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
	case "/help", "/start":
		reply = "Available commands:\n" +
			"/status — show peer status, traffic, and connections\n" +
			"/proxy — show Telegram proxy links\n" +
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
