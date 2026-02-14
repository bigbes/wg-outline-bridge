package bridge

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
	"github.com/blikh/wireguard-outline-bridge/internal/dns"
	"github.com/blikh/wireguard-outline-bridge/internal/geoip"
	"github.com/blikh/wireguard-outline-bridge/internal/mtproxy"
	mpcrypto "github.com/blikh/wireguard-outline-bridge/internal/mtproxy/crypto"
	"github.com/blikh/wireguard-outline-bridge/internal/mtproxy/telegram"
	"github.com/blikh/wireguard-outline-bridge/internal/observer"
	"github.com/blikh/wireguard-outline-bridge/internal/outline"
	"github.com/blikh/wireguard-outline-bridge/internal/proxy"
	"github.com/blikh/wireguard-outline-bridge/internal/routing"
	tgbot "github.com/blikh/wireguard-outline-bridge/internal/telegram"
	wg "github.com/blikh/wireguard-outline-bridge/internal/wireguard"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

type Bridge struct {
	configPath string
	logger     *slog.Logger

	mu            sync.Mutex
	cfg           *config.Config
	wgDev         *device.Device
	outlineClient *outline.SwappableClient
	tracker       *proxy.ConnTracker
	peerMon       *peerMonitor
}

func New(configPath string, cfg *config.Config, logger *slog.Logger) *Bridge {
	return &Bridge{
		configPath: configPath,
		cfg:        cfg,
		logger:     logger,
	}
}

func (b *Bridge) Run(ctx context.Context) error {
	addr, _, err := b.cfg.WireGuard.ParseAddress()
	if err != nil {
		return fmt.Errorf("parsing wireguard address: %w", err)
	}

	defaultCfg := b.cfg.DefaultOutline()
	defaultClient, err := outline.NewClient(defaultCfg.Transport)
	if err != nil {
		return fmt.Errorf("creating default outline client: %w", err)
	}
	b.outlineClient = outline.NewSwappableClient(defaultClient)
	b.logger.Info("default outline client created", "name", defaultCfg.Name, "transport", config.RedactTransport(defaultCfg.Transport))

	dialers := proxy.NewDialerSet(b.outlineClient)
	for _, o := range b.cfg.Outlines {
		if o.Default {
			continue
		}
		c, err := outline.NewClient(o.Transport)
		if err != nil {
			return fmt.Errorf("creating outline client %q: %w", o.Name, err)
		}
		dialers.Outlines[o.Name] = c
		b.logger.Info("outline client created", "name", o.Name)
	}

	for _, o := range b.cfg.Outlines {
		if o.HealthCheck.Enabled {
			dialer := b.outlineClient
			if !o.Default {
				if d, ok := dialers.Outlines[o.Name]; ok {
					dialer = outline.NewSwappableClient(d.(*outline.Client))
				}
			}
			go b.startHealthChecker(ctx, o.Name, dialer,
				time.Duration(o.HealthCheck.Interval)*time.Second,
				o.HealthCheck.Target)
			b.logger.Info("outline health checker started",
				"name", o.Name,
				"interval", o.HealthCheck.Interval,
				"target", o.HealthCheck.Target)
		}
	}

	tunDev, err := wg.CreateNetTUNWithStack([]netip.Addr{addr}, b.cfg.WireGuard.MTU, b.logger)
	if err != nil {
		return fmt.Errorf("creating netstack tun: %w", err)
	}
	defer tunDev.Close()

	b.tracker = proxy.NewConnTracker()

	var geoMgr *geoip.Manager
	if len(b.cfg.GeoIP) > 0 {
		entries := make([]geoip.GeoIPEntry, len(b.cfg.GeoIP))
		for i, g := range b.cfg.GeoIP {
			entries[i] = geoip.GeoIPEntry{Name: g.Name, Path: g.Path, Refresh: g.Refresh}
		}
		var err error
		cacheDir := filepath.Join(b.cfg.CacheDir, "geoip")
		geoMgr, err = geoip.NewManager(entries, cacheDir, b.outlineClient, b.logger)
		if err != nil {
			return fmt.Errorf("loading geoip databases: %w", err)
		}
		defer geoMgr.Close()
		geoMgr.StartRefresh(ctx)
	}

	router := routing.NewRouter(b.cfg.Routing, geoMgr, b.logger)

	downloader := routing.NewDownloader(b.outlineClient, router, b.cfg.Routing, b.logger)
	downloader.Start(ctx)

	tcpProxy := proxy.NewTCPProxy(router, dialers, b.tracker, b.logger)
	tcpProxy.SetupForwarder(tunDev.Stack)

	udpProxy := proxy.NewUDPProxy(router, dialers, b.tracker, b.logger)
	udpProxy.SetupForwarder(tunDev.Stack)

	b.logger.Info("proxies configured on gVisor stack")

	if b.cfg.DNS.Enabled {
		records := buildDNSRecords(b.cfg.DNS)
		rules := buildDNSRules(b.cfg.DNS, b.logger)
		dnsServer := dns.New(b.cfg.DNS.Listen, b.cfg.DNS.Upstream, records, rules, b.logger)
		if err := dnsServer.Start(ctx); err != nil {
			return fmt.Errorf("starting dns server: %w", err)
		}
		defer dnsServer.Stop()
	}

	if b.cfg.MTProxy.Enabled {
		if err := b.startMTProxy(ctx, dialers); err != nil {
			return fmt.Errorf("starting mtproxy: %w", err)
		}
	}

	wgLogger := newWireGuardLogger(b.logger, b.cfg.ParseLogLevel())
	b.wgDev = device.NewDevice(tunDev, conn.NewDefaultBind(), wgLogger)
	defer b.wgDev.Close()

	for name, peer := range b.cfg.Peers {
		b.logger.Info("configuring peer", "name", name, "public_key", peer.PublicKey, "allowed_ips", peer.AllowedIPs)
	}

	uapi, err := b.cfg.WireGuard.ToUAPI(b.cfg.Peers)
	if err != nil {
		return fmt.Errorf("generating UAPI config: %w", err)
	}
	if err := b.wgDev.IpcSet(uapi); err != nil {
		return fmt.Errorf("applying wireguard config: %w", err)
	}

	if err := b.wgDev.Up(); err != nil {
		return fmt.Errorf("bringing up wireguard: %w", err)
	}

	// TODO: peer monitor disabled for now
	// b.peerMon = newPeerMonitor(b.wgDev, b.cfg.Peers, b.logger)
	// go b.peerMon.run(ctx)

	if b.cfg.Telegram.Enabled {
		bot := tgbot.NewBot(b.cfg.Telegram.Token, b.cfg.Telegram.ChatID)
		obs := observer.New(bot, b, time.Duration(b.cfg.Telegram.Interval)*time.Second, b.cfg.Telegram.ChatID, b.logger)
		go obs.Run(ctx)
		b.logger.Info("telegram observer started", "interval", b.cfg.Telegram.Interval)
	}

	b.logger.Info("bridge running",
		"wg_address", addr.String(),
		"wg_port", b.cfg.WireGuard.ListenPort,
	)

	<-ctx.Done()
	b.logger.Info("shutting down bridge")
	return nil
}

func (b *Bridge) Reload() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.logger.Info("reloading configuration", "path", b.configPath)

	newCfg, err := config.Load(b.configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	newDefault := newCfg.DefaultOutline()
	oldDefault := b.cfg.DefaultOutline()
	if newDefault.Transport != oldDefault.Transport {
		b.logger.Info("default outline transport changed, reconnecting",
			"old", config.RedactTransport(oldDefault.Transport),
			"new", config.RedactTransport(newDefault.Transport),
		)
		newClient, err := outline.NewClient(newDefault.Transport)
		if err != nil {
			return fmt.Errorf("creating new default outline client: %w", err)
		}
		b.outlineClient.Swap(newClient)
		b.logger.Info("default outline client swapped")
	}

	diff := config.DiffPeers(b.cfg.Peers, newCfg.Peers)

	for name, peer := range diff.Removed {
		b.logger.Info("removing peer", "name", name, "public_key", peer.PublicKey, "allowed_ips", peer.AllowedIPs)

		uapi, err := config.PeerUAPIRemove(peer.PublicKey)
		if err != nil {
			b.logger.Error("failed to generate remove UAPI", "err", err)
			continue
		}
		if err := b.wgDev.IpcSet(uapi); err != nil {
			b.logger.Error("failed to remove peer via UAPI", "err", err)
			continue
		}

		peerIPs := peerAllowedIPs(peer)
		for _, ip := range peerIPs {
			closed := b.tracker.CloseBySource(ip)
			if closed > 0 {
				b.logger.Info("closed connections for removed peer", "ip", ip, "count", closed)
			}
		}
	}

	for name, peer := range diff.Added {
		b.logger.Info("adding peer", "name", name, "public_key", peer.PublicKey, "allowed_ips", peer.AllowedIPs)

		uapi, err := config.PeerUAPIAdd(peer)
		if err != nil {
			b.logger.Error("failed to generate add UAPI", "err", err)
			continue
		}
		if err := b.wgDev.IpcSet(uapi); err != nil {
			b.logger.Error("failed to add peer via UAPI", "err", err)
			continue
		}
	}

	b.cfg = newCfg
	// TODO: peer monitor disabled for now
	// if b.peerMon != nil {
	// 	b.peerMon.updatePeers(newCfg.Peers)
	// }

	b.logger.Info("configuration reloaded",
		"peers_added", len(diff.Added),
		"peers_removed", len(diff.Removed),
	)
	return nil
}

func (b *Bridge) startMTProxy(ctx context.Context, dialers *proxy.DialerSet) error {
	secrets := make([]mpcrypto.Secret, 0, len(b.cfg.MTProxy.Secrets))
	for _, s := range b.cfg.MTProxy.Secrets {
		secret, err := mpcrypto.ParseSecret(s)
		if err != nil {
			return fmt.Errorf("parsing mtproxy secret: %w", err)
		}
		secrets = append(secrets, secret)
	}

	var dialer mtproxy.StreamDialer = b.outlineClient
	if name := b.cfg.MTProxy.Outline; name != "" && name != "default" {
		if d, ok := dialers.Outlines[name]; ok {
			dialer = d
		}
	}

	endpoints := telegram.NewEndpointManager(b.cfg.MTProxy.Endpoints)

	serverCfg := mtproxy.ServerConfig{
		ListenAddrs: b.cfg.MTProxy.Listen,
		Secrets:     secrets,
	}
	if b.cfg.MTProxy.FakeTLS.Enabled {
		serverCfg.FakeTLS = &mtproxy.FakeTLSConfig{
			MaxClockSkewSec:     b.cfg.MTProxy.FakeTLS.MaxClockSkewSeconds,
			ReplayCacheTTLHours: b.cfg.MTProxy.FakeTLS.ReplayCacheTTLHours,
		}
	}

	srv := mtproxy.NewServer(serverCfg, dialer, endpoints, b.logger)
	go func() {
		if err := srv.Start(ctx); err != nil {
			b.logger.Error("mtproxy exited", "err", err)
		}
	}()

	b.logger.Info("mtproxy server started", "listen", b.cfg.MTProxy.Listen, "secrets", len(secrets), "fake_tls", b.cfg.MTProxy.FakeTLS.Enabled)
	return nil
}

// PeerStatuses implements observer.StatusProvider.
func (b *Bridge) PeerStatuses() []observer.PeerStatus {
	b.mu.Lock()
	peers := b.cfg.Peers
	b.mu.Unlock()

	statuses := b.getPeerStatuses()
	statusMap := make(map[string]peerStatus, len(statuses))
	for _, st := range statuses {
		pubB64 := hexToBase64(st.publicKeyHex)
		statusMap[pubB64] = st
	}

	var result []observer.PeerStatus
	for name, peer := range peers {
		if peer.Disabled {
			continue
		}
		ps := observer.PeerStatus{
			Name:      name,
			PublicKey: peer.PublicKey,
		}
		if st, ok := statusMap[peer.PublicKey]; ok {
			if st.lastHandshakeSec > 0 {
				ps.LastHandshake = time.Unix(st.lastHandshakeSec, st.lastHandshakeNsec)
			}
			ps.RxBytes = st.rxBytes
			ps.TxBytes = st.txBytes
		}
		peerIPs := peerAllowedIPs(peer)
		for _, ip := range peerIPs {
			ps.ActiveConnections += b.tracker.CountBySource(ip)
		}
		result = append(result, ps)
	}
	return result
}

// getPeerStatuses reads peer status from the WireGuard device via IPC.
func (b *Bridge) getPeerStatuses() []peerStatus {
	if b.wgDev == nil {
		return nil
	}
	ipcStr, err := b.wgDev.IpcGet()
	if err != nil {
		b.logger.Error("failed to get IPC status", "err", err)
		return nil
	}

	var statuses []peerStatus
	var current *peerStatus

	scanner := bufio.NewScanner(strings.NewReader(ipcStr))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			if current != nil {
				statuses = append(statuses, *current)
			}
			current = &peerStatus{publicKeyHex: value}
		case "last_handshake_time_sec":
			if current != nil {
				current.lastHandshakeSec, _ = strconv.ParseInt(value, 10, 64)
			}
		case "last_handshake_time_nsec":
			if current != nil {
				current.lastHandshakeNsec, _ = strconv.ParseInt(value, 10, 64)
			}
		case "rx_bytes":
			if current != nil {
				current.rxBytes, _ = strconv.ParseInt(value, 10, 64)
			}
		case "tx_bytes":
			if current != nil {
				current.txBytes, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	}
	if current != nil {
		statuses = append(statuses, *current)
	}
	return statuses
}

func peerAllowedIPs(peer config.PeerConfig) []netip.Addr {
	var addrs []netip.Addr
	for _, cidr := range strings.Split(peer.AllowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			addrs = append(addrs, prefix.Addr())
		} else if addr, err := netip.ParseAddr(cidr); err == nil {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func (b *Bridge) startHealthChecker(ctx context.Context, name string, dialer *outline.SwappableClient, interval time.Duration, target string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	check := func() {
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		conn, err := dialer.DialStream(checkCtx, target)
		if err != nil {
			b.logger.Warn("outline health check failed", "name", name, "target", target, "err", err)
			return
		}
		conn.Close()
		b.logger.Debug("outline health check passed", "name", name, "target", target)
	}

	check()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func newWireGuardLogger(logger *slog.Logger, level slog.Level) *device.Logger {
	wgLog := logger.With("component", "wireguard")
	l := &device.Logger{
		Errorf: func(format string, args ...any) {
			wgLog.Error(fmt.Sprintf(format, args...))
		},
	}
	if level <= slog.LevelDebug {
		l.Verbosef = func(format string, args ...any) {
			wgLog.Debug(fmt.Sprintf(format, args...))
		}
	}
	return l
}

func buildDNSRules(cfg config.DNSConfig, logger *slog.Logger) []dns.Rule {
	rules := make([]dns.Rule, 0, len(cfg.Rules))
	for _, rc := range cfg.Rules {
		rule := dns.Rule{
			Name:     rc.Name,
			Action:   rc.Action,
			Upstream: rc.Upstream,
		}
		if rule.Action == "upstream" && !strings.Contains(rule.Upstream, ":") {
			rule.Upstream += ":53"
		}
		for _, d := range rc.Domains {
			rule.Patterns = append(rule.Patterns, dns.ParseDomainPattern(d))
		}
		if len(rc.Lists) > 0 {
			var lists []dns.ListEntry
			for _, l := range rc.Lists {
				refresh := time.Duration(l.Refresh) * time.Second
				if refresh == 0 {
					refresh = 86400 * time.Second
				}
				format := l.Format
				if format == "" {
					format = "domains"
				}
				lists = append(lists, dns.ListEntry{
					URL:     l.URL,
					Format:  format,
					Refresh: refresh,
				})
			}
			rule.Blocklist = dns.NewBlocklistLoader(lists, logger)
		}
		rules = append(rules, rule)
	}
	return rules
}

func buildDNSRecords(cfg config.DNSConfig) map[string]dns.Record {
	records := make(map[string]dns.Record, len(cfg.Records))
	for name, rc := range cfg.Records {
		fqdn := strings.ToLower(name)
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		var rec dns.Record
		rec.TTL = rc.TTL
		for _, s := range rc.A {
			if addr, err := netip.ParseAddr(s); err == nil {
				rec.A = append(rec.A, addr)
			}
		}
		for _, s := range rc.AAAA {
			if addr, err := netip.ParseAddr(s); err == nil {
				rec.AAAA = append(rec.AAAA, addr)
			}
		}
		records[fqdn] = rec
	}
	return records
}
