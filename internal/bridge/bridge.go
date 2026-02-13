package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
	"github.com/blikh/wireguard-outline-bridge/internal/outline"
	"github.com/blikh/wireguard-outline-bridge/internal/proxy"
	"github.com/blikh/wireguard-outline-bridge/internal/routing"
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
	b.logger.Info("default outline client created", "name", defaultCfg.Name, "transport", defaultCfg.Transport)

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

	router := routing.NewRouter(b.cfg.Routing, b.logger)

	downloader := routing.NewDownloader(b.outlineClient, router, b.cfg.Routing, b.logger)
	downloader.Start(ctx)

	tcpProxy := proxy.NewTCPProxy(router, dialers, b.tracker, b.logger)
	tcpProxy.SetupForwarder(tunDev.Stack)

	udpProxy := proxy.NewUDPProxy(router, dialers, b.tracker, b.logger)
	udpProxy.SetupForwarder(tunDev.Stack)

	b.logger.Info("proxies configured on gVisor stack")

	wgLogger := device.NewLogger(device.LogLevelVerbose, "wireguard: ")
	b.wgDev = device.NewDevice(tunDev, conn.NewDefaultBind(), wgLogger)
	defer b.wgDev.Close()

	for _, peer := range b.cfg.WireGuard.Peers {
		b.logger.Info("configuring peer", "public_key", peer.PublicKey, "allowed_ips", peer.AllowedIPs)
	}

	uapi, err := b.cfg.WireGuard.ToUAPI()
	if err != nil {
		return fmt.Errorf("generating UAPI config: %w", err)
	}
	if err := b.wgDev.IpcSet(uapi); err != nil {
		return fmt.Errorf("applying wireguard config: %w", err)
	}

	if err := b.wgDev.Up(); err != nil {
		return fmt.Errorf("bringing up wireguard: %w", err)
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
			"old", oldDefault.Transport,
			"new", newDefault.Transport,
		)
		newClient, err := outline.NewClient(newDefault.Transport)
		if err != nil {
			return fmt.Errorf("creating new default outline client: %w", err)
		}
		b.outlineClient.Swap(newClient)
		b.logger.Info("default outline client swapped")
	}

	diff := config.DiffPeers(b.cfg.WireGuard.Peers, newCfg.WireGuard.Peers)

	for _, peer := range diff.Removed {
		b.logger.Info("removing peer", "public_key", peer.PublicKey, "allowed_ips", peer.AllowedIPs)

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

	for _, peer := range diff.Added {
		b.logger.Info("adding peer", "public_key", peer.PublicKey, "allowed_ips", peer.AllowedIPs)

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

	b.logger.Info("configuration reloaded",
		"peers_added", len(diff.Added),
		"peers_removed", len(diff.Removed),
	)
	return nil
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
