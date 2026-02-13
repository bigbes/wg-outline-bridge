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

	client, err := outline.NewClient(b.cfg.Outline.Transport)
	if err != nil {
		return fmt.Errorf("creating outline client: %w", err)
	}
	b.outlineClient = outline.NewSwappableClient(client)
	b.logger.Info("outline client created", "transport", b.cfg.Outline.Transport)

	if b.cfg.Outline.HealthCheck.Enabled {
		go b.startHealthChecker(ctx,
			time.Duration(b.cfg.Outline.HealthCheck.Interval)*time.Second,
			b.cfg.Outline.HealthCheck.Target)
		b.logger.Info("outline health checker started",
			"interval", b.cfg.Outline.HealthCheck.Interval,
			"target", b.cfg.Outline.HealthCheck.Target)
	}

	tunDev, err := wg.CreateNetTUNWithStack([]netip.Addr{addr}, b.cfg.WireGuard.MTU, b.logger)
	if err != nil {
		return fmt.Errorf("creating netstack tun: %w", err)
	}
	defer tunDev.Close()

	b.tracker = proxy.NewConnTracker()

	tcpProxy := proxy.NewTCPProxy(b.outlineClient, b.tracker, b.logger)
	tcpProxy.SetupForwarder(tunDev.Stack)

	udpProxy := proxy.NewUDPProxy(b.outlineClient, b.tracker, b.logger)
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

	if newCfg.Outline.Transport != b.cfg.Outline.Transport {
		b.logger.Info("outline transport changed, reconnecting",
			"old", b.cfg.Outline.Transport,
			"new", newCfg.Outline.Transport,
		)
		newClient, err := outline.NewClient(newCfg.Outline.Transport)
		if err != nil {
			return fmt.Errorf("creating new outline client: %w", err)
		}
		b.outlineClient.Swap(newClient)
		b.logger.Info("outline client swapped")
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

func (b *Bridge) startHealthChecker(ctx context.Context, interval time.Duration, target string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	check := func() {
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		conn, err := b.outlineClient.DialStream(checkCtx, target)
		if err != nil {
			b.logger.Warn("outline health check failed", "target", target, "err", err)
			return
		}
		conn.Close()
		b.logger.Debug("outline health check passed", "target", target)
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
