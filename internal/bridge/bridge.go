package bridge

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
	"github.com/blikh/wireguard-outline-bridge/internal/dns"
	"github.com/blikh/wireguard-outline-bridge/internal/geoip"
	"github.com/blikh/wireguard-outline-bridge/internal/miniapp"
	"github.com/blikh/wireguard-outline-bridge/internal/mtproxy"
	mpcrypto "github.com/blikh/wireguard-outline-bridge/internal/mtproxy/crypto"
	"github.com/blikh/wireguard-outline-bridge/internal/mtproxy/telegram"
	"github.com/blikh/wireguard-outline-bridge/internal/observer"
	"github.com/blikh/wireguard-outline-bridge/internal/proxy"
	"github.com/blikh/wireguard-outline-bridge/internal/proxyserver"
	"github.com/blikh/wireguard-outline-bridge/internal/routing"
	"github.com/blikh/wireguard-outline-bridge/internal/statsdb"
	tgbot "github.com/blikh/wireguard-outline-bridge/internal/telegram"
	"github.com/blikh/wireguard-outline-bridge/internal/upstream"
	outlineprovider "github.com/blikh/wireguard-outline-bridge/internal/upstream/providers/outline"
	wg "github.com/blikh/wireguard-outline-bridge/internal/wireguard"
)

type Bridge struct {
	configPath string
	logger     *slog.Logger
	startTime  time.Time

	mu        sync.Mutex
	cfg       *config.Config
	wgDev     wg.Device
	upstreams *upstream.Manager
	tracker   *proxy.ConnTracker
	peerMon       *peerMonitor
	mtSrv         *mtproxy.Server
	statsStore    *statsdb.Store
}

func New(configPath string, cfg *config.Config, logger *slog.Logger) *Bridge {
	return &Bridge{
		configPath: configPath,
		cfg:        cfg,
		logger:     logger,
		startTime:  time.Now(),
	}
}

func (b *Bridge) Run(ctx context.Context) error {
	addr, _, err := b.cfg.WireGuard.ParseAddress()
	if err != nil {
		return fmt.Errorf("parsing wireguard address: %w", err)
	}

	// Initialize upstream manager.
	b.upstreams = upstream.NewManager(ctx, b.logger)
	b.upstreams.RegisterFactory(outlineprovider.Factory{})

	specs := b.cfg.ToUpstreamSpecs()
	if err := b.upstreams.Apply(specs); err != nil {
		return fmt.Errorf("applying upstream specs: %w", err)
	}
	b.logger.Info("upstreams initialized", "count", len(specs))

	// Start upstream event listener for logging.
	go b.upstreamEventLoop(ctx)

	dialers := proxy.NewDialerSet(&upstreamAdapter{b.upstreams})

	backend := wg.NewBackend(b.cfg.WireGuard.Mode)
	b.logger.Info("using wireguard backend", "backend", backend.Name())

	tunDevice, netStack, tunCloser, err := backend.CreateTUN([]netip.Addr{addr}, b.cfg.WireGuard.MTU, b.logger)
	if err != nil {
		return fmt.Errorf("creating netstack tun: %w", err)
	}
	defer tunCloser()

	b.tracker = proxy.NewConnTracker()

	if b.cfg.Database.Path != "" {
		store, err := statsdb.Open(b.cfg.Database.Path, b.logger)
		if err != nil {
			return fmt.Errorf("opening stats db: %w", err)
		}
		b.statsStore = store
		if err := store.SetDaemonStartTime(time.Now()); err != nil {
			b.logger.Error("failed to set daemon start time", "err", err)
		}
		var statsWg sync.WaitGroup
		statsWg.Add(1)
		go func() {
			defer statsWg.Done()
			b.statsFlushLoop(ctx, time.Duration(b.cfg.Database.FlushInterval)*time.Second)
		}()
		defer func() {
			statsWg.Wait()
			store.Close()
		}()
		b.logger.Info("stats db opened", "path", b.cfg.Database.Path, "flush_interval", b.cfg.Database.FlushInterval)

		// Import file-based peers into DB if DB is empty
		dbPeers, err := store.ListPeers()
		if err != nil {
			b.logger.Error("failed to list db peers", "err", err)
		}
		if len(dbPeers) == 0 && len(b.cfg.Peers) > 0 {
			imported, err := store.ImportPeers(b.cfg.Peers)
			if err != nil {
				b.logger.Error("failed to import peers to database", "err", err)
			} else if imported > 0 {
				b.logger.Info("imported file peers to database", "count", imported)
			}
		} else if len(dbPeers) > 0 {
			b.cfg.Peers = dbPeers
		}

		// Import file-based secrets into DB if DB is empty
		dbSecrets, err := store.ListSecrets()
		if err != nil {
			b.logger.Error("failed to list db secrets", "err", err)
		}
		if len(dbSecrets) == 0 && len(b.cfg.MTProxy.Secrets) > 0 {
			imported, err := store.ImportSecrets(b.cfg.MTProxy.Secrets)
			if err != nil {
				b.logger.Error("failed to import secrets to database", "err", err)
			} else if imported > 0 {
				b.logger.Info("imported file secrets to database", "count", imported)
			}
		} else if len(dbSecrets) > 0 {
			b.cfg.MTProxy.Secrets = dbSecrets
		}

		// Import file-based proxy servers into DB if DB is empty
		dbProxies, err := store.ListProxyServers()
		if err != nil {
			b.logger.Error("failed to list db proxy servers", "err", err)
		}
		if len(dbProxies) == 0 && len(b.cfg.Proxies) > 0 {
			imported, err := store.ImportProxyServers(b.cfg.Proxies)
			if err != nil {
				b.logger.Error("failed to import proxy servers to database", "err", err)
			} else if imported > 0 {
				b.logger.Info("imported file proxy servers to database", "count", imported)
			}
		} else if len(dbProxies) > 0 {
			b.cfg.Proxies = dbProxies
		}

		// Import file-based upstreams into DB if DB is empty
		dbUpstreams, err := store.ListUpstreams()
		if err != nil {
			b.logger.Error("failed to list db upstreams", "err", err)
		}
		if len(dbUpstreams) == 0 && len(b.cfg.Upstreams) > 0 {
			imported, err := store.ImportUpstreams(b.cfg.Upstreams)
			if err != nil {
				b.logger.Error("failed to import upstreams to database", "err", err)
			} else if imported > 0 {
				b.logger.Info("imported file upstreams to database", "count", imported)
			}
		} else if len(dbUpstreams) > 0 {
			b.cfg.Upstreams = dbUpstreams
		}
	}

	var geoMgr *geoip.Manager
	if len(b.cfg.GeoIP) > 0 {
		entries := make([]geoip.GeoIPEntry, len(b.cfg.GeoIP))
		for i, g := range b.cfg.GeoIP {
			entries[i] = geoip.GeoIPEntry{Name: g.Name, Path: g.Path, Refresh: g.Refresh}
		}
		var err error
		cacheDir := filepath.Join(b.cfg.CacheDir, "geoip")
		geoMgr, err = geoip.NewManager(entries, cacheDir, b.upstreams.DefaultStreamDialer(), b.logger)
		if err != nil {
			return fmt.Errorf("loading geoip databases: %w", err)
		}
		defer geoMgr.Close()
		geoMgr.StartRefresh(ctx)
	}

	router := routing.NewRouter(b.cfg.Routing, geoMgr, b.logger)

	downloader := routing.NewDownloader(b.upstreams.DefaultStreamDialer(), router, b.cfg.Routing, b.logger)
	downloader.Start(ctx)

	tcpProxy := proxy.NewTCPProxy(router, dialers, b.tracker, b.logger)
	tcpProxy.SetupForwarder(netStack)

	udpProxy := proxy.NewUDPProxy(router, dialers, b.tracker, b.logger)
	if b.cfg.DNS.Enabled {
		udpProxy.SetDNSTarget(b.cfg.DNS.Listen)
	}
	udpProxy.SetupForwarder(netStack)

	b.logger.Info("proxies configured on gVisor stack")

	if b.cfg.MTProxy.Enabled {
		if err := b.startMTProxy(ctx, dialers); err != nil {
			return fmt.Errorf("starting mtproxy: %w", err)
		}
	}

	if len(b.cfg.Proxies) > 0 {
		if err := b.startProxyServers(ctx, dialers); err != nil {
			return fmt.Errorf("starting proxy servers: %w", err)
		}
	}

	wgDev, err := backend.CreateDevice(tunDevice, b.logger, b.cfg.ParseLogLevel())
	if err != nil {
		return fmt.Errorf("creating wireguard device: %w", err)
	}
	b.wgDev = wgDev
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

	if b.cfg.DNS.Enabled {
		records := buildDNSRecords(b.cfg.DNS)
		rules := buildDNSRules(b.cfg.DNS, b.logger)
		dnsServer := dns.New(b.cfg.DNS.Listen, b.cfg.DNS.Upstream, records, rules, b.logger)
		if err := dnsServer.Start(ctx); err != nil {
			return fmt.Errorf("starting dns server: %w", err)
		}
		defer dnsServer.Stop()
	}

	b.peerMon = newPeerMonitor(b.wgDev, b.cfg.Peers, b.logger)
	go b.peerMon.run(ctx)

	if b.cfg.Telegram.Enabled {
		bot := tgbot.NewBot(b.cfg.Telegram.Token, b.cfg.Telegram.ChatID)
		obs := observer.New(bot, b, b, b, time.Duration(b.cfg.Telegram.Interval)*time.Second, b.cfg.Telegram.ChatID, b.logger)
		go obs.Run(ctx)
		b.logger.Info("telegram observer started", "interval", b.cfg.Telegram.Interval)

		if b.cfg.MiniApp.Enabled {
			acmeDir := ""
			if b.cfg.CacheDir != "" {
				acmeDir = filepath.Join(b.cfg.CacheDir, "acme", "miniapp")
			}
			maSrv := miniapp.New(b, b, b, bot, b.statsStore, b.cfg.Telegram.Token, b.cfg.Telegram.AllowedUsers, b.cfg.MiniApp.Listen, b.cfg.MiniApp.Domain, b.cfg.MiniApp.ACMEEmail, acmeDir, b.logger)
			go func() {
				if err := maSrv.Run(ctx); err != nil {
					b.logger.Error("miniapp server error", "err", err)
				}
			}()
			if err := bot.SetChatMenuButton(ctx, maSrv.URL(), "Admin"); err != nil {
				b.logger.Error("failed to set chat menu button", "err", err)
			} else {
				b.logger.Info("telegram mini app registered", "url", maSrv.URL())
			}
		}
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

	// If DB is available, load peers and secrets from it
	if b.statsStore != nil {
		dbPeers, err := b.statsStore.ListPeers()
		if err != nil {
			b.logger.Error("failed to load peers from database", "err", err)
		} else if len(dbPeers) > 0 {
			newCfg.Peers = dbPeers
		}
		dbSecrets, err := b.statsStore.ListSecrets()
		if err != nil {
			b.logger.Error("failed to load secrets from database", "err", err)
		} else if len(dbSecrets) > 0 {
			newCfg.MTProxy.Secrets = dbSecrets
		}
		dbUpstreams, err := b.statsStore.ListUpstreams()
		if err != nil {
			b.logger.Error("failed to load upstreams from database", "err", err)
		} else if len(dbUpstreams) > 0 {
			newCfg.Upstreams = dbUpstreams
		}
	}

	// Reload upstreams.
	specs := newCfg.ToUpstreamSpecs()
	if err := b.upstreams.Apply(specs); err != nil {
		b.logger.Error("failed to reload upstreams", "err", err)
	} else {
		b.logger.Info("upstreams reloaded", "count", len(specs))
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

	// Update MTProxy secrets at runtime
	if b.mtSrv != nil && len(newCfg.MTProxy.Secrets) > 0 {
		secrets := make([]mpcrypto.Secret, 0, len(newCfg.MTProxy.Secrets))
		for _, s := range newCfg.MTProxy.Secrets {
			secret, err := mpcrypto.ParseSecret(s)
			if err != nil {
				b.logger.Error("failed to parse mtproxy secret during reload", "err", err)
				continue
			}
			secrets = append(secrets, secret)
		}
		if len(secrets) > 0 {
			b.mtSrv.UpdateSecrets(secrets, newCfg.MTProxy.Secrets)
		}
	}

	if b.peerMon != nil {
		b.peerMon.updatePeers(newCfg.Peers)
	}

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

	group := b.cfg.MTProxy.UpstreamGroup
	if group == "" {
		group = "default"
	}
	var dialer mtproxy.StreamDialer
	if d := b.upstreams.StreamDialerForGroup(group); d != nil {
		dialer = d
	} else {
		dialer = b.upstreams.DefaultStreamDialer()
	}

	endpoints := telegram.NewEndpointManager(b.cfg.MTProxy.Endpoints)

	serverCfg := mtproxy.ServerConfig{
		ListenAddrs: b.cfg.MTProxy.Listen,
		Secrets:     secrets,
		SecretHexes: b.cfg.MTProxy.Secrets,
	}
	if b.cfg.MTProxy.FakeTLS.Enabled {
		serverCfg.FakeTLS = &mtproxy.FakeTLSConfig{
			AllowedSNIs:         b.cfg.MTProxy.FakeTLS.SNI,
			MaxClockSkewSec:     b.cfg.MTProxy.FakeTLS.MaxClockSkewSeconds,
			ReplayCacheTTLHours: b.cfg.MTProxy.FakeTLS.ReplayCacheTTLHours,
		}
	}

	srv := mtproxy.NewServer(serverCfg, dialer, endpoints, b.logger)
	b.mtSrv = srv

	if err := srv.Listen(); err != nil {
		return fmt.Errorf("mtproxy: %w", err)
	}
	go srv.Serve(ctx)

	if b.cfg.MTProxy.StatsAddr != "" {
		statsSrv := mtproxy.NewStatsServer(b.cfg.MTProxy.StatsAddr, srv, b.logger)
		go func() {
			if err := statsSrv.Start(ctx); err != nil {
				b.logger.Error("mtproxy stats server exited", "err", err)
			}
		}()
	}

	b.logger.Info("mtproxy server started", "listen", b.cfg.MTProxy.Listen, "secrets", len(secrets), "fake_tls", b.cfg.MTProxy.FakeTLS.Enabled)
	return nil
}

func (b *Bridge) startProxyServers(ctx context.Context, dialers *proxy.DialerSet) error {
	for _, pcfg := range b.cfg.Proxies {
		group := pcfg.UpstreamGroup
		if group == "" {
			group = "default"
		}
		var dialer proxyserver.StreamDialer
		if d := b.upstreams.StreamDialerForGroup(group); d != nil {
			dialer = d
		} else {
			dialer = b.upstreams.DefaultStreamDialer()
		}

		acmeDir := ""
		if pcfg.TLS.Domain != "" && b.cfg.CacheDir != "" {
			acmeDir = filepath.Join(b.cfg.CacheDir, "acme", pcfg.Name)
		}

		srv := proxyserver.NewServer(proxyserver.ServerConfig{
			Name:      pcfg.Name,
			Type:      pcfg.Type,
			Listen:    pcfg.Listen,
			Username:  pcfg.Username,
			Password:  pcfg.Password,
			CertFile:  pcfg.TLS.CertFile,
			KeyFile:   pcfg.TLS.KeyFile,
			Domain:    pcfg.TLS.Domain,
			ACMEEmail: pcfg.TLS.ACMEEmail,
			ACMEDir:   acmeDir,
		}, dialer, b.logger)

		if err := srv.Listen(); err != nil {
			return fmt.Errorf("proxy %q: %w", pcfg.Name, err)
		}
		go srv.Serve(ctx)

		b.logger.Info("proxy server started", "name", pcfg.Name, "type", pcfg.Type, "listen", pcfg.Listen)
	}
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

	var dbStats map[string]statsdb.WGPeerRecord
	if b.statsStore != nil {
		dbStats, _ = b.statsStore.GetWGPeerStats()
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
		if rec, ok := dbStats[peer.PublicKey]; ok {
			ps.RxTotal = rec.RxTotal
			ps.TxTotal = rec.TxTotal
			ps.ConnectionsTotal = rec.ConnectionsTotal
		}
		peerIPs := peerAllowedIPs(peer)
		for _, ip := range peerIPs {
			ps.ActiveConnections += b.tracker.CountBySource(ip)
		}
		result = append(result, ps)
	}
	return result
}

// MTProxyStatus implements observer.StatusProvider.
func (b *Bridge) MTProxyStatus() observer.MTProxyStatus {
	if b.mtSrv == nil {
		return observer.MTProxyStatus{}
	}

	snap := b.mtSrv.StatsSnapshot()
	st := observer.MTProxyStatus{
		Enabled:           true,
		Connections:       snap.Connections.Load(),
		ActiveConnections: snap.ActiveConnections.Load(),
		TLSConnections:    snap.TLSConnections.Load(),
		HandshakeErrors:   snap.HandshakeErrors.Load(),
		BackendDialErrors: snap.BackendDialErrors.Load(),
		BytesC2B:          snap.BytesClientToBackend.Load(),
		BytesB2C:          snap.BytesBackendToClient.Load(),
	}

	secretSnap := b.mtSrv.SecretStatsSnapshot()

	var dbStats map[string]statsdb.MTSecretRecord
	if b.statsStore != nil {
		dbStats, _ = b.statsStore.GetMTSecretStats()
	}

	// Build per-secret client entries from both session and DB.
	secretKeys := make(map[string]struct{})
	for _, ss := range secretSnap {
		secretKeys[ss.SecretHex] = struct{}{}
	}
	for key := range dbStats {
		secretKeys[key] = struct{}{}
	}

	// Index session snapshots by hex.
	sessionByHex := make(map[string]mtproxy.SecretSnapshot, len(secretSnap))
	for _, ss := range secretSnap {
		sessionByHex[ss.SecretHex] = ss
	}

	for key := range secretKeys {
		c := observer.MTProxyClient{Secret: key}
		if ss, ok := sessionByHex[key]; ok {
			if ss.LastConnectionUnix > 0 {
				c.LastConnection = time.Unix(ss.LastConnectionUnix, 0)
			}
			c.Connections = ss.Connections
			c.BytesC2B = ss.BytesC2B
			c.BytesB2C = ss.BytesB2C
		}
		if rec, ok := dbStats[key]; ok {
			if c.LastConnection.IsZero() && rec.LastConnectionUnix > 0 {
				c.LastConnection = time.Unix(rec.LastConnectionUnix, 0)
			}
			c.ConnectionsTotal = rec.ConnectionsTotal
			c.BytesC2BTotal = rec.BytesC2BTotal
			c.BytesB2CTotal = rec.BytesB2CTotal
		}
		st.ConnectionsTotal += c.ConnectionsTotal
		st.BytesC2BTotal += c.BytesC2BTotal
		st.BytesB2CTotal += c.BytesB2CTotal
		st.BackendDialErrorsTotal += dbStats[key].BackendDialErrorsTotal
		st.Clients = append(st.Clients, c)
	}

	sort.Slice(st.Clients, func(i, j int) bool {
		return st.Clients[i].LastConnection.After(st.Clients[j].LastConnection)
	})

	return st
}

// UpstreamStatuses implements observer.StatusProvider.
func (b *Bridge) UpstreamStatuses() []observer.UpstreamStatus {
	statuses := b.upstreams.Statuses()
	result := make([]observer.UpstreamStatus, 0, len(statuses))
	for _, st := range statuses {
		result = append(result, observer.UpstreamStatus{
			Name:              st.Name,
			Type:              string(st.Type),
			Enabled:           st.Enabled,
			Default:           st.Default,
			State:             string(st.State),
			Groups:            st.Groups,
			RxBytes:           st.RxBytes,
			TxBytes:           st.TxBytes,
			ActiveConnections: st.ActiveConnections,
			LastError:         st.LastError,
		})
	}
	return result
}

// OutlineStatuses implements observer.StatusProvider (backward compat).
func (b *Bridge) OutlineStatuses() []observer.OutlineStatus {
	statuses := b.upstreams.Statuses()
	result := make([]observer.OutlineStatus, 0, len(statuses))
	for _, st := range statuses {
		result = append(result, observer.OutlineStatus{
			Name:              st.Name,
			Default:           st.Default,
			RxBytes:           st.RxBytes,
			TxBytes:           st.TxBytes,
			ActiveConnections: st.ActiveConnections,
		})
	}
	return result
}

// DaemonStatus implements observer.StatusProvider.
func (b *Bridge) DaemonStatus() observer.DaemonStatus {
	if b.statsStore == nil {
		return observer.DaemonStatus{StartTime: b.startTime}
	}
	t, err := b.statsStore.GetDaemonStartTime()
	if err != nil {
		return observer.DaemonStatus{StartTime: b.startTime}
	}
	return observer.DaemonStatus{StartTime: t}
}

// CurrentConfig returns the current config (thread-safe).
func (b *Bridge) CurrentConfig() *config.Config {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg
}

// AddPeer generates a new WireGuard peer, saves it to the database, and applies it to the running device.
func (b *Bridge) AddPeer(name string) (config.PeerConfig, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return config.PeerConfig{}, fmt.Errorf("database not configured")
	}

	if _, exists := b.cfg.Peers[name]; exists {
		return config.PeerConfig{}, fmt.Errorf("peer %q already exists", name)
	}

	privateKey, publicKey, err := config.GenerateKeyPair()
	if err != nil {
		return config.PeerConfig{}, fmt.Errorf("generating keys: %w", err)
	}

	presharedKey, err := config.GeneratePresharedKey()
	if err != nil {
		return config.PeerConfig{}, fmt.Errorf("generating preshared key: %w", err)
	}

	clientIP, err := config.NextPeerIP(b.cfg)
	if err != nil {
		return config.PeerConfig{}, fmt.Errorf("allocating IP: %w", err)
	}

	peer := config.PeerConfig{
		PrivateKey:   privateKey,
		PublicKey:    publicKey,
		PresharedKey: presharedKey,
		AllowedIPs:   clientIP + "/32",
	}

	if err := b.statsStore.UpsertPeer(name, peer); err != nil {
		return config.PeerConfig{}, fmt.Errorf("saving peer: %w", err)
	}

	if b.wgDev != nil {
		uapi, err := config.PeerUAPIAdd(peer)
		if err != nil {
			b.statsStore.DeletePeer(name)
			return config.PeerConfig{}, fmt.Errorf("generating UAPI: %w", err)
		}
		if err := b.wgDev.IpcSet(uapi); err != nil {
			b.statsStore.DeletePeer(name)
			return config.PeerConfig{}, fmt.Errorf("applying to wireguard: %w", err)
		}
	}

	b.cfg.Peers[name] = peer
	if b.peerMon != nil {
		b.peerMon.updatePeers(b.cfg.Peers)
	}

	b.logger.Info("peer added", "name", name, "public_key", publicKey, "allowed_ips", peer.AllowedIPs)
	return peer, nil
}

// DeletePeer removes a peer from the database and the running device.
func (b *Bridge) DeletePeer(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	peer, exists := b.cfg.Peers[name]
	if !exists {
		return fmt.Errorf("peer %q not found", name)
	}

	if _, _, err := b.statsStore.DeletePeer(name); err != nil {
		return fmt.Errorf("deleting from database: %w", err)
	}

	if b.wgDev != nil && !peer.Disabled {
		uapi, err := config.PeerUAPIRemove(peer.PublicKey)
		if err != nil {
			b.logger.Error("failed to generate remove UAPI", "name", name, "err", err)
		} else if err := b.wgDev.IpcSet(uapi); err != nil {
			b.logger.Error("failed to remove peer from wireguard", "name", name, "err", err)
		}
	}

	peerIPs := peerAllowedIPs(peer)
	for _, ip := range peerIPs {
		closed := b.tracker.CloseBySource(ip)
		if closed > 0 {
			b.logger.Info("closed connections for removed peer", "ip", ip, "count", closed)
		}
	}

	delete(b.cfg.Peers, name)
	if b.peerMon != nil {
		b.peerMon.updatePeers(b.cfg.Peers)
	}

	b.logger.Info("peer deleted", "name", name)
	return nil
}

// AddSecret generates a new MTProxy secret, saves it to the database.
// The MTProxy server needs a restart to pick up new secrets.
func (b *Bridge) AddSecret(secretType, comment string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return "", fmt.Errorf("database not configured")
	}

	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}

	secretHex := hex.EncodeToString(secret[:])
	switch secretType {
	case "faketls", "ee", "":
		secretHex = "ee" + secretHex
	case "padded", "dd":
		secretHex = "dd" + secretHex
	case "default":
		// no prefix
	default:
		return "", fmt.Errorf("unknown secret type: %s", secretType)
	}

	if err := b.statsStore.AddSecret(secretHex, comment); err != nil {
		return "", fmt.Errorf("saving secret: %w", err)
	}

	b.cfg.MTProxy.Secrets = append(b.cfg.MTProxy.Secrets, secretHex)

	b.logger.Info("mtproxy secret added", "type", secretType)
	return secretHex, nil
}

// DeleteSecret removes an MTProxy secret from the database.
// The MTProxy server needs a restart to stop accepting the deleted secret.
func (b *Bridge) DeleteSecret(secretHex string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	ok, err := b.statsStore.DeleteSecret(secretHex)
	if err != nil {
		return fmt.Errorf("deleting secret: %w", err)
	}
	if !ok {
		return fmt.Errorf("secret not found")
	}

	secrets := make([]string, 0, len(b.cfg.MTProxy.Secrets))
	for _, s := range b.cfg.MTProxy.Secrets {
		if s != secretHex {
			secrets = append(secrets, s)
		}
	}
	b.cfg.MTProxy.Secrets = secrets

	b.logger.Info("mtproxy secret deleted")
	return nil
}

// AddProxy saves a new proxy server config to the database.
// The bridge needs a restart to start serving the new proxy.
func (b *Bridge) AddProxy(p config.ProxyServerConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	for _, existing := range b.cfg.Proxies {
		if existing.Name == p.Name {
			return fmt.Errorf("proxy %q already exists", p.Name)
		}
	}

	if err := b.statsStore.AddProxyServer(p); err != nil {
		return fmt.Errorf("saving proxy: %w", err)
	}

	b.cfg.Proxies = append(b.cfg.Proxies, p)

	b.logger.Info("proxy server added", "name", p.Name, "type", p.Type, "listen", p.Listen)
	return nil
}

// DeleteProxy removes a proxy server config from the database.
// The bridge needs a restart to stop the proxy.
func (b *Bridge) DeleteProxy(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	found, err := b.statsStore.DeleteProxyServer(name)
	if err != nil {
		return fmt.Errorf("deleting proxy: %w", err)
	}
	if !found {
		return fmt.Errorf("proxy %q not found", name)
	}

	proxies := make([]config.ProxyServerConfig, 0, len(b.cfg.Proxies))
	for _, p := range b.cfg.Proxies {
		if p.Name != name {
			proxies = append(proxies, p)
		}
	}
	b.cfg.Proxies = proxies

	b.logger.Info("proxy server deleted", "name", name)
	return nil
}

// AddUpstream saves a new upstream config to the database and applies it.
func (b *Bridge) AddUpstream(u config.UpstreamConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	for _, existing := range b.cfg.Upstreams {
		if existing.Name == u.Name {
			return fmt.Errorf("upstream %q already exists", u.Name)
		}
	}

	if err := b.statsStore.AddUpstream(u); err != nil {
		return fmt.Errorf("saving upstream: %w", err)
	}

	b.cfg.Upstreams = append(b.cfg.Upstreams, u)

	if err := b.upstreams.Apply(b.cfg.ToUpstreamSpecs()); err != nil {
		b.logger.Error("failed to apply upstream specs", "err", err)
	}

	b.logger.Info("upstream added", "name", u.Name, "type", u.Type)
	return nil
}

// UpdateUpstream updates an existing upstream config in the database and re-applies.
func (b *Bridge) UpdateUpstream(u config.UpstreamConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	found := false
	for i, existing := range b.cfg.Upstreams {
		if existing.Name == u.Name {
			b.cfg.Upstreams[i] = u
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("upstream %q not found", u.Name)
	}

	if err := b.statsStore.UpdateUpstream(u); err != nil {
		return fmt.Errorf("updating upstream: %w", err)
	}

	if err := b.upstreams.Apply(b.cfg.ToUpstreamSpecs()); err != nil {
		b.logger.Error("failed to apply upstream specs", "err", err)
	}

	b.logger.Info("upstream updated", "name", u.Name)
	return nil
}

// DeleteUpstream removes an upstream config from the database and re-applies.
func (b *Bridge) DeleteUpstream(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	found, err := b.statsStore.DeleteUpstream(name)
	if err != nil {
		return fmt.Errorf("deleting upstream: %w", err)
	}
	if !found {
		return fmt.Errorf("upstream %q not found", name)
	}

	upstreams := make([]config.UpstreamConfig, 0, len(b.cfg.Upstreams))
	for _, u := range b.cfg.Upstreams {
		if u.Name != name {
			upstreams = append(upstreams, u)
		}
	}
	b.cfg.Upstreams = upstreams

	if err := b.upstreams.Apply(b.cfg.ToUpstreamSpecs()); err != nil {
		b.logger.Error("failed to apply upstream specs", "err", err)
	}

	b.logger.Info("upstream deleted", "name", name)
	return nil
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

func (b *Bridge) statsFlushLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.statsFlush()
			return
		case <-ticker.C:
			b.statsFlush()
		}
	}
}

func (b *Bridge) statsFlush() {
	store := b.statsStore
	if store == nil {
		return
	}

	statuses := b.getPeerStatuses()
	b.mu.Lock()
	peers := b.cfg.Peers
	b.mu.Unlock()

	nameByPub := make(map[string]string, len(peers))
	for name, peer := range peers {
		nameByPub[peer.PublicKey] = name
	}

	snapshots := make([]statsdb.WGPeerSnapshot, 0, len(statuses))
	for _, st := range statuses {
		pubB64 := hexToBase64(st.publicKeyHex)
		snapshots = append(snapshots, statsdb.WGPeerSnapshot{
			PublicKey:        pubB64,
			Name:             nameByPub[pubB64],
			LastHandshakeSec: st.lastHandshakeSec,
			RxBytes:          st.rxBytes,
			TxBytes:          st.txBytes,
		})
	}

	if len(snapshots) > 0 {
		if err := store.FlushWireGuardPeers(snapshots); err != nil {
			b.logger.Error("stats: failed to flush wg peers", "err", err)
		}
	}

	if b.mtSrv != nil {
		secretSnap := b.mtSrv.SecretStatsSnapshot()
		mtSnapshots := make([]statsdb.MTSecretSnapshot, 0, len(secretSnap))
		for _, ss := range secretSnap {
			mtSnapshots = append(mtSnapshots, statsdb.MTSecretSnapshot{
				SecretHex:          ss.SecretHex,
				LastConnectionUnix: ss.LastConnectionUnix,
				Connections:        ss.Connections,
				BytesC2B:           ss.BytesC2B,
				BytesB2C:           ss.BytesB2C,
				BackendDialErrors:  ss.BackendDialErrors,
			})
		}
		if len(mtSnapshots) > 0 {
			if err := store.FlushMTProxySecrets(mtSnapshots); err != nil {
				b.logger.Error("stats: failed to flush mtproxy secrets", "err", err)
			}
		}
	}
}

// upstreamAdapter wraps upstream.Manager to satisfy proxy.UpstreamProvider,
// bridging the identical-but-separate StreamDialer/PacketDialer interfaces.
type upstreamAdapter struct {
	mgr *upstream.Manager
}

func (a *upstreamAdapter) StreamDialerForGroup(group string) proxy.StreamDialer {
	return a.mgr.StreamDialerForGroup(group)
}

func (a *upstreamAdapter) PacketDialerForGroup(group string) proxy.PacketDialer {
	return a.mgr.PacketDialerForGroup(group)
}

func (b *Bridge) upstreamEventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-b.upstreams.Events():
			switch ev.NewState {
			case upstream.StateDegraded:
				b.logger.Warn("upstream degraded",
					"name", ev.Name, "err", ev.Error)
			case upstream.StateHealthy:
				b.logger.Info("upstream recovered",
					"name", ev.Name)
			case upstream.StateDisabled:
				b.logger.Info("upstream disabled",
					"name", ev.Name)
			}
		}
	}
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
