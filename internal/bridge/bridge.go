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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/dns"
	"github.com/bigbes/wireguard-outline-bridge/internal/geoip"
	"github.com/bigbes/wireguard-outline-bridge/internal/metrics"
	"github.com/bigbes/wireguard-outline-bridge/internal/miniapp"
	"github.com/bigbes/wireguard-outline-bridge/internal/observer"
	"github.com/bigbes/wireguard-outline-bridge/internal/proxy"
	mtproxy2 "github.com/bigbes/wireguard-outline-bridge/internal/proxy/mtproxy"
	mpcrypto "github.com/bigbes/wireguard-outline-bridge/internal/proxy/mtproxy/crypto"
	"github.com/bigbes/wireguard-outline-bridge/internal/proxy/mtproxy/telegram"
	"github.com/bigbes/wireguard-outline-bridge/internal/proxyserver"
	"github.com/bigbes/wireguard-outline-bridge/internal/routing"
	"github.com/bigbes/wireguard-outline-bridge/internal/statsdb"
	tgbot "github.com/bigbes/wireguard-outline-bridge/internal/telegram"
	"github.com/bigbes/wireguard-outline-bridge/internal/upstream"
	outlineprovider "github.com/bigbes/wireguard-outline-bridge/internal/upstream/providers/outline"
	wg "github.com/bigbes/wireguard-outline-bridge/internal/wireguard"
)

type Bridge struct {
	configPath string
	logger     *slog.Logger
	startTime  time.Time

	mu           sync.Mutex
	cfg          *config.Config
	ctx          context.Context
	wgDev        wg.Device
	upstreams    *upstream.Manager
	tracker      *proxy.ConnTracker
	peerResolver *proxy.PeerUpstreamResolver
	peerMon      *peerMonitor
	mtSrv        *mtproxy2.Server
	dnsSrv       *dns.Server
	statsStore   *statsdb.Store
	proxySrvs    map[string]*proxyserver.Server
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
	b.ctx = ctx
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
	b.peerResolver = proxy.NewPeerUpstreamResolver()

	if b.cfg.Database.Path != "" {
		// Note: peerResolver will be populated after peers are loaded from DB below.
		store, err := statsdb.Open(b.cfg.Database.Path, b.logger)
		if err != nil {
			return fmt.Errorf("opening stats db: %w", err)
		}
		b.statsStore = store
		if err := store.SetDaemonStartTime(time.Now()); err != nil {
			b.logger.Error("failed to set daemon start time", "err", err)
		}
		var statsWg sync.WaitGroup
		statsWg.Go(func() {
			b.statsFlushLoop(ctx, time.Duration(b.cfg.Database.FlushInterval)*time.Second)
		})
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

		dbSecrets, err := store.ListSecrets()
		if err != nil {
			b.logger.Error("failed to list db secrets", "err", err)
		}
		if len(dbSecrets) > 0 {
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

		// Seed config-file upstreams into DB (skips names already present),
		// then use the DB as the source of truth so webapp edits are preserved.
		if len(b.cfg.Upstreams) > 0 {
			imported, err := store.ImportUpstreams(b.cfg.Upstreams)
			if err != nil {
				b.logger.Error("failed to import upstreams to database", "err", err)
			} else if imported > 0 {
				b.logger.Info("imported file upstreams to database", "count", imported)
			}
		}
		dbUpstreams, err := store.ListUpstreams()
		if err != nil {
			b.logger.Error("failed to list db upstreams", "err", err)
		}
		if len(dbUpstreams) > 0 {
			b.cfg.Upstreams = dbUpstreams
		}

		// Re-apply upstream specs after merging DB state, since the upstream
		// manager was initialized before the database was opened.
		if err := b.upstreams.Apply(b.cfg.ToUpstreamSpecs()); err != nil {
			b.logger.Error("failed to re-apply upstream specs from db", "err", err)
		}

		// Seed config-file DNS records into DB, then use DB as source of truth.
		if len(b.cfg.DNS.Records) > 0 {
			imported, err := store.ImportDNSRecords(b.cfg.DNS.Records)
			if err != nil {
				b.logger.Error("failed to import dns records to database", "err", err)
			} else if imported > 0 {
				b.logger.Info("imported file dns records to database", "count", imported)
			}
		}
		dbDNSRecords, err := store.ListDNSRecords()
		if err != nil {
			b.logger.Error("failed to list db dns records", "err", err)
		}
		if len(dbDNSRecords) > 0 {
			b.cfg.DNS.Records = dbDNSRecords
		}

		// Seed config-file DNS rules into DB, then use DB as source of truth.
		if len(b.cfg.DNS.Rules) > 0 {
			imported, err := store.ImportDNSRules(b.cfg.DNS.Rules)
			if err != nil {
				b.logger.Error("failed to import dns rules to database", "err", err)
			} else if imported > 0 {
				b.logger.Info("imported file dns rules to database", "count", imported)
			}
		}
		dbDNSRules, err := store.ListDNSRules()
		if err != nil {
			b.logger.Error("failed to list db dns rules", "err", err)
		}
		if len(dbDNSRules) > 0 {
			b.cfg.DNS.Rules = dbDNSRules
		}

		// Load persisted DNS enabled state from DB (overrides config file).
		if dnsEnabled, ok := store.GetDNSEnabled(); ok {
			b.cfg.DNS.Enabled = dnsEnabled
		}
	}

	b.peerResolver.PopulateFromPeers(b.cfg.Peers)

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

	tcpProxy := proxy.NewTCPProxy(router, dialers, b.tracker, b.peerResolver, b.logger)
	tcpProxy.SetupForwarder(netStack)

	udpProxy := proxy.NewUDPProxy(router, dialers, b.tracker, b.peerResolver, b.logger)
	if b.cfg.DNS.Listen != "" {
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

	if b.cfg.DNS.Listen != "" {
		records := buildDNSRecords(b.cfg.DNS)
		var rules []dns.Rule
		if b.cfg.DNS.Enabled {
			rules = buildDNSRules(b.cfg.DNS, b.logger)
		}
		b.dnsSrv = dns.New(b.cfg.DNS.Listen, b.cfg.DNS.Upstream, records, rules, b.logger)
		if err := b.dnsSrv.Start(ctx); err != nil {
			return fmt.Errorf("starting dns server: %w", err)
		}
		defer b.dnsSrv.Stop()
	}

	b.peerMon = newPeerMonitor(b.wgDev, b.cfg.Peers, b.logger)
	go b.peerMon.run(ctx)

	if b.cfg.Telegram.Enabled {
		bot := tgbot.NewBot(b.cfg.Telegram.Token, b.cfg.Telegram.ChatID)
		var roleChecker observer.RoleChecker
		if b.statsStore != nil {
			roleChecker = b.statsStore
		}
		obs := observer.New(bot, b, b, b, roleChecker, time.Duration(b.cfg.Telegram.Interval)*time.Second, b.cfg.Telegram.ChatID, b.logger)
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
		dbDNSRules, err := b.statsStore.ListDNSRules()
		if err != nil {
			b.logger.Error("failed to load dns rules from database", "err", err)
		} else if len(dbDNSRules) > 0 {
			newCfg.DNS.Rules = dbDNSRules
		}
		if dnsEnabled, ok := b.statsStore.GetDNSEnabled(); ok {
			newCfg.DNS.Enabled = dnsEnabled
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
	b.reloadMTProxySecrets()

	// Reload DNS rules at runtime
	b.reloadDNSRules()

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

	resolver := b.buildMTProxyDialerResolver()

	endpoints := telegram.NewEndpointManager(b.cfg.MTProxy.Endpoints)

	serverCfg := mtproxy2.ServerConfig{
		ListenAddrs: b.cfg.MTProxy.Listen,
		Secrets:     secrets,
		SecretHexes: b.cfg.MTProxy.Secrets,
	}
	if b.cfg.MTProxy.FakeTLS.Enabled {
		serverCfg.FakeTLS = &mtproxy2.FakeTLSConfig{
			AllowedSNIs:         b.cfg.MTProxy.FakeTLS.SNI,
			MaxClockSkewSec:     b.cfg.MTProxy.FakeTLS.MaxClockSkewSeconds,
			ReplayCacheTTLHours: b.cfg.MTProxy.FakeTLS.ReplayCacheTTLHours,
		}
	}

	srv := mtproxy2.NewServer(serverCfg, resolver, endpoints, b.logger)
	b.mtSrv = srv

	if err := srv.Listen(); err != nil {
		return fmt.Errorf("mtproxy: %w", err)
	}
	go srv.Serve(ctx)

	if b.cfg.MTProxy.StatsAddr != "" {
		statsSrv := mtproxy2.NewStatsServer(b.cfg.MTProxy.StatsAddr, srv, b.logger)
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
	b.proxySrvs = make(map[string]*proxyserver.Server, len(b.cfg.Proxies))
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

		srvCfg := proxyserver.ServerConfig{
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
		}
		if b.cfg.DNS.Enabled {
			srvCfg.DNSAddr = b.cfg.DNS.Listen
		}

		srv := proxyserver.NewServer(srvCfg, dialer, b.logger)
		b.proxySrvs[pcfg.Name] = srv

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
		UniqueUsers:       snap.UniqueUsers.Load(),
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
	sessionByHex := make(map[string]mtproxy2.SecretSnapshot, len(secretSnap))
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
			c.ActiveConnections = ss.ActiveConnections
			c.UniqueUsers = ss.UniqueUsers
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
	if b.peerResolver != nil {
		for _, addr := range peerIPs {
			b.peerResolver.Delete(addr)
		}
	}
	if b.peerMon != nil {
		b.peerMon.updatePeers(b.cfg.Peers)
	}

	b.logger.Info("peer deleted", "name", name)
	return nil
}

// SetPeerDisabled enables or disables a peer by name.
func (b *Bridge) SetPeerDisabled(name string, disabled bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	peer, exists := b.cfg.Peers[name]
	if !exists {
		return fmt.Errorf("peer %q not found", name)
	}

	if peer.Disabled == disabled {
		return nil
	}

	peer.Disabled = disabled
	if err := b.statsStore.UpsertPeer(name, peer); err != nil {
		return fmt.Errorf("saving peer: %w", err)
	}

	if b.wgDev != nil {
		if disabled {
			uapi, err := config.PeerUAPIRemove(peer.PublicKey)
			if err != nil {
				b.logger.Error("failed to generate remove UAPI", "name", name, "err", err)
			} else if err := b.wgDev.IpcSet(uapi); err != nil {
				b.logger.Error("failed to remove peer from wireguard", "name", name, "err", err)
			}
		} else {
			uapi, err := config.PeerUAPIAdd(peer)
			if err != nil {
				b.logger.Error("failed to generate add UAPI", "name", name, "err", err)
			} else if err := b.wgDev.IpcSet(uapi); err != nil {
				b.logger.Error("failed to add peer to wireguard", "name", name, "err", err)
			}
		}
	}

	b.cfg.Peers[name] = peer
	if b.peerResolver != nil {
		for _, addr := range peerAllowedIPs(peer) {
			if disabled {
				b.peerResolver.Delete(addr)
			} else if peer.UpstreamGroup != "" {
				b.peerResolver.Set(addr, peer.UpstreamGroup)
			}
		}
	}
	if b.peerMon != nil {
		b.peerMon.updatePeers(b.cfg.Peers)
	}

	action := "enabled"
	if disabled {
		action = "disabled"
	}
	b.logger.Info("peer "+action, "name", name)
	return nil
}

// SetPeerUpstreamGroup changes the upstream group for a peer at runtime.
func (b *Bridge) SetPeerUpstreamGroup(name, group string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	peer, exists := b.cfg.Peers[name]
	if !exists {
		return fmt.Errorf("peer %q not found", name)
	}

	if peer.UpstreamGroup == group {
		return nil
	}

	if err := b.statsStore.SetPeerUpstreamGroup(name, group); err != nil {
		return fmt.Errorf("saving peer upstream group: %w", err)
	}

	peer.UpstreamGroup = group
	b.cfg.Peers[name] = peer

	if b.peerResolver != nil {
		for _, addr := range peerAllowedIPs(peer) {
			b.peerResolver.Set(addr, group)
		}
	}

	b.logger.Info("peer upstream group changed", "name", name, "upstream_group", group)
	return nil
}

// RenamePeer renames a peer from oldName to newName.
func (b *Bridge) RenamePeer(oldName, newName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	peer, exists := b.cfg.Peers[oldName]
	if !exists {
		return fmt.Errorf("peer %q not found", oldName)
	}

	if _, exists := b.cfg.Peers[newName]; exists {
		return fmt.Errorf("peer %q already exists", newName)
	}

	if err := b.statsStore.RenamePeer(oldName, newName); err != nil {
		return fmt.Errorf("renaming peer: %w", err)
	}

	delete(b.cfg.Peers, oldName)
	b.cfg.Peers[newName] = peer
	if b.peerMon != nil {
		b.peerMon.updatePeers(b.cfg.Peers)
	}

	b.logger.Info("peer renamed", "old_name", oldName, "new_name", newName)
	return nil
}

// AddSecret generates a new MTProxy secret, saves it to the database,
// and live-reloads the MTProxy server to accept the new secret immediately.
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
	b.reloadMTProxySecrets()

	b.logger.Info("mtproxy secret added", "type", secretType)
	return secretHex, nil
}

// DeleteSecret removes an MTProxy secret from the database
// and live-reloads the MTProxy server to stop accepting it immediately.
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
	b.reloadMTProxySecrets()

	b.logger.Info("mtproxy secret deleted")
	return nil
}

// reloadMTProxySecrets parses the current config secrets and pushes them
// to the running MTProxy server. Must be called with b.mu held.
func (b *Bridge) reloadMTProxySecrets() {
	if b.mtSrv == nil {
		return
	}
	hexes := b.cfg.MTProxy.Secrets
	secrets := make([]mpcrypto.Secret, 0, len(hexes))
	for _, s := range hexes {
		secret, err := mpcrypto.ParseSecret(s)
		if err != nil {
			b.logger.Error("failed to parse mtproxy secret", "err", err)
			continue
		}
		secrets = append(secrets, secret)
	}
	b.mtSrv.UpdateSecrets(secrets, hexes)
	b.mtSrv.SetDialerResolver(b.buildMTProxyDialerResolver())
}

// mtproxyDialerResolver resolves a StreamDialer per-secret based on
// upstream_group stored in the database.
type mtproxyDialerResolver struct {
	defaultDialer mtproxy2.StreamDialer
	perSecret     map[int]mtproxy2.StreamDialer // secretIdx -> dialer
}

func (r *mtproxyDialerResolver) ResolveDialer(secretIdx int) mtproxy2.StreamDialer {
	if d, ok := r.perSecret[secretIdx]; ok {
		return d
	}
	return r.defaultDialer
}

// buildMTProxyDialerResolver constructs a DialerResolver that maps each
// secret to its upstream group's dialer. Must be called with b.mu held.
func (b *Bridge) buildMTProxyDialerResolver() mtproxy2.DialerResolver {
	group := b.cfg.MTProxy.UpstreamGroup
	if group == "" {
		group = "default"
	}
	var defaultDialer mtproxy2.StreamDialer
	if d := b.upstreams.StreamDialerForGroup(group); d != nil {
		defaultDialer = d
	} else {
		defaultDialer = b.upstreams.DefaultStreamDialer()
	}

	var secretGroups map[string]string
	if b.statsStore != nil {
		secretGroups, _ = b.statsStore.ListSecretUpstreamGroups()
	}

	if len(secretGroups) == 0 {
		return &mtproxy2.SingleDialerResolver{Dialer: defaultDialer}
	}

	perSecret := make(map[int]mtproxy2.StreamDialer)
	for i, hex := range b.cfg.MTProxy.Secrets {
		sg, ok := secretGroups[hex]
		if !ok || sg == "" {
			continue
		}
		if d := b.upstreams.StreamDialerForGroup(sg); d != nil {
			perSecret[i] = d
		}
	}

	if len(perSecret) == 0 {
		return &mtproxy2.SingleDialerResolver{Dialer: defaultDialer}
	}

	return &mtproxyDialerResolver{
		defaultDialer: defaultDialer,
		perSecret:     perSecret,
	}
}

// SetProxyUpstreamGroup changes the upstream group for a running proxy server.
func (b *Bridge) SetProxyUpstreamGroup(name, group string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	idx := -1
	for i, p := range b.cfg.Proxies {
		if p.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("proxy %q not found", name)
	}

	if b.cfg.Proxies[idx].UpstreamGroup == group {
		return nil
	}

	if err := b.statsStore.SetProxyUpstreamGroup(name, group); err != nil {
		return fmt.Errorf("saving proxy upstream group: %w", err)
	}

	b.cfg.Proxies[idx].UpstreamGroup = group

	if srv, ok := b.proxySrvs[name]; ok {
		resolvedGroup := group
		if resolvedGroup == "" {
			resolvedGroup = "default"
		}
		var dialer proxyserver.StreamDialer
		if d := b.upstreams.StreamDialerForGroup(resolvedGroup); d != nil {
			dialer = d
		} else {
			dialer = b.upstreams.DefaultStreamDialer()
		}
		srv.SetDialer(dialer)
	}

	b.logger.Info("proxy upstream group changed", "name", name, "upstream_group", group)
	return nil
}

// SetSecretUpstreamGroup changes the upstream group for an MTProxy secret.
func (b *Bridge) SetSecretUpstreamGroup(secretHex, group string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	found := slices.Contains(b.cfg.MTProxy.Secrets, secretHex)
	if !found {
		return fmt.Errorf("secret %q not found", secretHex)
	}

	if err := b.statsStore.SetSecretUpstreamGroup(secretHex, group); err != nil {
		return fmt.Errorf("saving secret upstream group: %w", err)
	}

	b.reloadMTProxySecrets()

	b.logger.Info("secret upstream group changed", "secret", secretHex, "upstream_group", group)
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

// AddDNSRecord adds a new DNS record and hot-reloads the DNS server.
func (b *Bridge) AddDNSRecord(name string, rec config.DNSRecordConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	if _, exists := b.cfg.DNS.Records[name]; exists {
		return fmt.Errorf("dns record %q already exists", name)
	}

	if err := b.statsStore.UpsertDNSRecord(name, rec); err != nil {
		return fmt.Errorf("saving dns record: %w", err)
	}

	if b.cfg.DNS.Records == nil {
		b.cfg.DNS.Records = make(map[string]config.DNSRecordConfig)
	}
	b.cfg.DNS.Records[name] = rec
	b.reloadDNSRecords()

	b.logger.Info("dns record added", "name", name)
	return nil
}

// UpdateDNSRecord updates an existing DNS record and hot-reloads the DNS server.
func (b *Bridge) UpdateDNSRecord(name string, rec config.DNSRecordConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	if _, exists := b.cfg.DNS.Records[name]; !exists {
		return fmt.Errorf("dns record %q not found", name)
	}

	if err := b.statsStore.UpsertDNSRecord(name, rec); err != nil {
		return fmt.Errorf("saving dns record: %w", err)
	}

	b.cfg.DNS.Records[name] = rec
	b.reloadDNSRecords()

	b.logger.Info("dns record updated", "name", name)
	return nil
}

// DeleteDNSRecord removes a DNS record and hot-reloads the DNS server.
func (b *Bridge) DeleteDNSRecord(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	found, err := b.statsStore.DeleteDNSRecord(name)
	if err != nil {
		return fmt.Errorf("deleting dns record: %w", err)
	}
	if !found {
		return fmt.Errorf("dns record %q not found", name)
	}

	delete(b.cfg.DNS.Records, name)
	b.reloadDNSRecords()

	b.logger.Info("dns record deleted", "name", name)
	return nil
}

// reloadDNSRecords rebuilds and hot-reloads DNS records on the DNS server.
// Must be called with b.mu held.
func (b *Bridge) reloadDNSRecords() {
	if b.dnsSrv == nil {
		return
	}
	records := buildDNSRecords(b.cfg.DNS)
	b.dnsSrv.UpdateRecords(records)
}

func (b *Bridge) AddDNSRule(r config.DNSRuleConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	for _, existing := range b.cfg.DNS.Rules {
		if existing.Name == r.Name {
			return fmt.Errorf("dns rule %q already exists", r.Name)
		}
	}

	if err := b.statsStore.AddDNSRule(r); err != nil {
		return fmt.Errorf("saving dns rule: %w", err)
	}

	b.cfg.DNS.Rules = append(b.cfg.DNS.Rules, r)
	b.reloadDNSRules()

	b.logger.Info("dns rule added", "name", r.Name, "action", r.Action)
	return nil
}

// DeleteDNSRule removes a DNS rule from the database and hot-reloads the DNS server.
func (b *Bridge) DeleteDNSRule(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	found, err := b.statsStore.DeleteDNSRule(name)
	if err != nil {
		return fmt.Errorf("deleting dns rule: %w", err)
	}
	if !found {
		return fmt.Errorf("dns rule %q not found", name)
	}

	rules := make([]config.DNSRuleConfig, 0, len(b.cfg.DNS.Rules))
	for _, r := range b.cfg.DNS.Rules {
		if r.Name != name {
			rules = append(rules, r)
		}
	}
	b.cfg.DNS.Rules = rules
	b.reloadDNSRules()

	b.logger.Info("dns rule deleted", "name", name)
	return nil
}

// SetDNSEnabled toggles DNS resolution rules at runtime.
// When disabled, the DNS server keeps running but only forwards to the default upstream.
func (b *Bridge) SetDNSEnabled(enabled bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore != nil {
		if err := b.statsStore.SetDNSEnabled(enabled); err != nil {
			return fmt.Errorf("persisting dns enabled state: %w", err)
		}
	}

	b.cfg.DNS.Enabled = enabled
	b.reloadDNSRules()

	b.logger.Info("dns resolution toggled", "enabled", enabled)
	return nil
}

// reloadDNSRules rebuilds runtime DNS rules and hot-reloads the DNS server.
// When DNS resolution is disabled, rules are cleared so the server acts as a
// plain forwarder to the default upstream.
// Must be called with b.mu held.
func (b *Bridge) reloadDNSRules() {
	if b.dnsSrv == nil {
		return
	}
	var rules []dns.Rule
	if b.cfg.DNS.Enabled {
		rules = buildDNSRules(b.cfg.DNS, b.logger)
	}
	b.dnsSrv.UpdateRules(b.ctx, rules)
}

// CreateGroup creates a named upstream group in the database.
func (b *Bridge) CreateGroup(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	// Check if group already exists implicitly (from upstream assignments).
	for _, u := range b.cfg.Upstreams {
		if slices.Contains(u.Groups, name) {
			return fmt.Errorf("group %q already exists", name)
		}
	}

	if err := b.statsStore.CreateGroup(name); err != nil {
		return fmt.Errorf("creating group: %w", err)
	}

	b.logger.Info("group created", "name", name)
	return nil
}

// DeleteGroup removes a named upstream group and cleans up upstream references.
func (b *Bridge) DeleteGroup(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.statsStore == nil {
		return fmt.Errorf("database not configured")
	}

	// Remove the explicit group entry (may or may not exist).
	b.statsStore.DeleteGroup(name)

	// Remove group from all upstream configs in DB.
	updated, err := b.statsStore.RemoveGroupFromUpstreams(name)
	if err != nil {
		return fmt.Errorf("removing group from upstreams: %w", err)
	}

	// Update in-memory config.
	for i := range b.cfg.Upstreams {
		var filtered []string
		for _, g := range b.cfg.Upstreams[i].Groups {
			if g != name {
				filtered = append(filtered, g)
			}
		}
		b.cfg.Upstreams[i].Groups = filtered
	}

	if updated > 0 {
		if err := b.upstreams.Apply(b.cfg.ToUpstreamSpecs()); err != nil {
			b.logger.Error("failed to apply upstream specs", "err", err)
		}
	}

	b.logger.Info("group deleted", "name", name, "upstreams_updated", updated)
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
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

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
			b.refreshUpstreamMetrics()
		case <-ticker.C:
			b.refreshUpstreamMetrics()
		}
	}
}

func (b *Bridge) refreshUpstreamMetrics() {
	for _, st := range b.upstreams.Statuses() {
		healthy := float64(0)
		if st.State == upstream.StateHealthy {
			healthy = 1
		}
		metrics.UpstreamHealthy.WithLabelValues(st.Name).Set(healthy)
		metrics.UpstreamConnectionsActive.WithLabelValues(st.Name).Set(float64(st.ActiveConnections))
		metrics.UpstreamBytesTotal.WithLabelValues(st.Name, "rx").Set(float64(st.RxBytes))
		metrics.UpstreamBytesTotal.WithLabelValues(st.Name, "tx").Set(float64(st.TxBytes))
	}
}

func peerAllowedIPs(peer config.PeerConfig) []netip.Addr {
	var addrs []netip.Addr
	for cidr := range strings.SplitSeq(peer.AllowedIPs, ",") {
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
