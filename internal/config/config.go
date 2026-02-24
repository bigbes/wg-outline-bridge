package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"

	"github.com/bigbes/wireguard-outline-bridge/internal/upstream"
)

type Config struct {
	LogLevel          string                  `yaml:"log_level"`
	CacheDir          string                  `yaml:"cache_dir"`
	ObservabilityHTTP ObservabilityHTTPConfig `yaml:"observability_http"`
	WireGuard         WireGuardConfig         `yaml:"wireguard"`
	DNS               DNSConfig               `yaml:"dns"`
	MTProxy           MTProxyConfig           `yaml:"mtproxy"`
	Proxies           []ProxyServerConfig     `yaml:"proxies"`
	Telegram          TelegramConfig          `yaml:"telegram"`
	MiniApp           MiniAppConfig           `yaml:"miniapp"`
	Database          DatabaseConfig          `yaml:"database"`
	Upstreams         []UpstreamConfig        `yaml:"upstreams"`
	Routing           RoutingConfig           `yaml:"routing"`
	GeoIP             []GeoIPConfig           `yaml:"geoip"`
	PeersDir          string                  `yaml:"peers_dir"`
	Peers             map[string]PeerConfig   `yaml:"-"`
}

type ObservabilityHTTPConfig struct {
	Addr    string `yaml:"addr"`    // e.g. ":6060"
	Pprof   bool   `yaml:"pprof"`   // serve /debug/pprof/*
	Metrics bool   `yaml:"metrics"` // serve /metrics (Prometheus)
}

type WireGuardConfig struct {
	PrivateKey    string           `yaml:"private_key"`
	ListenPort    int              `yaml:"listen_port"`
	Address       string           `yaml:"address"`
	PublicAddress string           `yaml:"public_address"`
	MTU           int              `yaml:"mtu"`
	DNS           string           `yaml:"dns"`
	Mode          string           `yaml:"mode"`
	AmneziaWG     *AmneziaWGConfig `yaml:"amneziawg,omitempty"`
}

type AmneziaWGConfig struct {
	Jc   int    `yaml:"jc,omitempty"`
	Jmin int    `yaml:"jmin,omitempty"`
	Jmax int    `yaml:"jmax,omitempty"`
	S1   int    `yaml:"s1,omitempty"`
	S2   int    `yaml:"s2,omitempty"`
	S3   int    `yaml:"s3,omitempty"`
	S4   int    `yaml:"s4,omitempty"`
	H1   string `yaml:"h1,omitempty"`
	H2   string `yaml:"h2,omitempty"`
	H3   string `yaml:"h3,omitempty"`
	H4   string `yaml:"h4,omitempty"`
	I1   string `yaml:"i1,omitempty"`
	I2   string `yaml:"i2,omitempty"`
	I3   string `yaml:"i3,omitempty"`
	I4   string `yaml:"i4,omitempty"`
	I5   string `yaml:"i5,omitempty"`
}

type DNSConfig struct {
	Enabled  bool                       `yaml:"enabled"`
	Listen   string                     `yaml:"listen"`   // e.g. "10.100.0.1:53"
	Upstream string                     `yaml:"upstream"` // default upstream e.g. "1.1.1.1:53"
	Records  map[string]DNSRecordConfig `yaml:"records"`
	Rules    []DNSRuleConfig            `yaml:"rules"`
}

type DNSRecordConfig struct {
	A    []string `yaml:"a"`
	AAAA []string `yaml:"aaaa"`
	TTL  uint32   `yaml:"ttl"`
}

type DNSRuleConfig struct {
	Name     string          `yaml:"name"`
	Action   string          `yaml:"action"`   // "block" or "upstream"
	Upstream string          `yaml:"upstream"` // for action=upstream
	Domains  []string        `yaml:"domains"`  // glob patterns like "*.example.com"
	Lists    []DNSListConfig `yaml:"lists"`    // URL-based blocklists
}

type DNSListConfig struct {
	URL     string `yaml:"url"`
	Format  string `yaml:"format"`  // "hosts", "domains", or "auto" (default: "auto")
	Refresh int    `yaml:"refresh"` // seconds, default 86400
}

type PeerConfig struct {
	PrivateKey    string `yaml:"private_key"`
	PublicKey     string `yaml:"public_key"`
	AllowedIPs    string `yaml:"allowed_ips"`
	PresharedKey  string `yaml:"preshared_key"`
	Disabled      bool   `yaml:"disabled"`
	UpstreamGroup string `yaml:"-"`
}

type RoutingConfig struct {
	CIDRs    []CIDREntry     `yaml:"cidrs"`
	IPRules  []IPRuleConfig  `yaml:"ip_rules"`
	SNIRules []SNIRuleConfig `yaml:"sni_rules"`
}

type IPRuleConfig struct {
	Name          string         `yaml:"name"`
	Action        string         `yaml:"action"`
	UpstreamGroup string         `yaml:"upstream_group"`
	CIDRs         []string       `yaml:"cidrs"`
	ASNs          []int          `yaml:"asns"`
	Lists         []IPListConfig `yaml:"lists"`
}

type IPListConfig struct {
	URL     string `yaml:"url"`
	Refresh int    `yaml:"refresh"`
}

type SNIRuleConfig struct {
	Name          string   `yaml:"name"`
	Action        string   `yaml:"action"`
	UpstreamGroup string   `yaml:"upstream_group"`
	Domains       []string `yaml:"domains"`
}

// UpstreamConfig describes a generic upstream endpoint.
type UpstreamConfig struct {
	Name        string            `yaml:"name"`
	Type        string            `yaml:"type"` // "outline"
	Enabled     *bool             `yaml:"enabled,omitempty"`
	Default     bool              `yaml:"default"`
	Groups      []string          `yaml:"groups,omitempty"`
	Transport   string            `yaml:"transport,omitempty"`
	HealthCheck HealthCheckConfig `yaml:"health_check"`
}

// IsEnabled returns whether the upstream is enabled (defaults to true).
func (u *UpstreamConfig) IsEnabled() bool {
	if u.Enabled == nil {
		return true
	}
	return *u.Enabled
}

type HealthCheckConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval int    `yaml:"interval"`
	Target   string `yaml:"target"`
}

type GeoIPConfig struct {
	Name    string `yaml:"name"`
	Path    string `yaml:"path"`    // local file path or URL
	Refresh int    `yaml:"refresh"` // seconds
}

type MTProxyConfig struct {
	Enabled       bool             `yaml:"enabled"`
	Listen        []string         `yaml:"listen"`
	UpstreamGroup string           `yaml:"upstream_group"`
	Secrets       []string         `yaml:"secrets"`
	StatsAddr     string           `yaml:"stats_addr"`
	FakeTLS       FakeTLSConfig    `yaml:"fake_tls"`
	Endpoints     map[int][]string `yaml:"endpoints"`
}

type FakeTLSConfig struct {
	Enabled             bool     `yaml:"enabled"`
	SNI                 []string `yaml:"sni"`
	MaxClockSkewSeconds int      `yaml:"max_clock_skew_seconds"`
	ReplayCacheTTLHours int      `yaml:"replay_cache_ttl_hours"`
}

type ProxyServerConfig struct {
	Name          string         `yaml:"name"`
	Type          string         `yaml:"type"` // "socks5", "http", "https"
	Listen        string         `yaml:"listen"`
	UpstreamGroup string         `yaml:"upstream_group"`
	Username      string         `yaml:"username"` // optional auth
	Password      string         `yaml:"password"`
	TLS           ProxyTLSConfig `yaml:"tls"` // for https type only
}

type ProxyTLSConfig struct {
	CertFile  string `yaml:"cert_file"`
	KeyFile   string `yaml:"key_file"`
	Domain    string `yaml:"domain"`
	ACMEEmail string `yaml:"acme_email"`
}

type TelegramConfig struct {
	Enabled      bool    `yaml:"enabled"`
	Token        string  `yaml:"token"`
	ChatID       int64   `yaml:"chat_id"`
	Interval     int     `yaml:"interval"`      // status report interval in seconds
	AllowedUsers []int64 `yaml:"allowed_users"` // user IDs allowed in private chats
}

type MiniAppConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Listen    string `yaml:"listen"`     // e.g. ":443"
	Domain    string `yaml:"domain"`     // public domain for Telegram WebApp URL
	ACMEEmail string `yaml:"acme_email"` // optional email for Let's Encrypt
}

type DatabaseConfig struct {
	Path          string `yaml:"path"`
	FlushInterval int    `yaml:"flush_interval"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if cfg.WireGuard.MTU == 0 {
		cfg.WireGuard.MTU = 1420
	}
	if cfg.WireGuard.Mode == "" {
		cfg.WireGuard.Mode = "wireguard"
	}
	switch cfg.WireGuard.Mode {
	case "wireguard", "amneziawg":
	default:
		return nil, fmt.Errorf("wireguard.mode must be 'wireguard' or 'amneziawg', got %q", cfg.WireGuard.Mode)
	}
	if cfg.WireGuard.DNS == "" {
		cfg.WireGuard.DNS = "1.1.1.1"
	}
	if cfg.DNS.Enabled {
		if cfg.DNS.Listen == "" {
			cfg.DNS.Listen = "127.0.0.1:15353"
		}
		if cfg.DNS.Upstream == "" {
			cfg.DNS.Upstream = cfg.WireGuard.DNS
		}
		if !strings.Contains(cfg.DNS.Upstream, ":") {
			cfg.DNS.Upstream = cfg.DNS.Upstream + ":53"
		}
		// Point WireGuard clients at the virtual address for DNS.
		addr, _, err := cfg.WireGuard.ParseAddress()
		if err == nil {
			cfg.WireGuard.DNS = addr.String()
		}
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.CacheDir == "" {
		if userCache, err := os.UserCacheDir(); err == nil {
			cfg.CacheDir = filepath.Join(userCache, "wg-outline-bridge")
		}
	}
	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("at least one upstream entry is required")
	}

	for i := range cfg.Routing.IPRules {
		for j := range cfg.Routing.IPRules[i].Lists {
			if cfg.Routing.IPRules[i].Lists[j].Refresh == 0 {
				cfg.Routing.IPRules[i].Lists[j].Refresh = 86400
			}
		}
	}

	for i := range cfg.GeoIP {
		if cfg.GeoIP[i].Name == "" {
			cfg.GeoIP[i].Name = fmt.Sprintf("geoip-%d", i)
		}
		if cfg.GeoIP[i].Path == "" {
			return nil, fmt.Errorf("geoip entry %q: path is required", cfg.GeoIP[i].Name)
		}
		if cfg.GeoIP[i].Refresh == 0 {
			cfg.GeoIP[i].Refresh = 86400
		}
	}

	if cfg.Database.FlushInterval == 0 {
		cfg.Database.FlushInterval = 30
	}

	if cfg.MTProxy.Enabled {
		if len(cfg.MTProxy.Listen) == 0 {
			return nil, fmt.Errorf("mtproxy: at least one listen address is required")
		}
		for _, addr := range cfg.MTProxy.Listen {
			if err := validateListenPort(addr); err != nil {
				return nil, fmt.Errorf("mtproxy: %w", err)
			}
		}
		if cfg.MTProxy.FakeTLS.MaxClockSkewSeconds == 0 {
			cfg.MTProxy.FakeTLS.MaxClockSkewSeconds = 600
		}
		if cfg.MTProxy.FakeTLS.ReplayCacheTTLHours == 0 {
			cfg.MTProxy.FakeTLS.ReplayCacheTTLHours = 48
		}
		if len(cfg.MTProxy.FakeTLS.SNI) == 0 {
			cfg.MTProxy.FakeTLS.SNI = []string{"www.google.com"}
		}
	}

	for i := range cfg.Proxies {
		p := &cfg.Proxies[i]
		if p.Name == "" {
			return nil, fmt.Errorf("proxy entry %d: name is required", i)
		}
		switch p.Type {
		case "socks5", "http", "https":
		default:
			return nil, fmt.Errorf("proxy %q: type must be socks5, http, or https", p.Name)
		}
		if p.Listen == "" {
			return nil, fmt.Errorf("proxy %q: listen address is required", p.Name)
		}
		if err := validateListenPort(p.Listen); err != nil {
			return nil, fmt.Errorf("proxy %q: %w", p.Name, err)
		}
		if p.Type == "https" {
			if p.TLS.Domain == "" && (p.TLS.CertFile == "" || p.TLS.KeyFile == "") {
				return nil, fmt.Errorf("proxy %q: https requires tls.domain or tls.cert_file+tls.key_file", p.Name)
			}
		}
	}

	if cfg.Telegram.Enabled {
		if cfg.Telegram.Token == "" {
			return nil, fmt.Errorf("telegram: token is required")
		}
		if cfg.Telegram.Interval == 0 {
			cfg.Telegram.Interval = 300
		}
	}

	if cfg.MiniApp.Enabled {
		if cfg.MiniApp.Listen == "" {
			cfg.MiniApp.Listen = ":443"
		}
		if err := validateListenPort(cfg.MiniApp.Listen); err != nil {
			return nil, fmt.Errorf("miniapp: %w", err)
		}
		if cfg.MiniApp.Domain == "" {
			return nil, fmt.Errorf("miniapp: domain is required when enabled")
		}
		if !cfg.Telegram.Enabled || cfg.Telegram.Token == "" {
			return nil, fmt.Errorf("miniapp: requires telegram.enabled and telegram.token")
		}
		if len(cfg.Telegram.AllowedUsers) == 0 {
			return nil, fmt.Errorf("miniapp: requires telegram.allowed_users to restrict access")
		}
	}

	if cfg.PeersDir == "" {
		cfg.PeersDir = filepath.Join(filepath.Dir(path), "peers")
	}
	peers, err := LoadPeers(cfg.PeersDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading peers: %w", err)
	}
	if peers == nil {
		peers = make(map[string]PeerConfig)
	}
	cfg.Peers = peers

	return &cfg, nil
}

func LoadPeers(dir string) (map[string]PeerConfig, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	peers := make(map[string]PeerConfig)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wg.conf") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".wg.conf")
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading peer %q: %w", name, err)
		}
		var peer PeerConfig
		peerDec := yaml.NewDecoder(strings.NewReader(string(data)))
		peerDec.KnownFields(true)
		if err := peerDec.Decode(&peer); err != nil {
			return nil, fmt.Errorf("parsing peer %q: %w", name, err)
		}
		peers[name] = peer
	}
	return peers, nil
}

func SavePeer(dir, name string, peer PeerConfig) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating peers directory: %w", err)
	}
	data, err := yaml.Marshal(peer)
	if err != nil {
		return fmt.Errorf("marshaling peer: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, name+".wg.conf"), data, 0o600)
}

func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func Migrate(path string) (*Config, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("reading config file: %w", err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, false, fmt.Errorf("parsing config file: %w", err)
	}

	modified := false

	// Migrate old "outline:" (single object) to "outlines:" (array)
	if oldOutline, ok := raw["outline"]; ok {
		if _, hasNew := raw["outlines"]; !hasNew {
			outlineMap, _ := oldOutline.(map[string]any)
			if outlineMap == nil {
				outlineMap = map[string]any{}
			}
			transport, _ := outlineMap["transport"].(string)
			entry := map[string]any{
				"name":      "default",
				"transport": transport,
				"default":   true,
			}
			if hc, ok := outlineMap["health_check"]; ok {
				entry["health_check"] = hc
			}
			raw["outlines"] = []any{entry}
			delete(raw, "outline")
			modified = true
		}
	}

	// Migrate outlines → upstreams
	if outlinesRaw, ok := raw["outlines"]; ok {
		if _, hasUpstreams := raw["upstreams"]; !hasUpstreams {
			outlinesList, _ := outlinesRaw.([]any)
			if len(outlinesList) > 0 {
				upstreamsList := make([]any, 0, len(outlinesList))
				for _, o := range outlinesList {
					om, _ := o.(map[string]any)
					if om == nil {
						continue
					}
					u := map[string]any{
						"name": om["name"],
						"type": "outline",
					}
					if t, ok := om["transport"]; ok {
						u["transport"] = t
					}
					if d, ok := om["default"]; ok {
						u["default"] = d
					}
					if hc, ok := om["health_check"]; ok {
						u["health_check"] = hc
					}
					upstreamsList = append(upstreamsList, u)
				}
				raw["upstreams"] = upstreamsList
				delete(raw, "outlines")
				modified = true
			}
		}
	}

	if modified {
		newData, err := yaml.Marshal(raw)
		if err != nil {
			return nil, false, fmt.Errorf("marshaling migrated config: %w", err)
		}
		if err := os.WriteFile(path, newData, 0644); err != nil {
			return nil, false, fmt.Errorf("writing migrated config: %w", err)
		}
	}

	cfg, err := Load(path)
	if err != nil {
		return nil, false, err
	}
	return cfg, modified, nil
}

// DefaultUpstream returns the default upstream config, or nil if none.
func (c *Config) DefaultUpstream() *UpstreamConfig {
	for i := range c.Upstreams {
		if c.Upstreams[i].Default {
			return &c.Upstreams[i]
		}
	}
	return nil
}

// ToUpstreamSpecs converts configured upstreams to upstream.Spec slice.
func (c *Config) ToUpstreamSpecs() []upstream.Spec {
	specs := make([]upstream.Spec, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		spec := upstream.Spec{
			Name:    u.Name,
			Type:    upstream.Type(u.Type),
			Enabled: u.IsEnabled(),
			Default: u.Default,
			Groups:  u.Groups,
			HealthCheck: upstream.HealthCheckConfig{
				Enabled:  u.HealthCheck.Enabled,
				Interval: time.Duration(u.HealthCheck.Interval) * time.Second,
				Target:   u.HealthCheck.Target,
			},
		}
		// Build type-specific config JSON.
		switch u.Type {
		case "outline":
			cfgJSON, _ := json.Marshal(map[string]string{"transport": u.Transport})
			spec.Config = cfgJSON
		}
		specs = append(specs, spec)
	}
	return specs
}

func (c *Config) ParseLogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func validateListenPort(addr string) error {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port in %q: %w", addr, err)
	}
	if port < 1000 {
		return fmt.Errorf("listen port %d is below 1000, use port >= 1000", port)
	}
	return nil
}

func (c *WireGuardConfig) IsAmneziaWG() bool {
	return c.Mode == "amneziawg"
}

func (c *WireGuardConfig) ParseAddress() (netip.Addr, int, error) {
	prefix, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("parsing address: %w", err)
	}
	return prefix.Addr(), prefix.Bits(), nil
}

// ServerPublicIP returns the server's public IP address.
// It returns public_address if configured, otherwise queries ifconfig.me.
func (c *Config) ServerPublicIP() string {
	if c.WireGuard.PublicAddress != "" {
		return c.WireGuard.PublicAddress
	}
	if ip, err := detectPublicIP(); err == nil {
		return ip
	}
	return ""
}

func detectPublicIP() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://ifconfig.me/ip")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", fmt.Errorf("invalid IP from ifconfig.me: %q", ip)
	}
	return ip, nil
}

// TransportHost extracts the host (without port) from a transport URI
// like "ss://credentials@host:port/".
func TransportHost(uri string) string {
	at := strings.LastIndex(uri, "@")
	if at == -1 {
		return ""
	}
	hostPort := uri[at+1:]
	hostPort = strings.TrimRight(hostPort, "/")
	if host, _, ok := strings.Cut(hostPort, ":"); ok {
		return host
	}
	return hostPort
}

// RedactTransport obfuscates credentials in a transport URI,
// e.g. "ss://Y2hhY2hhMjA...@host:port/" becomes "ss://***@host:port/".
func RedactTransport(uri string) string {
	if at := strings.LastIndex(uri, "@"); at != -1 {
		scheme := uri[:strings.Index(uri, "//")+2]
		return scheme + "***" + uri[at:]
	}
	return uri
}

func writeUAPIInt(b *strings.Builder, key string, v int) {
	if v != 0 {
		fmt.Fprintf(b, "%s=%d\n", key, v)
	}
}

func writeUAPIStr(b *strings.Builder, key string, v string) {
	if v != "" {
		fmt.Fprintf(b, "%s=%s\n", key, v)
	}
}

func base64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decoding base64 key: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func PeerUAPIAdd(peer PeerConfig) (string, error) {
	var b strings.Builder
	pubHex, err := base64ToHex(peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	if peer.PresharedKey != "" {
		pskHex, err := base64ToHex(peer.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&b, "allowed_ip=%s\n", peer.AllowedIPs)
	return b.String(), nil
}

func PeerUAPIRemove(publicKey string) (string, error) {
	pubHex, err := base64ToHex(publicKey)
	if err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	return fmt.Sprintf("public_key=%s\nremove=true\n", pubHex), nil
}

type PeerDiff struct {
	Added   map[string]PeerConfig
	Removed map[string]PeerConfig
}

func DiffPeers(old, new map[string]PeerConfig) PeerDiff {
	diff := PeerDiff{
		Added:   make(map[string]PeerConfig),
		Removed: make(map[string]PeerConfig),
	}
	for name, p := range new {
		if p.Disabled {
			continue
		}
		if oldP, exists := old[name]; !exists || oldP.Disabled {
			diff.Added[name] = p
		}
	}
	for name, p := range old {
		if p.Disabled {
			continue
		}
		if newP, exists := new[name]; !exists || newP.Disabled {
			diff.Removed[name] = p
		}
	}
	return diff
}

func (c *WireGuardConfig) ToUAPI(peers map[string]PeerConfig) (string, error) {
	var b strings.Builder

	privHex, err := base64ToHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)

	if c.IsAmneziaWG() && c.AmneziaWG != nil {
		awg := c.AmneziaWG
		writeUAPIInt(&b, "jc", awg.Jc)
		writeUAPIInt(&b, "jmin", awg.Jmin)
		writeUAPIInt(&b, "jmax", awg.Jmax)
		writeUAPIInt(&b, "s1", awg.S1)
		writeUAPIInt(&b, "s2", awg.S2)
		writeUAPIInt(&b, "s3", awg.S3)
		writeUAPIInt(&b, "s4", awg.S4)
		writeUAPIStr(&b, "h1", awg.H1)
		writeUAPIStr(&b, "h2", awg.H2)
		writeUAPIStr(&b, "h3", awg.H3)
		writeUAPIStr(&b, "h4", awg.H4)
		writeUAPIStr(&b, "i1", awg.I1)
		writeUAPIStr(&b, "i2", awg.I2)
		writeUAPIStr(&b, "i3", awg.I3)
		writeUAPIStr(&b, "i4", awg.I4)
		writeUAPIStr(&b, "i5", awg.I5)
	}

	for _, peer := range peers {
		if peer.Disabled {
			continue
		}
		pubHex, err := base64ToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer public key: %w", err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pubHex)

		if peer.PresharedKey != "" {
			pskHex, err := base64ToHex(peer.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("preshared key: %w", err)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
		}

		fmt.Fprintf(&b, "allowed_ip=%s\n", peer.AllowedIPs)
	}

	return b.String(), nil
}

// ProxyLink holds a named Telegram proxy link.
type ProxyLink struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// ProxyLinks builds Telegram proxy links for all configured MTProxy secrets.
// The names map provides optional display names keyed by secret hex.
func ProxyLinks(cfg *Config, names map[string]string) []ProxyLink {
	serverIP := cfg.ServerPublicIP()
	if serverIP == "" {
		serverIP = "<SERVER_IP>"
	}

	if len(cfg.MTProxy.Listen) == 0 || len(cfg.MTProxy.Secrets) == 0 {
		return nil
	}

	_, port, err := net.SplitHostPort(cfg.MTProxy.Listen[0])
	if err != nil {
		return nil
	}

	links := make([]ProxyLink, 0, len(cfg.MTProxy.Secrets))
	for i, secret := range cfg.MTProxy.Secrets {
		linkSecret := secret
		// Append hex-encoded SNI to ee-prefixed secrets
		if len(secret) >= 2 && secret[:2] == "ee" && len(cfg.MTProxy.FakeTLS.SNI) > 0 {
			linkSecret = secret + hex.EncodeToString([]byte(cfg.MTProxy.FakeTLS.SNI[0]))
		}
		url := fmt.Sprintf("https://t.me/proxy?server=%s&port=%s&secret=%s", serverIP, port, linkSecret)
		name := names[secret]
		if name == "" {
			name = fmt.Sprintf("Proxy %d", i+1)
		}
		links = append(links, ProxyLink{
			Name:   name,
			URL:    url,
			Secret: secret,
		})
	}
	return links
}

// GenerateKeyPair generates a WireGuard private/public key pair,
// returning both as base64-encoded strings.
func GenerateKeyPair() (privateKeyB64, publicKeyB64 string, err error) {
	var privateKey [32]byte
	if _, err = rand.Read(privateKey[:]); err != nil {
		return "", "", fmt.Errorf("generating random bytes: %w", err)
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("computing public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(privateKey[:]),
		base64.StdEncoding.EncodeToString(publicKey), nil
}

// GeneratePresharedKey generates a random 32-byte preshared key,
// returning it as a base64-encoded string.
func GeneratePresharedKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// DerivePublicKey derives a WireGuard public key from a base64-encoded private key.
func DerivePublicKey(privateKeyB64 string) (string, error) {
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

// NextPeerIP finds the next available IP address for a new peer
// based on the server address and existing peer allocations.
func NextPeerIP(cfg *Config) (string, error) {
	addr, _, err := cfg.WireGuard.ParseAddress()
	if err != nil {
		return "", err
	}

	used := make(map[netip.Addr]bool)
	used[addr] = true
	for _, peer := range cfg.Peers {
		ip := strings.Split(peer.AllowedIPs, "/")[0]
		if a, err := netip.ParseAddr(ip); err == nil {
			used[a] = true
		}
	}

	candidate := addr.Next()
	for range 253 {
		if !used[candidate] {
			return candidate.String(), nil
		}
		candidate = candidate.Next()
	}

	return "", fmt.Errorf("no available IPs in subnet")
}
