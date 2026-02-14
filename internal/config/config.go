package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel    string                `yaml:"log_level"`
	CacheDir    string                `yaml:"cache_dir"`
	WireGuard   WireGuardConfig       `yaml:"wireguard"`
	DNS         DNSConfig             `yaml:"dns"`
	MTProxy     MTProxyConfig         `yaml:"mtproxy"`
	Telegram    TelegramConfig        `yaml:"telegram"`
	Outlines    []OutlineConfig       `yaml:"outlines"`
	Routing     RoutingConfig         `yaml:"routing"`
	GeoIP       []GeoIPConfig         `yaml:"geoip"`
	Peers       map[string]PeerConfig `yaml:"-"`
	PeersDir    string                `yaml:"-"`
}

type WireGuardConfig struct {
	PrivateKey    string `yaml:"private_key"`
	ListenPort    int    `yaml:"listen_port"`
	Address       string `yaml:"address"`
	PublicAddress string `yaml:"public_address"`
	MTU           int    `yaml:"mtu"`
	DNS           string `yaml:"dns"`
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
	Format  string `yaml:"format"`  // "hosts" or "domains" (default: "domains")
	Refresh int    `yaml:"refresh"` // seconds, default 86400
}

type PeerConfig struct {
	PrivateKey   string `yaml:"private_key"`
	PublicKey    string `yaml:"public_key"`
	AllowedIPs   string `yaml:"allowed_ips"`
	PresharedKey string `yaml:"preshared_key"`
	Disabled     bool   `yaml:"disabled"`
}

type RoutingConfig struct {
	ExcludeCIDRs []string        `yaml:"exclude_cidrs"`
	IPRules      []IPRuleConfig  `yaml:"ip_rules"`
	SNIRules     []SNIRuleConfig `yaml:"sni_rules"`
}

type IPRuleConfig struct {
	Name    string         `yaml:"name"`
	Action  string         `yaml:"action"`
	Outline string         `yaml:"outline"`
	CIDRs   []string       `yaml:"cidrs"`
	ASNs    []int          `yaml:"asns"`
	Lists   []IPListConfig `yaml:"lists"`
}

type IPListConfig struct {
	URL     string `yaml:"url"`
	Refresh int    `yaml:"refresh"`
}

type SNIRuleConfig struct {
	Name    string   `yaml:"name"`
	Action  string   `yaml:"action"`
	Outline string   `yaml:"outline"`
	Domains []string `yaml:"domains"`
}

type OutlineConfig struct {
	Name        string            `yaml:"name"`
	Transport   string            `yaml:"transport"`
	Default     bool              `yaml:"default"`
	HealthCheck HealthCheckConfig `yaml:"health_check"`
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
	Enabled     bool             `yaml:"enabled"`
	Listen      []string         `yaml:"listen"`
	Outline     string           `yaml:"outline"`
	Secrets     []string         `yaml:"secrets"`
	SecretsFile string           `yaml:"secrets_file"`
	StatsAddr   string           `yaml:"stats_addr"`
	FakeTLS     FakeTLSConfig    `yaml:"fake_tls"`
	Endpoints   map[int][]string `yaml:"endpoints"`
}

type FakeTLSConfig struct {
	Enabled             bool     `yaml:"enabled"`
	SNI                 []string `yaml:"sni"`
	MaxClockSkewSeconds int      `yaml:"max_clock_skew_seconds"`
	ReplayCacheTTLHours int      `yaml:"replay_cache_ttl_hours"`
}

type TelegramConfig struct {
	Enabled      bool    `yaml:"enabled"`
	Token        string  `yaml:"token"`
	ChatID       int64   `yaml:"chat_id"`
	Interval     int     `yaml:"interval"`      // status report interval in seconds
	AllowedUsers []int64 `yaml:"allowed_users"` // user IDs allowed in private chats
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if cfg.WireGuard.MTU == 0 {
		cfg.WireGuard.MTU = 1420
	}
	if cfg.WireGuard.DNS == "" {
		cfg.WireGuard.DNS = "1.1.1.1"
	}
	if cfg.DNS.Enabled {
		if cfg.DNS.Listen == "" {
			addr, _, err := cfg.WireGuard.ParseAddress()
			if err != nil {
				return nil, fmt.Errorf("parsing wireguard address for dns listen default: %w", err)
			}
			cfg.DNS.Listen = addr.String() + ":53"
		}
		if cfg.DNS.Upstream == "" {
			cfg.DNS.Upstream = cfg.WireGuard.DNS
		}
		if !strings.Contains(cfg.DNS.Upstream, ":") {
			cfg.DNS.Upstream = cfg.DNS.Upstream + ":53"
		}
		listenHost, _, _ := strings.Cut(cfg.DNS.Listen, ":")
		cfg.WireGuard.DNS = listenHost
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.CacheDir == "" {
		if userCache, err := os.UserCacheDir(); err == nil {
			cfg.CacheDir = filepath.Join(userCache, "wg-outline-bridge")
		}
	}
	if len(cfg.Outlines) == 0 {
		return nil, fmt.Errorf("at least one outline entry is required")
	}
	hasDefault := false
	for i := range cfg.Outlines {
		if cfg.Outlines[i].Name == "" {
			return nil, fmt.Errorf("outline entry %d: name is required", i)
		}
		if cfg.Outlines[i].Transport == "" {
			return nil, fmt.Errorf("outline %q: transport is required", cfg.Outlines[i].Name)
		}
		if cfg.Outlines[i].Default {
			if hasDefault {
				return nil, fmt.Errorf("outline %q: only one outline can be default", cfg.Outlines[i].Name)
			}
			hasDefault = true
		}
		if cfg.Outlines[i].HealthCheck.Interval == 0 {
			cfg.Outlines[i].HealthCheck.Interval = 30
		}
		if cfg.Outlines[i].HealthCheck.Target == "" {
			cfg.Outlines[i].HealthCheck.Target = "1.1.1.1:80"
		}
	}
	if !hasDefault {
		return nil, fmt.Errorf("no default outline configured: set default: true on one outline entry")
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

	if cfg.MTProxy.Enabled {
		if len(cfg.MTProxy.Listen) == 0 {
			return nil, fmt.Errorf("mtproxy: at least one listen address is required")
		}
		if cfg.MTProxy.SecretsFile == "" {
			cfg.MTProxy.SecretsFile = filepath.Join(filepath.Dir(path), "mtproxy.secrets")
		}
		fileSecrets, err := LoadSecretsFile(cfg.MTProxy.SecretsFile)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("mtproxy: loading secrets file: %w", err)
		}
		cfg.MTProxy.Secrets = append(cfg.MTProxy.Secrets, fileSecrets...)
		if cfg.MTProxy.FakeTLS.MaxClockSkewSeconds == 0 {
			cfg.MTProxy.FakeTLS.MaxClockSkewSeconds = 600
		}
		if cfg.MTProxy.FakeTLS.ReplayCacheTTLHours == 0 {
			cfg.MTProxy.FakeTLS.ReplayCacheTTLHours = 48
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

	cfg.PeersDir = filepath.Join(filepath.Dir(path), "peers")
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
		if err := yaml.Unmarshal(data, &peer); err != nil {
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

func (c *Config) DefaultOutline() *OutlineConfig {
	for i := range c.Outlines {
		if c.Outlines[i].Default {
			return &c.Outlines[i]
		}
	}
	return nil
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

// LoadSecretsFile reads secrets from a file, one per line.
// Supports line comments (# to end of line) and block comments (#~ to ~#).
func LoadSecretsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	text := stripBlockComments(string(data))

	var secrets []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		secrets = append(secrets, line)
	}
	return secrets, nil
}

// stripBlockComments removes all #~ ... ~# regions from text.
func stripBlockComments(text string) string {
	var b strings.Builder
	for {
		start := strings.Index(text, "#~")
		if start < 0 {
			b.WriteString(text)
			break
		}
		b.WriteString(text[:start])
		end := strings.Index(text[start+2:], "~#")
		if end < 0 {
			// Unterminated block comment: treat rest as comment.
			break
		}
		text = text[start+2+end+2:]
	}
	return b.String()
}

// ProxyLinks builds Telegram proxy links for all configured MTProxy secrets.
func ProxyLinks(cfg *Config) []string {
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

	links := make([]string, 0, len(cfg.MTProxy.Secrets))
	for _, secret := range cfg.MTProxy.Secrets {
		linkSecret := secret
		if cfg.MTProxy.FakeTLS.Enabled && len(cfg.MTProxy.FakeTLS.SNI) > 0 {
			// For fake TLS, the client secret is: ee + raw_secret_hex + hex(sni)
			// Strip any dd/ee prefix to get the raw 32-char hex secret
			raw := secret
			if len(raw) == 34 && (raw[:2] == "dd" || raw[:2] == "ee") {
				raw = raw[2:]
			}
			linkSecret = "ee" + raw + hex.EncodeToString([]byte(cfg.MTProxy.FakeTLS.SNI[0]))
		}
		link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%s&secret=%s", serverIP, port, linkSecret)
		links = append(links, link)
	}
	return links
}

// AppendSecret appends a secret line to the given file, creating it if needed.
func AppendSecret(path, secret string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening secrets file: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, secret); err != nil {
		return fmt.Errorf("writing secret: %w", err)
	}
	return nil
}
