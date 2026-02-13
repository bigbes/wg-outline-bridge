package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel  string          `yaml:"log_level"`
	WireGuard WireGuardConfig `yaml:"wireguard"`
	Outlines  []OutlineConfig `yaml:"outlines"`
	Routing   RoutingConfig   `yaml:"routing"`
	GeoIP     []GeoIPConfig   `yaml:"geoip"`
}

type WireGuardConfig struct {
	PrivateKey    string       `yaml:"private_key"`
	ListenPort    int          `yaml:"listen_port"`
	Address       string       `yaml:"address"`
	PublicAddress string       `yaml:"public_address"`
	MTU           int          `yaml:"mtu"`
	DNS           string       `yaml:"dns"`
	Peers         []PeerConfig `yaml:"peers"`
}

type PeerConfig struct {
	PublicKey    string `yaml:"public_key"`
	AllowedIPs   string `yaml:"allowed_ips"`
	PresharedKey string `yaml:"preshared_key"`
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
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
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

	return &cfg, nil
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
	Added   []PeerConfig
	Removed []PeerConfig
}

func DiffPeers(old, new []PeerConfig) PeerDiff {
	oldMap := make(map[string]PeerConfig, len(old))
	for _, p := range old {
		oldMap[p.PublicKey] = p
	}
	newMap := make(map[string]PeerConfig, len(new))
	for _, p := range new {
		newMap[p.PublicKey] = p
	}

	var diff PeerDiff
	for key, p := range newMap {
		if _, exists := oldMap[key]; !exists {
			diff.Added = append(diff.Added, p)
		}
	}
	for key, p := range oldMap {
		if _, exists := newMap[key]; !exists {
			diff.Removed = append(diff.Removed, p)
		}
	}
	return diff
}

func (c *WireGuardConfig) ToUAPI() (string, error) {
	var b strings.Builder

	privHex, err := base64ToHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)

	for _, peer := range c.Peers {
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
