package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WireGuard WireGuardConfig `yaml:"wireguard"`
	Outline   OutlineConfig   `yaml:"outline"`
}

type WireGuardConfig struct {
	PrivateKey string       `yaml:"private_key"`
	ListenPort int          `yaml:"listen_port"`
	Address    string       `yaml:"address"`
	MTU        int          `yaml:"mtu"`
	DNS        string       `yaml:"dns"`
	Peers      []PeerConfig `yaml:"peers"`
}

type PeerConfig struct {
	PublicKey    string `yaml:"public_key"`
	AllowedIPs   string `yaml:"allowed_ips"`
	PresharedKey string `yaml:"preshared_key"`
}

type OutlineConfig struct {
	Transport string `yaml:"transport"`
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

	return &cfg, nil
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
