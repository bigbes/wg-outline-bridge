package commands

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

func GenKeys(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("genkeys", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	name := fs.String("name", "", "name/label for this peer (required)")
	fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "error: -name is required")
		fs.Usage()
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		logger.Error("failed to generate keys", "err", err)
		os.Exit(1)
	}

	clientIP, err := nextPeerIP(cfg)
	if err != nil {
		logger.Error("failed to determine client IP", "err", err)
		os.Exit(1)
	}

	if err := appendPeerToConfig(*configPath, *name, publicKey, clientIP); err != nil {
		logger.Error("failed to update config", "err", err)
		os.Exit(1)
	}

	fmt.Println("=== Peer added to config ===")
	fmt.Printf("Name:        %s\n", *name)
	fmt.Printf("Client IP:   %s\n", clientIP)
	fmt.Printf("Public Key:  %s\n", publicKey)
	fmt.Println()
	fmt.Println("=== Client WireGuard config ===")
	fmt.Println()
	fmt.Println("[Interface]")
	fmt.Printf("PrivateKey = %s\n", privateKey)
	fmt.Printf("Address = %s/24\n", clientIP)
	fmt.Printf("DNS = %s\n", cfg.WireGuard.DNS)
	fmt.Println()
	fmt.Println("[Peer]")
	if serverPublicKey, err := derivePublicKey(cfg.WireGuard.PrivateKey); err == nil {
		fmt.Printf("PublicKey = %s\n", serverPublicKey)
	} else {
		fmt.Println("PublicKey = <failed to derive, check server private key>")
	}
	fmt.Printf("Endpoint = <SERVER_IP>:%d\n", cfg.WireGuard.ListenPort)
	fmt.Println("AllowedIPs = 0.0.0.0/0")
	fmt.Println("PersistentKeepalive = 25")
}

func generateKeyPair() (privateKeyB64, publicKeyB64 string, err error) {
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

func derivePublicKey(privateKeyB64 string) (string, error) {
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

func nextPeerIP(cfg *config.Config) (string, error) {
	addr, _, err := cfg.WireGuard.ParseAddress()
	if err != nil {
		return "", err
	}

	used := make(map[netip.Addr]bool)
	used[addr] = true
	for _, peer := range cfg.WireGuard.Peers {
		ip := strings.Split(peer.AllowedIPs, "/")[0]
		if a, err := netip.ParseAddr(ip); err == nil {
			used[a] = true
		}
	}

	candidate := addr.Next()
	for i := 0; i < 253; i++ {
		if !used[candidate] {
			return candidate.String(), nil
		}
		candidate = candidate.Next()
	}

	return "", fmt.Errorf("no available IPs in subnet")
}

func appendPeerToConfig(path, name, publicKey, clientIP string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing yaml: %w", err)
	}

	peersNode, err := findPeersNode(&doc)
	if err != nil {
		return err
	}

	if peersNode.Kind == yaml.ScalarNode || (peersNode.Kind == yaml.SequenceNode && peersNode.Style == yaml.FlowStyle) {
		peersNode.Kind = yaml.SequenceNode
		peersNode.Tag = "!!seq"
		peersNode.Style = 0
		peersNode.Value = ""
		if peersNode.Content == nil {
			peersNode.Content = nil
		}
	}

	peerMapping := &yaml.Node{
		Kind:        yaml.MappingNode,
		Tag:         "!!map",
		HeadComment: name,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "public_key"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: publicKey, Style: yaml.DoubleQuotedStyle},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "allowed_ips"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: clientIP + "/32", Style: yaml.DoubleQuotedStyle},
		},
	}

	peersNode.Content = append(peersNode.Content, peerMapping)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("marshaling yaml: %w", err)
	}
	enc.Close()

	return os.WriteFile(path, buf.Bytes(), 0o600)
}

func findPeersNode(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("invalid yaml document")
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("root is not a mapping")
	}

	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == "wireguard" {
			wgNode := root.Content[i+1]
			if wgNode.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("wireguard is not a mapping")
			}
			for j := 0; j < len(wgNode.Content)-1; j += 2 {
				if wgNode.Content[j].Value == "peers" {
					return wgNode.Content[j+1], nil
				}
			}
			return nil, fmt.Errorf("peers key not found under wireguard")
		}
	}

	return nil, fmt.Errorf("wireguard key not found in config")
}
