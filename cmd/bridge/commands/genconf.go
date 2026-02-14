package commands

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

func GenConf(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("genconf", flag.ExitOnError)
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

	presharedKey, err := generatePresharedKey()
	if err != nil {
		logger.Error("failed to generate preshared key", "err", err)
		os.Exit(1)
	}

	clientIP, err := nextPeerIP(cfg)
	if err != nil {
		logger.Error("failed to determine client IP", "err", err)
		os.Exit(1)
	}

	peer := config.PeerConfig{
		PrivateKey:   privateKey,
		PublicKey:    publicKey,
		PresharedKey: presharedKey,
		AllowedIPs:   clientIP + "/32",
	}
	if err := config.SavePeer(cfg.PeersDir, *name, peer); err != nil {
		logger.Error("failed to save peer", "err", err)
		os.Exit(1)
	}

	fmt.Println("=== Peer added to config ===")
	fmt.Printf("Name:        %s\n", *name)
	fmt.Printf("Client IP:   %s\n", clientIP)
	fmt.Printf("Public Key:  %s\n", publicKey)
	fmt.Println()
	serverIP := cfg.ServerPublicIP()
	endpoint := fmt.Sprintf("<SERVER_IP>:%d", cfg.WireGuard.ListenPort)
	if serverIP != "" {
		endpoint = fmt.Sprintf("%s:%d", serverIP, cfg.WireGuard.ListenPort)
	}

	allowedIPs := "0.0.0.0/0"
	excludes := cfg.Routing.ExcludeCIDRs
	if serverIP != "" {
		if addr, err := netip.ParseAddr(serverIP); err == nil {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			excludes = append(excludes, netip.PrefixFrom(addr, bits).String())
		}
	}
	if len(excludes) > 0 {
		var exPrefixes []netip.Prefix
		for _, cidr := range excludes {
			if p, err := netip.ParsePrefix(cidr); err == nil {
				exPrefixes = append(exPrefixes, p)
			} else {
				logger.Warn("invalid exclude CIDR, skipping", "cidr", cidr, "err", err)
			}
		}
		if len(exPrefixes) > 0 {
			base := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
			remaining := config.ExcludePrefixes(base, exPrefixes)
			parts := make([]string, len(remaining))
			for i, p := range remaining {
				parts[i] = p.String()
			}
			allowedIPs = strings.Join(parts, ", ")
		}
	}

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
	fmt.Printf("PresharedKey = %s\n", presharedKey)
	fmt.Printf("Endpoint = %s\n", endpoint)
	fmt.Printf("AllowedIPs = %s\n", allowedIPs)
	fmt.Println("PersistentKeepalive = 25")
}

func generatePresharedKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
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
	for _, peer := range cfg.Peers {
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

