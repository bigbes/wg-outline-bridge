package commands

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/statsdb"
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

	if cfg.Database.Path != "" {
		store, err := statsdb.Open(cfg.Database.Path, logger)
		if err != nil {
			logger.Error("failed to open database", "err", err)
			os.Exit(1)
		}
		defer store.Close()

		dbPeers, err := store.ListPeers()
		if err != nil {
			logger.Error("failed to load peers from database", "err", err)
			os.Exit(1)
		}
		if len(dbPeers) > 0 {
			cfg.Peers = dbPeers
		}
	}

	privateKey, publicKey, err := config.GenerateKeyPair()
	if err != nil {
		logger.Error("failed to generate keys", "err", err)
		os.Exit(1)
	}

	presharedKey, err := config.GeneratePresharedKey()
	if err != nil {
		logger.Error("failed to generate preshared key", "err", err)
		os.Exit(1)
	}

	clientIP, err := config.NextPeerIP(cfg)
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
	if cfg.Database.Path != "" {
		store, err := statsdb.Open(cfg.Database.Path, logger)
		if err != nil {
			logger.Error("failed to open database", "err", err)
			os.Exit(1)
		}
		defer store.Close()

		if err := store.UpsertPeer(*name, peer); err != nil {
			logger.Error("failed to save peer to database", "err", err)
			os.Exit(1)
		}
	} else {
		if err := config.SavePeer(cfg.PeersDir, *name, peer); err != nil {
			logger.Error("failed to save peer", "err", err)
			os.Exit(1)
		}
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
	cidrRules, err := config.ParseCIDRRules(cfg.Routing.CIDRs)
	if err != nil {
		logger.Error("failed to parse CIDR rules", "err", err)
		os.Exit(1)
	}
	if computed := config.ComputeAllowedIPs(cidrRules, serverIP); computed != "" {
		allowedIPs = computed
	}

	if cfg.WireGuard.IsAmneziaWG() {
		fmt.Println("=== Client AmneziaWG config ===")
	} else {
		fmt.Println("=== Client WireGuard config ===")
	}
	fmt.Println()
	fmt.Println("[Interface]")
	fmt.Printf("PrivateKey = %s\n", privateKey)
	fmt.Printf("Address = %s/24\n", clientIP)
	fmt.Printf("DNS = %s\n", cfg.WireGuard.DNS)
	if cfg.WireGuard.IsAmneziaWG() {
		printAWGInterfaceParams(cfg.WireGuard.AmneziaWG)
	}
	fmt.Println()
	fmt.Println("[Peer]")
	if serverPublicKey, err := config.DerivePublicKey(cfg.WireGuard.PrivateKey); err == nil {
		fmt.Printf("PublicKey = %s\n", serverPublicKey)
	} else {
		fmt.Println("PublicKey = <failed to derive, check server private key>")
	}
	fmt.Printf("PresharedKey = %s\n", presharedKey)
	fmt.Printf("Endpoint = %s\n", endpoint)
	fmt.Printf("AllowedIPs = %s\n", allowedIPs)
	fmt.Println("PersistentKeepalive = 25")
}
