package commands

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/statsdb"
)

func ShowConf(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("showconf", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	name := fs.String("name", "", "peer name (required)")
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

	peer, ok := cfg.Peers[*name]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: peer %q not found\n", *name)
		os.Exit(1)
	}

	// Derive the client IP from allowed_ips (strip the /32 prefix)
	clientIP := strings.Split(peer.AllowedIPs, "/")[0]

	// Build endpoint
	serverIP := cfg.ServerPublicIP()
	endpoint := fmt.Sprintf("<SERVER_IP>:%d", cfg.WireGuard.ListenPort)
	if serverIP != "" {
		endpoint = fmt.Sprintf("%s:%d", serverIP, cfg.WireGuard.ListenPort)
	}

	// Build AllowedIPs from CIDR rules
	allowedIPs := "0.0.0.0/0"
	cidrVars := map[string]string{"server_ip": serverIP}
	cidrs := cfg.Routing.CIDRs
	if peer.ExcludePrivate {
		cidrs = append(config.PrivateNetworkCIDRs(cfg.WireGuard.Address), cidrs...)
	}
	cidrRules, err := config.ParseCIDRRules(config.ExpandCIDRRuleVars(cidrs, cidrVars))
	if err != nil {
		logger.Error("failed to parse CIDR rules", "err", err)
		os.Exit(1)
	}
	excludeIP := ""
	if peer.ExcludeServer {
		excludeIP = serverIP
	}
	if computed := config.ComputeAllowedIPs(cidrRules, excludeIP); computed != "" {
		allowedIPs = computed
	}

	// Print client config
	fmt.Println("[Interface]")
	fmt.Printf("PrivateKey = %s\n", peer.PrivateKey)
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
	if peer.PresharedKey != "" {
		fmt.Printf("PresharedKey = %s\n", peer.PresharedKey)
	}
	fmt.Printf("Endpoint = %s\n", endpoint)
	fmt.Printf("AllowedIPs = %s\n", allowedIPs)
	fmt.Println("PersistentKeepalive = 25")
}
