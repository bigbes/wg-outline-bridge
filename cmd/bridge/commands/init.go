package commands

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

func Init(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	transport := fs.String("transport", "", "outline transport URI (ss://...)")
	listenPort := fs.Int("port", 51820, "WireGuard listen port")
	address := fs.String("address", "10.100.0.1/24", "WireGuard server address")
	fs.Parse(args)

	if *transport == "" {
		fmt.Fprintln(os.Stderr, "error: -transport is required (e.g. ss://...)")
		fs.Usage()
		os.Exit(1)
	}

	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		logger.Error("failed to generate server keys", "err", err)
		os.Exit(1)
	}

	content := fmt.Sprintf(`wireguard:
  private_key: "%s"
  listen_port: %d
  address: "%s"
  mtu: 1420
  dns: "1.1.1.1"
  peers: []

outline:
  transport: "%s"
`, privateKey, *listenPort, *address, *transport)

	dir := filepath.Dir(*configPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Error("failed to create config directory", "err", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*configPath, []byte(content), 0o600); err != nil {
		logger.Error("failed to write config", "err", err)
		os.Exit(1)
	}

	fmt.Println("=== Config initialized ===")
	fmt.Printf("Config:     %s\n", *configPath)
	fmt.Printf("Public Key: %s\n", publicKey)
	fmt.Printf("Port:       %d\n", *listenPort)
	fmt.Printf("Address:    %s\n", *address)
	fmt.Println()
	fmt.Println("Share the public key with clients.")
	fmt.Println("Run 'bridge genkeys -name <user>' to add peers.")
}
