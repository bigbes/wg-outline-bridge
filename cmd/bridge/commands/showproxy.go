package commands

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

func ShowProxy(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("showproxy", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	if !cfg.MTProxy.Enabled {
		fmt.Fprintln(os.Stderr, "error: mtproxy is not enabled in config")
		os.Exit(1)
	}

	links := config.ProxyLinks(cfg)
	if len(links) == 0 {
		fmt.Fprintln(os.Stderr, "error: no secrets configured")
		os.Exit(1)
	}

	fmt.Println("Telegram Proxy Links:")
	fmt.Println()
	for i, link := range links {
		fmt.Printf("  [%d] %s\n", i+1, link)
	}
}
