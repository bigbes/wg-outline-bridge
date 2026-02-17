package commands

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
	"github.com/blikh/wireguard-outline-bridge/internal/statsdb"
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

	if cfg.Database.Path != "" {
		store, err := statsdb.Open(cfg.Database.Path, logger)
		if err != nil {
			logger.Error("failed to open database", "err", err)
			os.Exit(1)
		}
		defer store.Close()

		dbSecrets, err := store.ListSecrets()
		if err != nil {
			logger.Error("failed to load secrets from database", "err", err)
			os.Exit(1)
		}
		if len(dbSecrets) > 0 {
			cfg.MTProxy.Secrets = dbSecrets
		}
	}

	if !cfg.MTProxy.Enabled {
		fmt.Fprintln(os.Stderr, "error: mtproxy is not enabled in config")
		os.Exit(1)
	}

	links := config.ProxyLinks(cfg, nil)
	if len(links) == 0 {
		fmt.Fprintln(os.Stderr, "error: no secrets configured")
		os.Exit(1)
	}

	fmt.Println("Telegram Proxy Links:")
	fmt.Println()
	for _, link := range links {
		fmt.Printf("  [%s] %s\n", link.Name, link.URL)
	}
}
