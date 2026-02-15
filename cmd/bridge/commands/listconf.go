package commands

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

func ListConf(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("listconf", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	if len(cfg.Peers) == 0 {
		fmt.Println("No peers configured")
		return
	}

	names := make([]string, 0, len(cfg.Peers))
	for name := range cfg.Peers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		peer := cfg.Peers[name]
		shortKey := peer.PublicKey
		if len(shortKey) > 8 {
			shortKey = shortKey[:8]
		}
		if peer.Disabled {
			fmt.Printf("[disabled] %s  %s\n", shortKey, name)
		} else {
			fmt.Printf("%s  %s\n", shortKey, name)
		}
	}
}
