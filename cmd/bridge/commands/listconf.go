package commands

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/statsdb"
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

	if len(cfg.Peers) == 0 {
		fmt.Println("No peers configured")
		return
	}

	type peerEntry struct {
		ID   int
		Name string
	}
	entries := make([]peerEntry, 0, len(cfg.Peers))
	for id, peer := range cfg.Peers {
		entries = append(entries, peerEntry{ID: id, Name: peer.Name})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })

	for _, e := range entries {
		fmt.Printf("%d\t%s\n", e.ID, e.Name)
	}
}
