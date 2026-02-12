package commands

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/blikh/wireguard-outline-bridge/internal/bridge"
	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

func RunBridge(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	b := bridge.New(*configPath, cfg, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-sighup:
				logger.Info("received SIGHUP, reloading config")
				if err := b.Reload(); err != nil {
					logger.Error("reload failed", "err", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := b.Run(ctx); err != nil {
		logger.Error("bridge error", "err", err)
		os.Exit(1)
	}
}
