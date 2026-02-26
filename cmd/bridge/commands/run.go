package commands

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bigbes/wireguard-outline-bridge/internal/bridge"
	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

const logo = `
 __      _____    ___  _   _ _____ 
 \ \    / / __|  / _ \| | | |_   _|
  \ \/\/ / (_ | | (_) | |_| | | |  
   \_/\_/ \___|  \___/ \___/  |_|  
   ~~ wireguard-outline-bridge ~~`

func RunBridge(args []string, logger *slog.Logger, version string, dirty bool) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	watch := fs.Bool("watch", false, "watch for binary updates and auto-restart")
	logPath := fs.String("log", "output.log", "path to output log file (only with --watch)")
	fs.Parse(args)

	if *watch {
		Watch([]string{"--config", *configPath, "--log", *logPath}, logger)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.ParseLogLevel()}))

	fmt.Println(logo)
	logger.Info("starting wireguard-outline-bridge", "version", version, "dirty", dirty)
	if bi, ok := debug.ReadBuildInfo(); ok {
		var buildAttrs []any
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs", "vcs.revision", "vcs.time", "vcs.modified":
				buildAttrs = append(buildAttrs, s.Key, s.Value)
			}
		}
		if len(buildAttrs) > 0 {
			logger.Info("build info", buildAttrs...)
		}
	}

	if obs := cfg.ObservabilityHTTP; obs.Addr != "" {
		mux := http.NewServeMux()
		if obs.Pprof {
			// Re-register pprof handlers on our mux (net/http/pprof init registers on DefaultServeMux).
			mux.HandleFunc("/debug/pprof/", http.DefaultServeMux.ServeHTTP)
		}
		if obs.Metrics {
			mux.Handle("/metrics", promhttp.Handler())
		}
		go func() {
			logger.Info("starting observability server", "addr", obs.Addr, "pprof", obs.Pprof, "metrics", obs.Metrics)
			if err := http.ListenAndServe(obs.Addr, mux); err != nil {
				logger.Error("observability server failed", "err", err)
			}
		}()
	}

	b := bridge.New(*configPath, cfg, logger, version, dirty)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	if err := b.Run(ctx); err != nil {
		cancel()
		logger.Error("bridge error", "err", err)
		os.Exit(1)
	}
	cancel()
}
