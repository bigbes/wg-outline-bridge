package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/blikh/wireguard-outline-bridge/cmd/bridge/commands"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		commands.RunBridge(os.Args[2:], logger)
	case "watch":
		commands.Watch(os.Args[2:], logger)
	case "genconf":
		commands.GenConf(os.Args[2:], logger)
	case "init":
		commands.Init(os.Args[2:], logger)
	case "showconf":
		commands.ShowConf(os.Args[2:], logger)
	case "gensecret":
		commands.GenSecret(os.Args[2:], logger)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: bridge <command> [options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  run       Start the WireGuard-Outline bridge")
	fmt.Fprintln(os.Stderr, "  watch     Run with auto-restart on binary update (wrapper)")
	fmt.Fprintln(os.Stderr, "  genconf   Generate a new peer keypair and add to config")
	fmt.Fprintln(os.Stderr, "  init      Generate a new server config with fresh keys")
	fmt.Fprintln(os.Stderr, "  showconf  Print WireGuard client config for a peer")
	fmt.Fprintln(os.Stderr, "  gensecret Generate a new MTProxy secret")
}
