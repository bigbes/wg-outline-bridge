package commands

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
	"github.com/blikh/wireguard-outline-bridge/internal/statsdb"
)

func GenSecret(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("gensecret", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	secretType := fs.String("type", "faketls", "secret type: faketls/ee (ee-prefix), padded/dd (dd-prefix), default (no prefix)")
	comment := fs.String("comment", "", "comment to add after the secret")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		logger.Error("failed to generate random bytes", "err", err)
		os.Exit(1)
	}

	secretHex := hex.EncodeToString(secret[:])
	switch *secretType {
	case "faketls", "ee":
		secretHex = "ee" + secretHex
	case "padded", "dd":
		secretHex = "dd" + secretHex
	case "default":
		// no prefix
	default:
		logger.Error("unknown secret type, must be faketls/ee, padded/dd, or default", "type", *secretType)
		os.Exit(1)
	}

	if cfg.Database.Path != "" {
		store, err := statsdb.Open(cfg.Database.Path, logger)
		if err != nil {
			logger.Error("failed to open database", "err", err)
			os.Exit(1)
		}
		defer store.Close()

		if err := store.AddSecret(secretHex, *comment); err != nil {
			logger.Error("failed to save secret to database", "err", err)
			os.Exit(1)
		}

		fmt.Printf("Secret:  %s\n", secretHex)
		fmt.Println("Saved to: database")
	} else {
		secretsFile := cfg.MTProxy.SecretsFile
		if secretsFile == "" {
			secretsFile = filepath.Join(filepath.Dir(*configPath), "mtproxy.secrets")
		}

		line := secretHex
		if *comment != "" {
			line += "  # " + *comment
		}

		if err := config.AppendSecret(secretsFile, line); err != nil {
			logger.Error("failed to save secret", "err", err)
			os.Exit(1)
		}

		fmt.Printf("Secret:  %s\n", secretHex)
		fmt.Printf("Saved to: %s\n", secretsFile)
	}
}
