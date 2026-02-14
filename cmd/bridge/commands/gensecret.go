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
)

func GenSecret(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("gensecret", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	padding := fs.Bool("dd", false, "generate dd-prefix secret (padding mode)")
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
	if *padding {
		secretHex = "dd" + secretHex
	}

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
