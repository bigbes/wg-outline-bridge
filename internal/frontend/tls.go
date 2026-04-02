package frontend

import (
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/acme/autocert"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

// buildTLSConfig creates a *tls.Config from the frontend configuration.
// Supports ACME (autocert) or static cert/key pair.
func buildTLSConfig(cfg config.FrontendConfig, acmeDir string) (*tls.Config, error) {
	if cfg.Domain != "" {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Email:      cfg.ACMEEmail,
		}
		if acmeDir != "" {
			m.Cache = autocert.DirCache(acmeDir)
		}
		tlsCfg := m.TLSConfig()
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		return tlsCfg, nil
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert/key: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}, nil
	}

	return nil, fmt.Errorf("frontend: domain (ACME) or cert_file+key_file required")
}
