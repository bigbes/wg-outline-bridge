// Package porttracker collects all TCP/UDP ports used by the bridge
// and exposes them for validation (e.g. when adding a new proxy).
package porttracker

import (
	"net"
	"strconv"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

// PortInfo describes a single used port.
type PortInfo struct {
	Port  int    `json:"port"`
	Owner string `json:"owner"` // e.g. "proxy:my-socks5", "wireguard", "dns"
	Proto string `json:"proto"` // "tcp", "udp", or "tcp+udp"
}

// UsedPorts returns all ports occupied by the current configuration.
func UsedPorts(cfg *config.Config) []PortInfo {
	var ports []PortInfo

	// WireGuard listen port (UDP).
	if cfg.WireGuard.ListenPort > 0 {
		ports = append(ports, PortInfo{
			Port:  cfg.WireGuard.ListenPort,
			Owner: "wireguard",
			Proto: "udp",
		})
	}

	// DNS server.
	if cfg.DNS.Enabled {
		if p := extractPort(cfg.DNS.Listen); p > 0 {
			ports = append(ports, PortInfo{
				Port:  p,
				Owner: "dns",
				Proto: "tcp+udp",
			})
		}
	}

	// MTProxy listeners.
	if cfg.MTProxy.Enabled {
		for _, addr := range cfg.MTProxy.Listen {
			if p := extractPort(addr); p > 0 {
				ports = append(ports, PortInfo{
					Port:  p,
					Owner: "mtproxy",
					Proto: "tcp",
				})
			}
		}
	}

	// Proxy servers.
	for _, ps := range cfg.Proxies {
		if p := extractPort(ps.Listen); p > 0 {
			owner := "proxy"
			if ps.Name != "" {
				owner = "proxy:" + ps.Name
			}
			ports = append(ports, PortInfo{
				Port:  p,
				Owner: owner,
				Proto: "tcp",
			})
		}
	}

	// MiniApp HTTPS server.
	if cfg.MiniApp.Enabled {
		if p := extractPort(cfg.MiniApp.Listen); p > 0 {
			ports = append(ports, PortInfo{
				Port:  p,
				Owner: "miniapp",
				Proto: "tcp",
			})
		}
	}

	// Observability HTTP server.
	if cfg.ObservabilityHTTP.Addr != "" {
		if p := extractPort(cfg.ObservabilityHTTP.Addr); p > 0 {
			ports = append(ports, PortInfo{
				Port:  p,
				Owner: "observability",
				Proto: "tcp",
			})
		}
	}

	return ports
}

// extractPort returns the port number from an address string like
// "0.0.0.0:1080", ":1080", or just "1080". Returns 0 on failure.
func extractPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// Maybe it's just a bare port number.
		portStr = addr
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 0
	}
	return p
}
