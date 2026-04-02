package porttracker

import (
	"testing"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

func TestUsedPorts(t *testing.T) {
	cfg := &config.Config{
		Frontend: config.FrontendConfig{
			Listen: ":443",
		},
		DNS: config.DNSConfig{
			Enabled: true,
			Listen:  "10.100.0.1:53",
		},
		Proxies: []config.ProxyServerConfig{
			{Name: "socks", Listen: "0.0.0.0:1080"},
			{Name: "http", Listen: ":8080"},
		},
		ObservabilityHTTP: config.ObservabilityHTTPConfig{
			Addr: ":6060",
		},
	}

	ports := UsedPorts(cfg)

	expected := map[int]string{
		443:  "frontend",
		53:   "dns",
		1080: "proxy:socks",
		8080: "proxy:http",
		6060: "observability",
	}

	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d: %+v", len(expected), len(ports), ports)
	}

	for _, pi := range ports {
		owner, ok := expected[pi.Port]
		if !ok {
			t.Errorf("unexpected port %d (owner=%s)", pi.Port, pi.Owner)
			continue
		}
		if pi.Owner != owner {
			t.Errorf("port %d: expected owner %q, got %q", pi.Port, owner, pi.Owner)
		}
	}
}

func TestUsedPorts_DisabledServices(t *testing.T) {
	cfg := &config.Config{
		Frontend: config.FrontendConfig{
			Listen: ":443",
		},
		DNS: config.DNSConfig{
			Enabled: false,
			Listen:  "10.100.0.1:53",
		},
	}

	ports := UsedPorts(cfg)
	// Frontend is always present.
	if len(ports) != 1 {
		t.Errorf("expected 1 port (frontend only), got %d: %+v", len(ports), ports)
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"0.0.0.0:1080", 1080},
		{":1080", 1080},
		{"1080", 1080},
		{"", 0},
		{"invalid", 0},
		{":0", 0},
		{":99999", 0},
	}
	for _, tt := range tests {
		got := extractPort(tt.input)
		if got != tt.want {
			t.Errorf("extractPort(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
