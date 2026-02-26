package routing

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

func TestRoutePort(t *testing.T) {
	logger := slog.Default()
	cfg := config.RoutingConfig{
		PortRules: []config.PortRuleConfig{
			{
				Name:   "block-torrent",
				Action: "block",
				Ports:  []string{"6881-6889", "6969"},
			},
			{
				Name:   "direct-http",
				Action: "direct",
				Ports:  []string{"80", "443"},
			},
		},
	}
	r := NewRouter(cfg, nil, logger)

	tests := []struct {
		name    string
		port    uint16
		wantOK  bool
		wantAct ActionType
	}{
		{"torrent port 6881", 6881, true, ActionBlock},
		{"torrent port 6885", 6885, true, ActionBlock},
		{"torrent port 6889", 6889, true, ActionBlock},
		{"tracker port 6969", 6969, true, ActionBlock},
		{"http port 80", 80, true, ActionDirect},
		{"https port 443", 443, true, ActionDirect},
		{"unmatched port 8080", 8080, false, ActionDefault},
		{"port below range 6880", 6880, false, ActionDefault},
		{"port above range 6890", 6890, false, ActionDefault},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Request{DestIP: netip.MustParseAddr("1.2.3.4"), DestPort: tt.port}
			dec, ok := r.RoutePort(req)
			if ok != tt.wantOK {
				t.Fatalf("RoutePort() matched=%v, want %v", ok, tt.wantOK)
			}
			if ok && dec.Action != tt.wantAct {
				t.Errorf("RoutePort() action=%v, want %v", dec.Action, tt.wantAct)
			}
		})
	}
}

func TestRouteProtocol(t *testing.T) {
	logger := slog.Default()
	cfg := config.RoutingConfig{
		ProtocolRules: []config.ProtocolRuleConfig{
			{
				Name:      "block-bt",
				Action:    "block",
				Protocols: []string{"bittorrent"},
			},
		},
	}
	r := NewRouter(cfg, nil, logger)

	tests := []struct {
		name     string
		protocol string
		wantOK   bool
		wantAct  ActionType
	}{
		{"bittorrent lowercase", "bittorrent", true, ActionBlock},
		{"bittorrent mixed case", "BitTorrent", true, ActionBlock},
		{"unknown protocol", "http", false, ActionDefault},
		{"empty protocol", "", false, ActionDefault},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec, ok := r.RouteProtocol(tt.protocol)
			if ok != tt.wantOK {
				t.Fatalf("RouteProtocol() matched=%v, want %v", ok, tt.wantOK)
			}
			if ok && dec.Action != tt.wantAct {
				t.Errorf("RouteProtocol() action=%v, want %v", dec.Action, tt.wantAct)
			}
		})
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    portRange
		wantErr bool
	}{
		{"single port", "6881", portRange{6881, 6881}, false},
		{"port range", "6881-6889", portRange{6881, 6889}, false},
		{"port 0", "0", portRange{0, 0}, false},
		{"max port", "65535", portRange{65535, 65535}, false},
		{"invalid", "abc", portRange{}, true},
		{"invalid range start", "abc-6889", portRange{}, true},
		{"invalid range end", "6881-abc", portRange{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePortRange(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePortRange(%q) error=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parsePortRange(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBlockAction(t *testing.T) {
	logger := slog.Default()
	cfg := config.RoutingConfig{
		IPRules: []config.IPRuleConfig{
			{
				Name:   "block-ips",
				Action: "block",
				CIDRs:  []string{"10.0.0.0/8"},
			},
		},
		SNIRules: []config.SNIRuleConfig{
			{
				Name:    "block-domains",
				Action:  "block",
				Domains: []string{"*.torrent.example.com"},
			},
		},
	}
	r := NewRouter(cfg, nil, logger)

	// IP block
	req := Request{DestIP: netip.MustParseAddr("10.1.2.3"), DestPort: 80}
	dec, ok := r.RouteIP(req)
	if !ok || dec.Action != ActionBlock {
		t.Errorf("expected IP block, got matched=%v action=%v", ok, dec.Action)
	}

	// SNI block
	req = Request{DestIP: netip.MustParseAddr("1.2.3.4"), DestPort: 443, SNI: "tracker.torrent.example.com"}
	dec, ok = r.RouteSNI(req)
	if !ok || dec.Action != ActionBlock {
		t.Errorf("expected SNI block, got matched=%v action=%v", ok, dec.Action)
	}
}
