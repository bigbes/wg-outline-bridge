package outline

import (
	"encoding/json"
	"fmt"

	"github.com/blikh/wireguard-outline-bridge/internal/upstream"
)

// OutlineConfig is the type-specific configuration for outline upstreams.
type OutlineConfig struct {
	Transport string `json:"transport"`
}

// Factory builds outline upstream dialers.
type Factory struct{}

// Type returns the upstream type this factory handles.
func (Factory) Type() upstream.Type {
	return upstream.TypeOutline
}

// Build creates an outline upstream from the given spec.
func (Factory) Build(spec upstream.Spec) (upstream.Built, error) {
	var cfg OutlineConfig
	if err := json.Unmarshal(spec.Config, &cfg); err != nil {
		return upstream.Built{}, fmt.Errorf("parsing outline config: %w", err)
	}
	if cfg.Transport == "" {
		return upstream.Built{}, fmt.Errorf("outline config: transport is required")
	}

	trafficClient, err := NewClient(cfg.Transport)
	if err != nil {
		return upstream.Built{}, fmt.Errorf("creating outline traffic client: %w", err)
	}
	swappable := NewSwappableClient(trafficClient)
	statsDialer := NewStatsDialer(spec.Name, swappable)

	healthClient, err := NewClient(cfg.Transport)
	if err != nil {
		return upstream.Built{}, fmt.Errorf("creating outline health client: %w", err)
	}

	return upstream.Built{
		TrafficDialer: statsDialer,
		HealthDialer:  healthClient,
		Stats: func() upstream.StatsSnapshot {
			snap := statsDialer.Snapshot()
			return upstream.StatsSnapshot{
				RxBytes:           snap.RxBytes,
				TxBytes:           snap.TxBytes,
				ActiveConnections: snap.ActiveConnections,
			}
		},
		Swap: func(newBuilt upstream.Built) {
			// For outline, we can swap the underlying client in the swappable wrapper.
			// This preserves existing stats and references.
			if newClient, ok := newBuilt.TrafficDialer.(*StatsDialer); ok {
				if underlying, ok2 := newClient.up.(*SwappableClient); ok2 {
					swappable.Swap(underlying.Get())
				}
			}
		},
	}, nil
}
