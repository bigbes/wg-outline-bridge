package outline

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/bigbes/wireguard-outline-bridge/internal/upstream"
)

// OutlineConfig is the type-specific configuration for outline upstreams.
type OutlineConfig struct {
	Transport string `json:"transport"`
}

// Factory builds outline upstream dialers.
// It deduplicates health-check dialers so upstreams sharing the same transport
// config reuse a single health-check client.
type Factory struct {
	mu            sync.Mutex
	healthDialers map[string]*Client
}

// Type returns the upstream type this factory handles.
func (f *Factory) Type() upstream.Type {
	return upstream.TypeOutline
}

// getHealthDialer returns a shared health dialer for the given transport config.
func (f *Factory) getHealthDialer(transport string) (*Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.healthDialers == nil {
		f.healthDialers = make(map[string]*Client)
	}

	if c, ok := f.healthDialers[transport]; ok {
		return c, nil
	}

	c, err := NewClient(transport)
	if err != nil {
		return nil, err
	}
	f.healthDialers[transport] = c
	return c, nil
}

// Build creates an outline upstream from the given spec.
func (f *Factory) Build(spec upstream.Spec) (upstream.Built, error) {
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

	healthClient, err := f.getHealthDialer(cfg.Transport)
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
