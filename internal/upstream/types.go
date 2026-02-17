package upstream

import (
	"context"
	"encoding/json"
	"net"
	"time"
)

// Type identifies the upstream provider type.
type Type string

const TypeOutline Type = "outline"

// State represents the runtime health state of an upstream.
type State string

const (
	StateHealthy  State = "healthy"
	StateDegraded State = "degraded"
	StateDisabled State = "disabled"
)

// Spec is the desired-state description of an upstream (persisted in DB/config).
type Spec struct {
	Name        string            `json:"name"`
	Type        Type              `json:"type"`
	Enabled     bool              `json:"enabled"`
	Default     bool              `json:"default"`
	Groups      []string          `json:"groups,omitempty"`
	Config      json.RawMessage   `json:"config"`
	HealthCheck HealthCheckConfig `json:"health_check"`
}

// HealthCheckConfig controls periodic upstream health verification.
type HealthCheckConfig struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
	Target   string        `json:"target"`
}

// EffectiveGroups returns all groups an upstream belongs to,
// including the implicit "upstream:<name>" group and "default" if it's the default.
func (s *Spec) EffectiveGroups() []string {
	groups := make([]string, 0, len(s.Groups)+2)
	groups = append(groups, "upstream:"+s.Name)
	if s.Default {
		groups = append(groups, "default")
	}
	groups = append(groups, s.Groups...)
	return groups
}

// StreamDialer dials TCP connections through an upstream.
type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

// PacketDialer dials UDP connections through an upstream.
type PacketDialer interface {
	DialPacket(ctx context.Context, addr string) (net.Conn, error)
}

// Dialer combines stream and packet dialing.
type Dialer interface {
	StreamDialer
	PacketDialer
}

// StatsSnapshot holds a point-in-time copy of upstream traffic statistics.
type StatsSnapshot struct {
	RxBytes           int64
	TxBytes           int64
	ActiveConnections int64
}

// Status is a read-only snapshot of an upstream's runtime state.
type Status struct {
	Name              string
	Type              Type
	Enabled           bool
	Default           bool
	State             State
	Groups            []string
	RxBytes           int64
	TxBytes           int64
	ActiveConnections int64
	LastError         string
}

// Event signals a state transition for an upstream.
type Event struct {
	Name     string
	OldState State
	NewState State
	Error    string
}

// Built is returned by a provider factory after creating an upstream's dialers.
type Built struct {
	// TrafficDialer is the stats-wrapped dialer used for actual traffic.
	TrafficDialer Dialer
	// HealthDialer is a separate dialer used for health checks (avoids polluting stats).
	HealthDialer StreamDialer
	// Stats returns current traffic statistics.
	Stats func() StatsSnapshot
	// Swap replaces the underlying client (for live reload without dropping references).
	Swap func(newBuilt Built)
}

// Factory creates upstream dialers from a spec.
type Factory interface {
	Type() Type
	Build(spec Spec) (Built, error)
}
