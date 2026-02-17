package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// entry holds the runtime state for a single upstream.
type entry struct {
	spec      Spec
	built     Built
	state     State
	lastError string

	healthCancel context.CancelFunc
}

// Manager owns all upstream entries and provides group-based dialer selection.
type Manager struct {
	mu        sync.RWMutex
	entries   map[string]*entry
	groups    map[string]*GroupSelector
	factories map[Type]Factory
	events    chan Event
	logger    *slog.Logger
	ctx       context.Context
}

// NewManager creates a new upstream manager.
func NewManager(ctx context.Context, logger *slog.Logger) *Manager {
	return &Manager{
		entries:   make(map[string]*entry),
		groups:    make(map[string]*GroupSelector),
		factories: make(map[Type]Factory),
		events:    make(chan Event, 64),
		logger:    logger,
		ctx:       ctx,
	}
}

// RegisterFactory adds a provider factory for the given upstream type.
func (m *Manager) RegisterFactory(f Factory) {
	m.factories[f.Type()] = f
}

// Apply takes a full set of upstream specs and reconciles them with the current state.
// New upstreams are created, removed ones are stopped, changed ones are swapped.
func (m *Manager) Apply(specs []Spec) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired := make(map[string]Spec, len(specs))
	for _, s := range specs {
		desired[s.Name] = s
	}

	// Remove upstreams that are no longer in specs.
	for name, e := range m.entries {
		if _, ok := desired[name]; !ok {
			m.stopEntry(e)
			delete(m.entries, name)
			m.logger.Info("upstream removed", "name", name)
		}
	}

	// Add or update upstreams.
	for _, spec := range specs {
		existing, ok := m.entries[spec.Name]
		if !ok {
			// New upstream.
			e, err := m.buildEntry(spec)
			if err != nil {
				m.logger.Error("failed to build upstream", "name", spec.Name, "err", err)
				continue
			}
			m.entries[spec.Name] = e
			m.logger.Info("upstream added", "name", spec.Name, "type", spec.Type)
		} else {
			// Update existing.
			if err := m.updateEntry(existing, spec); err != nil {
				m.logger.Error("failed to update upstream", "name", spec.Name, "err", err)
			}
		}
	}

	// Rebuild group selectors.
	m.rebuildGroups()

	return nil
}

func (m *Manager) buildEntry(spec Spec) (*entry, error) {
	factory, ok := m.factories[spec.Type]
	if !ok {
		return nil, fmt.Errorf("unknown upstream type %q", spec.Type)
	}

	built, err := factory.Build(spec)
	if err != nil {
		return nil, fmt.Errorf("building upstream %q: %w", spec.Name, err)
	}

	state := StateHealthy
	if !spec.Enabled {
		state = StateDisabled
	}

	e := &entry{
		spec:  spec,
		built: built,
		state: state,
	}

	if spec.Enabled && spec.HealthCheck.Enabled {
		m.startHealthCheck(e)
	}

	return e, nil
}

func (m *Manager) updateEntry(e *entry, spec Spec) error {
	oldEnabled := e.spec.Enabled
	e.spec = spec

	if !spec.Enabled {
		m.setEntryState(e, StateDisabled, "")
		if e.healthCancel != nil {
			e.healthCancel()
			e.healthCancel = nil
		}
		return nil
	}

	// Re-enable if was disabled.
	if !oldEnabled && spec.Enabled {
		m.setEntryState(e, StateHealthy, "")
	}

	// Restart health checker if config changed.
	if e.healthCancel != nil {
		e.healthCancel()
		e.healthCancel = nil
	}
	if spec.HealthCheck.Enabled {
		m.startHealthCheck(e)
	}

	return nil
}

func (m *Manager) stopEntry(e *entry) {
	if e.healthCancel != nil {
		e.healthCancel()
	}
}

func (m *Manager) setEntryState(e *entry, newState State, errMsg string) {
	oldState := e.state
	if oldState == newState {
		return
	}
	e.state = newState
	e.lastError = errMsg

	select {
	case m.events <- Event{
		Name:     e.spec.Name,
		OldState: oldState,
		NewState: newState,
		Error:    errMsg,
	}:
	default:
		m.logger.Warn("upstream event channel full, dropping event",
			"name", e.spec.Name, "old", oldState, "new", newState)
	}
}

func (m *Manager) rebuildGroups() {
	newGroups := make(map[string]*GroupSelector)

	for _, e := range m.entries {
		for _, group := range e.spec.EffectiveGroups() {
			gs, ok := newGroups[group]
			if !ok {
				gs = &GroupSelector{}
				newGroups[group] = gs
			}
			gs.members = append(gs.members, e)
		}
	}

	m.groups = newGroups
}

// Statuses returns the current status of all upstreams.
func (m *Manager) Statuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Status, 0, len(m.entries))
	for _, e := range m.entries {
		st := Status{
			Name:      e.spec.Name,
			Type:      e.spec.Type,
			Enabled:   e.spec.Enabled,
			Default:   e.spec.Default,
			State:     e.state,
			Groups:    e.spec.EffectiveGroups(),
			LastError: e.lastError,
		}
		if e.built.Stats != nil {
			snap := e.built.Stats()
			st.RxBytes = snap.RxBytes
			st.TxBytes = snap.TxBytes
			st.ActiveConnections = snap.ActiveConnections
		}
		result = append(result, st)
	}
	return result
}

// Events returns a channel that receives upstream state transition events.
func (m *Manager) Events() <-chan Event {
	return m.events
}

// StreamDialerForGroup returns a stream dialer from the given group using round-robin.
// Falls back to "default" group, then returns nil.
func (m *Manager) StreamDialerForGroup(group string) StreamDialer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if gs, ok := m.groups[group]; ok {
		if d := gs.pickStream(); d != nil {
			return d
		}
	}

	// Fallback to default group.
	if group != "default" {
		if gs, ok := m.groups["default"]; ok {
			if d := gs.pickStream(); d != nil {
				return d
			}
		}
	}

	return nil
}

// PacketDialerForGroup returns a packet dialer from the given group using round-robin.
// Falls back to "default" group, then returns nil.
func (m *Manager) PacketDialerForGroup(group string) PacketDialer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if gs, ok := m.groups[group]; ok {
		if d := gs.pickPacket(); d != nil {
			return d
		}
	}

	if group != "default" {
		if gs, ok := m.groups["default"]; ok {
			if d := gs.pickPacket(); d != nil {
				return d
			}
		}
	}

	return nil
}

// DefaultStreamDialer returns a stream dialer from the "default" group.
func (m *Manager) DefaultStreamDialer() StreamDialer {
	return m.StreamDialerForGroup("default")
}

// DefaultPacketDialer returns a packet dialer from the "default" group.
func (m *Manager) DefaultPacketDialer() PacketDialer {
	return m.PacketDialerForGroup("default")
}
