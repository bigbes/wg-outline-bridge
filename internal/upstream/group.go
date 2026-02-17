package upstream

import (
	"sync/atomic"
)

// GroupSelector performs round-robin selection among group members,
// skipping disabled and degraded upstreams.
type GroupSelector struct {
	members []*entry
	counter atomic.Uint64
}

func (gs *GroupSelector) pickStream() StreamDialer {
	e := gs.pick()
	if e == nil {
		return nil
	}
	return e.built.TrafficDialer
}

func (gs *GroupSelector) pickPacket() PacketDialer {
	e := gs.pick()
	if e == nil {
		return nil
	}
	return e.built.TrafficDialer
}

func (gs *GroupSelector) pick() *entry {
	n := len(gs.members)
	if n == 0 {
		return nil
	}

	start := gs.counter.Add(1) - 1
	for i := 0; i < n; i++ {
		idx := int((start + uint64(i)) % uint64(n))
		e := gs.members[idx]
		if e.state == StateHealthy {
			return e
		}
	}
	return nil
}
