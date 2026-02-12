package proxy

import (
	"io"
	"net/netip"
	"sync"
)

type ConnTracker struct {
	mu    sync.Mutex
	conns map[netip.Addr]map[io.Closer]struct{}
}

func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		conns: make(map[netip.Addr]map[io.Closer]struct{}),
	}
}

func (t *ConnTracker) Track(src netip.Addr, c io.Closer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conns[src] == nil {
		t.conns[src] = make(map[io.Closer]struct{})
	}
	t.conns[src][c] = struct{}{}
}

func (t *ConnTracker) Untrack(src netip.Addr, c io.Closer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if m, ok := t.conns[src]; ok {
		delete(m, c)
		if len(m) == 0 {
			delete(t.conns, src)
		}
	}
}

func (t *ConnTracker) CloseBySource(src netip.Addr) int {
	t.mu.Lock()
	m, ok := t.conns[src]
	if ok {
		delete(t.conns, src)
	}
	t.mu.Unlock()

	if !ok {
		return 0
	}

	count := 0
	for c := range m {
		c.Close()
		count++
	}
	return count
}
