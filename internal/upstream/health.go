package upstream

import (
	"context"
	"time"
)

func (m *Manager) startHealthCheck(e *entry) {
	if e.healthCancel != nil {
		e.healthCancel()
	}

	ctx, cancel := context.WithCancel(m.ctx)
	e.healthCancel = cancel

	interval := e.spec.HealthCheck.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}
	target := e.spec.HealthCheck.Target
	if target == "" {
		target = "1.1.1.1:80"
	}

	go m.runHealthCheck(ctx, e, interval, target)
}

func (m *Manager) runHealthCheck(ctx context.Context, e *entry, interval time.Duration, target string) {
	m.doHealthCheck(ctx, e, target)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.doHealthCheck(ctx, e, target)
		}
	}
}

func (m *Manager) doHealthCheck(ctx context.Context, e *entry, target string) {
	if e.built.HealthDialer == nil {
		return
	}

	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := e.built.HealthDialer.DialStream(checkCtx, target)
	if err != nil {
		m.logger.Warn("upstream health check failed",
			"name", e.spec.Name, "target", target, "err", err)
		m.mu.Lock()
		if e.state != StateDisabled {
			m.setEntryState(e, StateDegraded, err.Error())
		}
		m.mu.Unlock()
		return
	}
	conn.Close()

	m.logger.Debug("upstream health check passed",
		"name", e.spec.Name, "target", target)
	m.mu.Lock()
	if e.state == StateDegraded {
		m.setEntryState(e, StateHealthy, "")
	}
	m.mu.Unlock()
}
