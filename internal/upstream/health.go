package upstream

import (
	"context"
	"fmt"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/metrics"
)

const defaultLatencyThreshold = 3 * time.Second

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
	threshold := e.spec.HealthCheck.LatencyThreshold
	if threshold == 0 {
		threshold = defaultLatencyThreshold
	}

	go m.runHealthCheck(ctx, e, interval, target, threshold)
}

func (m *Manager) runHealthCheck(ctx context.Context, e *entry, interval time.Duration, target string, threshold time.Duration) {
	m.doHealthCheck(ctx, e, target, threshold)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.doHealthCheck(ctx, e, target, threshold)
		}
	}
}

func (m *Manager) doHealthCheck(ctx context.Context, e *entry, target string, threshold time.Duration) {
	if e.built.HealthDialer == nil {
		return
	}

	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := e.built.HealthDialer.DialStream(checkCtx, target)
	elapsed := time.Since(start)
	metrics.UpstreamHealthCheckLatency.WithLabelValues(e.spec.Name).Observe(elapsed.Seconds())

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

	if elapsed > threshold {
		m.logger.Warn("upstream health check too slow",
			"name", e.spec.Name, "target", target, "latency", elapsed, "threshold", threshold)
		m.mu.Lock()
		if e.state != StateDisabled {
			m.setEntryState(e, StateDegraded, fmt.Sprintf("latency %s exceeds threshold %s", elapsed, threshold))
		}
		m.mu.Unlock()
		return
	}

	m.logger.Debug("upstream health check passed",
		"name", e.spec.Name, "target", target, "latency", elapsed)
	m.mu.Lock()
	if e.state == StateDegraded {
		m.setEntryState(e, StateHealthy, "")
	}
	m.mu.Unlock()
}
