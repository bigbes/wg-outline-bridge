// Package healthmon provides host-level health probes and channel monitoring.
package healthmon

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/metrics"
)

// SchedStalls is an atomic counter shared between the scheduling probe and the monitor snapshot.
var schedStalls atomic.Int64

// ChannelStatter reports incomingPacket channel utilization.
type ChannelStatter interface {
	ChannelStats() (queueLen int, drops int64)
}

// HealthSnapshot holds a point-in-time health status for the Telegram observer.
type HealthSnapshot struct {
	SchedStalls  int64
	ChannelLen   int
	ChannelCap   int
	ChannelDrops int64
}

// Monitor coordinates health probes and channel stat polling.
type Monitor struct {
	logger  *slog.Logger
	targets []string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	chanStatter ChannelStatter
	lastDrops   int64

	// Snapshot fields updated by channel poller.
	mu          sync.Mutex
	channelLen  int
	channelCap  int
	channelDrop int64
}

// New creates a new health monitor. Targets are TCP addresses for the network probe
// (e.g., "1.1.1.1:80"). If empty, defaults to ["1.1.1.1:80"].
func New(logger *slog.Logger, targets []string) *Monitor {
	if len(targets) == 0 {
		targets = []string{"1.1.1.1:80"}
	}
	return &Monitor{
		logger:     logger.With("component", "healthmon"),
		targets:    targets,
		channelCap: 256, // matches netTUNCore channel capacity
	}
}

// Start launches all probes. Pass nil for cs if channel stats are unavailable.
func (m *Monitor) Start(ctx context.Context, cs ChannelStatter) {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.chanStatter = cs

	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		runSchedulingProbe(m.ctx, m.logger)
	}()
	go func() {
		defer m.wg.Done()
		runNetworkProbe(m.ctx, m.targets, m.logger)
	}()

	if cs != nil {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.pollChannelStats()
		}()
	}

	m.logger.Info("health monitor started", "targets", m.targets, "channel_stats", cs != nil)
}

// Stop cancels all probes and waits for them to finish.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

// Snapshot returns the current health status.
func (m *Monitor) Snapshot() HealthSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return HealthSnapshot{
		SchedStalls:  schedStalls.Load(),
		ChannelLen:   m.channelLen,
		ChannelCap:   m.channelCap,
		ChannelDrops: m.channelDrop,
	}
}

func (m *Monitor) pollChannelStats() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			qlen, drops := m.chanStatter.ChannelStats()

			metrics.WGChannelLength.Set(float64(qlen))
			if drops > m.lastDrops {
				metrics.WGChannelDrops.Add(float64(drops - m.lastDrops))
				m.lastDrops = drops
			}

			m.mu.Lock()
			m.channelLen = qlen
			m.channelDrop = drops
			m.mu.Unlock()
		}
	}
}
