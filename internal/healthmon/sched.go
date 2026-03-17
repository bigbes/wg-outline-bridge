package healthmon

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/metrics"
)

const (
	schedTickInterval = 100 * time.Millisecond
	schedStallThresh  = 500 * time.Millisecond
)

// runSchedulingProbe measures OS-level scheduling latency on a dedicated thread.
// It bumps GOMAXPROCS by 1 and locks the goroutine to an OS thread so that
// delays reflect kernel scheduling (CPU steal, host overload), not Go runtime contention.
func runSchedulingProbe(ctx context.Context, logger *slog.Logger) {
	runtime.GOMAXPROCS(runtime.GOMAXPROCS(0) + 1)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ticker := time.NewTicker(schedTickInterval)
	defer ticker.Stop()

	expected := time.Now().Add(schedTickInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			delay := now.Sub(expected)
			if delay < 0 {
				delay = 0
			}
			metrics.HostSchedLatency.Observe(delay.Seconds())
			if delay > schedStallThresh {
				metrics.HostSchedStalls.Inc()
				schedStalls.Add(1)
				logger.Warn("scheduling stall detected", "delay_ms", delay.Milliseconds())
			}
			expected = now.Add(schedTickInterval)
		}
	}
}
