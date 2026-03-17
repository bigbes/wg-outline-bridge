package healthmon

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/bigbes/wireguard-outline-bridge/internal/metrics"
)

const (
	netProbeInterval = 10 * time.Second
	netProbeTimeout  = 5 * time.Second
)

// runNetworkProbe periodically performs direct TCP connects to external targets
// to measure the host's network health (bypassing upstream proxies).
func runNetworkProbe(ctx context.Context, targets []string, logger *slog.Logger) {
	ticker := time.NewTicker(netProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, target := range targets {
				probeTarget(ctx, target, logger)
			}
		}
	}
}

func probeTarget(ctx context.Context, target string, logger *slog.Logger) {
	dialCtx, cancel := context.WithTimeout(ctx, netProbeTimeout)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
	elapsed := time.Since(start)

	if err != nil {
		metrics.HostNetProbeErrors.WithLabelValues(target).Inc()
		logger.Debug("network probe failed", "target", target, "err", err)
		return
	}
	conn.Close()
	metrics.HostNetConnectLatency.WithLabelValues(target).Observe(elapsed.Seconds())
}
