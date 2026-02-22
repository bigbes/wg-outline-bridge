// Package metrics provides Prometheus metrics for the bridge.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// TCP proxy metrics.
	TCPConnectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "tcp",
		Name:      "connections_total",
		Help:      "Total number of TCP connections handled.",
	})
	TCPConnectionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "tcp",
		Name:      "connections_active",
		Help:      "Number of currently active TCP connections.",
	})
	TCPDialErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "tcp",
		Name:      "dial_errors_total",
		Help:      "Total number of TCP dial errors.",
	})
	TCPBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "tcp",
		Name:      "bytes_total",
		Help:      "Total bytes transferred over TCP.",
	}, []string{"direction"}) // "rx" (upstream->client) or "tx" (client->upstream)

	// UDP proxy metrics.
	UDPSessionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "udp",
		Name:      "sessions_total",
		Help:      "Total number of UDP sessions handled.",
	})
	UDPSessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "udp",
		Name:      "sessions_active",
		Help:      "Number of currently active UDP sessions.",
	})
	UDPDialErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "udp",
		Name:      "dial_errors_total",
		Help:      "Total number of UDP dial errors.",
	})

	// Upstream metrics.
	UpstreamHealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "upstream",
		Name:      "healthy",
		Help:      "Whether the upstream is healthy (1) or not (0).",
	}, []string{"name"})
	UpstreamConnectionsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "upstream",
		Name:      "connections_active",
		Help:      "Active connections per upstream.",
	}, []string{"name"})
	UpstreamBytesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "upstream",
		Name:      "bytes_total",
		Help:      "Cumulative bytes per upstream (scraped from StatsDialer snapshots).",
	}, []string{"name", "direction"})
)

func init() {
	prometheus.MustRegister(
		TCPConnectionsTotal,
		TCPConnectionsActive,
		TCPDialErrors,
		TCPBytesTotal,

		UDPSessionsTotal,
		UDPSessionsActive,
		UDPDialErrors,

		UpstreamHealthy,
		UpstreamConnectionsActive,
		UpstreamBytesTotal,
	)
}
