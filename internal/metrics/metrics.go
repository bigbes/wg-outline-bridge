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
	TCPDialLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "bridge",
		Subsystem: "tcp",
		Name:      "dial_latency_seconds",
		Help:      "Time to establish upstream TCP connection.",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	})

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
	UDPDialLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "bridge",
		Subsystem: "udp",
		Name:      "dial_latency_seconds",
		Help:      "Time to establish upstream UDP session.",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
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
	UpstreamConnAge = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "bridge",
		Subsystem: "upstream",
		Name:      "connection_age_seconds",
		Help:      "Age of upstream connections at close time.",
		Buckets:   []float64{1, 10, 30, 60, 300, 600, 900, 1800, 3600},
	}, []string{"name"})

	// Host environment probes.
	HostSchedLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "bridge",
		Subsystem: "host",
		Name:      "scheduling_latency_seconds",
		Help:      "Scheduling latency measured by dedicated OS thread probe (100ms tick).",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	})
	HostSchedStalls = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "host",
		Name:      "scheduling_stalls_total",
		Help:      "Number of scheduling ticks delayed by more than 500ms.",
	})
	HostNetConnectLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "bridge",
		Subsystem: "host",
		Name:      "net_connect_latency_seconds",
		Help:      "TCP connect latency to probe targets (direct, not through upstream).",
		Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	}, []string{"target"})
	HostNetProbeErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "host",
		Name:      "net_connect_errors_total",
		Help:      "Failed TCP connect probes to external targets.",
	}, []string{"target"})

	// WireGuard channel metrics.
	WGChannelLength = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "wg",
		Name:      "incoming_channel_length",
		Help:      "Current length of the incomingPacket channel (0-256).",
	})
	WGChannelDrops = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "wg",
		Name:      "incoming_channel_drops_total",
		Help:      "Packets dropped because incomingPacket channel was full.",
	})

	// WireGuard peer metrics (from UAPI).
	WGPeerRxBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "wg",
		Name:      "peer_rx_bytes",
		Help:      "Received bytes per WireGuard peer.",
	}, []string{"name"})
	WGPeerTxBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "wg",
		Name:      "peer_tx_bytes",
		Help:      "Transmitted bytes per WireGuard peer.",
	}, []string{"name"})
	WGPeerLastHandshake = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "wg",
		Name:      "peer_last_handshake_seconds",
		Help:      "Unix timestamp of last WireGuard handshake per peer.",
	}, []string{"name"})
	WGPeerActiveConnections = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "wg",
		Name:      "peer_active_connections",
		Help:      "Active proxy connections per WireGuard peer.",
	}, []string{"name"})

	// MTProxy metrics.
	MTProxyConnectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "connections_total",
		Help:      "Total MTProxy connections accepted.",
	})
	MTProxyConnectionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "connections_active",
		Help:      "Currently active MTProxy connections.",
	})
	MTProxyUniqueUsers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "unique_users",
		Help:      "Unique remote IPs seen by MTProxy (session).",
	})
	MTProxyTLSConnectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "tls_connections_total",
		Help:      "Total MTProxy connections using fake TLS.",
	})
	MTProxyHandshakeErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "handshake_errors_total",
		Help:      "Total MTProxy handshake failures.",
	})
	MTProxyDialErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "dial_errors_total",
		Help:      "Total MTProxy backend dial failures.",
	})
	MTProxyBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "bytes_total",
		Help:      "Total bytes relayed by MTProxy.",
	}, []string{"direction"}) // "c2b" or "b2c"
	MTProxySecretConnectionsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "secret_connections_active",
		Help:      "Active connections per MTProxy secret.",
	}, []string{"secret"})
	MTProxySecretBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "bridge",
		Subsystem: "mtproxy",
		Name:      "secret_bytes_total",
		Help:      "Total bytes relayed per MTProxy secret.",
	}, []string{"secret", "direction"})
)

func init() {
	prometheus.MustRegister(
		// TCP
		TCPConnectionsTotal,
		TCPConnectionsActive,
		TCPDialErrors,
		TCPBytesTotal,
		TCPDialLatency,

		// UDP
		UDPSessionsTotal,
		UDPSessionsActive,
		UDPDialErrors,
		UDPDialLatency,

		// Upstream
		UpstreamHealthy,
		UpstreamConnectionsActive,
		UpstreamBytesTotal,
		UpstreamConnAge,

		// Host probes
		HostSchedLatency,
		HostSchedStalls,
		HostNetConnectLatency,
		HostNetProbeErrors,

		// WireGuard channel
		WGChannelLength,
		WGChannelDrops,

		// WireGuard peers
		WGPeerRxBytes,
		WGPeerTxBytes,
		WGPeerLastHandshake,
		WGPeerActiveConnections,

		// MTProxy
		MTProxyConnectionsTotal,
		MTProxyConnectionsActive,
		MTProxyUniqueUsers,
		MTProxyTLSConnectionsTotal,
		MTProxyHandshakeErrors,
		MTProxyDialErrors,
		MTProxyBytesTotal,
		MTProxySecretConnectionsActive,
		MTProxySecretBytesTotal,
	)
}
