package proxy

import (
	"context"
	"net"

	"github.com/blikh/wireguard-outline-bridge/internal/routing"
)

// DirectDialer connects directly without a proxy.
type DirectDialer struct{}

func (d *DirectDialer) DialStream(ctx context.Context, addr string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", addr)
}

func (d *DirectDialer) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "udp", addr)
}

// UpstreamProvider resolves upstream groups to dialers (implemented by upstream.Manager).
type UpstreamProvider interface {
	StreamDialerForGroup(group string) StreamDialer
	PacketDialerForGroup(group string) PacketDialer
}

// DialerSet maps routing decisions to concrete dialers.
type DialerSet struct {
	Direct   *DirectDialer
	Upstream UpstreamProvider
}

// NewDialerSet creates a new DialerSet backed by the given upstream provider.
func NewDialerSet(upstream UpstreamProvider) *DialerSet {
	return &DialerSet{
		Direct:   &DirectDialer{},
		Upstream: upstream,
	}
}

// StreamDialerFor returns the appropriate stream dialer for a routing decision.
func (ds *DialerSet) StreamDialerFor(dec routing.Decision) StreamDialer {
	switch dec.Action {
	case routing.ActionDirect:
		return ds.Direct
	case routing.ActionUpstream, routing.ActionOutline:
		if d := ds.Upstream.StreamDialerForGroup(dec.UpstreamGroup); d != nil {
			return d
		}
		// Fallback: try by legacy OutlineName
		if dec.OutlineName != "" {
			if d := ds.Upstream.StreamDialerForGroup("upstream:" + dec.OutlineName); d != nil {
				return d
			}
		}
		// Final fallback to default group
		if d := ds.Upstream.StreamDialerForGroup("default"); d != nil {
			return d
		}
		return ds.Direct
	default:
		if d := ds.Upstream.StreamDialerForGroup("default"); d != nil {
			return d
		}
		return ds.Direct
	}
}

// PacketDialerFor returns the appropriate packet dialer for a routing decision.
func (ds *DialerSet) PacketDialerFor(dec routing.Decision) PacketDialer {
	switch dec.Action {
	case routing.ActionDirect:
		return ds.Direct
	case routing.ActionUpstream, routing.ActionOutline:
		if d := ds.Upstream.PacketDialerForGroup(dec.UpstreamGroup); d != nil {
			return d
		}
		if dec.OutlineName != "" {
			if d := ds.Upstream.PacketDialerForGroup("upstream:" + dec.OutlineName); d != nil {
				return d
			}
		}
		if d := ds.Upstream.PacketDialerForGroup("default"); d != nil {
			return d
		}
		return ds.Direct
	default:
		if d := ds.Upstream.PacketDialerForGroup("default"); d != nil {
			return d
		}
		return ds.Direct
	}
}
