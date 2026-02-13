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

// StreamAndPacketDialer combines both dialer interfaces.
type StreamAndPacketDialer interface {
	StreamDialer
	PacketDialer
}

// DialerSet maps routing decisions to concrete dialers.
type DialerSet struct {
	Direct         *DirectDialer
	DefaultOutline StreamAndPacketDialer
	Outlines       map[string]StreamAndPacketDialer // named outlines
}

func NewDialerSet(defaultOutline StreamAndPacketDialer) *DialerSet {
	return &DialerSet{
		Direct:         &DirectDialer{},
		DefaultOutline: defaultOutline,
		Outlines:       make(map[string]StreamAndPacketDialer),
	}
}

func (ds *DialerSet) StreamDialerFor(dec routing.Decision) StreamDialer {
	switch dec.Action {
	case routing.ActionDirect:
		return ds.Direct
	case routing.ActionOutline:
		if d, ok := ds.Outlines[dec.OutlineName]; ok {
			return d
		}
		return ds.DefaultOutline
	default:
		return ds.DefaultOutline
	}
}

func (ds *DialerSet) PacketDialerFor(dec routing.Decision) PacketDialer {
	switch dec.Action {
	case routing.ActionDirect:
		return ds.Direct
	case routing.ActionOutline:
		if d, ok := ds.Outlines[dec.OutlineName]; ok {
			return d
		}
		return ds.DefaultOutline
	default:
		return ds.DefaultOutline
	}
}
