package wireguard

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// incomingPacketCapacity is the buffer between gVisor's outbound path and
	// the WireGuard device Read loop. 16384 prevents silent packet drops under
	// burst traffic (the previous value of 256 caused TCP ACK loss and freezes).
	// At ~128 KB of pointer storage this is cheap insurance against stalls.
	incomingPacketCapacity = 16384

	// tunBatchSize is the number of packets the WireGuard device may read or
	// write in a single call. Matches wireguard-go's conn.IdealBatchSize (128),
	// which is already pre-allocated on the bind side. Our Read() blocks on the
	// first packet then drains non-blocking, so a large value adds no latency —
	// it just raises the ceiling for burst absorption.
	tunBatchSize = 128
)

// netTUNCore contains the shared gVisor netstack TUN logic.
// It implements most of tun.Device methods but not Events(),
// which is provided by the backend-specific wrappers (wgTUN, awgTUN).
type netTUNCore struct {
	ep             *channel.Endpoint
	Stack          *stack.Stack
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
	hasV4, hasV6   bool
	logger         *slog.Logger
	closeOnce      sync.Once
	dropCount      atomic.Int64
}

// pktBufPool reuses byte slices for packet injection into gVisor,
// reducing GC pressure on the hot path.
var pktBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1500)
		return &b
	},
}

// createNetTUN creates a netTUNCore with a gVisor network stack.
func createNetTUN(localAddresses []netip.Addr, mtu int, logger *slog.Logger) (*netTUNCore, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        false,
	}

	dev := &netTUNCore{
		ep:             channel.New(1024, uint32(mtu), ""),
		Stack:          stack.New(opts),
		incomingPacket: make(chan *buffer.View, incomingPacketCapacity),
		mtu:            mtu,
		logger:         logger,
	}

	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if tcpipErr := dev.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}

	// Do NOT enable forwarding: it causes packets to be forwarded at the
	// network layer (back out through the channel) instead of being delivered
	// to the transport layer where TCP/UDP forwarders intercept them.
	// Promiscuous mode + spoofing are sufficient for accepting non-local packets.

	dev.notifyHandle = dev.ep.AddNotify(dev)

	if tcpipErr := dev.Stack.CreateNIC(1, dev.ep); tcpipErr != nil {
		return nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	if err := dev.Stack.SetPromiscuousMode(1, true); err != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %v", err)
	}

	if err := dev.Stack.SetSpoofing(1, true); err != nil {
		return nil, fmt.Errorf("SetSpoofing: %v", err)
	}

	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
			dev.hasV4 = true
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
			dev.hasV6 = true
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if tcpipErr := dev.Stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
			return nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
	}

	if dev.hasV4 {
		dev.Stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.Stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	return dev, nil
}

func (t *netTUNCore) File() *os.File        { return nil }
func (t *netTUNCore) MTU() (int, error)     { return t.mtu, nil }
func (t *netTUNCore) Name() (string, error) { return "wgbridge0", nil }
func (t *netTUNCore) BatchSize() int        { return tunBatchSize }

func (t *netTUNCore) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// Block on the first packet.
	view, ok := <-t.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	count := 1

	// Drain up to BatchSize-1 more packets without blocking.
	for count < len(bufs) {
		select {
		case view, ok = <-t.incomingPacket:
			if !ok {
				return count, os.ErrClosed
			}
			n, err = view.Read(bufs[count][offset:])
			if err != nil {
				return count, err
			}
			sizes[count] = n
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

func (t *netTUNCore) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		// Copy packet into a pooled buffer so the caller can reuse its
		// slice immediately while gVisor processes the packet.
		bp := pktBufPool.Get().(*[]byte)
		*bp = append((*bp)[:0], packet...)

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(*bp)})

		// Return the buffer to the pool after gVisor has consumed the data.
		// MakeWithData copies the bytes, so the pooled slice is safe to reuse.
		*bp = (*bp)[:0]
		pktBufPool.Put(bp)

		switch packet[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
			t.logger.Debug("tun: injected IPv4 packet into gVisor", "size", len(packet))
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
			t.logger.Debug("tun: injected IPv6 packet into gVisor", "size", len(packet))
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(bufs), nil
}

func (t *netTUNCore) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	select {
	case t.incomingPacket <- view:
		t.logger.Debug("tun: queued outgoing packet for WireGuard", "size", view.Size(), "queue_len", len(t.incomingPacket))
	default:
		t.dropCount.Add(1)
		t.logger.Warn("tun: dropping outgoing packet, channel full", "size", view.Size())
	}
}

// ChannelStats returns the current incomingPacket channel length and total drop count.
func (t *netTUNCore) ChannelStats() (queueLen int, drops int64) {
	return len(t.incomingPacket), t.dropCount.Load()
}

func (t *netTUNCore) Close() error {
	t.closeOnce.Do(func() {
		t.Stack.RemoveNIC(1)
		t.Stack.Close()
		t.ep.RemoveNotify(t.notifyHandle)
		t.ep.Close()
		close(t.incomingPacket)
	})
	return nil
}
