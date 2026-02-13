package wireguard

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
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

type NetTUN struct {
	ep             *channel.Endpoint
	Stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
	hasV4, hasV6   bool
	logger         *slog.Logger
	closeOnce      sync.Once
}

func CreateNetTUNWithStack(localAddresses []netip.Addr, mtu int, logger *slog.Logger) (*NetTUN, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        false,
	}

	dev := &NetTUN{
		ep:             channel.New(1024, uint32(mtu), ""),
		Stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View, 256),
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

	dev.events <- tun.EventUp
	return dev, nil
}

func (t *NetTUN) File() *os.File           { return nil }
func (t *NetTUN) Events() <-chan tun.Event { return t.events }
func (t *NetTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *NetTUN) Name() (string, error)    { return "wgbridge0", nil }
func (t *NetTUN) BatchSize() int           { return 1 }

func (t *NetTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-t.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	t.logger.Debug("tun: WireGuard read outgoing packet", "size", n)
	return 1, nil
}

func (t *NetTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
			srcIP := net.IP(packet[12:16])
			dstIP := net.IP(packet[16:20])
			t.logger.Debug("tun: injected IPv4 packet into gVisor", "size", len(packet), "src", srcIP, "dst", dstIP)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
			srcIP := net.IP(packet[8:24])
			dstIP := net.IP(packet[24:40])
			t.logger.Debug("tun: injected IPv6 packet into gVisor", "size", len(packet), "src", srcIP, "dst", dstIP)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(bufs), nil
}

func (t *NetTUN) WriteNotify() {
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
		t.logger.Warn("tun: dropping outgoing packet, channel full", "size", view.Size())
	}
}

func (t *NetTUN) Close() error {
	t.closeOnce.Do(func() {
		t.Stack.RemoveNIC(1)
		t.Stack.Close()
		t.ep.RemoveNotify(t.notifyHandle)
		t.ep.Close()
		close(t.events)
		close(t.incomingPacket)
	})
	return nil
}
