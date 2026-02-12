package wireguard

import (
	"fmt"
	"net/netip"
	"os"
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
}

func CreateNetTUNWithStack(localAddresses []netip.Addr, mtu int) (*NetTUN, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}

	dev := &NetTUN{
		ep:             channel.New(1024, uint32(mtu), ""),
		Stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
	}

	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if tcpipErr := dev.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}

	dev.Stack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	dev.Stack.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	dev.notifyHandle = dev.ep.AddNotify(dev)

	if tcpipErr := dev.Stack.CreateNIC(1, dev.ep); tcpipErr != nil {
		return nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
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
func (t *NetTUN) Events() <-chan tun.Event  { return t.events }
func (t *NetTUN) MTU() (int, error)         { return t.mtu, nil }
func (t *NetTUN) Name() (string, error)     { return "wgbridge0", nil }
func (t *NetTUN) BatchSize() int            { return 1 }

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
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
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
	t.incomingPacket <- view
}

func (t *NetTUN) Close() error {
	t.Stack.RemoveNIC(1)
	t.Stack.Close()
	t.ep.RemoveNotify(t.notifyHandle)
	t.ep.Close()
	if t.events != nil {
		close(t.events)
	}
	if t.incomingPacket != nil {
		close(t.incomingPacket)
	}
	return nil
}
