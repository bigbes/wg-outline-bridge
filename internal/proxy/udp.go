package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const udpSessionTimeout = 60 * time.Second

type PacketDialer interface {
	DialPacket(ctx context.Context, addr string) (net.Conn, error)
}

type UDPProxy struct {
	dialer  PacketDialer
	logger  *slog.Logger
	tracker *ConnTracker
}

func NewUDPProxy(dialer PacketDialer, tracker *ConnTracker, logger *slog.Logger) *UDPProxy {
	return &UDPProxy{dialer: dialer, tracker: tracker, logger: logger}
}

func (p *UDPProxy) SetupForwarder(s *stack.Stack) {
	fwd := udp.NewForwarder(s, p.handleRequest)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

func (p *UDPProxy) handleRequest(r *udp.ForwarderRequest) {
	id := r.ID()
	src := id.RemoteAddress.String()
	dest := net.JoinHostPort(id.LocalAddress.String(), itoa(id.LocalPort))

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		p.logger.Error("udp: failed to create endpoint", "src", src, "dest", dest, "err", tcpipErr)
		return
	}

	conn := gonet.NewUDPConn(&wq, ep)

	srcAddr, err := netip.ParseAddr(src)
	if err == nil {
		p.tracker.Track(srcAddr, conn)
	}

	go p.relay(conn, srcAddr, dest)
}

func (p *UDPProxy) relay(clientConn *gonet.UDPConn, srcAddr netip.Addr, dest string) {
	defer func() {
		clientConn.Close()
		if srcAddr.IsValid() {
			p.tracker.Untrack(srcAddr, clientConn)
		}
	}()

	p.logger.Info("udp: new session", "src", srcAddr, "dest", dest)

	outConn, err := p.dialer.DialPacket(context.Background(), dest)
	if err != nil {
		p.logger.Error("udp: failed to dial outline", "dest", dest, "err", err)
		return
	}
	defer outConn.Close()

	done := make(chan struct{}, 2)

	go func() {
		buf := make([]byte, 4096)
		for {
			clientConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
			n, err := clientConn.Read(buf)
			if err != nil {
				break
			}
			outConn.Write(buf[:n])
		}
		done <- struct{}{}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			outConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
			n, err := outConn.Read(buf)
			if err != nil {
				break
			}
			clientConn.Write(buf[:n])
		}
		done <- struct{}{}
	}()

	<-done
	p.logger.Debug("udp: session closed", "src", srcAddr, "dest", dest)
}
