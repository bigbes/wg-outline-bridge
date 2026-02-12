package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

type TCPProxy struct {
	dialer  StreamDialer
	logger  *slog.Logger
	tracker *ConnTracker
}

func NewTCPProxy(dialer StreamDialer, tracker *ConnTracker, logger *slog.Logger) *TCPProxy {
	return &TCPProxy{dialer: dialer, tracker: tracker, logger: logger}
}

func (p *TCPProxy) SetupForwarder(s *stack.Stack) {
	fwd := tcp.NewForwarder(s, 0, 1024, p.handleRequest)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

func (p *TCPProxy) handleRequest(r *tcp.ForwarderRequest) {
	id := r.ID()
	src := id.RemoteAddress.String()
	dest := net.JoinHostPort(id.LocalAddress.String(), itoa(id.LocalPort))

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		p.logger.Error("tcp: failed to create endpoint", "src", src, "dest", dest, "err", tcpipErr)
		r.Complete(true)
		return
	}
	r.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)

	srcAddr, err := netip.ParseAddr(src)
	if err == nil {
		p.tracker.Track(srcAddr, conn)
	}

	go p.proxy(conn, srcAddr, dest)
}

func (p *TCPProxy) proxy(clientConn *gonet.TCPConn, srcAddr netip.Addr, dest string) {
	defer func() {
		clientConn.Close()
		if srcAddr.IsValid() {
			p.tracker.Untrack(srcAddr, clientConn)
		}
	}()

	p.logger.Info("tcp: new connection", "src", srcAddr, "dest", dest)

	outConn, err := p.dialer.DialStream(context.Background(), dest)
	if err != nil {
		p.logger.Error("tcp: failed to dial outline", "dest", dest, "err", err)
		return
	}
	defer outConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(outConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, outConn)
	}()

	wg.Wait()
	p.logger.Debug("tcp: connection closed", "src", srcAddr, "dest", dest)
}

func itoa(port uint16) string {
	return fmt.Sprintf("%d", port)
}
