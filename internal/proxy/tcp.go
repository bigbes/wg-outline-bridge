package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/bigbes/wireguard-outline-bridge/internal/metrics"
	"github.com/bigbes/wireguard-outline-bridge/internal/routing"
)

type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

type TCPProxy struct {
	router  *routing.Router
	dialers *DialerSet
	logger  *slog.Logger
	tracker *ConnTracker
}

func NewTCPProxy(router *routing.Router, dialers *DialerSet, tracker *ConnTracker, logger *slog.Logger) *TCPProxy {
	return &TCPProxy{router: router, dialers: dialers, tracker: tracker, logger: logger}
}

func (p *TCPProxy) SetupForwarder(s *stack.Stack) {
	fwd := tcp.NewForwarder(s, 0, 1024, p.handleRequest)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

func (p *TCPProxy) handleRequest(r *tcp.ForwarderRequest) {
	id := r.ID()
	src := id.RemoteAddress.String()
	destIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	destPort := id.LocalPort
	dest := net.JoinHostPort(id.LocalAddress.String(), itoa(destPort))

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

	go p.proxy(conn, srcAddr, dest, destIP, destPort)
}

func (p *TCPProxy) proxy(clientConn *gonet.TCPConn, srcAddr netip.Addr, dest string, destIP netip.Addr, destPort uint16) {
	metrics.TCPConnectionsTotal.Inc()
	metrics.TCPConnectionsActive.Inc()
	defer func() {
		metrics.TCPConnectionsActive.Dec()
		clientConn.Close()
		if srcAddr.IsValid() {
			p.tracker.Untrack(srcAddr, clientConn)
		}
	}()

	req := routing.Request{DestIP: destIP, DestPort: destPort}

	dec, matched := p.router.RouteIP(req)

	var clientReader io.Reader = clientConn
	if !matched && destPort == 443 {
		br := bufio.NewReaderSize(clientConn, 32*1024)
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		sni := PeekSNI(br)
		clientConn.SetReadDeadline(time.Time{})
		if sni != "" {
			req.SNI = sni
			if sniDec, ok := p.router.RouteSNI(req); ok {
				dec = sniDec
				matched = true
			}
		}
		clientReader = br
	}

	dialer := p.dialers.StreamDialerFor(dec)
	routeDesc := "default"
	if matched {
		routeDesc = fmt.Sprintf("%s(%s)", dec.Action, dec.RuleName)
	}

	p.logger.Debug("tcp: new connection", "src", srcAddr, "dest", dest, "route", routeDesc, "sni", req.SNI)

	outConn, err := dialer.DialStream(context.Background(), dest)
	if err != nil {
		metrics.TCPDialErrors.Inc()
		p.logger.Error("tcp: failed to dial", "dest", dest, "route", routeDesc, "err", err)
		return
	}
	defer outConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(outConn, clientReader)
		metrics.TCPBytesTotal.WithLabelValues("tx").Add(float64(n))
		p.logger.Debug("tcp: client -> upstream done", "src", srcAddr, "dest", dest, "bytes", n, "err", err)
		outConn.Close() // unblock upstream -> client read
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, outConn)
		metrics.TCPBytesTotal.WithLabelValues("rx").Add(float64(n))
		p.logger.Debug("tcp: upstream -> client done", "src", srcAddr, "dest", dest, "bytes", n, "err", err)
		clientConn.Close() // unblock client -> upstream read
	}()

	wg.Wait()
	p.logger.Debug("tcp: connection closed", "src", srcAddr, "dest", dest)
}

func itoa(port uint16) string {
	return fmt.Sprintf("%d", port)
}
