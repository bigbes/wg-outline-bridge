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

const tcpIdleTimeout = 5 * time.Minute

type StreamDialer interface {
	DialStream(ctx context.Context, addr string) (net.Conn, error)
}

type TCPProxy struct {
	router       *routing.Router
	dialers      *DialerSet
	logger       *slog.Logger
	tracker      *ConnTracker
	peerResolver *PeerUpstreamResolver
}

func NewTCPProxy(router *routing.Router, dialers *DialerSet, tracker *ConnTracker, peerResolver *PeerUpstreamResolver, logger *slog.Logger) *TCPProxy {
	return &TCPProxy{router: router, dialers: dialers, tracker: tracker, peerResolver: peerResolver, logger: logger}
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

	if !matched {
		if portDec, ok := p.router.RoutePort(req); ok {
			dec = portDec
			matched = true
		}
	}

	if matched && dec.Action == routing.ActionBlock {
		p.logger.Info("tcp: blocked by rule", "src", srcAddr, "dest", dest, "rule", dec.RuleName)
		return
	}

	var clientReader io.Reader = clientConn
	var br *bufio.Reader
	if !matched && destPort == 443 {
		br = bufio.NewReaderSize(clientConn, 32*1024)
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

	if matched && dec.Action == routing.ActionBlock {
		p.logger.Info("tcp: blocked by rule", "src", srcAddr, "dest", dest, "rule", dec.RuleName)
		return
	}

	if p.router.HasProtocolRules() {
		if br == nil {
			br = bufio.NewReaderSize(clientConn, 32*1024)
			clientReader = br
		}
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		peeked, _ := br.Peek(20)
		clientConn.SetReadDeadline(time.Time{})
		if proto := routing.DetectTCPProtocol(peeked); proto != "" {
			if protoDec, ok := p.router.RouteProtocol(proto); ok {
				dec = protoDec
				matched = true
				if dec.Action == routing.ActionBlock {
					p.logger.Info("tcp: protocol blocked", "src", srcAddr, "dest", dest, "protocol", proto, "rule", dec.RuleName)
					return
				}
			}
		}
	}

	if !matched && p.peerResolver != nil {
		if group := p.peerResolver.GroupFor(srcAddr); group != "" {
			dec = routing.Decision{
				Action:        routing.ActionUpstream,
				UpstreamGroup: group,
				RuleName:      "peer-default",
			}
			matched = true
		}
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

	idle := &idleTimer{timeout: tcpIdleTimeout, a: clientConn, b: outConn}
	idle.touch()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(outConn, &activityReader{r: clientReader, idle: idle})
		metrics.TCPBytesTotal.WithLabelValues("tx").Add(float64(n))
		p.logger.Debug("tcp: client -> upstream done", "src", srcAddr, "dest", dest, "bytes", n, "err", err)
		outConn.Close() // unblock upstream -> client read
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, &activityReader{r: outConn, idle: idle})
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

// idleTimer tracks bidirectional activity and sets read deadlines on both
// connections. Activity on either side extends the deadline for both,
// preventing premature timeout during one-way data flows while still
// catching half-open connections where neither side sends data.
type idleTimer struct {
	timeout time.Duration
	a, b    interface{ SetReadDeadline(time.Time) error }
}

func (t *idleTimer) touch() {
	deadline := time.Now().Add(t.timeout)
	t.a.SetReadDeadline(deadline)
	t.b.SetReadDeadline(deadline)
}

// activityReader wraps a reader and signals the idle timer on each successful read.
type activityReader struct {
	r    io.Reader
	idle *idleTimer
}

func (r *activityReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.idle.touch()
	}
	return n, err
}
