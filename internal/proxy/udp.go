package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/blikh/wireguard-outline-bridge/internal/metrics"
	"github.com/blikh/wireguard-outline-bridge/internal/routing"
)

const udpSessionTimeout = 60 * time.Second

type PacketDialer interface {
	DialPacket(ctx context.Context, addr string) (net.Conn, error)
}

type UDPProxy struct {
	router    *routing.Router
	dialers   *DialerSet
	logger    *slog.Logger
	tracker   *ConnTracker
	dnsTarget string // if set, intercept port-53 and relay to this address
}

func NewUDPProxy(router *routing.Router, dialers *DialerSet, tracker *ConnTracker, logger *slog.Logger) *UDPProxy {
	return &UDPProxy{router: router, dialers: dialers, tracker: tracker, logger: logger}
}

func (p *UDPProxy) SetDNSTarget(addr string) {
	p.dnsTarget = addr
}

func (p *UDPProxy) SetupForwarder(s *stack.Stack) {
	fwd := udp.NewForwarder(s, p.handleRequest)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

func (p *UDPProxy) handleRequest(r *udp.ForwarderRequest) {
	id := r.ID()
	src := id.RemoteAddress.String()
	destIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	destPort := id.LocalPort
	dest := net.JoinHostPort(id.LocalAddress.String(), itoa(destPort))

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

	// Intercept DNS queries (port 53) and relay to local DNS server
	if destPort == 53 && p.dnsTarget != "" {
		go p.relayDNS(conn, srcAddr, dest)
		return
	}

	go p.relay(conn, srcAddr, dest, destIP, destPort)
}

func (p *UDPProxy) relay(clientConn *gonet.UDPConn, srcAddr netip.Addr, dest string, destIP netip.Addr, destPort uint16) {
	metrics.UDPSessionsTotal.Inc()
	metrics.UDPSessionsActive.Inc()
	defer func() {
		metrics.UDPSessionsActive.Dec()
		clientConn.Close()
		if srcAddr.IsValid() {
			p.tracker.Untrack(srcAddr, clientConn)
		}
	}()

	req := routing.Request{DestIP: destIP, DestPort: destPort}
	dec, matched := p.router.RouteIP(req)
	dialer := p.dialers.PacketDialerFor(dec)
	routeDesc := "default"
	if matched {
		routeDesc = fmt.Sprintf("%s(%s)", dec.Action, dec.RuleName)
	}
	p.logger.Debug("udp: new session", "src", srcAddr, "dest", dest, "route", routeDesc)

	outConn, err := dialer.DialPacket(context.Background(), dest)
	if err != nil {
		metrics.UDPDialErrors.Inc()
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
				p.logger.Debug("udp: client read done", "src", srcAddr, "dest", dest, "err", err)
				break
			}
			if _, err := outConn.Write(buf[:n]); err != nil {
				p.logger.Error("udp: write to outline failed", "src", srcAddr, "dest", dest, "size", n, "err", err)
				break
			}
			p.logger.Debug("udp: client -> outline", "src", srcAddr, "dest", dest, "bytes", n)
		}
		done <- struct{}{}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			outConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
			n, err := outConn.Read(buf)
			if err != nil {
				p.logger.Debug("udp: outline read done", "src", srcAddr, "dest", dest, "err", err)
				break
			}
			if _, err := clientConn.Write(buf[:n]); err != nil {
				p.logger.Error("udp: write to client failed", "src", srcAddr, "dest", dest, "size", n, "err", err)
				break
			}
			p.logger.Debug("udp: outline -> client", "src", srcAddr, "dest", dest, "bytes", n)
		}
		done <- struct{}{}
	}()

	<-done
	p.logger.Debug("udp: session closed", "src", srcAddr, "dest", dest)
}

func (p *UDPProxy) relayDNS(clientConn *gonet.UDPConn, srcAddr netip.Addr, origDest string) {
	defer func() {
		clientConn.Close()
		if srcAddr.IsValid() {
			p.tracker.Untrack(srcAddr, clientConn)
		}
	}()

	p.logger.Debug("udp: dns intercept", "src", srcAddr, "orig_dest", origDest, "dns_target", p.dnsTarget)

	buf := make([]byte, 4096)
	for {
		clientConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
		n, err := clientConn.Read(buf)
		if err != nil {
			return
		}

		dnsConn, err := net.DialTimeout("udp", p.dnsTarget, 5*time.Second)
		if err != nil {
			p.logger.Error("udp: dns dial failed", "target", p.dnsTarget, "err", err)
			return
		}

		dnsConn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := dnsConn.Write(buf[:n]); err != nil {
			dnsConn.Close()
			p.logger.Error("udp: dns write failed", "err", err)
			return
		}

		respN, err := dnsConn.Read(buf)
		dnsConn.Close()
		if err != nil {
			p.logger.Error("udp: dns read failed", "err", err)
			return
		}

		if _, err := clientConn.Write(buf[:respN]); err != nil {
			return
		}
	}
}
