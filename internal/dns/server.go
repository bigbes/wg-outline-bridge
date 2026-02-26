package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	dnspkg "github.com/miekg/dns"
)

type Record struct {
	A    []netip.Addr
	AAAA []netip.Addr
	TTL  uint32
}

type Rule struct {
	Name      string
	Action    string // "block" or "upstream"
	Upstream  string // for action=upstream
	Patterns  []DomainPattern
	Blocklist *BlocklistLoader
	PeerIDs   []int // if set, rule applies only to these peer IDs; empty = all
}

// PeerIDResolver maps peer VPN IPs to peer IDs.
type PeerIDResolver interface {
	IDFor(ip netip.Addr) (int, bool)
}

type DomainPattern struct {
	exact  string
	suffix string
}

func ParseDomainPattern(s string) DomainPattern {
	s = strings.ToLower(s)
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	if strings.HasPrefix(s, "*.") {
		return DomainPattern{suffix: s[1:]} // keep the dot: ".example.com."
	}
	return DomainPattern{exact: s}
}

func (p DomainPattern) matches(fqdn string) bool {
	if p.exact != "" {
		return fqdn == p.exact
	}
	if p.suffix != "" {
		return strings.HasSuffix(fqdn, p.suffix)
	}
	return false
}

type Server struct {
	upstream     string
	records      map[string]Record
	mu           sync.RWMutex
	rules        []Rule
	enabled      bool // when false, skip records/rules and only forward
	logger       *slog.Logger
	server       *dnspkg.Server
	peerResolver PeerIDResolver
}

func New(listenAddr, upstream string, records map[string]Record, rules []Rule, enabled bool, logger *slog.Logger) *Server {
	s := &Server{
		upstream: upstream,
		records:  records,
		rules:    rules,
		enabled:  enabled,
		logger:   logger,
	}

	s.server = &dnspkg.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: s,
	}

	return s
}

func (s *Server) Start(ctx context.Context) error {
	for i := range s.rules {
		if s.rules[i].Blocklist != nil {
			s.rules[i].Blocklist.Start(ctx)
		}
	}

	ready := make(chan struct{})
	s.server.NotifyStartedFunc = func() {
		close(ready)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("dns: starting server: %w", err)
	case <-ready:
		s.logger.Info("dns: server started", "addr", s.server.Addr, "upstream", s.upstream)
		return nil
	}
}

func (s *Server) Stop() error {
	return s.server.Shutdown()
}

// UpdateRules replaces the current rules with new ones, starting any
// blocklist loaders. Must not be called concurrently with Start.
func (s *Server) UpdateRules(ctx context.Context, rules []Rule) {
	for i := range rules {
		if rules[i].Blocklist != nil {
			rules[i].Blocklist.Start(ctx)
		}
	}

	s.mu.Lock()
	s.rules = rules
	s.mu.Unlock()
}

// UpdateRecords replaces the current local records map.
func (s *Server) UpdateRecords(records map[string]Record) {
	s.mu.Lock()
	s.records = records
	s.mu.Unlock()
}

// SetEnabled toggles DNS resolution. When disabled, the server skips
// records, rules, and blocklists and only forwards to the default upstream.
func (s *Server) SetEnabled(enabled bool) {
	s.mu.Lock()
	s.enabled = enabled
	s.mu.Unlock()
}

// SetPeerResolver sets the resolver used to map peer IPs to peer IDs
// for per-peer DNS rule filtering.
func (s *Server) SetPeerResolver(r PeerIDResolver) {
	s.peerResolver = r
}

func (s *Server) ServeDNS(w dnspkg.ResponseWriter, r *dnspkg.Msg) {
	s.serveDNSWithPeer(w, r, netip.Addr{})
}

// HandleQueryForPeer processes a DNS query on behalf of a specific peer,
// returning the serialized response. Per-peer DNS rules are applied based
// on the peer IP.
func (s *Server) HandleQueryForPeer(peerIP netip.Addr, request []byte) ([]byte, error) {
	msg := new(dnspkg.Msg)
	if err := msg.Unpack(request); err != nil {
		return nil, fmt.Errorf("dns: unpacking query: %w", err)
	}

	w := &bufResponseWriter{}
	s.serveDNSWithPeer(w, msg, peerIP)
	return w.msg, nil
}

func (s *Server) serveDNSWithPeer(w dnspkg.ResponseWriter, r *dnspkg.Msg, peerIP netip.Addr) {
	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]
	name := strings.ToLower(q.Name)

	s.mu.RLock()
	enabled := s.enabled
	s.mu.RUnlock()

	s.logger.Debug("dns: query received",
		"name", name, "type", dnspkg.TypeToString[q.Qtype],
		"peer", peerIP, "enabled", enabled)

	// When DNS resolution is disabled, skip all processing and just forward.
	if !enabled {
		s.logger.Debug("dns: disabled, forwarding to default upstream", "name", name)
		s.forward(w, r, s.upstream, "")
		return
	}

	// 1. Static local records
	s.mu.RLock()
	rec, hasRec := s.records[name]
	s.mu.RUnlock()
	if hasRec {
		s.logger.Debug("dns: matched local record", "name", name)
		s.serveLocalRecord(w, r, q, rec)
		return
	}

	// Resolve peer ID for per-peer rule filtering.
	peerID := 0
	peerKnown := false
	if peerIP.IsValid() && s.peerResolver != nil {
		peerID, peerKnown = s.peerResolver.IDFor(peerIP)
	}
	s.logger.Debug("dns: peer resolution", "name", name, "peerIP", peerIP,
		"peerID", peerID, "peerKnown", peerKnown,
		"hasResolver", s.peerResolver != nil)

	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	s.logger.Debug("dns: evaluating rules", "name", name, "ruleCount", len(rules))

	// 2. Rules (first match wins)
	for i := range rules {
		rule := &rules[i]
		peerMatch := ruleAppliesToPeer(rule.PeerIDs, peerID, peerKnown)
		if !peerMatch {
			s.logger.Debug("dns: rule skipped (peer mismatch)",
				"name", name, "rule", rule.Name,
				"rulePeerIDs", rule.PeerIDs, "peerID", peerID, "peerKnown", peerKnown)
			continue
		}
		matched := s.ruleMatches(rule, name)
		if !matched {
			s.logger.Debug("dns: rule skipped (no domain match)",
				"name", name, "rule", rule.Name, "action", rule.Action,
				"patterns", len(rule.Patterns), "hasBlocklist", rule.Blocklist != nil)
			continue
		}

		s.logger.Debug("dns: rule matched",
			"name", name, "rule", rule.Name, "action", rule.Action)
		switch rule.Action {
		case "block":
			s.serveBlocked(w, r, q, rule.Name)
		case "upstream":
			s.forward(w, r, rule.Upstream, rule.Name)
		}
		return
	}

	// 3. Default upstream
	s.logger.Debug("dns: no rule matched, forwarding to default upstream", "name", name)
	s.forward(w, r, s.upstream, "")
}

func ruleAppliesToPeer(peerIDs []int, peerID int, peerKnown bool) bool {
	if len(peerIDs) == 0 {
		return true
	}
	if !peerKnown {
		return false
	}
	return slices.Contains(peerIDs, peerID)
}

func (s *Server) ruleMatches(rule *Rule, fqdn string) bool {
	for _, p := range rule.Patterns {
		if p.matches(fqdn) {
			return true
		}
	}
	if rule.Blocklist != nil && rule.Blocklist.IsBlocked(fqdn) {
		return true
	}
	return false
}

func (s *Server) serveLocalRecord(w dnspkg.ResponseWriter, r *dnspkg.Msg, q dnspkg.Question, rec Record) {
	msg := new(dnspkg.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	ttl := rec.TTL
	if ttl == 0 {
		ttl = 60
	}

	switch q.Qtype {
	case dnspkg.TypeA:
		for _, addr := range rec.A {
			msg.Answer = append(msg.Answer, &dnspkg.A{
				Hdr: dnspkg.RR_Header{Name: q.Name, Rrtype: dnspkg.TypeA, Class: dnspkg.ClassINET, Ttl: ttl},
				A:   addr.AsSlice(),
			})
		}
	case dnspkg.TypeAAAA:
		for _, addr := range rec.AAAA {
			msg.Answer = append(msg.Answer, &dnspkg.AAAA{
				Hdr:  dnspkg.RR_Header{Name: q.Name, Rrtype: dnspkg.TypeAAAA, Class: dnspkg.ClassINET, Ttl: ttl},
				AAAA: addr.AsSlice(),
			})
		}
	}

	s.logger.Debug("dns: local record", "name", q.Name, "type", dnspkg.TypeToString[q.Qtype])
	if err := w.WriteMsg(msg); err != nil {
		s.logger.Error("dns: failed to write response", "err", err)
	}
}

func (s *Server) serveBlocked(w dnspkg.ResponseWriter, r *dnspkg.Msg, q dnspkg.Question, ruleName string) {
	msg := new(dnspkg.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	switch q.Qtype {
	case dnspkg.TypeA:
		msg.Answer = append(msg.Answer, &dnspkg.A{
			Hdr: dnspkg.RR_Header{Name: q.Name, Rrtype: dnspkg.TypeA, Class: dnspkg.ClassINET, Ttl: 300},
			A:   net.IPv4zero,
		})
	case dnspkg.TypeAAAA:
		msg.Answer = append(msg.Answer, &dnspkg.AAAA{
			Hdr:  dnspkg.RR_Header{Name: q.Name, Rrtype: dnspkg.TypeAAAA, Class: dnspkg.ClassINET, Ttl: 300},
			AAAA: net.IPv6zero,
		})
	default:
		msg.SetRcode(r, dnspkg.RcodeNameError)
	}

	s.logger.Debug("dns: blocked", "name", q.Name, "rule", ruleName)
	if err := w.WriteMsg(msg); err != nil {
		s.logger.Error("dns: failed to write response", "err", err)
	}
}

func (s *Server) forward(w dnspkg.ResponseWriter, r *dnspkg.Msg, upstream, ruleName string) {
	client := &dnspkg.Client{Timeout: 5 * time.Second}
	resp, _, err := client.Exchange(r, upstream)
	if err != nil {
		s.logger.Error("dns: failed to forward query", "name", r.Question[0].Name, "upstream", upstream, "err", err)
		msg := new(dnspkg.Msg)
		msg.SetRcode(r, dnspkg.RcodeServerFailure)
		w.WriteMsg(msg)
		return
	}

	if ruleName != "" {
		s.logger.Debug("dns: forwarded", "name", r.Question[0].Name, "upstream", upstream, "rule", ruleName)
	} else {
		s.logger.Debug("dns: forwarded", "name", r.Question[0].Name, "upstream", upstream)
	}
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error("dns: failed to write response", "err", err)
	}
}

// bufResponseWriter captures a DNS response for programmatic use.
type bufResponseWriter struct {
	msg []byte
}

func (w *bufResponseWriter) LocalAddr() net.Addr  { return nil }
func (w *bufResponseWriter) RemoteAddr() net.Addr { return nil }
func (w *bufResponseWriter) WriteMsg(msg *dnspkg.Msg) error {
	var err error
	w.msg, err = msg.Pack()
	return err
}
func (w *bufResponseWriter) Write(b []byte) (int, error) {
	w.msg = make([]byte, len(b))
	copy(w.msg, b)
	return len(b), nil
}
func (w *bufResponseWriter) Close() error        { return nil }
func (w *bufResponseWriter) TsigStatus() error   { return nil }
func (w *bufResponseWriter) TsigTimersOnly(bool) {}
func (w *bufResponseWriter) Hijack()             {}
