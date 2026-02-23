package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
	upstream string
	records  map[string]Record
	mu       sync.RWMutex
	rules    []Rule
	logger   *slog.Logger
	server   *dnspkg.Server
}

func New(listenAddr, upstream string, records map[string]Record, rules []Rule, logger *slog.Logger) *Server {
	s := &Server{
		upstream: upstream,
		records:  records,
		rules:    rules,
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

func (s *Server) ServeDNS(w dnspkg.ResponseWriter, r *dnspkg.Msg) {
	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]
	name := strings.ToLower(q.Name)

	// 1. Static local records
	if rec, ok := s.records[name]; ok {
		s.serveLocalRecord(w, r, q, rec)
		return
	}

	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	// 2. Rules (first match wins)
	for i := range rules {
		rule := &rules[i]
		if !s.ruleMatches(rule, name) {
			continue
		}

		switch rule.Action {
		case "block":
			s.serveBlocked(w, r, q, rule.Name)
		case "upstream":
			s.forward(w, r, rule.Upstream, rule.Name)
		}
		return
	}

	// 3. Default upstream
	s.forward(w, r, s.upstream, "")
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
