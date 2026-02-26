package routing

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/geoip"
)

type ActionType string

const (
	ActionDirect   ActionType = "direct"
	ActionUpstream ActionType = "upstream"
	ActionBlock    ActionType = "block"
	ActionDefault  ActionType = "default"
)

type Decision struct {
	Action        ActionType
	UpstreamGroup string // group to select upstream from
	RuleName      string // for logging
}

type Request struct {
	DestIP    netip.Addr
	DestPort  uint16
	SNI       string
	PeerID    int  // source peer ID, for per-peer rule filtering
	PeerKnown bool // true when PeerID was resolved from a known peer
}

type geoipMatch struct {
	dbName  string // empty means default (first) database
	country string // ISO country code
}

type ipRule struct {
	name         string
	action       Decision
	prefixes     []netip.Prefix
	listKeys     []string // URL keys and "asn:<number>" keys into urlPrefixes
	geoipMatches []geoipMatch
	peerIDs      []int // if set, rule applies only to these peer IDs; empty = all
}

type sniRule struct {
	name    string
	action  Decision
	patterns []domainPattern
	peerIDs  []int
}

type portRange struct {
	from uint16
	to   uint16
}

func (pr portRange) contains(port uint16) bool {
	return port >= pr.from && port <= pr.to
}

type portRule struct {
	name    string
	action  Decision
	ranges  []portRange
	peerIDs []int
}

type protocolRule struct {
	name      string
	action    Decision
	protocols []string
	peerIDs   []int
}

type Router struct {
	ipRules       []ipRule
	sniRules      []sniRule
	portRules     []portRule
	protocolRules []protocolRule
	logger        *slog.Logger
	geoMgr        *geoip.Manager

	mu          sync.RWMutex
	enabled     bool
	urlPrefixes map[string][]netip.Prefix
}

func NewRouter(cfg config.RoutingConfig, geoMgr *geoip.Manager, logger *slog.Logger) *Router {
	r := &Router{
		logger:      logger,
		geoMgr:      geoMgr,
		enabled:     true,
		urlPrefixes: make(map[string][]netip.Prefix),
	}

	for _, rule := range cfg.IPRules {
		ir := ipRule{
			name:    rule.Name,
			action:  parseAction(ipRuleAdapter(rule)),
			peerIDs: rule.PeerIDs,
		}
		for _, cidr := range rule.CIDRs {
			if rest, ok := strings.CutPrefix(cidr, "geoip:"); ok {
				ir.geoipMatches = append(ir.geoipMatches, parseGeoIPMatch(rest))
				continue
			}
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				logger.Warn("routing: invalid CIDR in rule", "rule", rule.Name, "cidr", cidr, "err", err)
				continue
			}
			ir.prefixes = append(ir.prefixes, prefix)
		}
		for _, list := range rule.Lists {
			ir.listKeys = append(ir.listKeys, list.URL)
		}
		for _, asn := range rule.ASNs {
			ir.listKeys = append(ir.listKeys, ASNKey(asn))
		}
		r.ipRules = append(r.ipRules, ir)
	}

	for _, rule := range cfg.SNIRules {
		sr := sniRule{
			name:    rule.Name,
			action:  parseAction(sniRuleAdapter(rule)),
			peerIDs: rule.PeerIDs,
		}
		for _, domain := range rule.Domains {
			sr.patterns = append(sr.patterns, parseDomainPattern(domain))
		}
		r.sniRules = append(r.sniRules, sr)
	}

	for _, rule := range cfg.PortRules {
		pr := portRule{
			name:    rule.Name,
			action:  parseAction(portRuleAdapter(rule)),
			peerIDs: rule.PeerIDs,
		}
		for _, portSpec := range rule.Ports {
			parsed, err := parsePortRange(portSpec)
			if err != nil {
				logger.Warn("routing: invalid port in rule", "rule", rule.Name, "port", portSpec, "err", err)
				continue
			}
			pr.ranges = append(pr.ranges, parsed)
		}
		r.portRules = append(r.portRules, pr)
	}

	for _, rule := range cfg.ProtocolRules {
		pr := protocolRule{
			name:      rule.Name,
			action:    parseAction(protocolRuleAdapter(rule)),
			protocols: rule.Protocols,
			peerIDs:   rule.PeerIDs,
		}
		r.protocolRules = append(r.protocolRules, pr)
	}

	return r
}

type ruleConfig interface {
	actionType() string
	upstreamGroup() string
	ruleName() string
}

type ipRuleAdapter config.IPRuleConfig

func (a ipRuleAdapter) actionType() string    { return a.Action }
func (a ipRuleAdapter) upstreamGroup() string { return a.UpstreamGroup }
func (a ipRuleAdapter) ruleName() string      { return a.Name }

type sniRuleAdapter config.SNIRuleConfig

func (a sniRuleAdapter) actionType() string    { return a.Action }
func (a sniRuleAdapter) upstreamGroup() string { return a.UpstreamGroup }
func (a sniRuleAdapter) ruleName() string      { return a.Name }

type portRuleAdapter config.PortRuleConfig

func (a portRuleAdapter) actionType() string    { return a.Action }
func (a portRuleAdapter) upstreamGroup() string { return a.UpstreamGroup }
func (a portRuleAdapter) ruleName() string      { return a.Name }

type protocolRuleAdapter config.ProtocolRuleConfig

func (a protocolRuleAdapter) actionType() string    { return a.Action }
func (a protocolRuleAdapter) upstreamGroup() string { return a.UpstreamGroup }
func (a protocolRuleAdapter) ruleName() string      { return a.Name }

func parseAction(rule ruleConfig) Decision {
	d := Decision{
		RuleName: rule.ruleName(),
	}
	switch ActionType(rule.actionType()) {
	case ActionDirect:
		d.Action = ActionDirect
	case ActionUpstream:
		d.Action = ActionUpstream
		d.UpstreamGroup = rule.upstreamGroup()
	case ActionBlock:
		d.Action = ActionBlock
	default:
		d.Action = ActionDefault
	}
	return d
}

// ruleAppliesToPeer returns true if the rule should be evaluated for the given peer.
// If the rule has no peer restrictions, it applies to all peers.
func ruleAppliesToPeer(rulePeerIDs []int, peerID int, peerKnown bool) bool {
	if len(rulePeerIDs) == 0 {
		return true
	}
	if !peerKnown {
		return false
	}
	for _, id := range rulePeerIDs {
		if id == peerID {
			return true
		}
	}
	return false
}

// SetEnabled toggles whether routing rules are evaluated at runtime.
func (r *Router) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

// IsEnabled returns whether routing rules are currently active.
func (r *Router) IsEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

func (r *Router) RouteIP(req Request) (Decision, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.enabled {
		return Decision{}, false
	}

	for i := range r.ipRules {
		rule := &r.ipRules[i]
		if !ruleAppliesToPeer(rule.peerIDs, req.PeerID, req.PeerKnown) {
			continue
		}
		for _, prefix := range rule.prefixes {
			if prefix.Contains(req.DestIP) {
				return rule.action, true
			}
		}
		for _, key := range rule.listKeys {
			for _, prefix := range r.urlPrefixes[key] {
				if prefix.Contains(req.DestIP) {
					return rule.action, true
				}
			}
		}
		for _, gm := range rule.geoipMatches {
			cc := r.geoMgr.LookupCountry(gm.dbName, req.DestIP)
			if cc == gm.country {
				return rule.action, true
			}
		}
	}
	return Decision{}, false
}

func (r *Router) RouteSNI(req Request) (Decision, bool) {
	enabled := r.IsEnabled()
	r.logger.Debug("routing: SNI lookup",
		"sni", req.SNI, "destIP", req.DestIP, "destPort", req.DestPort,
		"peerID", req.PeerID, "peerKnown", req.PeerKnown,
		"enabled", enabled, "ruleCount", len(r.sniRules))
	if !enabled {
		return Decision{}, false
	}
	for i := range r.sniRules {
		rule := &r.sniRules[i]
		if !ruleAppliesToPeer(rule.peerIDs, req.PeerID, req.PeerKnown) {
			r.logger.Debug("routing: SNI rule skipped (peer mismatch)",
				"sni", req.SNI, "rule", rule.name,
				"rulePeerIDs", rule.peerIDs, "peerID", req.PeerID, "peerKnown", req.PeerKnown)
			continue
		}
		for _, pattern := range rule.patterns {
			if pattern.matches(req.SNI) {
				r.logger.Debug("routing: SNI rule matched",
					"sni", req.SNI, "rule", rule.name, "action", rule.action.Action,
					"pattern", pattern.String())
				return rule.action, true
			}
		}
		r.logger.Debug("routing: SNI rule skipped (no domain match)",
			"sni", req.SNI, "rule", rule.name, "action", rule.action.Action,
			"patternCount", len(rule.patterns))
	}
	r.logger.Debug("routing: SNI no rule matched", "sni", req.SNI)
	return Decision{}, false
}

// RoutePort checks port-based rules for the given request.
func (r *Router) RoutePort(req Request) (Decision, bool) {
	if !r.IsEnabled() {
		return Decision{}, false
	}
	for i := range r.portRules {
		rule := &r.portRules[i]
		if !ruleAppliesToPeer(rule.peerIDs, req.PeerID, req.PeerKnown) {
			continue
		}
		for _, pr := range rule.ranges {
			if pr.contains(req.DestPort) {
				return rule.action, true
			}
		}
	}
	return Decision{}, false
}

// RouteProtocol checks protocol-based rules for the given protocol identifier.
func (r *Router) RouteProtocol(protocol string, peerID int, peerKnown bool) (Decision, bool) {
	if !r.IsEnabled() {
		return Decision{}, false
	}
	for i := range r.protocolRules {
		rule := &r.protocolRules[i]
		if !ruleAppliesToPeer(rule.peerIDs, peerID, peerKnown) {
			continue
		}
		for _, p := range rule.protocols {
			if strings.EqualFold(p, protocol) {
				return rule.action, true
			}
		}
	}
	return Decision{}, false
}

// HasProtocolRules returns true if any protocol rules are configured and routing is enabled.
func (r *Router) HasProtocolRules() bool {
	if !r.IsEnabled() {
		return false
	}
	return len(r.protocolRules) > 0
}

// parsePortRange parses a port spec like "6881" or "6881-6889".
func parsePortRange(s string) (portRange, error) {
	if from, to, ok := strings.Cut(s, "-"); ok {
		fromPort, err := strconv.ParseUint(from, 10, 16)
		if err != nil {
			return portRange{}, fmt.Errorf("invalid port: %s", from)
		}
		toPort, err := strconv.ParseUint(to, 10, 16)
		if err != nil {
			return portRange{}, fmt.Errorf("invalid port: %s", to)
		}
		return portRange{from: uint16(fromPort), to: uint16(toPort)}, nil
	}
	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return portRange{}, fmt.Errorf("invalid port: %s", s)
	}
	return portRange{from: uint16(port), to: uint16(port)}, nil
}

func (r *Router) UpdateIPList(key string, prefixes []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.urlPrefixes[key] = prefixes
}

// ASNKey returns the lookup key used for an ASN in the prefix map.
func ASNKey(asn int) string {
	return fmt.Sprintf("asn:%d", asn)
}

// parseGeoIPMatch parses "CC" or "dbname:CC" into a geoipMatch.
func parseGeoIPMatch(s string) geoipMatch {
	if dbName, cc, ok := strings.Cut(s, ":"); ok {
		return geoipMatch{dbName: dbName, country: strings.ToUpper(cc)}
	}
	return geoipMatch{country: strings.ToUpper(s)}
}
