package routing

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

type ActionType string

const (
	ActionDirect  ActionType = "direct"
	ActionOutline ActionType = "outline"
	ActionDefault ActionType = "default"
)

type Decision struct {
	Action      ActionType
	OutlineName string // only when Action == ActionOutline
	RuleName    string // for logging
}

type Request struct {
	DestIP   netip.Addr
	DestPort uint16
	SNI      string
}

type ipRule struct {
	name     string
	action   Decision
	prefixes []netip.Prefix
	listKeys []string // URL keys and "asn:<number>" keys into urlPrefixes
}

type sniRule struct {
	name     string
	action   Decision
	patterns []domainPattern
}

type Router struct {
	ipRules  []ipRule
	sniRules []sniRule
	logger   *slog.Logger

	mu          sync.RWMutex
	urlPrefixes map[string][]netip.Prefix
}

func NewRouter(cfg config.RoutingConfig, logger *slog.Logger) *Router {
	r := &Router{
		logger:      logger,
		urlPrefixes: make(map[string][]netip.Prefix),
	}

	for _, rule := range cfg.IPRules {
		ir := ipRule{
			name:   rule.Name,
			action: parseAction(ipRuleAdapter(rule)),
		}
		for _, cidr := range rule.CIDRs {
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
			name:   rule.Name,
			action: parseAction(sniRuleAdapter(rule)),
		}
		for _, domain := range rule.Domains {
			sr.patterns = append(sr.patterns, parseDomainPattern(domain))
		}
		r.sniRules = append(r.sniRules, sr)
	}

	return r
}

type ruleConfig interface {
	actionType() string
	outlineName() string
	ruleName() string
}

type ipRuleAdapter config.IPRuleConfig

func (a ipRuleAdapter) actionType() string  { return a.Action }
func (a ipRuleAdapter) outlineName() string { return a.Outline }
func (a ipRuleAdapter) ruleName() string    { return a.Name }

type sniRuleAdapter config.SNIRuleConfig

func (a sniRuleAdapter) actionType() string  { return a.Action }
func (a sniRuleAdapter) outlineName() string { return a.Outline }
func (a sniRuleAdapter) ruleName() string    { return a.Name }

func parseAction(rule ruleConfig) Decision {
	d := Decision{
		RuleName: rule.ruleName(),
	}
	switch ActionType(rule.actionType()) {
	case ActionDirect:
		d.Action = ActionDirect
	case ActionOutline:
		d.Action = ActionOutline
		d.OutlineName = rule.outlineName()
	default:
		d.Action = ActionDefault
	}
	return d
}

func (r *Router) RouteIP(req Request) (Decision, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := range r.ipRules {
		rule := &r.ipRules[i]
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
	}
	return Decision{}, false
}

func (r *Router) RouteSNI(req Request) (Decision, bool) {
	for i := range r.sniRules {
		rule := &r.sniRules[i]
		for _, pattern := range rule.patterns {
			if pattern.matches(req.SNI) {
				return rule.action, true
			}
		}
	}
	return Decision{}, false
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
