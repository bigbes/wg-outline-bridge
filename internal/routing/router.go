package routing

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
	"github.com/bigbes/wireguard-outline-bridge/internal/geoip"
)

type ActionType string

const (
	ActionDirect   ActionType = "direct"
	ActionOutline  ActionType = "outline"
	ActionUpstream ActionType = "upstream"
	ActionDefault  ActionType = "default"
)

type Decision struct {
	Action        ActionType
	UpstreamGroup string // group to select upstream from
	OutlineName   string // deprecated: kept for backward compat
	RuleName      string // for logging
}

type Request struct {
	DestIP   netip.Addr
	DestPort uint16
	SNI      string
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
	geoMgr   *geoip.Manager

	mu          sync.RWMutex
	urlPrefixes map[string][]netip.Prefix
}

func NewRouter(cfg config.RoutingConfig, geoMgr *geoip.Manager, logger *slog.Logger) *Router {
	r := &Router{
		logger:      logger,
		geoMgr:      geoMgr,
		urlPrefixes: make(map[string][]netip.Prefix),
	}

	for _, rule := range cfg.IPRules {
		ir := ipRule{
			name:   rule.Name,
			action: parseAction(ipRuleAdapter(rule)),
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
	upstreamGroup() string
	ruleName() string
}

type ipRuleAdapter config.IPRuleConfig

func (a ipRuleAdapter) actionType() string    { return a.Action }
func (a ipRuleAdapter) outlineName() string   { return a.Outline }
func (a ipRuleAdapter) upstreamGroup() string { return a.UpstreamGroup }
func (a ipRuleAdapter) ruleName() string      { return a.Name }

type sniRuleAdapter config.SNIRuleConfig

func (a sniRuleAdapter) actionType() string    { return a.Action }
func (a sniRuleAdapter) outlineName() string   { return a.Outline }
func (a sniRuleAdapter) upstreamGroup() string { return a.UpstreamGroup }
func (a sniRuleAdapter) ruleName() string      { return a.Name }

func parseAction(rule ruleConfig) Decision {
	d := Decision{
		RuleName: rule.ruleName(),
	}
	switch ActionType(rule.actionType()) {
	case ActionDirect:
		d.Action = ActionDirect
	case ActionOutline, ActionUpstream:
		d.Action = ActionUpstream
		d.UpstreamGroup = rule.upstreamGroup()
		d.OutlineName = rule.outlineName()
		if d.UpstreamGroup == "" && d.OutlineName != "" {
			d.UpstreamGroup = "upstream:" + d.OutlineName
		}
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

// parseGeoIPMatch parses "CC" or "dbname:CC" into a geoipMatch.
func parseGeoIPMatch(s string) geoipMatch {
	if dbName, cc, ok := strings.Cut(s, ":"); ok {
		return geoipMatch{dbName: dbName, country: strings.ToUpper(cc)}
	}
	return geoipMatch{country: strings.ToUpper(s)}
}
