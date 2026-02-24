package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var templateVarRe = regexp.MustCompile(`\{\{\s*\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)

// CIDREntry represents a routing CIDR with its mode (allow/disallow).
type CIDREntry struct {
	CIDR string `json:"cidr" yaml:"-"`
	Mode string `json:"mode" yaml:"-"` // "allow" or "disallow"
}

// String returns the prefixed string representation (e.g. "d:10.0.0.0/8").
func (e CIDREntry) String() string {
	switch e.Mode {
	case "allow":
		return "a:" + e.CIDR
	case "disallow":
		return "d:" + e.CIDR
	default:
		return e.CIDR
	}
}

// ParseCIDREntry parses a prefixed CIDR string (e.g. "d:10.0.0.0/8") into a CIDREntry.
func ParseCIDREntry(s string) (CIDREntry, error) {
	action, cidr, err := parseCIDRRule(s)
	if err != nil {
		return CIDREntry{}, err
	}
	return CIDREntry{Mode: action, CIDR: cidr}, nil
}

func (e *CIDREntry) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("expected string, got %v", value.Kind)
	}
	action, cidr, err := parseCIDRRule(value.Value)
	if err != nil {
		return err
	}
	e.Mode = action
	e.CIDR = cidr
	return nil
}

// ExpandCIDRRuleVars replaces template variables in CIDR rules.
// Variables use the syntax {{ $var_name }} and are looked up in the
// provided vars map. Unknown or empty variables are left unexpanded
// (which will cause a parse error downstream, giving a clear message).
func ExpandCIDRRuleVars(entries []CIDREntry, vars map[string]string) []CIDREntry {
	out := make([]CIDREntry, len(entries))
	for i, entry := range entries {
		out[i] = CIDREntry{
			Mode: entry.Mode,
			CIDR: templateVarRe.ReplaceAllStringFunc(entry.CIDR, func(match string) string {
				sub := templateVarRe.FindStringSubmatch(match)
				if len(sub) < 2 {
					return match
				}
				if v, ok := vars[sub[1]]; ok && v != "" {
					return v
				}
				return match
			}),
		}
	}
	return out
}

// PrivateNetworkCIDRs returns CIDR entries that exclude private/special IP
// ranges from VPN routing while allowing the WireGuard subnet itself.
// The wgAddress should be the WireGuard server address (e.g. "10.100.0.1/24").
func PrivateNetworkCIDRs(wgAddress string) []CIDREntry {
	entries := []CIDREntry{
		{Mode: "disallow", CIDR: "10.0.0.0/8"},
		{Mode: "disallow", CIDR: "127.0.0.0/8"},
		{Mode: "disallow", CIDR: "172.16.0.0/12"},
		{Mode: "disallow", CIDR: "192.168.0.0/16"},
	}
	if wgAddress != "" {
		if prefix, err := netip.ParsePrefix(wgAddress); err == nil {
			// Allow the WireGuard subnet (must come before deny rules).
			entries = append([]CIDREntry{{Mode: "allow", CIDR: prefix.Masked().String()}}, entries...)
		}
	}
	// Allow everything else not matched by the deny rules above.
	entries = append(entries, CIDREntry{Mode: "allow", CIDR: "*"})
	return entries
}

// CIDRRule is a single allow/disallow rule.
type CIDRRule struct {
	Action   string // "allow" or "disallow"
	Prefix   netip.Prefix
	Wildcard bool
}

// CIDRRules is an ordered list of CIDR rules evaluated top-to-bottom
// (first match wins).
type CIDRRules struct {
	Rules []CIDRRule
}

// ParseCIDRRules converts CIDREntry values into an ordered rule set.
// Each entry carries its action (Mode) and CIDR value already parsed
// at YAML load time. Wildcard entries ("*") are always placed last
// regardless of position.
//
// Template variables (e.g. "{{ $server_ip }}/32") should be expanded with
// ExpandCIDRRuleVars before calling this function.
func ParseCIDRRules(entries []CIDREntry) (*CIDRRules, error) {
	result := &CIDRRules{}
	var wildcard *CIDRRule
	for _, entry := range entries {
		cidr := strings.TrimSpace(entry.CIDR)
		if cidr == "" {
			continue
		}

		if cidr == "*" {
			wildcard = &CIDRRule{
				Action:   entry.Mode,
				Wildcard: true,
				Prefix:   netip.MustParsePrefix("0.0.0.0/0"),
			}
			continue
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR entry %q: %w", cidr, err)
		}

		result.Rules = append(result.Rules, CIDRRule{
			Action: entry.Mode,
			Prefix: prefix.Masked(),
		})
	}
	// Wildcard is always last.
	if wildcard != nil {
		result.Rules = append(result.Rules, *wildcard)
	}
	return result, nil
}

// parseCIDRRule parses a single rule string and returns (action, value).
func parseCIDRRule(rule string) (string, string, error) {
	for _, prefix := range []struct {
		short, long, action string
	}{
		{"a:", "allow:", "allow"},
		{"d:", "disallow:", "disallow"},
	} {
		if strings.HasPrefix(rule, prefix.long) {
			return prefix.action, strings.TrimSpace(rule[len(prefix.long):]), nil
		}
		if strings.HasPrefix(rule, prefix.short) {
			return prefix.action, strings.TrimSpace(rule[len(prefix.short):]), nil
		}
	}

	// Bare CIDR without prefix — treat as disallow for backward compatibility.
	if _, err := netip.ParsePrefix(rule); err == nil {
		return "disallow", rule, nil
	}

	return "", "", fmt.Errorf("unknown format, expected 'a:<cidr>', 'd:<cidr>', 'allow:<cidr>', or 'disallow:<cidr>'")
}

// ComputeAllowedIPs computes the WireGuard AllowedIPs string from CIDR rules
// and an optional server IP to exclude.
//
// Rules are evaluated top-to-bottom (first match wins). For each rule, only the
// portion not yet decided by earlier rules takes effect. Allow rules add their
// undecided portion to the result; disallow rules simply mark it as decided.
func ComputeAllowedIPs(rules *CIDRRules, serverIP string) string {
	if len(rules.Rules) == 0 {
		// No rules: default to allow all.
		allowed := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		allowed = excludeServerIP(allowed, serverIP)
		return joinPrefixes(allowed)
	}

	var decided []netip.Prefix
	var allowed []netip.Prefix

	for _, rule := range rules.Rules {
		ruleRange := []netip.Prefix{rule.Prefix}
		// Compute the undecided portion of this rule's range.
		effective := ExcludePrefixes(ruleRange, decided)
		if rule.Action == "allow" {
			allowed = append(allowed, effective...)
		}
		// Mark the entire rule range as decided.
		decided = append(decided, rule.Prefix)
	}

	allowed = excludeServerIP(allowed, serverIP)
	sortPrefixes(allowed)
	return joinPrefixes(allowed)
}

func sortPrefixes(p []netip.Prefix) {
	sort.Slice(p, func(i, j int) bool {
		ai, aj := p[i].Addr(), p[j].Addr()
		if ai != aj {
			return ai.Less(aj)
		}
		return p[i].Bits() < p[j].Bits()
	})
}

func excludeServerIP(prefixes []netip.Prefix, serverIP string) []netip.Prefix {
	if serverIP == "" {
		return prefixes
	}
	addr, err := netip.ParseAddr(serverIP)
	if err != nil {
		return prefixes
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return ExcludePrefixes(prefixes, []netip.Prefix{netip.PrefixFrom(addr, bits)})
}

func joinPrefixes(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return ""
	}
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

// ExcludePrefixes removes exclude prefixes from base prefixes and returns the
// remaining set. For example, excluding 10.0.0.0/8 from 0.0.0.0/0 returns a
// set of prefixes covering everything except 10.0.0.0/8.
func ExcludePrefixes(base []netip.Prefix, exclude []netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, len(base))
	copy(result, base)

	for _, ex := range exclude {
		var next []netip.Prefix
		for _, p := range result {
			next = append(next, subtractPrefix(p, ex)...)
		}
		result = next
	}

	sort.Slice(result, func(i, j int) bool {
		ai, aj := result[i].Addr(), result[j].Addr()
		if ai != aj {
			return ai.Less(aj)
		}
		return result[i].Bits() < result[j].Bits()
	})

	return result
}

// subtractPrefix removes the "remove" prefix from "from" and returns the
// remaining prefixes. If they don't overlap, returns "from" unchanged.
func subtractPrefix(from, remove netip.Prefix) []netip.Prefix {
	if !from.Overlaps(remove) {
		return []netip.Prefix{from}
	}
	if remove.Bits() <= from.Bits() && remove.Contains(from.Addr()) {
		return nil
	}

	bits := from.Bits() + 1
	if from.Addr().Is4() && bits > 32 {
		return []netip.Prefix{from}
	}
	if from.Addr().Is6() && bits > 128 {
		return []netip.Prefix{from}
	}

	left, right := splitPrefix(from)

	var result []netip.Prefix
	result = append(result, subtractPrefix(left, remove)...)
	result = append(result, subtractPrefix(right, remove)...)
	return result
}

// splitPrefix splits a prefix into two halves with one more bit of prefix length.
func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	addr := p.Addr()

	left := netip.PrefixFrom(addr, bits)

	if addr.Is4() {
		raw := addr.As4()
		byteIndex := (bits - 1) / 8
		bitIndex := 7 - ((bits - 1) % 8)
		raw[byteIndex] |= 1 << bitIndex
		right := netip.PrefixFrom(netip.AddrFrom4(raw), bits)
		return left, right
	}

	raw := addr.As16()
	byteIndex := (bits - 1) / 8
	bitIndex := 7 - ((bits - 1) % 8)
	raw[byteIndex] |= 1 << bitIndex
	right := netip.PrefixFrom(netip.AddrFrom16(raw), bits)
	return left, right
}
