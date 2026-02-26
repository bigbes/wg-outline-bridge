package routing

import "strings"

type domainPattern struct {
	exact  string // non-empty for exact match
	suffix string // non-empty for *.suffix match (stored without *.)
}

func parseDomainPattern(s string) domainPattern {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "*.") {
		return domainPattern{suffix: s[2:]}
	}
	return domainPattern{exact: s}
}

func (p domainPattern) String() string {
	if p.exact != "" {
		return p.exact
	}
	return "*." + p.suffix
}

func (p domainPattern) matches(domain string) bool {
	domain = strings.ToLower(domain)
	if p.exact != "" {
		return domain == p.exact
	}
	if p.suffix != "" {
		return strings.HasSuffix(domain, "."+p.suffix)
	}
	return false
}
