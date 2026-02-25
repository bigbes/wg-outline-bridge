package dns

import "testing"

func TestDetectBlocklistFormat(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"hosts with 0.0.0.0", "0.0.0.0 ads.example.com", "hosts"},
		{"hosts with 127.0.0.1", "127.0.0.1 tracker.example.com", "hosts"},
		{"hosts with ::1", "::1 tracker.example.com", "hosts"},
		{"domain only", "ads.example.com", "domains"},
		{"wildcard domain", "*.ads.example.com", "domains"},
		{"single word", "localhost", "domains"},
		{"adblock rule", "||ads.example.com^", "adblock"},
		{"adblock rule with options", "||tracker.example.com^$third-party", "adblock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlocklistFormat(tt.line)
			if got != tt.want {
				t.Errorf("detectBlocklistFormat(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestDetectHeaderSyntax(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"adblock syntax", "! Syntax: AdBlock", "adblock"},
		{"adblock plus filter list", "! Syntax: Adblock Plus Filter List", "adblock"},
		{"adguard syntax", "! Syntax: AdGuard", "adblock"},
		{"domains with subdomains", "# Syntax: Domains (including possible subdomains)", "domains-wildcards"},
		{"domains without subdomains", "# Syntax: Domains (without subdomains)", "domains"},
		{"domains plain", "# Syntax: Domains", "domains"},
		{"hosts with subdomains", "# Syntax: Hosts (including possible subdomains)", "hosts"},
		{"hosts plain", "# Syntax: Hosts", "hosts"},
		{"not a syntax line", "# Title: Some Blocklist", ""},
		{"empty comment", "# ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectHeaderSyntax(tt.line)
			if got != tt.want {
				t.Errorf("detectHeaderSyntax(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestIsBlockedWithSuffixes(t *testing.T) {
	bl := &BlocklistLoader{
		domains: map[string]bool{
			"exact.example.com.": true,
		},
		suffixes: []string{
			".wildcard.com.",
		},
	}

	tests := []struct {
		fqdn string
		want bool
	}{
		{"exact.example.com.", true},
		{"other.example.com.", false},
		{"sub.wildcard.com.", true},
		{"deep.sub.wildcard.com.", true},
		{"wildcard.com.", false}, // suffix is ".wildcard.com.", doesn't match "wildcard.com."
		{"notwildcard.com.", false},
	}
	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			if got := bl.IsBlocked(tt.fqdn); got != tt.want {
				t.Errorf("IsBlocked(%q) = %v, want %v", tt.fqdn, got, tt.want)
			}
		})
	}
}

func TestParseAdblockLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"basic rule", "||ads.example.com^", "ads.example.com"},
		{"rule with options", "||tracker.example.com^$third-party", "tracker.example.com"},
		{"subdomain rule", "||sub.ads.example.com^", "sub.ads.example.com"},
		{"no caret", "||ads.example.com", "ads.example.com"},
		{"exception rule", "@@||allowed.example.com^", ""},
		{"path rule", "||example.com/ads^", ""},
		{"wildcard rule", "||*.example.com^", ""},
		{"not adblock format", "ads.example.com", ""},
		{"empty after prefix", "||^", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAdblockLine(tt.line)
			if got != tt.want {
				t.Errorf("parseAdblockLine(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}
