package config

import (
	"net/netip"
	"testing"
)

func TestExpandCIDRRuleVars(t *testing.T) {
	tests := []struct {
		name  string
		rules []CIDREntry
		vars  map[string]string
		want  []CIDREntry
	}{
		{
			name:  "server_ip substituted",
			rules: []CIDREntry{{Mode: "disallow", CIDR: "{{ $server_ip }}/32"}, {Mode: "allow", CIDR: "*"}},
			vars:  map[string]string{"server_ip": "203.0.113.1"},
			want:  []CIDREntry{{Mode: "disallow", CIDR: "203.0.113.1/32"}, {Mode: "allow", CIDR: "*"}},
		},
		{
			name:  "no spacing in braces",
			rules: []CIDREntry{{Mode: "disallow", CIDR: "{{$server_ip}}/32"}},
			vars:  map[string]string{"server_ip": "10.0.0.1"},
			want:  []CIDREntry{{Mode: "disallow", CIDR: "10.0.0.1/32"}},
		},
		{
			name:  "unknown var left unexpanded",
			rules: []CIDREntry{{Mode: "disallow", CIDR: "{{ $unknown }}/32"}},
			vars:  map[string]string{"server_ip": "10.0.0.1"},
			want:  []CIDREntry{{Mode: "disallow", CIDR: "{{ $unknown }}/32"}},
		},
		{
			name:  "empty var left unexpanded",
			rules: []CIDREntry{{Mode: "disallow", CIDR: "{{ $server_ip }}/32"}},
			vars:  map[string]string{"server_ip": ""},
			want:  []CIDREntry{{Mode: "disallow", CIDR: "{{ $server_ip }}/32"}},
		},
		{
			name:  "no vars no change",
			rules: []CIDREntry{{Mode: "disallow", CIDR: "10.0.0.0/8"}, {Mode: "allow", CIDR: "*"}},
			vars:  map[string]string{"server_ip": "1.2.3.4"},
			want:  []CIDREntry{{Mode: "disallow", CIDR: "10.0.0.0/8"}, {Mode: "allow", CIDR: "*"}},
		},
		{
			name:  "nil vars",
			rules: []CIDREntry{{Mode: "disallow", CIDR: "{{ $server_ip }}/32"}},
			vars:  nil,
			want:  []CIDREntry{{Mode: "disallow", CIDR: "{{ $server_ip }}/32"}},
		},
		{
			name:  "multiple vars in one rule",
			rules: []CIDREntry{{Mode: "disallow", CIDR: "{{ $server_ip }}/{{ $bits }}"}},
			vars:  map[string]string{"server_ip": "1.2.3.0", "bits": "24"},
			want:  []CIDREntry{{Mode: "disallow", CIDR: "1.2.3.0/24"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandCIDRRuleVars(tt.rules, tt.vars)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d rules, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].Mode != tt.want[i].Mode || got[i].CIDR != tt.want[i].CIDR {
					t.Errorf("rule %d: got {Mode:%q CIDR:%q}, want {Mode:%q CIDR:%q}",
						i, got[i].Mode, got[i].CIDR, tt.want[i].Mode, tt.want[i].CIDR)
				}
			}
		})
	}
}

func TestExcludePrefixes(t *testing.T) {
	tests := []struct {
		name    string
		base    []string
		exclude []string
		want    []string
	}{
		{
			name:    "exclude /8 from /0",
			base:    []string{"0.0.0.0/0"},
			exclude: []string{"10.0.0.0/8"},
			want: []string{
				"0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8",
				"12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3",
				"64.0.0.0/2", "128.0.0.0/1",
			},
		},
		{
			name:    "exclude /1 from /0",
			base:    []string{"0.0.0.0/0"},
			exclude: []string{"0.0.0.0/1"},
			want:    []string{"128.0.0.0/1"},
		},
		{
			name:    "no overlap",
			base:    []string{"192.168.0.0/16"},
			exclude: []string{"10.0.0.0/8"},
			want:    []string{"192.168.0.0/16"},
		},
		{
			name:    "complete removal",
			base:    []string{"10.0.0.0/8"},
			exclude: []string{"10.0.0.0/8"},
			want:    nil,
		},
		{
			name:    "exclude larger covers base",
			base:    []string{"10.1.0.0/16"},
			exclude: []string{"10.0.0.0/8"},
			want:    nil,
		},
		{
			name:    "exclude multiple from /0",
			base:    []string{"0.0.0.0/0"},
			exclude: []string{"10.0.0.0/8", "192.168.0.0/16"},
			want: []string{
				"0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8",
				"12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3",
				"64.0.0.0/2", "128.0.0.0/2",
				"192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13",
				"192.169.0.0/16", "192.170.0.0/15", "192.172.0.0/14",
				"192.176.0.0/12", "192.192.0.0/10",
				"193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6",
				"200.0.0.0/5", "208.0.0.0/4", "224.0.0.0/3",
			},
		},
		{
			name:    "exclude /24 from /16",
			base:    []string{"192.168.0.0/16"},
			exclude: []string{"192.168.1.0/24"},
			want: []string{
				"192.168.0.0/24", "192.168.2.0/23", "192.168.4.0/22",
				"192.168.8.0/21", "192.168.16.0/20", "192.168.32.0/19",
				"192.168.64.0/18", "192.168.128.0/17",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var base, exclude []netip.Prefix
			for _, s := range tt.base {
				base = append(base, netip.MustParsePrefix(s))
			}
			for _, s := range tt.exclude {
				exclude = append(exclude, netip.MustParsePrefix(s))
			}

			got := ExcludePrefixes(base, exclude)

			if len(got) != len(tt.want) {
				var gotStrs []string
				for _, p := range got {
					gotStrs = append(gotStrs, p.String())
				}
				t.Fatalf("got %d prefixes %v, want %d %v", len(got), gotStrs, len(tt.want), tt.want)
			}

			for i, p := range got {
				if p.String() != tt.want[i] {
					t.Errorf("prefix %d: got %s, want %s", i, p.String(), tt.want[i])
				}
			}
		})
	}
}

func TestParseCIDRRules(t *testing.T) {
	tests := []struct {
		name    string
		entries []CIDREntry
		want    []CIDRRule
		wantErr bool
	}{
		{
			name:    "disallow with d: prefix",
			entries: []CIDREntry{{Mode: "disallow", CIDR: "192.168.0.0/16"}},
			want: []CIDRRule{
				{Action: "disallow", Prefix: netip.MustParsePrefix("192.168.0.0/16")},
			},
		},
		{
			name:    "allow with a: prefix",
			entries: []CIDREntry{{Mode: "allow", CIDR: "10.0.0.0/8"}},
			want: []CIDRRule{
				{Action: "allow", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
			},
		},
		{
			name:    "full prefixes",
			entries: []CIDREntry{{Mode: "allow", CIDR: "10.0.0.0/8"}, {Mode: "disallow", CIDR: "192.168.0.0/16"}},
			want: []CIDRRule{
				{Action: "allow", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
				{Action: "disallow", Prefix: netip.MustParsePrefix("192.168.0.0/16")},
			},
		},
		{
			name:    "wildcard placed last",
			entries: []CIDREntry{{Mode: "allow", CIDR: "*"}, {Mode: "disallow", CIDR: "10.0.0.0/8"}},
			want: []CIDRRule{
				{Action: "disallow", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
				{Action: "allow", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Wildcard: true},
			},
		},
		{
			name:    "bare CIDR treated as disallow",
			entries: []CIDREntry{{Mode: "disallow", CIDR: "192.168.0.0/16"}},
			want: []CIDRRule{
				{Action: "disallow", Prefix: netip.MustParsePrefix("192.168.0.0/16")},
			},
		},
		{
			name: "order preserved with wildcard last",
			entries: []CIDREntry{
				{Mode: "allow", CIDR: "10.100.0.0/24"},
				{Mode: "disallow", CIDR: "10.0.0.0/8"},
				{Mode: "disallow", CIDR: "192.168.0.0/16"},
				{Mode: "allow", CIDR: "*"},
			},
			want: []CIDRRule{
				{Action: "allow", Prefix: netip.MustParsePrefix("10.100.0.0/24")},
				{Action: "disallow", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
				{Action: "disallow", Prefix: netip.MustParsePrefix("192.168.0.0/16")},
				{Action: "allow", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Wildcard: true},
			},
		},
		{
			name:    "invalid CIDR",
			entries: []CIDREntry{{Mode: "disallow", CIDR: "not-a-cidr"}},
			wantErr: true,
		},
		{
			name: "empty rules",
		},
		{
			name:    "non-canonical prefix is masked",
			entries: []CIDREntry{{Mode: "allow", CIDR: "10.0.0.1/24"}},
			want: []CIDRRule{
				{Action: "allow", Prefix: netip.MustParsePrefix("10.0.0.0/24")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCIDRRules(tt.entries)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got.Rules) != len(tt.want) {
				t.Fatalf("got %d rules, want %d", len(got.Rules), len(tt.want))
			}
			for i, r := range got.Rules {
				w := tt.want[i]
				if r.Action != w.Action || r.Prefix != w.Prefix || r.Wildcard != w.Wildcard {
					t.Errorf("rule %d: got {%s %s wildcard=%v}, want {%s %s wildcard=%v}",
						i, r.Action, r.Prefix, r.Wildcard, w.Action, w.Prefix, w.Wildcard)
				}
			}
		})
	}
}

func TestComputeAllowedIPs(t *testing.T) {
	tests := []struct {
		name     string
		entries  []CIDREntry
		serverIP string
		want     string
	}{
		{
			name: "no rules defaults to allow all",
			want: "0.0.0.0/0",
		},
		{
			name:    "disallow only (implicit deny rest)",
			entries: []CIDREntry{{Mode: "disallow", CIDR: "10.0.0.0/8"}},
			want:    "",
		},
		{
			name:    "disallow then allow all",
			entries: []CIDREntry{{Mode: "disallow", CIDR: "10.0.0.0/8"}, {Mode: "allow", CIDR: "*"}},
			want: "0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, " +
				"16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/1",
		},
		{
			name: "allow subnet then disallow parent then allow all",
			entries: []CIDREntry{
				{Mode: "allow", CIDR: "10.100.0.0/24"},
				{Mode: "disallow", CIDR: "10.0.0.0/8"},
				{Mode: "disallow", CIDR: "127.0.0.0/8"},
				{Mode: "disallow", CIDR: "172.16.0.0/12"},
				{Mode: "disallow", CIDR: "192.168.0.0/16"},
				{Mode: "allow", CIDR: "*"},
			},
			want: "0.0.0.0/5, 8.0.0.0/7, 10.100.0.0/24, 11.0.0.0/8, 12.0.0.0/6, " +
				"16.0.0.0/4, 32.0.0.0/3, " +
				"64.0.0.0/3, 96.0.0.0/4, 112.0.0.0/5, 120.0.0.0/6, 124.0.0.0/7, 126.0.0.0/8, " +
				"128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, " +
				"172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, " +
				"173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, " +
				"192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, " +
				"192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, " +
				"192.176.0.0/12, 192.192.0.0/10, " +
				"193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, " +
				"200.0.0.0/5, 208.0.0.0/4, 224.0.0.0/3",
		},
		{
			name:    "only explicit allows",
			entries: []CIDREntry{{Mode: "allow", CIDR: "10.0.0.0/8"}, {Mode: "allow", CIDR: "192.168.0.0/16"}},
			want:    "10.0.0.0/8, 192.168.0.0/16",
		},
		{
			name:     "server IP excluded",
			entries:  []CIDREntry{{Mode: "allow", CIDR: "203.0.113.0/24"}},
			serverIP: "203.0.113.1",
			want: "203.0.113.0/32, 203.0.113.2/31, 203.0.113.4/30, " +
				"203.0.113.8/29, 203.0.113.16/28, 203.0.113.32/27, " +
				"203.0.113.64/26, 203.0.113.128/25",
		},
		{
			name:    "disallow all",
			entries: []CIDREntry{{Mode: "disallow", CIDR: "*"}},
			want:    "",
		},
		{
			name:     "server IP via template variable",
			entries:  []CIDREntry{{Mode: "disallow", CIDR: "{{ $server_ip }}/32"}, {Mode: "allow", CIDR: "203.0.113.0/24"}},
			serverIP: "203.0.113.1",
			want: "203.0.113.0/32, 203.0.113.2/31, 203.0.113.4/30, " +
				"203.0.113.8/29, 203.0.113.16/28, 203.0.113.32/27, " +
				"203.0.113.64/26, 203.0.113.128/25",
		},
		{
			name:    "bare CIDR backward compat with allow all",
			entries: []CIDREntry{{Mode: "disallow", CIDR: "192.168.0.0/16"}, {Mode: "allow", CIDR: "*"}},
			want: "0.0.0.0/1, 128.0.0.0/2, " +
				"192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, " +
				"192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, " +
				"192.176.0.0/12, 192.192.0.0/10, " +
				"193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, " +
				"200.0.0.0/5, 208.0.0.0/4, 224.0.0.0/3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expanded := ExpandCIDRRuleVars(tt.entries, map[string]string{"server_ip": tt.serverIP})
			rules, err := ParseCIDRRules(expanded)
			if err != nil {
				t.Fatalf("ParseCIDRRules: %v", err)
			}
			got := ComputeAllowedIPs(rules, tt.serverIP)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}
