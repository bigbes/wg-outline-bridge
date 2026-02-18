package config

import (
	"net/netip"
	"testing"
)

func TestExpandCIDRRuleVars(t *testing.T) {
	tests := []struct {
		name  string
		rules []string
		vars  map[string]string
		want  []string
	}{
		{
			name:  "server_ip substituted",
			rules: []string{"d:{{ $server_ip }}/32", "a:*"},
			vars:  map[string]string{"server_ip": "203.0.113.1"},
			want:  []string{"d:203.0.113.1/32", "a:*"},
		},
		{
			name:  "no spacing in braces",
			rules: []string{"d:{{$server_ip}}/32"},
			vars:  map[string]string{"server_ip": "10.0.0.1"},
			want:  []string{"d:10.0.0.1/32"},
		},
		{
			name:  "unknown var left unexpanded",
			rules: []string{"d:{{ $unknown }}/32"},
			vars:  map[string]string{"server_ip": "10.0.0.1"},
			want:  []string{"d:{{ $unknown }}/32"},
		},
		{
			name:  "empty var left unexpanded",
			rules: []string{"d:{{ $server_ip }}/32"},
			vars:  map[string]string{"server_ip": ""},
			want:  []string{"d:{{ $server_ip }}/32"},
		},
		{
			name:  "no vars no change",
			rules: []string{"d:10.0.0.0/8", "a:*"},
			vars:  map[string]string{"server_ip": "1.2.3.4"},
			want:  []string{"d:10.0.0.0/8", "a:*"},
		},
		{
			name:  "nil vars",
			rules: []string{"d:{{ $server_ip }}/32"},
			vars:  nil,
			want:  []string{"d:{{ $server_ip }}/32"},
		},
		{
			name:  "multiple vars in one rule",
			rules: []string{"d:{{ $server_ip }}/{{ $bits }}"},
			vars:  map[string]string{"server_ip": "1.2.3.0", "bits": "24"},
			want:  []string{"d:1.2.3.0/24"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandCIDRRuleVars(tt.rules, tt.vars)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d rules, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("rule %d: got %q, want %q", i, got[i], tt.want[i])
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
		rules   []string
		want    []CIDRRule
		wantErr bool
	}{
		{
			name:  "disallow with d: prefix",
			rules: []string{"d:192.168.0.0/16"},
			want: []CIDRRule{
				{Action: "disallow", Prefix: netip.MustParsePrefix("192.168.0.0/16")},
			},
		},
		{
			name:  "allow with a: prefix",
			rules: []string{"a:10.0.0.0/8"},
			want: []CIDRRule{
				{Action: "allow", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
			},
		},
		{
			name:  "full prefixes",
			rules: []string{"allow:10.0.0.0/8", "disallow:192.168.0.0/16"},
			want: []CIDRRule{
				{Action: "allow", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
				{Action: "disallow", Prefix: netip.MustParsePrefix("192.168.0.0/16")},
			},
		},
		{
			name:  "wildcard placed last",
			rules: []string{"a:*", "d:10.0.0.0/8"},
			want: []CIDRRule{
				{Action: "disallow", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
				{Action: "allow", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Wildcard: true},
			},
		},
		{
			name:  "bare CIDR treated as disallow",
			rules: []string{"192.168.0.0/16"},
			want: []CIDRRule{
				{Action: "disallow", Prefix: netip.MustParsePrefix("192.168.0.0/16")},
			},
		},
		{
			name:  "order preserved with wildcard last",
			rules: []string{"a:10.100.0.0/24", "d:10.0.0.0/8", "d:192.168.0.0/16", "a:*"},
			want: []CIDRRule{
				{Action: "allow", Prefix: netip.MustParsePrefix("10.100.0.0/24")},
				{Action: "disallow", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
				{Action: "disallow", Prefix: netip.MustParsePrefix("192.168.0.0/16")},
				{Action: "allow", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Wildcard: true},
			},
		},
		{
			name:    "invalid rule",
			rules:   []string{"x:something"},
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			rules:   []string{"d:not-a-cidr"},
			wantErr: true,
		},
		{
			name: "empty rules",
		},
		{
			name:  "non-canonical prefix is masked",
			rules: []string{"a:10.0.0.1/24"},
			want: []CIDRRule{
				{Action: "allow", Prefix: netip.MustParsePrefix("10.0.0.0/24")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCIDRRules(tt.rules)
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
		rules    []string
		serverIP string
		want     string
	}{
		{
			name: "no rules defaults to allow all",
			want: "0.0.0.0/0",
		},
		{
			name:  "disallow only (implicit deny rest)",
			rules: []string{"d:10.0.0.0/8"},
			want:  "",
		},
		{
			name:  "disallow then allow all",
			rules: []string{"d:10.0.0.0/8", "a:*"},
			want: "0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, " +
				"16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/1",
		},
		{
			name:  "allow subnet then disallow parent then allow all",
			rules: []string{"a:10.100.0.0/24", "d:10.0.0.0/8", "d:127.0.0.0/8", "d:172.16.0.0/12", "d:192.168.0.0/16", "a:*"},
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
			name:  "only explicit allows",
			rules: []string{"a:10.0.0.0/8", "a:192.168.0.0/16"},
			want:  "10.0.0.0/8, 192.168.0.0/16",
		},
		{
			name:     "server IP excluded",
			rules:    []string{"a:203.0.113.0/24"},
			serverIP: "203.0.113.1",
			want: "203.0.113.0/32, 203.0.113.2/31, 203.0.113.4/30, " +
				"203.0.113.8/29, 203.0.113.16/28, 203.0.113.32/27, " +
				"203.0.113.64/26, 203.0.113.128/25",
		},
		{
			name:  "disallow all",
			rules: []string{"d:*"},
			want:  "",
		},
		{
			name:     "server IP via template variable",
			rules:    []string{"d:{{ $server_ip }}/32", "a:203.0.113.0/24"},
			serverIP: "203.0.113.1",
			want: "203.0.113.0/32, 203.0.113.2/31, 203.0.113.4/30, " +
				"203.0.113.8/29, 203.0.113.16/28, 203.0.113.32/27, " +
				"203.0.113.64/26, 203.0.113.128/25",
		},
		{
			name:  "bare CIDR backward compat with allow all",
			rules: []string{"192.168.0.0/16", "a:*"},
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
			expanded := ExpandCIDRRuleVars(tt.rules, map[string]string{"server_ip": tt.serverIP})
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
