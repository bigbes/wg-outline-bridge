package config

import (
	"net/netip"
	"testing"
)

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
