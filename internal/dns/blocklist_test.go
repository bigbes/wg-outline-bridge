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
