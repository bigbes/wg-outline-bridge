package crypto

import (
	"testing"
)

func TestParseSecret(t *testing.T) {
	tests := []struct {
		input   string
		wantPad bool
		wantErr bool
	}{
		{"0123456789abcdef0123456789abcdef", false, false},
		{"dd0123456789abcdef0123456789abcdef", true, false},
		{"ee0123456789abcdef0123456789abcdef", false, false},
		{"short", false, true},
		{"zz0123456789abcdef0123456789abcdef", false, true},
	}

	for _, tt := range tests {
		s, err := ParseSecret(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSecret(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if err == nil && s.Padding != tt.wantPad {
			t.Errorf("ParseSecret(%q).Padding = %v, want %v", tt.input, s.Padding, tt.wantPad)
		}
	}
}
