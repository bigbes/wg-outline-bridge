package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestGenerateHeaderRoundtrip(t *testing.T) {
	// GenerateHeader produces a header that a receiver (Telegram DC, no secret)
	// can decode to find the correct tag and DC ID.
	tests := []struct {
		tag  uint32
		dcID int16
	}{
		{TagCompact, 2},
		{TagMedium, 1},
		{TagMediumPadded, 5},
		{TagMediumPadded, -2},
	}

	for _, tt := range tests {
		header, _, _, err := GenerateHeader(tt.tag, tt.dcID)
		if err != nil {
			t.Fatalf("GenerateHeader(0x%08x, %d) error: %v", tt.tag, tt.dcID, err)
		}

		// Simulate the DC-side: derive key from wire bytes (no secret, just 32 bytes)
		readKey := sha256.Sum256(header[8:40])
		var readIV [16]byte
		copy(readIV[:], header[40:56])

		block, err := aes.NewCipher(readKey[:])
		if err != nil {
			t.Fatal(err)
		}
		stream := cipher.NewCTR(block, readIV[:])

		var decrypted [64]byte
		stream.XORKeyStream(decrypted[:], header[:])

		tag := binary.LittleEndian.Uint32(decrypted[56:60])
		dcID := int16(binary.LittleEndian.Uint16(decrypted[60:62]))

		if tag != tt.tag {
			t.Errorf("tag mismatch: got 0x%08x, want 0x%08x", tag, tt.tag)
		}
		if dcID != tt.dcID {
			t.Errorf("dcID mismatch: got %d, want %d", dcID, tt.dcID)
		}
	}
}

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
