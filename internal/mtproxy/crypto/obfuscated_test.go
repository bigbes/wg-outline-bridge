package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestGenerateBackendHeader(t *testing.T) {
	tests := []int16{2, 1, -3, 5}

	for _, dcID := range tests {
		header, enc, dec, err := GenerateBackendHeader(TagMediumPadded, dcID)
		if err != nil {
			t.Fatalf("GenerateBackendHeader(%d) error: %v", dcID, err)
		}

		// Simulate DC-side: derive key from raw header bytes (no SHA256, no secret)
		// DC sees the wire bytes where key+iv are plaintext (restored after encryption)
		block, err := aes.NewCipher(header[8:40])
		if err != nil {
			t.Fatal(err)
		}
		stream := cipher.NewCTR(block, header[40:56])

		// DC decrypts the full frame to read tag+dcID at [56:64]
		var decrypted [64]byte
		stream.XORKeyStream(decrypted[:], header[:])

		tag := binary.LittleEndian.Uint32(decrypted[56:60])
		gotDC := int16(binary.LittleEndian.Uint16(decrypted[60:62]))

		if tag != TagMediumPadded {
			t.Errorf("dc=%d: tag mismatch: got 0x%08x, want 0x%08x", dcID, tag, TagMediumPadded)
		}
		if gotDC != dcID {
			t.Errorf("dc=%d: dcID mismatch: got %d", dcID, gotDC)
		}

		// Verify encrypt/decrypt streams work for payload
		payload := []byte("test payload data for roundtrip")
		encrypted := make([]byte, len(payload))
		enc.XORKeyStream(encrypted, payload)

		// DC decrypts using the same stream (advanced past header)
		decPayload := make([]byte, len(encrypted))
		// DC's stream is already at position 64 after decrypting header
		stream.XORKeyStream(decPayload, encrypted)
		if string(decPayload) != string(payload) {
			t.Errorf("payload roundtrip failed: got %q", decPayload)
		}

		// Verify decrypt stream reads what DC sends
		dcPayload := []byte("response from telegram dc")
		// DC derives write key from inverted key+iv block (reverse of bytes 8-55)
		var dcEncKey [32]byte
		var dcEncIV [16]byte
		for i := 0; i < 32; i++ {
			dcEncKey[i] = header[55-i]
		}
		for i := 0; i < 16; i++ {
			dcEncIV[i] = header[23-i]
		}
		dcBlock, _ := aes.NewCipher(dcEncKey[:])
		dcStream := cipher.NewCTR(dcBlock, dcEncIV[:])

		dcEncrypted := make([]byte, len(dcPayload))
		dcStream.XORKeyStream(dcEncrypted, dcPayload)

		decFromDC := make([]byte, len(dcEncrypted))
		dec.XORKeyStream(decFromDC, dcEncrypted)
		if string(decFromDC) != string(dcPayload) {
			t.Errorf("DC->proxy roundtrip failed: got %q", decFromDC)
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
