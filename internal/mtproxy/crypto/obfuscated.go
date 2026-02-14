package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Protocol tags decoded from the obfuscated header.
const (
	TagCompact      uint32 = 0xefefefef
	TagMedium       uint32 = 0xeeeeeeee
	TagMediumPadded uint32 = 0xdddddddd
)

// Secret represents a parsed MTProxy secret.
type Secret struct {
	Raw     [16]byte
	Padding bool // dd-prefix secret enables padding mode
}

// ParseSecret parses a hex-encoded secret string.
// Supports optional "dd" prefix for padding mode, and optional "ee" prefix.
func ParseSecret(hex string) (Secret, error) {
	var s Secret

	// Strip known prefixes
	if len(hex) == 34 {
		prefix := hex[:2]
		switch prefix {
		case "dd":
			s.Padding = true
			hex = hex[2:]
		case "ee":
			hex = hex[2:]
		default:
			return s, fmt.Errorf("unknown secret prefix %q, expected 32 or 34 hex chars", prefix)
		}
	}

	if len(hex) != 32 {
		return s, fmt.Errorf("secret must be 32 hex chars (or 34 with dd/ee prefix), got %d", len(hex))
	}

	for i := 0; i < 16; i++ {
		b, err := parseHexByte(hex[i*2], hex[i*2+1])
		if err != nil {
			return s, fmt.Errorf("invalid hex at position %d: %w", i*2, err)
		}
		s.Raw[i] = b
	}
	return s, nil
}

func parseHexByte(hi, lo byte) (byte, error) {
	h, ok1 := hexVal(hi)
	l, ok2 := hexVal(lo)
	if !ok1 || !ok2 {
		return 0, fmt.Errorf("invalid hex char")
	}
	return h<<4 | l, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ObfuscatedHeader holds the parsed result of a 64-byte obfuscated header.
type ObfuscatedHeader struct {
	Tag     uint32
	DCID    int16
	Encrypt cipher.Stream // proxy -> client (encrypt outgoing)
	Decrypt cipher.Stream // client -> proxy (decrypt incoming)
}

// DecryptHeader attempts to decrypt and parse the 64-byte obfuscated header
// using the given secrets. Returns the parsed header on success.
//
// Based on the C implementation in net/net-tcp-rpc-ext-server.c:1271-1367:
//   - Derive read key: SHA256(header[8:40] + secret)
//   - Read IV: header[40:56]
//   - Derive write key: SHA256(reverse(header[24:56]) + secret)
//   - Write IV: reverse(header[8:24])
//   - Decrypt header with read stream, check tag at offset 56
func DecryptHeader(header [64]byte, secrets []Secret) (*ObfuscatedHeader, error) {
	for _, secret := range secrets {
		result, err := tryDecryptHeader(header, secret)
		if err == nil {
			return result, nil
		}
	}
	return nil, fmt.Errorf("no matching secret found")
}

func tryDecryptHeader(header [64]byte, secret Secret) (*ObfuscatedHeader, error) {
	// Derive read key: SHA256(header[8:40] + secret[0:16])
	var readKeyInput [48]byte
	copy(readKeyInput[:32], header[8:40])
	copy(readKeyInput[32:], secret.Raw[:])
	readKey := sha256.Sum256(readKeyInput[:])

	// Read IV: header[40:56]
	var readIV [16]byte
	copy(readIV[:], header[40:56])

	// Derive write key: SHA256(reverse(header[24:56]) + secret[0:16])
	var writeKeyInput [48]byte
	for i := 0; i < 32; i++ {
		writeKeyInput[i] = header[55-i]
	}
	copy(writeKeyInput[32:], secret.Raw[:])
	writeKey := sha256.Sum256(writeKeyInput[:])

	// Write IV: reverse(header[8:24])
	var writeIV [16]byte
	for i := 0; i < 16; i++ {
		writeIV[i] = header[23-i]
	}

	// Create read (decrypt) stream and decrypt the entire 64-byte header
	readBlock, err := aes.NewCipher(readKey[:])
	if err != nil {
		return nil, fmt.Errorf("creating read cipher: %w", err)
	}
	readStream := cipher.NewCTR(readBlock, readIV[:])

	// Decrypt the header in-place to check the tag
	var decrypted [64]byte
	readStream.XORKeyStream(decrypted[:], header[:])

	// Check tag at offset 56-59
	tag := binary.LittleEndian.Uint32(decrypted[56:60])
	if tag != TagCompact && tag != TagMedium && tag != TagMediumPadded {
		return nil, fmt.Errorf("invalid tag %08x", tag)
	}

	// For dd-prefix secrets, only accept padding mode tag
	if secret.Padding && tag != TagMediumPadded {
		return nil, fmt.Errorf("padding secret requires dd tag")
	}

	// Extract DC ID (signed int16 at offset 60)
	dcID := int16(binary.LittleEndian.Uint16(decrypted[60:62]))

	// Create write (encrypt) stream
	writeBlock, err := aes.NewCipher(writeKey[:])
	if err != nil {
		return nil, fmt.Errorf("creating write cipher: %w", err)
	}
	writeStream := cipher.NewCTR(writeBlock, writeIV[:])

	return &ObfuscatedHeader{
		Tag:     tag,
		DCID:    dcID,
		Encrypt: writeStream,
		Decrypt: readStream, // continues from position 64
	}, nil
}
