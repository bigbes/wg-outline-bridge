package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

// GenerateHeader creates a new 64-byte obfuscated2 header for a backend connection
// (no secret involved). Returns the header to send, plus encrypt/decrypt streams
// for the backend leg.
//
// The receiver (Telegram DC) derives keys from the wire bytes, so we:
//  1. Generate random bytes for header[0:56] (these go on the wire as-is)
//  2. Derive key/IV from those wire bytes
//  3. Construct header[56:64] by XORing tag/dcID with the keystream at offset 56
//
// Encrypt: used to encrypt data sent to the backend (continues from position 64).
// Decrypt: used to decrypt data received from the backend (starts at position 0).
func GenerateHeader(tag uint32, dcID int16) (header [64]byte, encrypt cipher.Stream, decrypt cipher.Stream, err error) {
	for {
		if _, err = rand.Read(header[:56]); err != nil {
			return header, nil, nil, fmt.Errorf("generating random header: %w", err)
		}

		// Ensure first bytes don't look like known protocols
		first := header[0]
		if first == 0xef || first == 0x48 || first == 0x44 ||
			first == 0x50 || first == 0x47 || first == 0x16 || first == 0x14 {
			continue
		}
		first4 := binary.LittleEndian.Uint32(header[:4])
		if first4 == 0x00000000 || first4 == TagCompact || first4 == TagMedium || first4 == TagMediumPadded {
			continue
		}
		break
	}

	// Derive encrypt key from wire bytes: SHA256(header[8:40]), IV = header[40:56]
	encKey := sha256.Sum256(header[8:40])
	var encIV [16]byte
	copy(encIV[:], header[40:56])

	encBlock, err := aes.NewCipher(encKey[:])
	if err != nil {
		return header, nil, nil, fmt.Errorf("creating encrypt cipher: %w", err)
	}
	encStream := cipher.NewCTR(encBlock, encIV[:])

	// Advance the encrypt stream by 56 bytes to reach the tag position
	var skip [56]byte
	encStream.XORKeyStream(skip[:], skip[:])

	// Construct the plaintext for positions 56-63: tag(4) + dcID(2) + padding(2)
	var plain [8]byte
	binary.LittleEndian.PutUint32(plain[0:4], tag)
	binary.LittleEndian.PutUint16(plain[4:6], uint16(dcID))
	// plain[6:8] stays zero (padding)

	// XOR with keystream to produce wire bytes at header[56:64]
	encStream.XORKeyStream(header[56:], plain[:])

	// encStream is now at position 64, ready for payload

	// Ensure the final header[0:4] still passes the first-byte checks after
	// we set [56:64]. Re-check first4 against encrypted tag values — but
	// header[0:56] is unchanged, so no re-check needed.

	// Derive decrypt key (for data we receive): SHA256(reverse(header[24:56])),
	// IV = reverse(header[8:24])
	var decKeyInput [32]byte
	for i := 0; i < 32; i++ {
		decKeyInput[i] = header[55-i]
	}
	decKey := sha256.Sum256(decKeyInput[:])
	var decIV [16]byte
	for i := 0; i < 16; i++ {
		decIV[i] = header[23-i]
	}

	decBlock, err := aes.NewCipher(decKey[:])
	if err != nil {
		return header, nil, nil, fmt.Errorf("creating decrypt cipher: %w", err)
	}
	decStream := cipher.NewCTR(decBlock, decIV[:])

	return header, encStream, decStream, nil
}
