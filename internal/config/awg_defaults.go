package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

// GenerateAWGDefaults produces a randomized AmneziaWG 2.0 configuration with
// CPS templates that mimic QUIC traffic. All binary prefixes are randomized
// per server so each installation has a unique protocol signature.
//
// The i1 QUIC-like header uses a DCID length byte > 20 so the frontend
// UDP mux can distinguish real QUIC from AWG CPS.
func GenerateAWGDefaults() *AmneziaWGConfig {
	cfg := &AmneziaWGConfig{
		Jc:   randInt(4, 8),
		Jmin: randInt(200, 400),
		Jmax: randInt(800, 1100),
		S1:   randInt(50, 150),
		S2:   randInt(30, 70),
		S3:   randInt(30, 70),
		S4:   randInt(15, 40),
		H1:   generateHeaderRange(),
		H2:   generateHeaderRange(),
		H3:   generateHeaderRange(),
		H4:   generateHeaderRange(),
	}

	cfg.I1 = generateI1()
	cfg.I2 = generateI2()
	cfg.I3 = generateI3()
	cfg.I4 = generateI4()
	cfg.I5 = generateI5()

	return cfg
}

// generateHeaderRange produces a random H-parameter range string like
// "630453732-630481535". The range base is random (500M–2B) with a
// spread of 10K–50K so values don't overlap with WG message types (1–4).
func generateHeaderRange() string {
	base := randInt(500_000_000, 2_000_000_000)
	spread := randInt(10_000, 50_000)
	return fmt.Sprintf("%d-%d", base, base+spread)
}

// generateI1 builds a QUIC v1 Initial–mimicking CPS template (~900–1200 bytes).
//
// Layout:
//
//	[0]     0xC0               — QUIC long header (form=1 + fixed=1 + type=00)
//	[1:5]   0x00000001         — QUIC version 1
//	[5]     DCID length        — >20 so the frontend UDP mux can distinguish real QUIC from AWG CPS
//	[6:N]   random bytes       — fake DCID + SCID header data
//	        <rc M>             — random alphanumeric (visible in hex dumps)
//	        <c>                — packet counter (8 bytes)
//	        <t>                — timestamp (8 bytes)
//	        <r P>              — random padding to reach ~1200 bytes total
func generateI1() string {
	// Build the binary prefix: QUIC v1 header + DCID len + random header bytes.
	// Random bytes as fake DCID + SCID + token header data.
	fakeHeader := randomBytes(randInt(20, 40))
	prefix := make([]byte, 0, 6+len(fakeHeader))
	prefix = append(prefix, 0xc0, 0x00, 0x00, 0x00, 0x01)

	// DCID length > 20 prevents UDP mux from classifying as real QUIC.
	prefix = append(prefix, byte(randInt(21, 63)))
	prefix = append(prefix, fakeHeader...)

	rcLen := randInt(10, 30)
	rPad := randInt(800, 1100)

	return fmt.Sprintf("<b 0x%s><rc %d><c><t><r %d>",
		hex.EncodeToString(prefix), rcLen, rPad)
}

// generateI2 builds a medium-length CPS template (~60–110 bytes).
func generateI2() string {
	prefix := randomBytes(randInt(5, 15))
	return fmt.Sprintf("<rc %d><b 0x%s><r %d><c><t><rd %d>",
		randInt(3, 8),
		hex.EncodeToString(prefix),
		randInt(20, 50),
		randInt(5, 12))
}

// generateI3 builds a medium-length CPS template (~50–90 bytes).
func generateI3() string {
	prefix := randomBytes(randInt(5, 12))
	return fmt.Sprintf("<rd %d><b 0x%s><rc %d><r %d><t><c>",
		randInt(4, 10),
		hex.EncodeToString(prefix),
		randInt(4, 8),
		randInt(10, 30))
}

// generateI4 builds a shorter CPS template (~50–80 bytes).
func generateI4() string {
	prefix := randomBytes(randInt(4, 10))
	return fmt.Sprintf("<c><t><b 0x%s><r %d><rc %d><rd %d>",
		hex.EncodeToString(prefix),
		randInt(15, 35),
		randInt(5, 10),
		randInt(3, 8))
}

// generateI5 builds the largest non-QUIC CPS template (~300–600 bytes)
// to increase total junk volume before the real handshake.
func generateI5() string {
	prefix := randomBytes(randInt(8, 18))
	return fmt.Sprintf("<b 0x%s><r %d><t><rc %d><c><rd %d>",
		hex.EncodeToString(prefix),
		randInt(300, 500),
		randInt(5, 12),
		randInt(4, 10))
}

// MergeAWGConfig copies non-zero/non-empty fields from src into dst.
// This allows explicit YAML values to override generated defaults.
func MergeAWGConfig(dst, src *AmneziaWGConfig) {
	if src.Jc != 0 {
		dst.Jc = src.Jc
	}
	if src.Jmin != 0 {
		dst.Jmin = src.Jmin
	}
	if src.Jmax != 0 {
		dst.Jmax = src.Jmax
	}
	if src.S1 != 0 {
		dst.S1 = src.S1
	}
	if src.S2 != 0 {
		dst.S2 = src.S2
	}
	if src.S3 != 0 {
		dst.S3 = src.S3
	}
	if src.S4 != 0 {
		dst.S4 = src.S4
	}
	if src.H1 != "" {
		dst.H1 = src.H1
	}
	if src.H2 != "" {
		dst.H2 = src.H2
	}
	if src.H3 != "" {
		dst.H3 = src.H3
	}
	if src.H4 != "" {
		dst.H4 = src.H4
	}
	if src.I1 != "" {
		dst.I1 = src.I1
	}
	if src.I2 != "" {
		dst.I2 = src.I2
	}
	if src.I3 != "" {
		dst.I3 = src.I3
	}
	if src.I4 != "" {
		dst.I4 = src.I4
	}
	if src.I5 != "" {
		dst.I5 = src.I5
	}
}

// randInt returns a cryptographically random int in [min, max].
func randInt(min, max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return min + int(n.Int64())
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return b
}
