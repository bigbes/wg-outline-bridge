package config

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateAWGDefaults_Ranges(t *testing.T) {
	for range 50 {
		cfg := GenerateAWGDefaults()

		if cfg.Jc < 4 || cfg.Jc > 8 {
			t.Errorf("Jc=%d out of range [4,8]", cfg.Jc)
		}
		if cfg.Jmin < 200 || cfg.Jmin > 400 {
			t.Errorf("Jmin=%d out of range [200,400]", cfg.Jmin)
		}
		if cfg.Jmax < 800 || cfg.Jmax > 1100 {
			t.Errorf("Jmax=%d out of range [800,1100]", cfg.Jmax)
		}
		if cfg.S1 < 50 || cfg.S1 > 150 {
			t.Errorf("S1=%d out of range [50,150]", cfg.S1)
		}
		if cfg.S2 < 30 || cfg.S2 > 70 {
			t.Errorf("S2=%d out of range [30,70]", cfg.S2)
		}
		if cfg.S3 < 30 || cfg.S3 > 70 {
			t.Errorf("S3=%d out of range [30,70]", cfg.S3)
		}
		if cfg.S4 < 15 || cfg.S4 > 40 {
			t.Errorf("S4=%d out of range [15,40]", cfg.S4)
		}

		// H params should be non-empty ranges.
		for _, h := range []string{cfg.H1, cfg.H2, cfg.H3, cfg.H4} {
			if !strings.Contains(h, "-") {
				t.Errorf("H param %q should contain a range separator", h)
			}
		}

		// All I1-I5 must be non-empty.
		for i, tmpl := range []string{cfg.I1, cfg.I2, cfg.I3, cfg.I4, cfg.I5} {
			if tmpl == "" {
				t.Errorf("I%d must not be empty", i+1)
			}
		}
	}
}

func TestGenerateAWGDefaults_I1QUICHeader(t *testing.T) {
	for range 50 {
		cfg := GenerateAWGDefaults()

		// I1 should start with QUIC v1 long header binary prefix.
		if !strings.HasPrefix(cfg.I1, "<b 0xc000000001") {
			t.Errorf("I1 should start with QUIC v1 header: %s", cfg.I1)
		}

		// Extract the binary prefix hex to verify structure.
		hexStr := extractBinaryHex(cfg.I1)
		if hexStr == "" {
			t.Fatalf("could not extract binary hex from I1: %s", cfg.I1)
		}
		raw, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Fatalf("invalid hex in I1: %v", err)
		}
		// Minimum: 5 (QUIC header) + 1 (DCID len) + 20 (fake header) = 26 bytes.
		if len(raw) < 26 {
			t.Errorf("I1 binary prefix too short: %d bytes", len(raw))
		}

		// DCID len (byte 5) must be > 20 to prevent
		// UDP mux from classifying CPS packet as real QUIC.
		dcidLen := raw[5]
		if dcidLen <= 20 {
			t.Errorf("I1 DCID len=%d, must be > 20", dcidLen)
		}
	}
}

func TestGenerateAWGDefaults_TemplateDirectives(t *testing.T) {
	cfg := GenerateAWGDefaults()

	// I1 should contain <c>, <t>, <r N>, <rc N>.
	for _, d := range []string{"<c>", "<t>", "<r ", "<rc "} {
		if !strings.Contains(cfg.I1, d) {
			t.Errorf("I1 missing directive %q: %s", d, cfg.I1)
		}
	}

	// Each of I2-I5 should contain <c> and <t>.
	for i, tmpl := range []string{cfg.I2, cfg.I3, cfg.I4, cfg.I5} {
		if !strings.Contains(tmpl, "<c>") {
			t.Errorf("I%d missing <c>: %s", i+2, tmpl)
		}
		if !strings.Contains(tmpl, "<t>") {
			t.Errorf("I%d missing <t>: %s", i+2, tmpl)
		}
	}
}

func TestGenerateAWGDefaults_UniquePerCall(t *testing.T) {
	a := GenerateAWGDefaults()
	b := GenerateAWGDefaults()

	// Binary prefixes should differ between calls (randomized per server).
	if a.I1 == b.I1 {
		t.Error("two calls produced identical I1 — binary prefix should be randomized")
	}
	if a.H1 == b.H1 && a.H2 == b.H2 && a.H3 == b.H3 && a.H4 == b.H4 {
		t.Error("two calls produced identical H1-H4 — very unlikely with random generation")
	}
}

func TestMergeAWGConfig(t *testing.T) {
	dst := &AmneziaWGConfig{
		Jc:   5,
		Jmin: 300,
		Jmax: 900,
		S1:   100,
		S2:   50,
		H1:   "1500000000-1500010000",
		H2:   "1600000000-1600010000",
		H3:   "1700000000-1700010000",
		H4:   "1800000000-1800010000",
		I1:   "<b 0xc000000001ff><rc 20><c><t><r 900>",
		I2:   "<rc 5><b 0xaabb><r 30><c><t><rd 8>",
	}

	src := &AmneziaWGConfig{
		Jc: 10,             // override
		H1: "999-1000",     // override
		I1: "<b 0xcustom>", // override
	}

	MergeAWGConfig(dst, src)

	if dst.Jc != 10 {
		t.Errorf("Jc=%d, want 10", dst.Jc)
	}
	if dst.Jmin != 300 {
		t.Errorf("Jmin=%d, want 300 (unchanged)", dst.Jmin)
	}
	if dst.H1 != "999-1000" {
		t.Errorf("H1=%s, want 999-1000", dst.H1)
	}
	if dst.H2 != "1600000000-1600010000" {
		t.Errorf("H2=%s, want unchanged", dst.H2)
	}
	if dst.I1 != "<b 0xcustom>" {
		t.Errorf("I1=%s, want <b 0xcustom>", dst.I1)
	}
	if dst.I2 != "<rc 5><b 0xaabb><r 30><c><t><rd 8>" {
		t.Errorf("I2=%s, want unchanged", dst.I2)
	}
}

// extractBinaryHex extracts the hex string from the first <b 0x...> directive.
func extractBinaryHex(tmpl string) string {
	const prefix = "<b 0x"
	idx := strings.Index(tmpl, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := strings.Index(tmpl[start:], ">")
	if end < 0 {
		return ""
	}
	return tmpl[start : start+end]
}
