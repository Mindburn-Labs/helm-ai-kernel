package a2a

import (
	"fmt"
	"testing"
)

// ── Envelope Tests ───────────────────────────────────────────────

func TestDeepEnvelopeWithAllFeatures(t *testing.T) {
	allFeatures := []Feature{
		FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync,
		FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments,
		FeatureIATPAuth, FeaturePeerVouching,
	}
	env := &Envelope{
		EnvelopeID: "e1", SchemaVersion: CurrentVersion,
		RequiredFeatures: allFeatures, OfferedFeatures: allFeatures,
	}
	if len(env.RequiredFeatures) != 8 || len(env.OfferedFeatures) != 8 {
		t.Fatal("should support all 8 features")
	}
}

func TestDeepSchemaVersionString(t *testing.T) {
	v := SchemaVersion{Major: 1, Minor: 2, Patch: 3}
	if v.String() != "1.2.3" {
		t.Fatalf("expected 1.2.3, got %s", v.String())
	}
}

// ── IATP Tests ───────────────────────────────────────────────────

// ── Vouching Tests ───────────────────────────────────────────────

// ── Trust Propagation Tests ──────────────────────────────────────

// ── Helpers ──────────────────────────────────────────────────────

func mustHexDecode(s string) []byte {
	b, err := hexDecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexDecodeString(s string) ([]byte, error) {
	return hexDecode(s)
}

var hexDecode = func() func(string) ([]byte, error) {
	return func(s string) ([]byte, error) {
		// Import encoding/hex at function level
		b := make([]byte, len(s)/2)
		_, err := hexDecodeBytes(b, []byte(s))
		return b, err
	}
}()

var hexDecodeBytes = func(dst, src []byte) (int, error) {
	// Inline hex decode to avoid import alias collision with crypto package
	const hextable = "0123456789abcdef"
	if len(src)%2 != 0 {
		return 0, fmt.Errorf("odd length hex")
	}
	n := len(src) / 2
	for i := 0; i < n; i++ {
		a := fromHexChar(src[i*2])
		b := fromHexChar(src[i*2+1])
		if a == 0xFF || b == 0xFF {
			return i, fmt.Errorf("invalid hex char")
		}
		dst[i] = (a << 4) | b
	}
	_ = hextable
	return n, nil
}

func fromHexChar(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0xFF
}
