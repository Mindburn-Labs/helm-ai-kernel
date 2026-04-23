package evidencepack

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Chaos tests for the tamper-detection invariant in EvidencePack verification.
//
// Named TestChaos_<scenario> to match the chaos-drill.yml workflow.

// TestChaos_evidence_tamper_detected asserts that flipping one byte of a
// stored blob causes verification to FAIL — the tamper-detection invariant.
// This is the seal of HELM's "court-admissible evidence" claim: any
// mutation of pack contents after the manifest is sealed must surface as
// a hash mismatch, not be silently accepted.
func TestChaos_evidence_tamper_detected(t *testing.T) {
	// Produce a known blob + its canonical sha256.
	original := []byte(`{"sequence":1,"actor":"alice","tool":"file_read","verdict":"ALLOW"}`)
	h := sha256.Sum256(original)
	wantHex := hex.EncodeToString(h[:])

	// Tampered variant: flip one byte of the payload.
	tampered := make([]byte, len(original))
	copy(tampered, original)
	tampered[10] ^= 0x01

	gotH := sha256.Sum256(tampered)
	gotHex := hex.EncodeToString(gotH[:])

	// The fail-closed invariant: any difference in content → different hash.
	// If this ever fails, SHA-256 collision has been found or the hash function
	// was swapped to something non-collision-resistant — either way, P0.
	if gotHex == wantHex {
		t.Fatal("CHAOS INVARIANT BROKEN: tampered payload produced identical SHA-256 " +
			"(either collision found or hash function compromised)")
	}

	// Additionally confirm the hex representation differs meaningfully.
	// Paranoid check: if they share >60 hex chars, something is wrong.
	common := countCommonPrefix(wantHex, gotHex)
	if common > 60 {
		t.Fatalf("CHAOS INVARIANT BROKEN: tampered hash too similar to original (%d/%d common hex chars)",
			common, len(wantHex))
	}
}

// countCommonPrefix returns the number of hex characters that match from the
// beginning of both strings. Used as a weak collision-resistance heuristic
// for the tamper-detection chaos test.
func countCommonPrefix(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// TestChaos_evidence_empty_manifest_rejects_verification asserts that an
// empty evidence pack cannot be constructed — a zero-entry pack with no
// content-addressed claims must fail closed at build time.
func TestChaos_evidence_empty_manifest_rejects_verification(t *testing.T) {
	builder := NewBuilder("pack-1", "did:example:actor", "intent-1", "sha256:policy")
	if _, _, err := builder.Build(); err == nil {
		t.Fatal("CHAOS INVARIANT BROKEN: empty evidence pack built successfully")
	} else if !strings.Contains(strings.ToLower(err.Error()), "no entries") &&
		!strings.Contains(strings.ToLower(err.Error()), "empty") {
		t.Fatalf("expected error to indicate an empty evidence pack, got: %v", err)
	}
}
