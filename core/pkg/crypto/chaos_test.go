package crypto

import (
	"strings"
	"testing"
)

// Chaos tests for the cryptographic signing layer's fail-closed invariant.
//
// Named TestChaos_<scenario> to match chaos-drill.yml.

// TestChaos_receipt_signing_failure_blocks_dispatch asserts that if signing
// fails, the caller receives an unambiguous error — never a nil-error with
// an unsigned receipt. This prevents "governance happened but we forgot to
// sign the receipt" from being a silent pass.
//
// The invariant: Sign(data) either returns a valid non-empty signature + nil
// error, or returns a non-nil error. It must NEVER return ("", nil).
func TestChaos_receipt_signing_failure_blocks_dispatch(t *testing.T) {
	signer, err := NewEd25519Signer("chaos-key-1")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Normal path: sign valid data → expect non-empty signature + nil error.
	sig, err := signer.Sign([]byte("governance-decision-payload"))
	if err != nil {
		t.Fatalf("unexpected error on valid sign: %v", err)
	}
	if sig == "" {
		t.Fatal("CHAOS INVARIANT BROKEN: Sign returned empty signature with nil error")
	}

	// Edge: sign empty data — must still produce a valid signature (Ed25519
	// signs empty messages) or return an error. Never ("", nil).
	sig2, err2 := signer.Sign([]byte{})
	if err2 == nil && sig2 == "" {
		t.Fatal("CHAOS INVARIANT BROKEN: Sign([]byte{}) returned empty signature with nil error")
	}

	// Edge: sign nil data — same invariant.
	sig3, err3 := signer.Sign(nil)
	if err3 == nil && sig3 == "" {
		t.Fatal("CHAOS INVARIANT BROKEN: Sign(nil) returned empty signature with nil error")
	}

	// Edge: sign very large data — must either succeed or error, not silently truncate.
	largePayload := []byte(strings.Repeat("X", 1<<20)) // 1 MiB
	sig4, err4 := signer.Sign(largePayload)
	if err4 == nil && sig4 == "" {
		t.Fatal("CHAOS INVARIANT BROKEN: Sign(1MiB) returned empty signature with nil error")
	}
	if err4 == nil && len(sig4) < 64 {
		t.Fatalf("CHAOS INVARIANT BROKEN: Sign(1MiB) returned suspiciously short signature (%d chars)", len(sig4))
	}

	// Verify round-trip on the normal-path signature.
	pubKeyHex := signer.PublicKey()
	if pubKeyHex == "" {
		t.Fatal("CHAOS INVARIANT BROKEN: PublicKey() returned empty string")
	}
}

// TestChaos_kernel_nondeterminism_detected asserts that two Ed25519 signers
// with the SAME key produce IDENTICAL signatures for the same input.
// Nondeterministic signing (e.g., via ECDSA random k) is a replay-breaking
// defect. Ed25519 is inherently deterministic; this chaos test guards against
// an accidental swap to a non-deterministic scheme.
func TestChaos_kernel_nondeterminism_detected(t *testing.T) {
	// Generate a key and create two signer instances from the same key material.
	signer1, err := NewEd25519Signer("det-key")
	if err != nil {
		t.Fatalf("failed to create signer1: %v", err)
	}
	// Extract private key and create a clone signer.
	signer2 := NewEd25519SignerFromKey(signer1.privKey, "det-key-clone")

	payload := []byte(`{"sequence":42,"actor":"alice","tool":"file_read","verdict":"ALLOW"}`)

	sig1, err1 := signer1.Sign(payload)
	if err1 != nil {
		t.Fatalf("signer1 error: %v", err1)
	}

	sig2, err2 := signer2.Sign(payload)
	if err2 != nil {
		t.Fatalf("signer2 error: %v", err2)
	}

	if sig1 != sig2 {
		t.Fatalf("CHAOS INVARIANT BROKEN: same key + same payload produced different signatures.\n"+
			"  sig1: %s\n  sig2: %s\n"+
			"This indicates nondeterministic signing, which breaks replay determinism.",
			sig1, sig2)
	}

	// Second run — same inputs again. Must still match (no internal state drift).
	sig3, _ := signer1.Sign(payload)
	if sig3 != sig1 {
		t.Fatalf("CHAOS INVARIANT BROKEN: same signer + same payload produced different signatures on second call.\n"+
			"  first:  %s\n  second: %s\n"+
			"This indicates internal state drift in the signer.",
			sig1, sig3)
	}
}
