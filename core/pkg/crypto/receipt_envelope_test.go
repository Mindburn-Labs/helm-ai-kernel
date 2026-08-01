package crypto

// F-05/F-06 regressions for the v5 receipt envelope.

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func testSigner(t *testing.T) *Ed25519Signer {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	s, err := NewEd25519SignerFromSeed(seed, "test-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

// F-06: the v4 preimage joined fields with a bare ":" and escaped nothing, so
// shifting a colon across a field boundary produced an identical preimage and
// one signature verified two distinct receipts. A JCS object cannot collide
// this way.
func TestF06_FieldBoundaryShiftNoLongerCollides(t *testing.T) {
	a := &contracts.Receipt{ReceiptID: "a", DecisionID: "b:c", EffectID: "e", Status: "OK"}
	b := &contracts.Receipt{ReceiptID: "a:b", DecisionID: "c", EffectID: "e", Status: "OK"}

	if string(ReceiptPreimageV4(a)) != string(ReceiptPreimageV4(b)) {
		t.Fatal("the v4 collision no longer reproduces — this test has stopped " +
			"demonstrating what it claims (negative control)")
	}

	pa, err := ReceiptPreimageV5(a)
	if err != nil {
		t.Fatalf("v5 preimage: %v", err)
	}
	pb, err := ReceiptPreimageV5(b)
	if err != nil {
		t.Fatalf("v5 preimage: %v", err)
	}
	if string(pa) == string(pb) {
		t.Fatalf("two distinct receipts share a v5 preimage — one signature would "+
			"verify both:\n%s", pa)
	}
}

// The signature must not be an input to the value it authenticates.
func TestF05_SignatureItselfIsExcludedFromThePreimage(t *testing.T) {
	r := &contracts.Receipt{ReceiptID: "r", DecisionID: "d", Status: "APPLIED"}
	before, err := ReceiptPreimageV5(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = "abcdef"
	after, err := ReceiptPreimageV5(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the signature field changed its own preimage — verification could never succeed")
	}
}

// Migration: receipts signed under v4 must keep verifying, and be reported as
// legacy so callers can surface them rather than treat them as equivalent.
func TestF05_LegacyV4ReceiptsStillVerifyAndAreReportedAsSuch(t *testing.T) {
	s := testSigner(t)
	r := &contracts.Receipt{
		ReceiptID: "legacy-1", DecisionID: "dec-1", EffectID: "eff-1",
		Status: "APPLIED", OutputHash: "sha256:out", ArgsHash: "sha256:args",
	}
	// Sign the way the pre-change signer did.
	sig, err := s.Sign(ReceiptPreimageV4(r))
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = sig

	ok, version, err := VerifyReceiptSignature(s.PublicKey(), r)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("a v4-signed receipt stopped verifying — the migration is not backward compatible")
	}
	if version != ReceiptPreimageLegacy {
		t.Fatalf("version = %q, want %q: callers cannot flag legacy receipts", version, ReceiptPreimageLegacy)
	}
}
