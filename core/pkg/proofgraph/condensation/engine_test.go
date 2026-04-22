package condensation

import (
	"testing"
	"time"
)

func TestAccumulateAndCheckpoint(t *testing.T) {
	e := NewEngine()

	// Accumulate 4 receipts
	for i := 0; i < 4; i++ {
		e.Accumulate(Receipt{
			ID:       "r" + string(rune('0'+i)),
			Hash:     hashString("receipt-" + string(rune('0'+i))),
			RiskTier: RiskLow,
		})
	}

	if e.AccumulatedCount() != 4 {
		t.Fatalf("expected 4 accumulated, got %d", e.AccumulatedCount())
	}

	cp, err := e.CreateCheckpoint(1, 4)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	if cp.MerkleRoot == "" {
		t.Fatal("expected non-empty Merkle root")
	}
	if cp.LeafCount != 4 {
		t.Fatalf("expected 4 leaves, got %d", cp.LeafCount)
	}
	if e.AccumulatedCount() != 0 {
		t.Fatal("accumulator should be reset after checkpoint")
	}
}

func TestCheckpointEmpty(t *testing.T) {
	e := NewEngine()
	_, err := e.CreateCheckpoint(0, 0)
	if err != ErrEmptyReceipts {
		t.Fatalf("expected ErrEmptyReceipts, got %v", err)
	}
}

func TestInclusionProofVerification(t *testing.T) {
	e := NewEngine()

	receipts := []Receipt{
		{ID: "r0", Hash: hashString("data-0"), RiskTier: RiskLow},
		{ID: "r1", Hash: hashString("data-1"), RiskTier: RiskMedium},
		{ID: "r2", Hash: hashString("data-2"), RiskTier: RiskLow},
		{ID: "r3", Hash: hashString("data-3"), RiskTier: RiskHigh},
	}
	for _, r := range receipts {
		e.Accumulate(r)
	}

	_, err := e.CreateCheckpoint(10, 13)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	// Verify inclusion proofs for all receipts
	for _, r := range receipts {
		proof, err := e.GetProof(r.ID)
		if err != nil {
			t.Fatalf("get proof %s: %v", r.ID, err)
		}

		valid, err := VerifyInclusion(proof)
		if err != nil {
			t.Fatalf("verify %s: %v", r.ID, err)
		}
		if !valid {
			t.Fatalf("inclusion proof invalid for %s", r.ID)
		}
	}
}

func TestInclusionProofTampered(t *testing.T) {
	e := NewEngine()
	e.Accumulate(Receipt{ID: "r0", Hash: hashString("data"), RiskTier: RiskLow})
	e.Accumulate(Receipt{ID: "r1", Hash: hashString("data2"), RiskTier: RiskLow})

	_, err := e.CreateCheckpoint(1, 2)
	if err != nil {
		t.Fatal(err)
	}

	proof, _ := e.GetProof("r0")

	// Tamper with receipt hash
	tampered := *proof
	tampered.ReceiptHash = hashString("tampered")

	valid, err := VerifyInclusion(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("tampered proof should not verify")
	}
}

func TestCondense(t *testing.T) {
	e := NewEngine()
	e.Accumulate(Receipt{ID: "r0", Hash: hashString("data"), RiskTier: RiskLow})
	e.Accumulate(Receipt{ID: "r1", Hash: hashString("data2"), RiskTier: RiskLow})

	_, err := e.CreateCheckpoint(1, 2)
	if err != nil {
		t.Fatal(err)
	}

	condensed, err := e.Condense("r0")
	if err != nil {
		t.Fatalf("condense: %v", err)
	}
	if condensed.OriginalID != "r0" {
		t.Fatalf("expected r0, got %s", condensed.OriginalID)
	}
	if condensed.Proof == nil {
		t.Fatal("expected non-nil proof")
	}

	// Verify the condensed proof
	valid, _ := VerifyInclusion(condensed.Proof)
	if !valid {
		t.Fatal("condensed proof should verify")
	}
}

func TestCondenseNotFound(t *testing.T) {
	e := NewEngine()
	_, err := e.Condense("nonexistent")
	if err != ErrReceiptNotFound {
		t.Fatalf("expected ErrReceiptNotFound, got %v", err)
	}
}

func TestVerifyCheckpoint(t *testing.T) {
	e := NewEngine()

	hashes := []string{
		hashString("a"),
		hashString("b"),
		hashString("c"),
	}
	for i, h := range hashes {
		e.Accumulate(Receipt{ID: "r" + string(rune('0'+i)), Hash: h, RiskTier: RiskLow})
	}

	cp, _ := e.CreateCheckpoint(1, 3)

	valid, err := VerifyCheckpoint(cp, hashes)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("checkpoint should verify")
	}

	// Wrong hashes
	valid, _ = VerifyCheckpoint(cp, []string{hashString("x"), hashString("y"), hashString("z")})
	if valid {
		t.Fatal("checkpoint should not verify with wrong hashes")
	}
}

func TestVerifyInclusionNil(t *testing.T) {
	_, err := VerifyInclusion(nil)
	if err != ErrInvalidProof {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}

func TestSingleLeafCheckpoint(t *testing.T) {
	e := NewEngine()
	e.Accumulate(Receipt{ID: "solo", Hash: hashString("only"), RiskTier: RiskLow})

	cp, err := e.CreateCheckpoint(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LeafCount != 1 {
		t.Fatalf("expected 1 leaf, got %d", cp.LeafCount)
	}

	proof, _ := e.GetProof("solo")
	valid, _ := VerifyInclusion(proof)
	if !valid {
		t.Fatal("single-leaf proof should verify")
	}
}

func TestMerkleRootDeterminism(t *testing.T) {
	leaves := []string{hashString("a"), hashString("b"), hashString("c"), hashString("d")}
	r1 := computeMerkleRoot(leaves)
	r2 := computeMerkleRoot(leaves)
	if r1 != r2 {
		t.Fatalf("Merkle root not deterministic: %q vs %q", r1, r2)
	}
}

func TestOddLeafCount(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 5; i++ {
		e.Accumulate(Receipt{
			ID:       "r" + string(rune('0'+i)),
			Hash:     hashString("data-" + string(rune('0'+i))),
			RiskTier: RiskLow,
		})
	}

	cp, err := e.CreateCheckpoint(1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LeafCount != 5 {
		t.Fatalf("expected 5 leaves, got %d", cp.LeafCount)
	}

	// Verify all proofs for odd-count tree
	for i := 0; i < 5; i++ {
		proof, _ := e.GetProof("r" + string(rune('0'+i)))
		valid, err := VerifyInclusion(proof)
		if err != nil {
			t.Fatalf("verify r%d: %v", i, err)
		}
		if !valid {
			t.Fatalf("proof invalid for r%d in odd-leaf tree", i)
		}
	}
}

func TestCheckpointUsesInjectedClock(t *testing.T) {
	ts := time.Date(2026, 3, 8, 17, 0, 0, 0, time.UTC)
	e := NewEngine().WithClock(func() time.Time { return ts })
	e.Accumulate(Receipt{ID: "r0", Hash: hashString("data"), RiskTier: RiskLow})

	cp, err := e.CreateCheckpoint(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !cp.CreatedAt.Equal(ts) {
		t.Fatalf("created_at = %v, want %v", cp.CreatedAt, ts)
	}
}

func TestCheckpointDuplicateRejected(t *testing.T) {
	e := NewEngine()
	first := []Receipt{
		{ID: "r0", Hash: hashString("data-0"), RiskTier: RiskLow},
		{ID: "r1", Hash: hashString("data-1"), RiskTier: RiskLow},
	}
	for _, r := range first {
		e.Accumulate(r)
	}
	if _, err := e.CreateCheckpoint(1, 2); err != nil {
		t.Fatalf("first checkpoint failed: %v", err)
	}

	for _, r := range first {
		e.Accumulate(r)
	}
	if _, err := e.CreateCheckpoint(1, 2); err != ErrCheckpointExists {
		t.Fatalf("expected ErrCheckpointExists, got %v", err)
	}
}
