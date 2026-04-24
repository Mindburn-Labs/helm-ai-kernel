package condensation

import (
	"testing"
	"time"
)

// ── Engine Basics ───────────────────────────────────────────────

func TestNewEngine_EmptyState(t *testing.T) {
	e := NewEngine()
	if e.AccumulatedCount() != 0 {
		t.Error("new engine should have 0 accumulated")
	}
}

func TestEngine_Accumulate(t *testing.T) {
	e := NewEngine()
	e.Accumulate(Receipt{ID: "r1", Hash: hashString("data1")})
	e.Accumulate(Receipt{ID: "r2", Hash: hashString("data2")})
	if e.AccumulatedCount() != 2 {
		t.Errorf("expected 2, got %d", e.AccumulatedCount())
	}
}

func TestEngine_CreateCheckpoint_Empty(t *testing.T) {
	e := NewEngine()
	_, err := e.CreateCheckpoint(0, 10)
	if err != ErrEmptyReceipts {
		t.Errorf("expected ErrEmptyReceipts, got %v", err)
	}
}

func TestEngine_CreateCheckpoint_ProducesRoot(t *testing.T) {
	e := NewEngine()
	e.Accumulate(Receipt{ID: "r1", Hash: hashString("a")})
	e.Accumulate(Receipt{ID: "r2", Hash: hashString("b")})
	cp, err := e.CreateCheckpoint(1, 10)
	if err != nil {
		t.Fatalf("CreateCheckpoint: %v", err)
	}
	if cp.MerkleRoot == "" {
		t.Error("checkpoint should have non-empty merkle root")
	}
	if cp.LeafCount != 2 {
		t.Errorf("expected 2 leaves, got %d", cp.LeafCount)
	}
}

func TestEngine_CreateCheckpoint_ResetsAccumulator(t *testing.T) {
	e := NewEngine()
	e.Accumulate(Receipt{ID: "r1", Hash: hashString("x")})
	_, _ = e.CreateCheckpoint(0, 5)
	if e.AccumulatedCount() != 0 {
		t.Error("accumulator should be reset after checkpoint")
	}
}

func TestEngine_WithClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := NewEngine().WithClock(func() time.Time { return fixed })
	e.Accumulate(Receipt{ID: "r1", Hash: hashString("a")})
	cp, _ := e.CreateCheckpoint(0, 1)
	if !cp.CreatedAt.Equal(fixed) {
		t.Errorf("expected fixed time, got %v", cp.CreatedAt)
	}
}

// ── Proofs ──────────────────────────────────────────────────────

func TestEngine_GetProof_AfterCheckpoint(t *testing.T) {
	e := NewEngine()
	e.Accumulate(Receipt{ID: "r1", Hash: hashString("a")})
	e.Accumulate(Receipt{ID: "r2", Hash: hashString("b")})
	_, _ = e.CreateCheckpoint(0, 5)
	proof, err := e.GetProof("r1")
	if err != nil {
		t.Fatalf("GetProof: %v", err)
	}
	if proof.ReceiptID != "r1" {
		t.Errorf("expected r1, got %s", proof.ReceiptID)
	}
}

func TestEngine_GetProof_NotFound(t *testing.T) {
	e := NewEngine()
	_, err := e.GetProof("nonexistent")
	if err != ErrReceiptNotFound {
		t.Errorf("expected ErrReceiptNotFound, got %v", err)
	}
}

// ── Condense ────────────────────────────────────────────────────

func TestEngine_Condense(t *testing.T) {
	e := NewEngine()
	e.Accumulate(Receipt{ID: "r1", Hash: hashString("data"), RiskTier: RiskLow})
	_, _ = e.CreateCheckpoint(0, 1)
	condensed, err := e.Condense("r1")
	if err != nil {
		t.Fatalf("Condense: %v", err)
	}
	if condensed.OriginalID != "r1" {
		t.Errorf("expected original ID r1, got %s", condensed.OriginalID)
	}
	if condensed.Proof == nil {
		t.Error("condensed receipt should have proof")
	}
}

// ── Verification ────────────────────────────────────────────────

func TestVerifyInclusion_SingleReceipt(t *testing.T) {
	e := NewEngine()
	h := hashString("only")
	e.Accumulate(Receipt{ID: "r1", Hash: h})
	_, _ = e.CreateCheckpoint(0, 1)
	proof, _ := e.GetProof("r1")
	valid, err := VerifyInclusion(proof)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if !valid {
		t.Error("inclusion proof should be valid")
	}
}

func TestVerifyInclusion_NilProof(t *testing.T) {
	_, err := VerifyInclusion(nil)
	if err != ErrInvalidProof {
		t.Errorf("expected ErrInvalidProof, got %v", err)
	}
}

func TestVerifyCheckpoint_Valid(t *testing.T) {
	e := NewEngine()
	h1, h2 := hashString("a"), hashString("b")
	e.Accumulate(Receipt{ID: "r1", Hash: h1})
	e.Accumulate(Receipt{ID: "r2", Hash: h2})
	cp, _ := e.CreateCheckpoint(0, 5)
	valid, err := VerifyCheckpoint(cp, []string{h1, h2})
	if err != nil {
		t.Fatalf("VerifyCheckpoint: %v", err)
	}
	if !valid {
		t.Error("checkpoint should verify against original hashes")
	}
}

func TestVerifyCheckpoint_WrongCount(t *testing.T) {
	cp := &Checkpoint{LeafCount: 3, MerkleRoot: "root"}
	_, err := VerifyCheckpoint(cp, []string{"a", "b"})
	if err == nil {
		t.Error("should reject mismatched count")
	}
}

func TestVerifyCheckpoint_NilCheckpoint(t *testing.T) {
	_, err := VerifyCheckpoint(nil, []string{"a"})
	if err != ErrEmptyReceipts {
		t.Errorf("expected ErrEmptyReceipts, got %v", err)
	}
}

// ── Merkle Helpers ──────────────────────────────────────────────

func TestComputeMerkleRoot_Deterministic(t *testing.T) {
	leaves := []string{hashString("x"), hashString("y"), hashString("z")}
	r1 := computeMerkleRoot(leaves)
	r2 := computeMerkleRoot(leaves)
	if r1 != r2 {
		t.Error("merkle root should be deterministic")
	}
}
