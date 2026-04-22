package kernel

import (
	"testing"
)

func TestDeterministicPRNGSeed(t *testing.T) {
	config := PRNGConfig{
		Algorithm:   PRNGAlgorithmHMACSHA256,
		SeedLength:  32,
		Derivation:  SeedDerivationLoopID,
		RecordToLog: false,
	}

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	prng, err := NewDeterministicPRNG(config, seed, "loop-1", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Seed should return hex encoded seed
	s := prng.Seed()
	if len(s) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Seed length = %d, want 64", len(s))
	}
}

func TestDeterministicPRNGLoopID(t *testing.T) {
	config := DefaultPRNGConfig()
	config.RecordToLog = false

	seed := make([]byte, 32)
	prng, _ := NewDeterministicPRNG(config, seed, "my-loop", nil)

	if prng.LoopID() != "my-loop" {
		t.Errorf("LoopID() = %q, want my-loop", prng.LoopID())
	}
}

func TestDeterministicPRNGFloat64(t *testing.T) {
	config := DefaultPRNGConfig()
	config.RecordToLog = false

	seed := make([]byte, 32)
	prng, _ := NewDeterministicPRNG(config, seed, "test", nil)

	f := prng.Float64()
	if f < 0 || f >= 1 {
		t.Errorf("Float64() = %f, want [0, 1)", f)
	}
}

func TestDeterministicPRNGIntn(t *testing.T) {
	config := DefaultPRNGConfig()
	config.RecordToLog = false

	seed := make([]byte, 32)
	prng, _ := NewDeterministicPRNG(config, seed, "test", nil)

	// n <= 0 returns 0
	if prng.Intn(0) != 0 {
		t.Error("Intn(0) should return 0")
	}
	if prng.Intn(-5) != 0 {
		t.Error("Intn(-5) should return 0")
	}

	// n > 0 returns [0, n)
	n := prng.Intn(100)
	if n < 0 || n >= 100 {
		t.Errorf("Intn(100) = %d, want [0, 100)", n)
	}
}

func TestDeterministicPRNGBytes(t *testing.T) {
	config := DefaultPRNGConfig()
	config.RecordToLog = false

	seed := make([]byte, 32)
	prng, _ := NewDeterministicPRNG(config, seed, "test", nil)

	b := prng.Bytes(16)
	if len(b) != 16 {
		t.Errorf("Bytes(16) length = %d, want 16", len(b))
	}

	// Different call should produce different bytes
	b2 := prng.Bytes(16)
	same := true
	for i := range b {
		if b[i] != b2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Bytes should produce different values on each call")
	}
}

func TestNewDeterministicPRNGInvalidSeedLength(t *testing.T) {
	config := PRNGConfig{
		Algorithm:  PRNGAlgorithmHMACSHA256,
		SeedLength: 32,
	}

	seed := make([]byte, 16) // wrong size
	_, err := NewDeterministicPRNG(config, seed, "test", nil)
	if err == nil {
		t.Error("Should error on invalid seed length")
	}
}

func TestDeriveSeed(t *testing.T) {
	parent := make([]byte, 32)
	for i := range parent {
		parent[i] = byte(i)
	}

	child1 := DeriveSeed(parent, "child-1")
	child2 := DeriveSeed(parent, "child-2")

	if len(child1) != 32 {
		t.Errorf("DeriveSeed length = %d, want 32", len(child1))
	}

	// Different inputs should produce different seeds
	same := true
	for i := range child1 {
		if child1[i] != child2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Different derivation inputs should produce different seeds")
	}
}

func TestSeedFromLoopID(t *testing.T) {
	root := make([]byte, 32)
	seed := SeedFromLoopID(root, "loop-123")
	if len(seed) != 32 {
		t.Errorf("SeedFromLoopID length = %d, want 32", len(seed))
	}
}
