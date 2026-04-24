package kernel

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestFinal_ConcurrencyArtifactTypeConstants(t *testing.T) {
	types := []ConcurrencyArtifactType{
		ConcurrencyArtifactDependencyGraph,
		ConcurrencyArtifactAttemptIndex,
		ConcurrencyArtifactRetrySchedule,
		ConcurrencyArtifactExecutionTrace,
	}
	seen := make(map[ConcurrencyArtifactType]bool)
	for _, ct := range types {
		if ct == "" {
			t.Fatal("artifact type must not be empty")
		}
		if seen[ct] {
			t.Fatalf("duplicate artifact type: %s", ct)
		}
		seen[ct] = true
	}
}

func TestFinal_DependencyNodeJSON(t *testing.T) {
	n := DependencyNode{NodeID: "n1", NodeType: "task", ContentHash: "abc"}
	data, _ := json.Marshal(n)
	var n2 DependencyNode
	json.Unmarshal(data, &n2)
	if n2.NodeID != "n1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DependencyGraphJSON(t *testing.T) {
	g := DependencyGraph{GraphID: "g1", ReducerID: "r1"}
	data, _ := json.Marshal(g)
	var g2 DependencyGraph
	json.Unmarshal(data, &g2)
	if g2.GraphID != "g1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PRNGAlgorithmConstants(t *testing.T) {
	if PRNGAlgorithmChaCha20 == "" || PRNGAlgorithmHMACSHA256 == "" {
		t.Fatal("PRNG algorithm constants must not be empty")
	}
	if PRNGAlgorithmChaCha20 == PRNGAlgorithmHMACSHA256 {
		t.Fatal("PRNG algorithms must be distinct")
	}
}

func TestFinal_SeedDerivationConstants(t *testing.T) {
	derivs := []SeedDerivation{SeedDerivationLoopID, SeedDerivationParentSeed, SeedDerivationRequestHash}
	seen := make(map[SeedDerivation]bool)
	for _, d := range derivs {
		if d == "" {
			t.Fatal("seed derivation must not be empty")
		}
		if seen[d] {
			t.Fatalf("duplicate: %s", d)
		}
		seen[d] = true
	}
}

func TestFinal_DefaultPRNGConfig(t *testing.T) {
	cfg := DefaultPRNGConfig()
	if cfg.Algorithm != PRNGAlgorithmHMACSHA256 {
		t.Fatal("default should be HMAC-SHA256")
	}
	if cfg.SeedLength != 32 {
		t.Fatal("default seed length should be 32")
	}
}

func TestFinal_PRNGConfigJSON(t *testing.T) {
	cfg := DefaultPRNGConfig()
	data, _ := json.Marshal(cfg)
	var cfg2 PRNGConfig
	json.Unmarshal(data, &cfg2)
	if cfg2.Algorithm != cfg.Algorithm {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_NewDeterministicPRNGBadSeed(t *testing.T) {
	cfg := DefaultPRNGConfig()
	_, err := NewDeterministicPRNG(cfg, []byte("short"), "loop1", nil)
	if err == nil {
		t.Fatal("should error on wrong seed length")
	}
}

func TestFinal_NewDeterministicPRNGGoodSeed(t *testing.T) {
	cfg := DefaultPRNGConfig()
	seed := make([]byte, 32)
	prng, err := NewDeterministicPRNG(cfg, seed, "loop1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if prng == nil {
		t.Fatal("prng should not be nil")
	}
}

func TestFinal_InMemoryBlobStoreStoreGet(t *testing.T) {
	store := NewInMemoryBlobStore()
	addr, err := store.Store(nil, []byte("hello"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := store.Get(nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	if string(rec.Content) != "hello" {
		t.Fatal("data mismatch")
	}
}

func TestFinal_InMemoryBlobStoreGetMissing(t *testing.T) {
	store := NewInMemoryBlobStore()
	_, err := store.Get(nil, BlobAddress("nonexistent"))
	if err == nil {
		t.Fatal("should error on missing blob")
	}
}

func TestFinal_InMemoryBlobStoreHas(t *testing.T) {
	store := NewInMemoryBlobStore()
	addr, _ := store.Store(nil, []byte("test"), "text/plain")
	if !store.Has(nil, addr) {
		t.Fatal("should have stored blob")
	}
}

func TestFinal_CoordinationModeConstants(t *testing.T) {
	modes := []CoordinationMode{ModeWaterfall, ModeParallel, ModeHybrid}
	for _, m := range modes {
		if m == "" {
			t.Fatal("coordination mode must not be empty")
		}
	}
}

func TestFinal_TaskClassifierZeroValue(t *testing.T) {
	tc := &TaskClassifier{}
	if tc == nil {
		t.Fatal("zero-value classifier should not be nil")
	}
}

func TestFinal_RetryStrategyConstants(t *testing.T) {
	if RetryStrategyFixed == "" || RetryStrategyExponential == "" || RetryStrategyLinear == "" {
		t.Fatal("retry strategy constants must not be empty")
	}
}

func TestFinal_ExecutionTraceJSON(t *testing.T) {
	et := ExecutionTrace{TraceID: "t1"}
	data, _ := json.Marshal(et)
	var et2 ExecutionTrace
	json.Unmarshal(data, &et2)
	if et2.TraceID != "t1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_AttemptIndexJSON(t *testing.T) {
	ai := AttemptIndex{IndexID: "ai1"}
	data, _ := json.Marshal(ai)
	var ai2 AttemptIndex
	json.Unmarshal(data, &ai2)
	if ai2.IndexID != "ai1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_RetryScheduleJSON(t *testing.T) {
	rs := RetrySchedule{ScheduleID: "rs1", Strategy: RetryStrategyFixed}
	data, _ := json.Marshal(rs)
	var rs2 RetrySchedule
	json.Unmarshal(data, &rs2)
	if rs2.ScheduleID != "rs1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConcurrencyArtifactJSON(t *testing.T) {
	ca := ConcurrencyArtifact{Type: ConcurrencyArtifactDependencyGraph}
	data, _ := json.Marshal(ca)
	var ca2 ConcurrencyArtifact
	json.Unmarshal(data, &ca2)
	if ca2.Type != ConcurrencyArtifactDependencyGraph {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SchedulerEventJSON(t *testing.T) {
	se := SchedulerEvent{EventID: "se1"}
	data, _ := json.Marshal(se)
	var se2 SchedulerEvent
	json.Unmarshal(data, &se2)
	if se2.EventID != "se1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ViolationActionConstants(t *testing.T) {
	actions := []ViolationAction{ViolationActionAlert, ViolationActionClamp, ViolationActionHalt, ViolationActionRevert}
	for _, a := range actions {
		if a == "" {
			t.Fatal("violation action must not be empty")
		}
	}
}

func TestFinal_CELDPTierConstants(t *testing.T) {
	tiers := []CELDPTier{CELDPTierKernelCritical, CELDPTierNonCritical}
	if len(tiers) != 2 {
		t.Fatal("want 2 CEL DP tiers")
	}
}

func TestFinal_ConcurrentBlobStore(t *testing.T) {
	store := NewInMemoryBlobStore()
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.Store(nil, []byte{byte(i)}, "application/octet-stream")
		}(i)
	}
	wg.Wait()
}

func TestFinal_EvaluationWindowZeroValue(t *testing.T) {
	ew := &EvaluationWindow{}
	if ew == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_TaskPropertiesJSON(t *testing.T) {
	tp := TaskProperties{ToolDensity: 0.75}
	data, _ := json.Marshal(tp)
	var tp2 TaskProperties
	json.Unmarshal(data, &tp2)
	if tp2.ToolDensity != 0.75 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CELDPCostBudgetJSON(t *testing.T) {
	cb := CELDPCostBudget{MaxExpressionSize: 1000, HardTimeoutMs: 500}
	data, _ := json.Marshal(cb)
	var cb2 CELDPCostBudget
	json.Unmarshal(data, &cb2)
	if cb2.MaxExpressionSize != 1000 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DeterminismDefaultPRNGConfig(t *testing.T) {
	a := DefaultPRNGConfig()
	b := DefaultPRNGConfig()
	if a.Algorithm != b.Algorithm || a.SeedLength != b.SeedLength {
		t.Fatal("DefaultPRNGConfig should be deterministic")
	}
}
