package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// TEST-003: Benchmark tests for Guardian policy evaluation.

func benchGuardian(tb testing.TB) *Guardian {
	tb.Helper()
	signer, err := crypto.NewEd25519Signer("bench-key")
	if err != nil {
		tb.Fatal(err)
	}
	graph := prg.NewGraph()
	_ = graph.AddRule("safe-tool", prg.RequirementSet{
		ID:    "allow-safe",
		Logic: prg.AND,
	})
	return NewGuardian(signer, graph, nil)
}

func BenchmarkGuardian_EvaluateDecision(b *testing.B) {
	g := benchGuardian(b)
	req := DecisionRequest{
		Principal: "bench-principal",
		Action:    "EXECUTE_TOOL",
		Resource:  "safe-tool",
		Context:   map[string]interface{}{"key": "value"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = g.EvaluateDecision(context.Background(), req)
	}
}

func BenchmarkGuardian_EvaluateDecisionCachedInterceptors(b *testing.B) {
	g := benchGuardian(b)
	req := DecisionRequest{
		Principal: "bench-principal",
		Action:    "EXECUTE_TOOL",
		Resource:  "safe-tool",
		Context:   map[string]interface{}{"key": "value"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = g.EvaluateDecision(context.Background(), req)
	}
}

func TestGuardianEvaluateDecisionAllocBudget(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation budget is not stable under race instrumentation")
	}

	g := benchGuardian(t)
	req := DecisionRequest{
		Principal: "bench-principal",
		Action:    "EXECUTE_TOOL",
		Resource:  "safe-tool",
		Context:   map[string]interface{}{"key": "value"},
	}

	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = g.EvaluateDecision(context.Background(), req)
	})
	// V2 request-bound decision signatures canonicalize the complete authority
	// envelope. The previous pre-V2 budget (147) no longer measured the shipped
	// execution contract; keep a regression guard with headroom over the
	// measured V2 baseline (426 allocs/op on the supported Go toolchain).
	if allocs > 500 {
		t.Fatalf("alloc regression: got %.0f allocs/op, want <=500", allocs)
	}
}

func TestGuardianBoundaryInterceptorsCached(t *testing.T) {
	g := benchGuardian(t)
	if got, want := len(g.boundaryChain), 6; got != want {
		t.Fatalf("boundaryChain len = %d, want %d", got, want)
	}
	before := g.boundaryChain[1]

	req := DecisionRequest{
		Principal: "bench-principal",
		Action:    "EXECUTE_TOOL",
		Resource:  "safe-tool",
		Context:   map[string]interface{}{"key": "value"},
	}
	if _, err := g.EvaluateDecision(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if after := g.boundaryChain[1]; after != before {
		t.Fatal("boundary interceptor was rebuilt")
	}
}
