package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
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
		Action:    "execute",
		Resource:  "safe-tool",
		Context:   map[string]interface{}{"key": "value"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = g.EvaluateDecision(context.Background(), req)
	}
}
