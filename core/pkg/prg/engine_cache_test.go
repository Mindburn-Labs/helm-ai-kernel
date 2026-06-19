package prg

import (
	"fmt"
	"testing"
)

func TestEvaluateRequirementSet_CachesCompiledRequirementExpressions(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	rs := RequirementSet{
		ID:    "cached",
		Logic: AND,
		Requirements: []Requirement{
			{ID: "level", Expression: `input["level"] >= 3`},
		},
	}

	for i := 0; i < 2; i++ {
		result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{"level": 4})
		if err != nil {
			t.Fatal(err)
		}
		if !result {
			t.Fatal("expected requirement set to pass")
		}
	}

	pe.mu.RLock()
	_, cached := pe.prgCache[`input["level"] >= 3`]
	cacheSize := len(pe.prgCache)
	pe.mu.RUnlock()
	if !cached {
		t.Fatal("expected requirement expression to be cached")
	}
	if cacheSize != 1 {
		t.Fatalf("expected one compiled program, got %d", cacheSize)
	}
}

func TestCompileRequirementSet_DetectsCompileErrorBeforeEvaluation(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	rs := RequirementSet{
		ID:    "bad-snapshot",
		Logic: AND,
		Requirements: []Requirement{
			{ID: "bad", Expression: "not valid cel !!!"},
		},
	}

	if err := pe.CompileRequirementSet(rs); err == nil {
		t.Fatal("expected compile error before requirement-set evaluation")
	}
}

func TestCompileGraph_DetectsNestedRequirementCompileError(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	graph := NewGraph()
	if err := graph.AddRule("deploy", RequirementSet{
		ID:    "parent",
		Logic: AND,
		Children: []RequirementSet{
			{
				ID:    "child",
				Logic: AND,
				Requirements: []Requirement{
					{ID: "bad", Expression: "not valid cel !!!"},
				},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := pe.CompileGraph(graph); err == nil {
		t.Fatal("expected graph precompile to reject nested invalid CEL")
	}
}

func TestEvaluateRequirementSet_ANDShortCircuits(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	rs := RequirementSet{
		ID:    "and-short-circuit",
		Logic: AND,
		Requirements: []Requirement{
			{ID: "deny-first", Expression: "false"},
			{ID: "would-fail-if-compiled", Expression: "not valid cel !!!"},
		},
	}

	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatalf("expected short-circuit to avoid later compile error: %v", err)
	}
	if result {
		t.Fatal("expected AND to deny on first false requirement")
	}
}

func TestEvaluateRequirementSet_ORShortCircuits(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	rs := RequirementSet{
		ID:    "or-short-circuit",
		Logic: OR,
		Requirements: []Requirement{
			{ID: "allow-first", Expression: "true"},
			{ID: "would-fail-if-compiled", Expression: "not valid cel !!!"},
		},
	}

	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatalf("expected short-circuit to avoid later compile error: %v", err)
	}
	if !result {
		t.Fatal("expected OR to allow on first true requirement")
	}
}

func TestEvaluateRequirementSet_NOTShortCircuits(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	rs := RequirementSet{
		ID:    "not-short-circuit",
		Logic: NOT,
		Requirements: []Requirement{
			{ID: "false-first", Expression: "false"},
			{ID: "would-fail-if-compiled", Expression: "not valid cel !!!"},
		},
	}

	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatalf("expected short-circuit to avoid later compile error: %v", err)
	}
	if !result {
		t.Fatal("expected NOT to pass when the first child result is false")
	}
}

func BenchmarkEvaluateRequirementSet_CachedRequirements(b *testing.B) {
	for _, n := range []int{1, 50, 1000} {
		b.Run(fmt.Sprintf("all_true_n=%d", n), func(b *testing.B) {
			pe, err := NewPolicyEngine()
			if err != nil {
				b.Fatal(err)
			}
			rs, input := benchmarkRequirementSet(n, false)
			if err := pe.CompileRequirementSet(rs); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := pe.EvaluateRequirementSet(rs, input)
				if err != nil {
					b.Fatal(err)
				}
				if !result {
					b.Fatal("expected requirement set to pass")
				}
			}
		})
	}
}

func BenchmarkEvaluateRequirementSet_ANDShortCircuit(b *testing.B) {
	for _, n := range []int{1, 50, 1000} {
		b.Run(fmt.Sprintf("first_false_n=%d", n), func(b *testing.B) {
			pe, err := NewPolicyEngine()
			if err != nil {
				b.Fatal(err)
			}
			rs, input := benchmarkRequirementSet(n, true)
			if err := pe.CompileRequirementSet(rs); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := pe.EvaluateRequirementSet(rs, input)
				if err != nil {
					b.Fatal(err)
				}
				if result {
					b.Fatal("expected requirement set to short-circuit false")
				}
			}
		})
	}
}

func benchmarkRequirementSet(n int, firstFalse bool) (RequirementSet, map[string]interface{}) {
	reqs := make([]Requirement, 0, n)
	input := make(map[string]interface{}, n)
	for i := 0; i < n; i++ {
		value := i
		operator := "=="
		if firstFalse && i == 0 {
			value = -1
			operator = "=="
		}
		key := fmt.Sprintf("v%d", i)
		input[key] = i
		reqs = append(reqs, Requirement{
			ID:         key,
			Expression: fmt.Sprintf(`input["%s"] %s %d`, key, operator, value),
		})
	}
	return RequirementSet{ID: "bench", Logic: AND, Requirements: reqs}, input
}
