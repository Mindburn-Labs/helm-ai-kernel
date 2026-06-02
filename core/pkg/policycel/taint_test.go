package policycel

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

func TestRewritePRGTaintContains(t *testing.T) {
	got := RewritePRGTaintContains(`taint_contains("pii") && true`)
	want := `taint_contains(input.taint, "pii") && true`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestRewritePolicyPackTaintContains(t *testing.T) {
	got := RewritePolicyPackTaintContains(`!taint_contains("credential")`)
	want := `!taint_contains(taint, "credential")`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestTaintEnvOptionsEvaluateContains(t *testing.T) {
	env, err := cel.NewEnv(TaintEnvOptions()...)
	if err != nil {
		t.Fatalf("new env: %v", err)
	}
	ast, issues := env.Compile(`taint_contains(taint, "pii") && !taint_contains(taint, "secret")`)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile expression: %v", issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program: %v", err)
	}
	out, _, err := program.Eval(map[string]any{"taint": []string{"credential", "pii"}})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if out != types.True {
		t.Fatalf("eval output = %v, want true", out)
	}
}

func TestTaintContainsBindingRejectsNonContainer(t *testing.T) {
	if got := taintContainsBinding(types.String("not-a-list"), types.String("pii")); got != types.False {
		t.Fatalf("taintContainsBinding with non-container = %v, want false", got)
	}
}
