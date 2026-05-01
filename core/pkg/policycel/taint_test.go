package policycel

import "testing"

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
