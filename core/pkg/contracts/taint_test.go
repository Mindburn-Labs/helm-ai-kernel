package contracts

import "testing"

func TestNormalizeTaintLabels(t *testing.T) {
	got := NormalizeTaintLabels([]string{" PII ", "pii", "Credential", ""})
	want := []string{TaintPII, TaintCredential}
	if len(got) != len(want) {
		t.Fatalf("expected %d labels, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("label %d: expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestTaintLabelsFromContext(t *testing.T) {
	labels := TaintLabelsFromContext(map[string]interface{}{
		"taint": "pii, credential secret",
	})
	for _, label := range []string{TaintPII, TaintCredential, TaintSecret} {
		if !TaintContains(labels, label) {
			t.Fatalf("expected %s in %v", label, labels)
		}
	}
}
