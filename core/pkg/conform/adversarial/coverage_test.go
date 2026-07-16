package adversarial

// quantum_posture: fixtures exercise classical Ed25519 signature shape and do
// not represent cryptographic verification or post-quantum assurance.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluateCoverageRejectsMissingPositiveControls(t *testing.T) {
	result := EvaluateCoverage(t.TempDir())
	if result.Pass || result.CoveredSuites != 0 || result.MissingSuites != 10 || len(result.Checks) != 10 {
		t.Fatalf("empty coverage result=%+v, want 10 missing suites", result)
	}
}

func TestEvaluateCoverageAcceptsAllPositiveControls(t *testing.T) {
	dir := t.TempDir()
	writePassingCoverageArtifacts(t, dir)

	result := EvaluateCoverage(dir)
	if !result.Pass || result.CoveredSuites != 10 || result.MissingSuites != 0 || len(result.Checks) != 10 {
		t.Fatalf("complete coverage result=%+v, want all suites covered", result)
	}
	for _, check := range result.Checks {
		if !check.Covered || check.EvidenceCount == 0 {
			t.Fatalf("coverage check=%+v, want positive evidence", check)
		}
	}

	if err := os.Remove(filepath.Join(dir, "08_TAPES", "entry_001.json")); err != nil {
		t.Fatal(err)
	}
	result = EvaluateCoverage(dir)
	if result.Pass || result.MissingSuites != 1 || result.Checks[5].SuiteID != "ADV-06" || result.Checks[5].Covered {
		t.Fatalf("missing tape coverage result=%+v, want only ADV-06 missing", result)
	}
}

func TestCoverageRejectsLegacyToolDirectoryAndPlaceholderSignature(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, "10_TOOLS")
	canonicalDir := filepath.Join(dir, "99_EXT", "adversarial", "tools")
	if err := os.MkdirAll(legacyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(canonicalDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(legacyDir, "legacy.json"), map[string]any{"signatures": []string{"placeholder"}})
	if check := toolManifestCoverage(dir); check.Covered {
		t.Fatalf("legacy tool directory unexpectedly covered ADV-08: %+v", check)
	}
	writeJSON(t, filepath.Join(canonicalDir, "canonical.json"), map[string]any{"signatures": []string{"placeholder"}})
	if check := toolManifestCoverage(dir); check.Covered {
		t.Fatalf("placeholder signature unexpectedly covered ADV-08: %+v", check)
	}
}

func writePassingCoverageArtifacts(t *testing.T, dir string) {
	t.Helper()
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	for _, path := range []string{receiptsDir, filepath.Join(dir, "08_TAPES"), filepath.Join(dir, "99_EXT", "adversarial", "tools"), filepath.Join(dir, "06_LOGS")} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	receipts := []map[string]any{
		{"seq": 1, "action_type": "policy_decision", "decision_id": "decision-1", "tenant_id": "tenant-1", "parent_receipt_hashes": []string{"genesis"}},
		{"seq": 2, "action_type": "budget_decrement", "tenant_id": "tenant-1", "parent_receipt_hashes": []string{"receipt-1"}},
		{"seq": 3, "action_type": "budget_exhausted", "tenant_id": "tenant-1", "parent_receipt_hashes": []string{"receipt-2"}},
		{"seq": 4, "action_type": "approval_action", "decision_id": "decision-1", "tenant_id": "tenant-1", "parent_receipt_hashes": []string{"receipt-3"}},
		{"seq": 5, "action_type": "effect_attempt", "decision_id": "decision-1", "effect_class": "E4", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"receipt-4"}},
	}
	for i, receipt := range receipts {
		writeJSON(t, filepath.Join(receiptsDir, []string{"001.json", "002.json", "003.json", "004.json", "005.json"}[i]), receipt)
	}
	writeJSON(t, filepath.Join(dir, "08_TAPES", "entry_001.json"), map[string]any{"value_hash": "sha256:value", "data_class": "internal"})
	writeJSON(t, filepath.Join(dir, "99_EXT", "adversarial", "tools", "tool.json"), map[string]any{
		"name": "covered-tool",
		"signatures": []map[string]any{{
			"algorithm": "ed25519",
			"key_id":    "sha256:campaign-key",
			"signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}},
	})
	writeJSON(t, filepath.Join(dir, "06_LOGS", "receipt_emission_panic.json"), map[string]any{"last_good_seq": 5})
}
