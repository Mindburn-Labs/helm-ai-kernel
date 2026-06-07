package verifier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

// createValidBundleFixture creates a minimal valid evidence bundle directory
// with all required structural elements for the hardened verifier:
// manifest.json, 00_INDEX.json, proofgraph.json, receipts/ with a receipt.
func createValidBundleFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// manifest.json
	writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{
		"session_id":  "test-session-001",
		"version":     "1.0.0",
		"exported_at": "2026-01-01T00:00:00Z",
		"file_hashes": map[string]string{},
	})

	// 00_INDEX.json
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"gates":   []string{"G0", "G1"},
	})

	// proofgraph.json (required for chain_integrity)
	writeJSON(t, filepath.Join(dir, "proofgraph.json"), map[string]any{
		"version": "1.0.0",
		"nodes":   []any{},
		"edges":   []any{},
	})

	// receipts/ directory with a receipt containing decision_hash
	receiptsDir := filepath.Join(dir, "receipts")
	if err := os.MkdirAll(receiptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(receiptsDir, "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"status":        "APPLIED",
		"lamport_clock": 1,
	})

	sealVerifierFixture(t, dir, "test-session-001")
	return dir
}

func createValidCanonicalBundleFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"entries": []any{},
	})
	writeJSON(t, filepath.Join(dir, "01_SCORE.json"), map[string]any{
		"pass": true,
	})
	for _, subdir := range []string{
		"02_PROOFGRAPH",
		"03_TELEMETRY",
		"04_EXPORTS",
		"05_DIFFS",
		"06_LOGS",
		"07_ATTESTATIONS",
		"08_TAPES",
		"09_SCHEMAS",
		"12_REPORTS",
	} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(receiptsDir, "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"status":        "APPLIED",
		"lamport_clock": 1,
	})

	sealVerifierFixture(t, dir, "canonical-test")
	return dir
}

func sealVerifierFixture(t *testing.T, dir, packID string) {
	t.Helper()
	if _, err := evidencepkg.SealEvidencePack(context.Background(), dir, evidencepkg.SealEvidencePackOptions{
		PackID:  packID,
		DataDir: t.TempDir(),
	}); err != nil {
		t.Fatalf("seal fixture: %v", err)
	}
}

func TestVerifyBundle_Valid(t *testing.T) {
	dir := createValidBundleFixture(t)

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Verified {
		t.Errorf("expected PASS, got FAIL: %s", report.Summary)
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("  FAIL: %s — %s", c.Name, c.Reason)
			}
		}
	}
	if report.VerifierVer != VerifierVersion {
		t.Errorf("expected version %s, got %s", VerifierVersion, report.VerifierVer)
	}
}

func TestVerifyBundle_CanonicalProofGraphReceipts(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Verified {
		t.Errorf("expected PASS, got FAIL: %s", report.Summary)
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("  FAIL: %s — %s", c.Name, c.Reason)
			}
		}
	}
}

func TestVerifyBundle_RequiresEvidencePackSeal(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"entries": []any{},
	})
	writeJSON(t, filepath.Join(dir, "01_SCORE.json"), map[string]any{"pass": true})
	for _, subdir := range []string{"02_PROOFGRAPH", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS", "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "12_REPORTS"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "02_PROOFGRAPH", "receipts"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(dir, "02_PROOFGRAPH", "receipts", "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"lamport_clock": 1,
	})

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("unsealed native EvidencePack must fail verification")
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "evidence_pack_seal" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing evidence_pack_seal failure: %+v", report.Checks)
	}
}

func TestVerifyBundleRejectsUntrustedEmbeddedSignatures(t *testing.T) {
	dir := createValidBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"status":        "APPLIED",
		"lamport_clock": 1,
		"signature":     "attacker-controlled",
	})

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("bundle with untrusted embedded receipt signature must fail verification")
	}
	var found bool
	for _, check := range report.Checks {
		if check.Name == "embedded_signature_trust" && !check.Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing embedded signature trust failure: %+v", report.Checks)
	}
	if report.SignatureValidCount >= report.SignatureTotalCount {
		t.Fatalf("unverified embedded signature was counted as valid: valid=%d total=%d", report.SignatureValidCount, report.SignatureTotalCount)
	}
}

func TestVerifyBundle_MissingManifest(t *testing.T) {
	dir := t.TempDir()

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verified {
		t.Error("expected FAIL for missing manifest")
	}

	// Should fail on structure check
	found := false
	for _, c := range report.Checks {
		if c.Name == "structure" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Error("expected structure check to fail")
	}
}

func TestVerifyBundle_HashMismatch(t *testing.T) {
	dir := createValidBundleFixture(t)

	// Write a file
	os.WriteFile(filepath.Join(dir, "receipt.json"), []byte(`{"id":"r1"}`), 0o644)

	// Overwrite manifest with wrong hash
	manifest := map[string]any{
		"session_id":  "test-session-002",
		"version":     "1.0.0",
		"exported_at": "2026-01-01T00:00:00Z",
		"file_hashes": map[string]string{
			"receipt.json": "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	writeJSON(t, filepath.Join(dir, "manifest.json"), manifest)

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verified {
		t.Error("expected FAIL for hash mismatch")
	}

	hashFailed := false
	for _, c := range report.Checks {
		if c.Name == "hash:receipt.json" && !c.Pass {
			hashFailed = true
		}
	}
	if !hashFailed {
		t.Error("expected hash check to fail for receipt.json")
	}
}

func TestVerifyBundle_IndexHashMismatch(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"entries": []any{
			map[string]any{
				"path":   "01_SCORE.json",
				"sha256": "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	})

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verified {
		t.Fatal("expected FAIL for indexed hash mismatch")
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "index_integrity" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Fatal("expected index_integrity check to fail")
	}
}

func TestVerifyBundle_EUAIActProfileValidatesWhenPresent(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "04_EXPORTS", "ai_act_profile.json"), map[string]any{
		"eu_ai_act_profile": map[string]any{
			"profile_id":                             "eu-ai-act:hr:1",
			"role_map":                               map[string]any{"deployer": "customer"},
			"risk_category":                          "high-risk Annex III employment",
			"relevant_articles":                      []string{"Article 9", "Article 14", "Article 26", "Article 27", "Article 49"},
			"high_risk_reasons":                      []string{"employment and worker management"},
			"provider_or_deployer_role":              "deployer",
			"risk_management_refs":                   []string{"risk:1"},
			"data_governance_refs":                   []string{"data:1"},
			"log_record_refs":                        []string{"logs:1"},
			"transparency_notice_refs":               []string{"instructions:1"},
			"human_oversight_refs":                   []string{"oversight:1"},
			"accuracy_robustness_cybersecurity_refs": []string{"security:1"},
			"fria_refs":                              []string{"fria:1"},
			"affected_person_notice_refs":            []string{"notice:1"},
			"registration_refs":                      []string{"registration:1"},
			"redaction_profile":                      "employment_minimized",
			"timeline_status":                        "FINAL",
			"redaction_metadata":                     map[string]string{"profile": "employment_minimized"},
		},
	})

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Verified {
		t.Fatalf("expected PASS, got %s", report.Summary)
	}
	assertCheck(t, report, "eu_ai_act_profile", true)
}

func TestVerifyBundle_EUAIActProfileRejectsMissingRequiredRefs(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "04_EXPORTS", "ai_act_profile.json"), map[string]any{
		"eu_ai_act_profile": map[string]any{
			"profile_id":                "eu-ai-act:hr:1",
			"role_map":                  map[string]any{"deployer": "customer"},
			"risk_category":             "high-risk Annex III employment",
			"relevant_articles":         []string{"Article 14"},
			"provider_or_deployer_role": "deployer",
			"redaction_profile":         "employment_minimized",
			"timeline_status":           "FINAL",
		},
	})

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verified {
		t.Fatal("expected EU AI Act profile failure")
	}
	assertCheck(t, report, "eu_ai_act_profile", false)
}

func TestVerifyBundle_ValidWithHashes(t *testing.T) {
	dir := createValidBundleFixture(t)

	// Write a file and compute correct hash
	content := []byte(`{"id":"r1","type":"receipt"}`)
	os.WriteFile(filepath.Join(dir, "receipt.json"), content, 0o644)
	hash := sha256Hex(content)

	// Overwrite manifest with correct hash
	manifest := map[string]any{
		"session_id":  "test-session-003",
		"version":     "1.0.0",
		"exported_at": "2026-01-01T00:00:00Z",
		"file_hashes": map[string]string{
			"receipt.json": hash,
		},
	}
	writeJSON(t, filepath.Join(dir, "manifest.json"), manifest)

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Verified {
		t.Errorf("expected PASS, got FAIL: %s", report.Summary)
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("  FAIL: %s — %s", c.Name, c.Reason)
			}
		}
	}
}

func TestVerifyBundle_MissingProofGraph(t *testing.T) {
	dir := t.TempDir()

	// Create manifest + index but no proofgraph
	writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{"session_id": "s1", "version": "1.0.0"})
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{"version": "1.0.0"})

	// Create receipts so only proofgraph is missing
	receiptsDir := filepath.Join(dir, "receipts")
	os.MkdirAll(receiptsDir, 0o755)
	writeJSON(t, filepath.Join(receiptsDir, "r1.json"), map[string]any{"decision_hash": "sha256:abc"})

	report, _ := VerifyBundle(dir)
	if report.Verified {
		t.Error("expected FAIL for missing proof graph")
	}

	chainFailed := false
	for _, c := range report.Checks {
		if c.Name == "chain_integrity" && !c.Pass {
			chainFailed = true
		}
	}
	if !chainFailed {
		t.Error("expected chain_integrity check to fail")
	}
}

func TestVerifyBundle_MissingReceipts(t *testing.T) {
	dir := t.TempDir()

	// Create manifest + index + proofgraph but no receipts
	writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{"session_id": "s1", "version": "1.0.0"})
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{"version": "1.0.0"})
	writeJSON(t, filepath.Join(dir, "proofgraph.json"), map[string]any{"nodes": []any{}})

	report, _ := VerifyBundle(dir)
	if report.Verified {
		t.Error("expected FAIL for missing receipts")
	}

	lamportFailed := false
	for _, c := range report.Checks {
		if c.Name == "lamport_monotonicity" && !c.Pass {
			lamportFailed = true
		}
	}
	if !lamportFailed {
		t.Error("expected lamport_monotonicity check to fail")
	}
}

func TestVerifyBundle_JSONOutput(t *testing.T) {
	dir := createValidBundleFixture(t)

	report, _ := VerifyBundle(dir)

	// Ensure the report serializes cleanly
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("cannot marshal report: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty JSON output")
	}

	// Roundtrip
	var rt VerifyReport
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("cannot unmarshal report: %v", err)
	}
	if rt.Bundle != dir {
		t.Errorf("bundle mismatch after roundtrip")
	}
}

func TestVerifyBundle_GoldenFixtureRoots(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "fixtures", "minimal")
	expectedPath := filepath.Join(fixtureDir, "EXPECTED.json")

	var expected struct {
		BundleRoot string `json:"bundle_root"`
		MerkleRoot string `json:"merkle_root"`
	}
	expectedData, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected roots: %v", err)
	}
	if err := json.Unmarshal(expectedData, &expected); err != nil {
		t.Fatalf("parse expected roots: %v", err)
	}

	report, err := VerifyBundle(fixtureDir)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if report.Roots.ManifestRootHash != expected.BundleRoot {
		t.Fatalf("manifest root mismatch: expected %s, got %s", expected.BundleRoot, report.Roots.ManifestRootHash)
	}
	if report.Roots.MerkleRoot != expected.MerkleRoot {
		t.Fatalf("merkle root mismatch: expected %s, got %s", expected.MerkleRoot, report.Roots.MerkleRoot)
	}
	if report.Roots.EntryCount != 2 {
		t.Fatalf("entry count mismatch: expected 2, got %d", report.Roots.EntryCount)
	}
}

func assertCheck(t *testing.T, report *VerifyReport, name string, pass bool) {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			if check.Pass != pass {
				t.Fatalf("check %s pass = %v, want %v; reason=%s", name, check.Pass, pass, check.Reason)
			}
			return
		}
	}
	t.Fatalf("check %s not found in %#v", name, report.Checks)
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
