package adversarial

// quantum_posture: fixtures exercise deterministic classical Ed25519 keys and
// do not represent post-quantum assurance.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

func TestEvaluateCoverageRejectsMissingPositiveControls(t *testing.T) {
	result := EvaluateCoverage(t.TempDir(), VerificationOptions{})
	if result.Pass || result.CoveredSuites != 0 || result.MissingSuites != 10 || len(result.Checks) != 10 {
		t.Fatalf("empty coverage result=%+v, want 10 missing suites", result)
	}
}

func TestEvaluateCoverageAcceptsAllPositiveControls(t *testing.T) {
	dir := t.TempDir()
	publicKeyHex := writePassingCoverageArtifacts(t, dir)

	result := EvaluateCoverageWithOptions(dir, VerificationOptions{CampaignPublicKeyHex: publicKeyHex})
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
	result = EvaluateCoverageWithOptions(dir, VerificationOptions{CampaignPublicKeyHex: publicKeyHex})
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
	if check := toolManifestCoverage(dir, VerificationOptions{}); check.Covered {
		t.Fatalf("legacy tool directory unexpectedly covered ADV-08: %+v", check)
	}
	writeJSON(t, filepath.Join(canonicalDir, "canonical.json"), map[string]any{"signatures": []string{"placeholder"}})
	if check := toolManifestCoverage(dir, VerificationOptions{}); check.Covered {
		t.Fatalf("placeholder signature unexpectedly covered ADV-08: %+v", check)
	}
}

func writePassingCoverageArtifacts(t *testing.T, dir string) string {
	t.Helper()
	privateKey, publicKeyHex := campaignTestKey()
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	for _, path := range []string{receiptsDir, filepath.Join(dir, "08_TAPES"), filepath.Join(dir, "99_EXT", "adversarial", "tools"), filepath.Join(dir, "06_LOGS")} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	receipts := []map[string]any{
		{"receipt_id": "receipt-1", "receipt_hash": "receipt-1", "seq": 1, "action_type": "policy_decision", "status": "APPLIED", "decision_id": "decision-1", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"genesis"}},
		{"receipt_id": "receipt-2", "receipt_hash": "receipt-2", "seq": 2, "action_type": "budget_decrement", "tenant_id": "tenant-1", "parent_receipt_hashes": []string{"receipt-1"}},
		{"receipt_id": "receipt-3", "receipt_hash": "receipt-3", "seq": 3, "action_type": "budget_exhausted", "tenant_id": "tenant-1", "parent_receipt_hashes": []string{"receipt-2"}},
		{"receipt_id": "receipt-4", "receipt_hash": "receipt-4", "seq": 4, "action_type": "approval_action", "status": "APPROVED", "decision_id": "decision-1", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"receipt-3"}},
		{"receipt_id": "receipt-5", "receipt_hash": "receipt-5", "seq": 5, "action_type": "effect_attempt", "decision_id": "decision-1", "effect_class": "E4", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"receipt-4"}},
	}
	receipts[0] = signCampaignDocument(t, receipts[0], "campaign_signatures", privateKey)
	receipts[3] = signCampaignDocument(t, receipts[3], "campaign_signatures", privateKey)
	for i, receipt := range receipts {
		writeJSON(t, filepath.Join(receiptsDir, []string{"001.json", "002.json", "003.json", "004.json", "005.json"}[i]), receipt)
	}
	writeJSON(t, filepath.Join(dir, "08_TAPES", "entry_001.json"), map[string]any{"value_hash": "sha256:value", "data_class": "internal"})
	toolManifest := signCampaignDocument(t, map[string]any{"name": "covered-tool"}, "signatures", privateKey)
	writeJSON(t, filepath.Join(dir, "99_EXT", "adversarial", "tools", "tool.json"), toolManifest)
	writeJSON(t, filepath.Join(dir, "06_LOGS", "receipt_emission_panic.json"), map[string]any{"last_good_seq": 5})
	return publicKeyHex
}

func campaignTestKey() (ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte("helm-adversarial-campaign-test-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey, hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

func signCampaignDocument(t *testing.T, document map[string]any, field string, privateKey ed25519.PrivateKey) map[string]any {
	t.Helper()
	payload := make(map[string]any, len(document))
	for key, value := range document {
		if key != field {
			payload[key] = value
		}
	}
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(publicKey)
	payload[field] = []any{map[string]any{
		"algorithm": "ed25519",
		"key_id":    "sha256:" + hex.EncodeToString(keyHash[:]),
		"signature": hex.EncodeToString(ed25519.Sign(privateKey, canonical)),
	}}
	return payload
}
