package adversarial

// quantum_posture: fixtures exercise deterministic classical Ed25519 keys and
// do not represent post-quantum assurance.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
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
	sourceReceipt := filepath.Join(dir, "02_PROOFGRAPH", "receipts", "005.json")
	sourceBefore, err := os.ReadFile(sourceReceipt)
	if err != nil {
		t.Fatal(err)
	}
	opts := campaignVerificationOptionsForPack(t, dir, publicKeyHex)

	result := EvaluateCoverageWithOptions(dir, opts)
	if !result.Pass || result.CoveredSuites != 10 || result.MissingSuites != 0 || len(result.Checks) != 10 {
		t.Fatalf("complete coverage result=%+v, want all suites covered", result)
	}
	for _, check := range result.Checks {
		if !check.Covered || check.EvidenceCount == 0 || check.MutationID == "" || !check.PositiveControlPassed || !check.MutationApplied || !check.MutationRejected || !check.MutationRestored {
			t.Fatalf("coverage check=%+v, want positive evidence and a rejected deterministic mutation", check)
		}
	}
	sourceAfter, err := os.ReadFile(sourceReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceBefore, sourceAfter) {
		t.Fatal("coverage mutations modified the source EvidencePack")
	}

	if err := os.Remove(filepath.Join(dir, "08_TAPES", "entry_001.json")); err != nil {
		t.Fatal(err)
	}
	writeCoverageIndex(t, dir)
	result = EvaluateCoverageWithOptions(dir, campaignVerificationOptionsForPack(t, dir, publicKeyHex))
	if result.Pass || result.MissingSuites != 1 || result.Checks[5].SuiteID != "ADV-06" || result.Checks[5].Covered {
		t.Fatalf("missing tape coverage result=%+v, want only ADV-06 missing", result)
	}
}

func TestCoverageRejectsAnAlreadyFailingPositiveControl(t *testing.T) {
	dir := t.TempDir()
	publicKeyHex := writePassingCoverageArtifacts(t, dir)
	receiptPath := filepath.Join(dir, "02_PROOFGRAPH", "receipts", "005.json")
	receipt := loadMutationJSON(receiptPath)
	receipt["seq"] = float64(7)
	if !writeTestMutationJSON(receiptPath, receipt) {
		t.Fatal("could not create pre-failing positive control")
	}
	writeCoverageIndex(t, dir)

	result := EvaluateCoverageWithOptions(dir, campaignVerificationOptionsForPack(t, dir, publicKeyHex))
	check := result.Checks[0]
	if check.SuiteID != "ADV-01" || check.Covered || check.PositiveControlPassed || check.MutationApplied || check.MutationRejected || check.MutationRestored {
		t.Fatalf("pre-failing control check=%+v, want fail-closed differential coverage", check)
	}
}

func TestCoverageRejectsMutationWorkspaceOverTheByteLimit(t *testing.T) {
	dir := t.TempDir()
	publicKeyHex := writePassingCoverageArtifacts(t, dir)
	opts := campaignVerificationOptionsForPack(t, dir, publicKeyHex)
	oversized := filepath.Join(dir, "oversized-untrusted-artifact.bin")
	if err := os.WriteFile(oversized, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversized, maxCoverageMutationBytes+1); err != nil {
		t.Fatal(err)
	}

	result := EvaluateCoverageWithOptions(dir, opts)
	if result.Pass || result.CoveredSuites != 0 || result.MissingSuites != 10 {
		t.Fatalf("oversized mutation workspace result=%+v, want all coverage to fail closed", result)
	}
	for _, check := range result.Checks {
		if check.PositiveControlPassed || check.MutationApplied || check.MutationRejected || check.MutationRestored {
			t.Fatalf("oversized workspace check=%+v, want no unbounded control or mutation execution", check)
		}
	}
	aggregate := RunAllWithOptions(dir, opts)
	if aggregate.Pass || aggregate.PassedSuites != 0 || aggregate.FailedSuites != 10 || len(aggregate.Suites) != 10 {
		t.Fatalf("oversized aggregate=%+v, want all suites to fail closed before unbounded reads", aggregate)
	}
}

func TestCoverageSnapshotMustMatchExternallyVerifiedRoots(t *testing.T) {
	t.Run("unindexed post-verification file", func(t *testing.T) {
		dir := t.TempDir()
		publicKeyHex := writePassingCoverageArtifacts(t, dir)
		opts := campaignVerificationOptionsForPack(t, dir, publicKeyHex)
		if err := os.WriteFile(filepath.Join(dir, "post-verification.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}

		result := EvaluateCoverageWithOptions(dir, opts)
		if result.Pass || result.CoveredSuites != 0 || result.MissingSuites != 10 {
			t.Fatalf("post-verification addition result=%+v, want all coverage to fail closed", result)
		}
	})

	t.Run("reindexed pack requires a newly verified root", func(t *testing.T) {
		dir := t.TempDir()
		publicKeyHex := writePassingCoverageArtifacts(t, dir)
		oldOpts := campaignVerificationOptionsForPack(t, dir, publicKeyHex)
		if err := os.WriteFile(filepath.Join(dir, "99_EXT", "adversarial", "campaign-context.json"), []byte(`{"version":"v2"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		writeCoverageIndex(t, dir)

		staleResult := EvaluateCoverageWithOptions(dir, oldOpts)
		if staleResult.Pass || staleResult.CoveredSuites != 0 || staleResult.MissingSuites != 10 {
			t.Fatalf("stale root result=%+v, want all coverage to fail closed", staleResult)
		}
		freshResult := EvaluateCoverageWithOptions(dir, campaignVerificationOptionsForPack(t, dir, publicKeyHex))
		if !freshResult.Pass || freshResult.CoveredSuites != 10 {
			t.Fatalf("newly verified root result=%+v, want complete coverage", freshResult)
		}
	})
}

func TestCoverageMutationRestoresTheWorkspace(t *testing.T) {
	dir := t.TempDir()
	_ = writePassingCoverageArtifacts(t, dir)
	receiptPath := filepath.Join(dir, "02_PROOFGRAPH", "receipts", "005.json")
	before, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	applied, rejected, restored := runCoverageMutation(dir, adv01ReceiptGapInjection(), mandatoryCoverageMutations()["ADV-01"])
	if !applied || !rejected || !restored {
		t.Fatalf("mutation applied=%t rejected=%t restored=%t, want exact detector rejection and restoration", applied, rejected, restored)
	}
	after, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("coverage mutation was not restored byte-for-byte")
	}
}

func TestCoverageRequiresTheExpectedDetectorToRejectItsMutation(t *testing.T) {
	dir := t.TempDir()
	_ = writePassingCoverageArtifacts(t, dir)
	mutation := mandatoryCoverageMutations()["ADV-01"]
	alwaysPass := &Suite{ID: "ADV-01", Run: func(string) *SuiteResult {
		return &SuiteResult{SuiteID: "ADV-01", Pass: true}
	}}
	applied, rejected, restored := runCoverageMutation(dir, alwaysPass, mutation)
	if !applied || rejected || !restored {
		t.Fatalf("mutation probe applied=%t rejected=%t restored=%t, want applied mutation without detector rejection", applied, rejected, restored)
	}
	unrelatedFailure := &Suite{ID: "ADV-01", Run: func(string) *SuiteResult {
		return &SuiteResult{
			SuiteID: "ADV-01",
			Pass:    false,
			TestResults: []TestResult{{
				TestID: "UNRELATED-T1",
				Pass:   false,
			}},
		}
	}}
	applied, rejected, restored = runCoverageMutation(dir, unrelatedFailure, mutation)
	if !applied || rejected || !restored {
		t.Fatalf("unrelated failure applied=%t rejected=%t restored=%t, want only the expected detector to prove rejection", applied, rejected, restored)
	}
}

func TestCoverageMutationReportsRestoreFailure(t *testing.T) {
	mutation := coverageMutation{
		ID:             "restore-failure/v1",
		ExpectedTestID: "ADV-01-T1",
		Apply: func(string) (restoreCoverageMutation, bool) {
			return func() bool { return false }, true
		},
	}
	suite := &Suite{ID: "ADV-01", Run: func(string) *SuiteResult {
		return &SuiteResult{SuiteID: "ADV-01", Pass: false, TestResults: []TestResult{{TestID: "ADV-01-T1", Pass: false}}}
	}}
	applied, rejected, restored := runCoverageMutation(t.TempDir(), suite, mutation)
	if !applied || !rejected || restored {
		t.Fatalf("restore failure applied=%t rejected=%t restored=%t, want explicit dirty-workspace signal", applied, rejected, restored)
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
	privateKey, publicKeyHex := campaignTestKey()
	validManifest := signCampaignDocument(t, map[string]any{"name": "canonical", "campaign_id": testCampaignID, "run_id": testCampaignRunID}, "signatures", campaignToolManifestSignatureDomain, privateKey)
	writeJSON(t, filepath.Join(canonicalDir, "canonical.json"), validManifest)
	if result := adv08ToolManifestForge(campaignVerificationOptions(publicKeyHex)).Run(dir); result.Pass {
		t.Fatalf("legacy manifest was ignored beside a valid canonical manifest: %+v", result)
	}
	writeJSON(t, filepath.Join(canonicalDir, "canonical.json"), map[string]any{"signatures": []string{"placeholder"}})
	if check := toolManifestCoverage(dir, VerificationOptions{}); check.Covered {
		t.Fatalf("placeholder signature unexpectedly covered ADV-08: %+v", check)
	}
}

func TestCampaignSignaturesAreDomainSeparated(t *testing.T) {
	privateKey, publicKeyHex := campaignTestKey()
	receipt := signCampaignDocument(t, map[string]any{"name": "repurposed-receipt"}, "campaign_signatures", campaignReceiptSignatureDomain, privateKey)
	receipt["signatures"] = receipt["campaign_signatures"]
	delete(receipt, "campaign_signatures")

	if verifyCampaignSignatures(receipt, "signatures", campaignToolManifestSignatureDomain, publicKeyHex) {
		t.Fatal("receipt signature was accepted in the tool-manifest domain")
	}
	manifest := signCampaignDocument(t, map[string]any{"name": "real-tool"}, "signatures", campaignToolManifestSignatureDomain, privateKey)
	if !verifyCampaignSignatures(manifest, "signatures", campaignToolManifestSignatureDomain, publicKeyHex) {
		t.Fatal("domain-bound tool-manifest signature was rejected")
	}
	signature := manifest["signatures"].([]any)[0].(map[string]any)
	signature["signature"] = "hex:" + signature["signature"].(string)
	if verifyCampaignSignatures(manifest, "signatures", campaignToolManifestSignatureDomain, publicKeyHex) {
		t.Fatal("non-canonical hex-prefixed signature was accepted")
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
		{"receipt_id": "receipt-1", "receipt_hash": "receipt-1", "seq": 1, "action_type": "policy_decision", "status": "ALLOW", "decision_id": "decision-1", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"genesis"}},
		{"receipt_id": "receipt-2", "receipt_hash": "receipt-2", "seq": 2, "action_type": "budget_decrement", "budget_snapshot_ref": "budget-1", "tenant_id": "tenant-1", "parent_receipt_hashes": []string{"receipt-1"}},
		{"receipt_id": "receipt-3", "receipt_hash": "receipt-3", "seq": 3, "action_type": "budget_exhausted", "budget_snapshot_ref": "budget-1", "tenant_id": "tenant-1", "parent_receipt_hashes": []string{"receipt-2"}},
		{"receipt_id": "receipt-4", "receipt_hash": "receipt-4", "seq": 4, "action_type": "approval_action", "status": "APPROVED", "decision_id": "decision-1", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"receipt-3"}},
		{"receipt_id": "receipt-5", "receipt_hash": "receipt-5", "seq": 5, "action_type": "effect_attempt", "decision_id": "decision-1", "effect_class": "E4", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"receipt-4"}},
	}
	for _, receipt := range receipts {
		receipt["campaign_id"] = testCampaignID
		receipt["run_id"] = testCampaignRunID
	}
	receipts[0] = signCampaignDocument(t, receipts[0], "campaign_signatures", campaignReceiptSignatureDomain, privateKey)
	receipts[3] = signCampaignDocument(t, receipts[3], "campaign_signatures", campaignReceiptSignatureDomain, privateKey)
	for i, receipt := range receipts {
		writeJSON(t, filepath.Join(receiptsDir, []string{"001.json", "002.json", "003.json", "004.json", "005.json"}[i]), receipt)
	}
	value := []byte("campaign-tape-value")
	valueHash := sha256.Sum256(value)
	writeJSON(t, filepath.Join(dir, "08_TAPES", "entry_001.json"), map[string]any{"value": value, "value_hash": hex.EncodeToString(valueHash[:]), "data_class": "internal"})
	toolManifest := signCampaignDocument(t, map[string]any{"name": "covered-tool", "campaign_id": testCampaignID, "run_id": testCampaignRunID}, "signatures", campaignToolManifestSignatureDomain, privateKey)
	writeJSON(t, filepath.Join(dir, "99_EXT", "adversarial", "tools", "tool.json"), toolManifest)
	writeJSON(t, filepath.Join(dir, "06_LOGS", "receipt_emission_panic.json"), map[string]any{"last_good_seq": 5})
	writeCoverageIndex(t, dir)
	return publicKeyHex
}

func writeCoverageIndex(t *testing.T, dir string) {
	t.Helper()
	entries := make([]map[string]string, 0)
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "00_INDEX.json" || rel == evidence.EvidencePackSealPath {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		entries = append(entries, map[string]string{"path": rel, "sha256": hex.EncodeToString(digest[:])})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i]["path"] < entries[j]["path"] })
	data, err := json.MarshalIndent(map[string]any{"version": "1.0.0", "entries": entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func campaignTestKey() (ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte("helm-adversarial-campaign-test-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey, hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

const (
	testCampaignID    = "campaign:test-clean-room"
	testCampaignRunID = "run:test-001"
)

func campaignVerificationOptions(publicKeyHex string) VerificationOptions {
	return VerificationOptions{
		CampaignPublicKeyHex: publicKeyHex,
		CampaignID:           testCampaignID,
		RunID:                testCampaignRunID,
	}
}

func campaignVerificationOptionsForPack(t *testing.T, dir, publicKeyHex string) VerificationOptions {
	t.Helper()
	roots, err := evidence.VerifyEvidencePackIndexRoots(dir)
	if err != nil {
		t.Fatalf("verify fixture EvidencePack roots: %v", err)
	}
	opts := campaignVerificationOptions(publicKeyHex)
	opts.VerifiedEvidenceIndexHash = roots.IndexHash
	opts.VerifiedEvidenceMerkleRoot = roots.MerkleRoot
	opts.VerifiedEvidenceEntryCount = roots.EntryCount
	return opts
}

func writeTestMutationJSON(path string, value map[string]interface{}) bool {
	data, err := json.Marshal(value)
	if err != nil {
		return false
	}
	return os.WriteFile(path, data, 0o600) == nil
}

func signCampaignDocument(t *testing.T, document map[string]any, field, domain string, privateKey ed25519.PrivateKey) map[string]any {
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
	signedMessage := []byte(domain)
	signedMessage = append(signedMessage, 0)
	signedMessage = append(signedMessage, canonical...)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(publicKey)
	payload[field] = []any{map[string]any{
		"algorithm": "ed25519",
		"key_id":    "sha256:" + hex.EncodeToString(keyHash[:]),
		"signature": hex.EncodeToString(ed25519.Sign(privateKey, signedMessage)),
	}}
	return payload
}
