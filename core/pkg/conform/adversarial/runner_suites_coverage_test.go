package adversarial

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var _ func(string) *AggregateResult = RunAll

func TestRunAllEmptyEvidenceFailsClosedAndWritesReport(t *testing.T) {
	dir := t.TempDir()

	result := RunAll(dir)
	if result.Pass || result.PassedSuites != 0 || result.FailedSuites != 10 || len(result.Suites) != 10 {
		t.Fatalf("empty evidence result = %+v, want all suites rejected for missing positive controls", result)
	}
	if result.EvidenceDir != dir {
		t.Fatalf("evidence dir = %q, want %q", result.EvidenceDir, dir)
	}
	if err := WriteReport(dir, result); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	reportPath := filepath.Join(dir, "12_REPORTS", "adversarial_report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var decoded AggregateResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if decoded.Pass || decoded.FailedSuites != 10 {
		t.Fatalf("decoded report = %+v, want fail-closed aggregate", decoded)
	}

	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(filePath, []byte("file"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	if err := WriteReport(filePath, result); err == nil || !strings.Contains(err.Error(), "create report dir") {
		t.Fatalf("WriteReport with file evidence dir error = %v, want create report dir error", err)
	}
}

func TestRunAllAcceptsCompletePositiveControls(t *testing.T) {
	dir := t.TempDir()
	publicKeyHex := writePassingCoverageArtifacts(t, dir)

	result := RunAllWithOptions(dir, VerificationOptions{CampaignPublicKeyHex: publicKeyHex})
	if !result.Pass || result.PassedSuites != 10 || result.FailedSuites != 0 || len(result.Suites) != 10 {
		t.Fatalf("complete evidence result = %+v, want all suites passing", result)
	}
}

func TestRunAllDetectsAdversarialEvidenceFailures(t *testing.T) {
	dir := t.TempDir()
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	tapesDir := filepath.Join(dir, "08_TAPES")
	toolsDir := filepath.Join(dir, "99_EXT", "adversarial", "tools")
	for _, path := range []string{receiptsDir, tapesDir, toolsDir} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}

	writeJSON(t, filepath.Join(receiptsDir, "001_budget_exhausted.json"), map[string]any{
		"seq":                 1,
		"action_type":         "budget_exhausted",
		"budget_snapshot_ref": "budget-1",
		"tenant_id":           "tenant-a",
	})
	writeJSON(t, filepath.Join(receiptsDir, "003_effect_without_policy.json"), map[string]any{
		"seq":                   3,
		"action_type":           "effect_attempt",
		"decision_id":           "decision-effect",
		"effect_class":          "E4",
		"tenant_id":             "tenant-b",
		"parent_receipt_hashes": []string{"parent-effect"},
	})
	writeJSON(t, filepath.Join(receiptsDir, "004_budget_decrement.json"), map[string]any{
		"seq":                   4,
		"action_type":           "budget_decrement",
		"budget_snapshot_ref":   "budget-1",
		"tenant_id":             "tenant-a",
		"parent_receipt_hashes": []string{"parent-fork"},
	})
	writeJSON(t, filepath.Join(receiptsDir, "005_second_child.json"), map[string]any{
		"seq":                   5,
		"action_type":           "noop",
		"tenant_id":             "tenant-a",
		"parent_receipt_hashes": []string{"parent-fork"},
	})
	writeJSON(t, filepath.Join(tapesDir, "entry_001.json"), map[string]any{
		"value": "missing required fields",
	})
	writeJSON(t, filepath.Join(toolsDir, "tool.json"), map[string]any{
		"name": "unsigned-tool",
	})
	writeJSON(t, filepath.Join(dir, "panic.json"), map[string]any{
		"last_good_seq": 4,
	})

	result := RunAll(dir)
	if result.Pass || result.FailedSuites != 10 || result.PassedSuites != 0 {
		t.Fatalf("bad evidence result = %+v, want all suites failing", result)
	}
	reasons := map[string]string{}
	for _, suite := range result.Suites {
		if len(suite.TestResults) != 1 {
			t.Fatalf("%s test count = %d, want 1", suite.SuiteID, len(suite.TestResults))
		}
		if suite.Pass || suite.TestResults[0].Pass {
			t.Fatalf("%s passed unexpectedly: %+v", suite.SuiteID, suite)
		}
		reasons[suite.SuiteID] = suite.TestResults[0].Reason
	}
	for id, fragment := range map[string]string{
		"ADV-01": "RECEIPT_GAP_DETECTED",
		"ADV-02": "effects without policy decisions",
		"ADV-03": "DAG forks detected",
		"ADV-04": "BUDGET_OVERDRAFT",
		"ADV-05": "effects without envelope binding",
		"ADV-06": "missing required fields",
		"ADV-07": "multiple tenants",
		"ADV-08": "without signatures",
		"ADV-09": "receipts emitted after panic",
		"ADV-10": "without approval",
	} {
		if !strings.Contains(reasons[id], fragment) {
			t.Fatalf("%s reason = %q, want fragment %q", id, reasons[id], fragment)
		}
	}
}

func TestAdversarialSuiteHelpers(t *testing.T) {
	if !IsHighFinalityAction("E4", "tool_call") || !IsHighFinalityAction("E5", "tool_call") || !IsHighFinalityAction("E3", "connector_call") {
		t.Fatalf("high-finality action helper missed a high-finality case")
	}
	if IsHighFinalityAction("E2", "connector_call") || IsHighFinalityAction("E3", "tool_call") {
		t.Fatalf("high-finality action helper accepted a non-high-finality case")
	}

	dir := t.TempDir()
	receiptA := filepath.Join(dir, "policy.json")
	receiptB := filepath.Join(dir, "approval.json")
	writeJSON(t, receiptA, map[string]any{"seq": 10, "action_type": "policy_decision", "decision_id": "decision-1"})
	writeJSON(t, receiptB, map[string]any{"seq": 11, "action_type": "approval_action", "decision_id": "decision-1"})
	files := []string{receiptA, receiptB, filepath.Join(dir, "missing.json")}
	if got := loadReceipt(filepath.Join(dir, "missing.json")); got != nil {
		t.Fatalf("loadReceipt missing file = %#v, want nil", got)
	}
	if seqs := loadSequenceNumbers(files); len(seqs) != 2 || seqs[0] != 10 || seqs[1] != 11 {
		t.Fatalf("loadSequenceNumbers = %#v, want [10 11]", seqs)
	}
	if !hasPolicyReceiptForDecision(files, "decision-1") || hasPolicyReceiptForDecision(files, "missing") {
		t.Fatalf("policy receipt lookup returned unexpected result")
	}
	if !hasApprovalForDecision(files, "decision-1") || hasApprovalForDecision(files, "missing") {
		t.Fatalf("approval receipt lookup returned unexpected result")
	}
}

func TestIndividualSuitePassingBranches(t *testing.T) {
	dir := t.TempDir()
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		t.Fatalf("mkdir receipts: %v", err)
	}
	writeJSON(t, filepath.Join(receiptsDir, "001.json"), map[string]any{"seq": 1})
	writeJSON(t, filepath.Join(receiptsDir, "002.json"), map[string]any{"seq": 2})
	writeJSON(t, filepath.Join(dir, "panic.json"), map[string]any{"last_good_seq": 2})

	if result := adv01ReceiptGapInjection().Run(dir); !result.Pass || result.TestResults[0].Reason != "no gaps in receipt sequence" {
		t.Fatalf("ADV-01 no-gap result = %+v, want pass", result)
	}
	if result := adv09ReceiptEmissionPanicHijack().Run(dir); !result.Pass || result.TestResults[0].Reason != "emission correctly halted after panic" {
		t.Fatalf("ADV-09 halted result = %+v, want pass", result)
	}

	if err := os.WriteFile(filepath.Join(dir, "panic.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid panic record: %v", err)
	}
	if result := adv09ReceiptEmissionPanicHijack().Run(dir); result.Pass || result.TestResults[0].Reason != "panic record unreadable" {
		t.Fatalf("ADV-09 unreadable panic result = %+v, want fail", result)
	}
}

func TestPanicEvidenceCannotBeShadowedByCanonicalRecord(t *testing.T) {
	dir := t.TempDir()
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(filepath.Join(dir, "06_LOGS"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(dir, "06_LOGS", "receipt_emission_panic.json"), map[string]any{"last_good_seq": 99})
	writeJSON(t, filepath.Join(dir, "panic.json"), map[string]any{"last_good_seq": 1})
	writeJSON(t, filepath.Join(receiptsDir, "002.json"), map[string]any{"seq": 2})

	result := adv09ReceiptEmissionPanicHijack().Run(dir)
	if result.Pass || !strings.Contains(result.TestResults[0].Reason, "receipts emitted after panic") {
		t.Fatalf("shadowed panic result = %+v, want restrictive boundary failure", result)
	}
}

func TestReceiptSequenceRejectsDuplicateAndMissingValues(t *testing.T) {
	for name, seqs := range map[string][]any{
		"duplicate":       {1, 1},
		"missing":         {1, nil},
		"missing genesis": {2, 3},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
			if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
				t.Fatal(err)
			}
			for index, seq := range seqs {
				receipt := map[string]any{"action_type": "noop"}
				if seq != nil {
					receipt["seq"] = seq
				}
				writeJSON(t, filepath.Join(receiptsDir, fmt.Sprintf("%03d.json", index)), receipt)
			}
			if result := adv01ReceiptGapInjection().Run(dir); result.Pass || result.TestResults[0].Reason != "RECEIPT_GAP_DETECTED" {
				t.Fatalf("ADV-01 accepted %s sequence: %+v", name, result)
			}
		})
	}
}

func TestCryptographicSuitesRejectForgeryAndPostHocAuthorization(t *testing.T) {
	t.Run("tool manifest tamper", func(t *testing.T) {
		dir := t.TempDir()
		publicKeyHex := writePassingCoverageArtifacts(t, dir)
		path := filepath.Join(dir, "99_EXT", "adversarial", "tools", "tool.json")
		var manifest map[string]any
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			t.Fatalf("read tool manifest: %v", err)
		}
		manifest["name"] = "forged-tool"
		writeJSON(t, path, manifest)
		if result := adv08ToolManifestForge(VerificationOptions{CampaignPublicKeyHex: publicKeyHex}).Run(dir); result.Pass {
			t.Fatalf("tampered tool manifest passed: %+v", result)
		}
	})

	t.Run("post-hoc policy", func(t *testing.T) {
		dir := t.TempDir()
		privateKey, publicKeyHex := campaignTestKey()
		receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
		if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
			t.Fatal(err)
		}
		effect := map[string]any{"receipt_id": "effect", "receipt_hash": "effect", "seq": 1, "action_type": "effect_attempt", "decision_id": "decision-1", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"genesis"}}
		policy := map[string]any{"receipt_id": "policy", "receipt_hash": "policy", "seq": 2, "action_type": "policy_decision", "status": "APPLIED", "decision_id": "decision-1", "tenant_id": "tenant-1", "envelope_id": "envelope-1", "envelope_hash": "sha256:envelope", "parent_receipt_hashes": []string{"effect"}}
		writeJSON(t, filepath.Join(receiptsDir, "001.json"), effect)
		writeJSON(t, filepath.Join(receiptsDir, "002.json"), signCampaignDocument(t, policy, "campaign_signatures", campaignReceiptSignatureDomain, privateKey))
		if result := adv02PolicyBypass(VerificationOptions{CampaignPublicKeyHex: publicKeyHex}).Run(dir); result.Pass {
			t.Fatalf("post-hoc policy passed: %+v", result)
		}
	})

	t.Run("cross-tenant authorization", func(t *testing.T) {
		dir := t.TempDir()
		privateKey, publicKeyHex := campaignTestKey()
		_ = writePassingCoverageArtifacts(t, dir)
		path := filepath.Join(dir, "02_PROOFGRAPH", "receipts", "001.json")
		var policy map[string]any
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &policy) != nil {
			t.Fatalf("read policy receipt: %v", err)
		}
		policy["tenant_id"] = "tenant-b"
		policy = signCampaignDocument(t, policy, "campaign_signatures", campaignReceiptSignatureDomain, privateKey)
		writeJSON(t, path, policy)
		if result := adv02PolicyBypass(VerificationOptions{CampaignPublicKeyHex: publicKeyHex}).Run(dir); result.Pass {
			t.Fatalf("cross-tenant policy passed: %+v", result)
		}
	})

	t.Run("tape value tamper", func(t *testing.T) {
		dir := t.TempDir()
		_ = writePassingCoverageArtifacts(t, dir)
		path := filepath.Join(dir, "08_TAPES", "entry_001.json")
		var entry map[string]any
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &entry) != nil {
			t.Fatalf("read tape entry: %v", err)
		}
		entry["value"] = "Zm9yZ2Vk"
		writeJSON(t, path, entry)
		if result := adv06TapeReplayTamper().Run(dir); result.Pass {
			t.Fatalf("tampered tape passed: %+v", result)
		}
	})
}

func TestMalformedTapeAndMissingTenantFailClosed(t *testing.T) {
	t.Run("malformed tape beside valid tape", func(t *testing.T) {
		dir := t.TempDir()
		tapesDir := filepath.Join(dir, "08_TAPES")
		if err := os.MkdirAll(tapesDir, 0o750); err != nil {
			t.Fatal(err)
		}
		value := []byte("valid")
		digest := sha256.Sum256(value)
		writeJSON(t, filepath.Join(tapesDir, "entry_001.json"), map[string]any{"value": value, "value_hash": hex.EncodeToString(digest[:]), "data_class": "internal"})
		if err := os.WriteFile(filepath.Join(tapesDir, "entry_002.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if result := adv06TapeReplayTamper().Run(dir); result.Pass {
			t.Fatalf("malformed tape passed beside valid tape: %+v", result)
		}
	})

	t.Run("unknown tape data class", func(t *testing.T) {
		dir := t.TempDir()
		tapesDir := filepath.Join(dir, "08_TAPES")
		if err := os.MkdirAll(tapesDir, 0o750); err != nil {
			t.Fatal(err)
		}
		value := []byte("classified")
		digest := sha256.Sum256(value)
		writeJSON(t, filepath.Join(tapesDir, "entry_001.json"), map[string]any{"value": value, "value_hash": hex.EncodeToString(digest[:]), "data_class": "invented-class"})
		if result := adv06TapeReplayTamper().Run(dir); result.Pass {
			t.Fatalf("unknown tape data class passed: %+v", result)
		}
		if coverage := tapeCoverage(dir); coverage.Covered {
			t.Fatalf("unknown tape data class satisfied ADV-06 coverage: %+v", coverage)
		}
	})

	t.Run("missing tenant", func(t *testing.T) {
		dir := t.TempDir()
		receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
		if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
			t.Fatal(err)
		}
		writeJSON(t, filepath.Join(receiptsDir, "001.json"), map[string]any{"seq": 1, "action_type": "noop"})
		if result := adv07TenantCrossleak().Run(dir); result.Pass {
			t.Fatalf("receipt without tenant passed: %+v", result)
		}
	})
}

func TestBudgetBoundaryUsesExplicitScope(t *testing.T) {
	dir := t.TempDir()
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	exhaustedPath := filepath.Join(receiptsDir, "999.json")
	decrementPath := filepath.Join(receiptsDir, "001.json")
	writeJSON(t, exhaustedPath, map[string]any{"seq": 1, "action_type": "budget_exhausted", "budget_snapshot_ref": "budget-a"})
	writeJSON(t, decrementPath, map[string]any{"seq": 2, "action_type": "budget_decrement", "budget_snapshot_ref": "budget-b"})

	if result := adv04BudgetOverdraft().Run(dir); !result.Pass {
		t.Fatalf("unrelated budget decrement was treated as overdraft: %+v", result)
	}
	coverage := budgetBoundaryCoverage([]map[string]interface{}{loadReceipt(exhaustedPath), loadReceipt(decrementPath)})
	if coverage.Covered {
		t.Fatalf("unrelated budgets satisfied ADV-04 coverage: %+v", coverage)
	}

	writeJSON(t, decrementPath, map[string]any{"seq": 2, "action_type": "budget_decrement", "budget_snapshot_ref": "budget-a"})
	if result := adv04BudgetOverdraft().Run(dir); result.Pass || result.TestResults[0].Reason != "BUDGET_OVERDRAFT" {
		t.Fatalf("same-budget overdraft was accepted: %+v", result)
	}

	writeJSON(t, exhaustedPath, map[string]any{"seq": 1, "action_type": "budget_exhausted", "budget_id": "budget-a"})
	writeJSON(t, decrementPath, map[string]any{"seq": 2, "action_type": "budget_decrement", "decision_id": "budget-a"})
	if result := adv04BudgetOverdraft().Run(dir); result.Pass || result.TestResults[0].Reason != "budget boundary contains an unscoped or unsequenced receipt" {
		t.Fatalf("mixed fallback scope keys bypassed budget boundary: %+v", result)
	}
	coverage = budgetBoundaryCoverage([]map[string]interface{}{loadReceipt(exhaustedPath), loadReceipt(decrementPath)})
	if coverage.Covered {
		t.Fatalf("mixed fallback scope keys satisfied ADV-04 coverage: %+v", coverage)
	}
}

func TestReceiptSequenceIgnoresFilenameOrder(t *testing.T) {
	dir := t.TempDir()
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(receiptsDir, "999.json"), map[string]any{"seq": 1})
	writeJSON(t, filepath.Join(receiptsDir, "001.json"), map[string]any{"seq": 2})
	if result := adv01ReceiptGapInjection().Run(dir); !result.Pass {
		t.Fatalf("contiguous receipts were rejected because filenames were reordered: %+v", result)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
