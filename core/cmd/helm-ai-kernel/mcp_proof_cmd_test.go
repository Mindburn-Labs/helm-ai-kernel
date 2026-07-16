package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	lpreceipts "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
)

func TestRunMCPProofProducesGovernedEffectEvidencePack(t *testing.T) {
	outRoot := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := runMCPProof([]string{
		"--scenario", "all",
		"--out", outRoot,
		"--run-id", "mcp-proof-test",
		"--at", "2026-06-09T00:00:00Z",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMCPProof code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}

	var summary mcpProofSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v\n%s", err, stdout.String())
	}
	if summary.RunID != "mcp_proof_test" {
		t.Fatalf("run id = %q", summary.RunID)
	}
	if summary.SchemaVersion != "helm.mcp.proof/v3" {
		t.Fatalf("schema version = %q", summary.SchemaVersion)
	}
	if summary.ProofScope != "complete" || !summary.CompletePositiveAndNegative || !summary.ProofComplete {
		t.Fatalf("complete proof was not marked complete: %#v", summary)
	}
	if !summary.OfflineVerified {
		t.Fatalf("offline verifier did not pass: %#v", summary)
	}
	if !summary.TamperRejected {
		t.Fatalf("tampered EvidencePack was not rejected: %#v", summary)
	}
	if !summary.DurationGatePass || summary.DurationLimitMS != 60_000 || summary.DurationMS >= summary.DurationLimitMS {
		t.Fatalf("60-second duration gate failed: %#v", summary)
	}
	if !summary.NegativeCasesNoDispatch || summary.DispatchCount != 1 || !summary.ReplayNoRedispatch {
		t.Fatalf("positive/negative dispatch summary invalid: %#v", summary)
	}
	if len(summary.Scenarios) != 8 {
		t.Fatalf("scenario count = %d, want 8", len(summary.Scenarios))
	}
	if _, err := os.Stat(filepath.Join(summary.EvidencePackRef, "07_ATTESTATIONS", "evidence_pack.sig")); err != nil {
		t.Fatalf("sealed EvidencePack missing: %v", err)
	}
	if _, err := os.Stat(summary.EvidencePackArchive); err != nil {
		t.Fatalf("EvidencePack archive missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outRoot, "mcp_proof_test", "verification_report.json")); err != nil {
		t.Fatalf("verification report missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(summary.EvidencePackRef, "12_REPORTS", "60_second_gate.json")); err != nil {
		t.Fatalf("duration gate report missing: %v", err)
	}

	positive := findMCPProofScenario(t, summary.Scenarios, "approved_reversible_local_effect")
	if positive.Verdict != "ALLOW" || !positive.Dispatched || positive.DispatchCount != 1 || !positive.ReplayNoRedispatch {
		t.Fatalf("positive scenario did not execute exactly once: %#v", positive)
	}
	if positive.ExecutionReceiptRef == "" || positive.ExecutionReceiptHash == "" ||
		positive.ReplayReceiptRef == "" || positive.ReplayReceiptHash == "" ||
		!positive.ReplayEnvelopeEqual || positive.EffectArtifactRef == "" {
		t.Fatalf("positive scenario missing execution evidence: %#v", positive)
	}
	effectData, err := os.ReadFile(filepath.Join(summary.EvidencePackRef, filepath.FromSlash(positive.EffectArtifactRef)))
	if err != nil {
		t.Fatalf("read reversible effect artifact: %v", err)
	}
	if !strings.Contains(string(effectData), "HELM governed reversible local effect") {
		t.Fatalf("unexpected reversible effect artifact: %q", effectData)
	}
	executionReceiptData, err := os.ReadFile(filepath.Join(summary.EvidencePackRef, filepath.FromSlash(positive.ExecutionReceiptRef)))
	if err != nil {
		t.Fatalf("read execution receipt: %v", err)
	}
	var executionReceipt contracts.Receipt
	if err := json.Unmarshal(executionReceiptData, &executionReceipt); err != nil {
		t.Fatalf("decode execution receipt: %v", err)
	}
	if executionReceipt.EffectID != mcpEffectReceiptPrefix+positive.ScenarioID || executionReceipt.Signature == "" {
		t.Fatalf("execution receipt is not signed and effect-bound: %#v", executionReceipt)
	}
	if executionReceipt.OutputHash != lpreceipts.HashBytes(effectData) {
		t.Fatalf("execution receipt does not bind exact effect bytes: output=%s effect=%s", executionReceipt.OutputHash, lpreceipts.HashBytes(effectData))
	}
	if executionReceipt.Type != "" || executionReceipt.DecisionHash != "" || executionReceipt.Metadata != nil {
		t.Fatalf("execution receipt contains mutable proof extensions: %#v", executionReceipt)
	}
	replayReceiptData, err := os.ReadFile(filepath.Join(summary.EvidencePackRef, filepath.FromSlash(positive.ReplayReceiptRef)))
	if err != nil {
		t.Fatalf("read replayed execution receipt: %v", err)
	}
	if !bytes.Equal(executionReceiptData, replayReceiptData) || positive.ExecutionReceiptHash != positive.ReplayReceiptHash {
		t.Fatalf("durable replayed receipt envelope changed\noriginal=%s\nreplay=%s", executionReceiptData, replayReceiptData)
	}
	inputsData, err := os.ReadFile(filepath.Join(summary.EvidencePackRef, filepath.FromSlash(positive.AuthorizationInputsRef)))
	if err != nil {
		t.Fatalf("read authorization inputs: %v", err)
	}
	if lpreceipts.HashBytes(inputsData) != positive.AuthorizationInputsHash {
		t.Fatalf("authorization inputs hash mismatch")
	}
	evaluationData, err := os.ReadFile(filepath.Join(summary.EvidencePackRef, filepath.FromSlash(positive.AuthorizationEvaluationRef)))
	if err != nil {
		t.Fatalf("read authorization evaluation: %v", err)
	}
	if lpreceipts.HashBytes(evaluationData) != positive.AuthorizationEvaluationHash {
		t.Fatalf("authorization evaluation hash mismatch")
	}
	var evaluation mcpProofAuthorizationEvaluation
	if err := json.Unmarshal(evaluationData, &evaluation); err != nil {
		t.Fatalf("decode authorization evaluation: %v", err)
	}
	if evaluation.AuthorizationInputsHash != positive.AuthorizationInputsHash || evaluation.AuthorizationInputsRef != positive.AuthorizationInputsRef {
		t.Fatalf("authorization evaluation is not bound to its inputs: %#v", evaluation)
	}
	decisionData, err := os.ReadFile(filepath.Join(summary.EvidencePackRef, "02_PROOFGRAPH", "decisions", positive.ScenarioID+".json"))
	if err != nil {
		t.Fatalf("read signed execution decision: %v", err)
	}
	var executionDecision contracts.DecisionRecord
	if err := json.Unmarshal(decisionData, &executionDecision); err != nil {
		t.Fatalf("decode signed execution decision: %v", err)
	}
	if executionDecision.PolicyDecisionHash != positive.AuthorizationEvaluationHash || executionDecision.Signature == "" {
		t.Fatalf("signed execution decision is not bound to authorization evaluation: %#v", executionDecision)
	}
	publicKey, err := hex.DecodeString(executionReceipt.PublicKeySet[helmcrypto.SigPrefixEd25519])
	if err != nil {
		t.Fatalf("decode execution receipt public key: %v", err)
	}
	decisionVerifier, err := helmcrypto.NewEd25519Verifier(publicKey)
	if err != nil {
		t.Fatalf("create execution decision verifier: %v", err)
	}
	if verified, err := decisionVerifier.VerifyDecision(&executionDecision); err != nil || !verified {
		t.Fatalf("execution decision signature does not verify: verified=%t err=%v", verified, err)
	}
	tamperedDecision := executionDecision
	tamperedDecision.PolicyDecisionHash = positive.AuthorizationInputsHash
	if verified, err := decisionVerifier.VerifyDecision(&tamperedDecision); err != nil || verified {
		t.Fatalf("tampered authorization-evaluation hash must invalidate decision signature: verified=%t err=%v", verified, err)
	}

	reasons := map[string]bool{}
	for _, result := range summary.Scenarios {
		if result.Verdict != "ALLOW" && (result.Dispatched || result.DispatchCount != 0) {
			t.Fatalf("negative scenario %s dispatched unexpectedly: %#v", result.ScenarioID, result)
		}
		if result.ReceiptRef == "" || result.ReceiptHash == "" || result.AuthorizationInputsRef == "" || result.AuthorizationInputsHash == "" || result.AuthorizationEvaluationRef == "" || result.AuthorizationEvaluationHash == "" {
			t.Fatalf("%s missing receipt ref/hash: %#v", result.ScenarioID, result)
		}
		reasons[result.Reason] = true

		var receipt contracts.Receipt
		data, err := os.ReadFile(filepath.Join(summary.EvidencePackRef, filepath.FromSlash(result.ReceiptRef)))
		if err != nil {
			t.Fatalf("read receipt for %s: %v", result.ScenarioID, err)
		}
		if err := json.Unmarshal(data, &receipt); err != nil {
			t.Fatalf("decode receipt for %s: %v", result.ScenarioID, err)
		}
		if receipt.Signature == "" || receipt.EffectID != mcpPolicyReceiptPrefix+result.ScenarioID || receipt.Status != result.Verdict {
			t.Fatalf("receipt for %s is not signed and status/effect-bound: %#v", result.ScenarioID, receipt)
		}
		if receipt.OutputHash != result.AuthorizationEvaluationHash || receipt.ArgsHash != result.AuthorizationInputsHash {
			t.Fatalf("receipt for %s does not bind authentic authorization artifacts: %#v", result.ScenarioID, receipt)
		}
		if receipt.Type != "" || receipt.DecisionHash != "" || receipt.Metadata != nil {
			t.Fatalf("receipt for %s contains mutable proof extensions: %#v", result.ScenarioID, receipt)
		}
		if lpreceipts.HashBytes(data) != result.ReceiptHash {
			t.Fatalf("receipt hash mismatch for %s", result.ScenarioID)
		}
	}

	for _, reason := range []string{
		"ERR_MCP_SERVER_QUARANTINED",
		"ERR_MCP_APPROVAL_RECEIPT_REQUIRED",
		"ERR_MCP_APPROVAL_SCOPE_OR_EXPIRY",
		"ERR_MCP_LAUNCH_SCOPE_MISMATCH",
		"ERR_MCP_TOOL_QUARANTINED",
		"ERR_MCP_SCHEMA_DRIFT",
	} {
		if !reasons[reason] {
			t.Fatalf("missing proof reason %s in %#v", reason, reasons)
		}
	}
}

func findMCPProofScenario(t *testing.T, scenarios []mcpProofScenarioResult, id string) mcpProofScenarioResult {
	t.Helper()
	for _, scenario := range scenarios {
		if scenario.ScenarioID == id {
			return scenario
		}
	}
	t.Fatalf("scenario %q not found in %#v", id, scenarios)
	return mcpProofScenarioResult{}
}

func TestRunMCPProofSupportsFocusedScenario(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPProof([]string{
		"--scenario", "schema_drift",
		"--out", t.TempDir(),
		"--run-id", "schema-drift",
		"--at", "2026-06-09T00:00:00Z",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMCPProof code=%d stderr=%s", code, stderr.String())
	}
	var summary mcpProofSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(summary.Scenarios) != 1 || summary.Scenarios[0].Reason != "ERR_MCP_SCHEMA_DRIFT" {
		t.Fatalf("focused scenario summary = %#v", summary.Scenarios)
	}
	if summary.ProofScope != "vector_only" || summary.ProofComplete || summary.CompletePositiveAndNegative || !summary.NegativeCasesNoDispatch {
		t.Fatalf("focused negative run must be explicitly vector-only: %#v", summary)
	}
}

func TestRunMCPProofSupportsFocusedPositiveScenario(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPProof([]string{
		"--scenario", "approved_reversible_local_effect",
		"--out", t.TempDir(),
		"--run-id", "focused-positive",
		"--at", "2026-06-09T00:00:00Z",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMCPProof code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var summary mcpProofSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(summary.Scenarios) != 1 {
		t.Fatalf("scenario count=%d, want 1", len(summary.Scenarios))
	}
	positive := summary.Scenarios[0]
	if positive.Verdict != "ALLOW" || positive.DispatchCount != 1 || !positive.ReplayNoRedispatch {
		t.Fatalf("focused positive scenario = %#v", positive)
	}
	if summary.ProofScope != "vector_only" || summary.ProofComplete || summary.CompletePositiveAndNegative || summary.NegativeCasesNoDispatch {
		t.Fatalf("focused positive run must be explicitly vector-only: %#v", summary)
	}
}

func TestRunMCPProofRejectsUnknownScenario(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPProof([]string{"--scenario", "not-real", "--out", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown --scenario") {
		t.Fatalf("missing unknown scenario error: %s", stderr.String())
	}
}

func TestRunMCPProofRejectsVerificationBypass(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMCPProof([]string{"--verify=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runMCPProof code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires offline and tamper-negative verification") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunMCPCmdHelpIncludesProof(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPCmd([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "proof") {
		t.Fatalf("mcp help does not include proof:\n%s", stdout.String())
	}
}
