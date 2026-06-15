package workstation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	CertificationObserveOnly           = "observe-only"
	CertificationEnforceable           = "enforceable"
	CertificationHighRiskEffectCapable = "high-risk-effect-capable"
)

type CertificationCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type AdapterCertificationResult struct {
	AdapterID    string               `json:"adapter_id"`
	Requested    string               `json:"requested"`
	CertifiedAs  string               `json:"certified_as"`
	Passed       bool                 `json:"passed"`
	Checks       []CertificationCheck `json:"checks"`
	CertifiedAt  time.Time            `json:"certified_at"`
	FixtureRoot  string               `json:"fixture_root"`
	FixtureRefs  []string             `json:"fixture_refs"`
	ObservedOnly bool                 `json:"observed_only"`
}

func CertifyAdapterFixtures(adapterID, fixtureRoot, requested string) AdapterCertificationResult {
	if adapterID == "" {
		adapterID = "workstation-manifest-adapter"
	}
	if requested == "" {
		requested = CertificationObserveOnly
	}
	result := AdapterCertificationResult{
		AdapterID:   adapterID,
		Requested:   requested,
		CertifiedAt: time.Unix(0, 0).UTC(),
		FixtureRoot: fixtureRoot,
		FixtureRefs: []string{
			"allowed-observe",
			"allowed-draft",
			"denied-network",
			"denied-memory",
			"denied-recurring-loop",
			"prompt-injection-tainted",
			"raw-mcp-tunnel-bypass",
			"ambiguous-resume",
			"subagent-sidechain-summary",
			"tainted-browser-pdf-authorization",
			"demo",
		},
		ObservedOnly: requested == CertificationObserveOnly,
	}
	add := func(id string, ok bool, msg string) {
		status := "PASS"
		if !ok {
			status = "FAIL"
			result.Passed = false
		}
		result.Checks = append(result.Checks, CertificationCheck{ID: id, Status: status, Message: msg})
	}
	result.Passed = true

	observeOK, observeMsg := certifyObserveOnly(fixtureRoot)
	add("observe.deterministic_receipt_replay", observeOK, observeMsg)
	add("observe.schema_artifacts_present", requiredFixtureFilesExist(fixtureRoot, "allowed-observe"), "allowed observe fixture has required artifact set")
	if requested == CertificationObserveOnly {
		result.CertifiedAs = CertificationObserveOnly
		result.Passed = observeOK && requiredFixtureFilesExist(fixtureRoot, "allowed-observe")
		return result
	}

	enforceOK, enforceMsg := certifyEnforceable()
	add("enforce.denies_forbidden_network_and_memory", enforceOK, enforceMsg)
	add("enforce.allows_draft_edit", certifyDraftDecision(), "draft edit decision is permitted and signed")
	if requested == CertificationEnforceable {
		result.CertifiedAs = CertificationEnforceable
		result.Passed = allChecksPass(result.Checks)
		return result
	}

	highRiskOK, highRiskMsg := certifyHighRiskFixtures(fixtureRoot)
	add("high_risk.memory_loop_and_taint_fixtures", highRiskOK, highRiskMsg)
	result.CertifiedAs = CertificationHighRiskEffectCapable
	result.Passed = allChecksPass(result.Checks)
	return result
}

func certifyObserveOnly(root string) (bool, string) {
	fixture := filepath.Join(root, "allowed-draft")
	first, err := ImportArtifactDir(fixture, ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	second, err := ImportArtifactDir(fixture, ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	if first.Receipt.ReceiptHash != second.Receipt.ReceiptHash || first.ReplayRootHash != second.ReplayRootHash {
		return false, "receipt hash or replay root changed for same artifact set"
	}
	for i := range first.ProofGraph {
		if first.ProofGraph[i].NodeHash != second.ProofGraph[i].NodeHash {
			return false, fmt.Sprintf("proofgraph node %d hash changed", i)
		}
	}
	ok, err := VerifyReceiptSignature(first.Receipt)
	if err != nil || !ok {
		return false, fmt.Sprintf("receipt signature invalid: %v", err)
	}
	return true, "same artifact set produces identical receipt, ProofGraph hashes, and replay root"
}

func certifyEnforceable() (bool, string) {
	profile := DefaultObserveDraftProfile()
	network, err := Decide(profile, decisionRequest("network", "https://forbidden.example"), DecisionOptions{})
	if err != nil {
		return false, err.Error()
	}
	memory, err := Decide(profile, decisionRequest("memory", "memory://repo-rule"), DecisionOptions{})
	if err != nil {
		return false, err.Error()
	}
	if network.Verdict != contracts.WorkstationVerdictDeny || memory.Verdict != contracts.WorkstationVerdictDeny {
		return false, "network and memory operate effects must deny under default profile"
	}
	if ok, _ := VerifyDecisionReceiptSignature(network); !ok {
		return false, "network deny receipt signature did not verify"
	}
	if ok, _ := VerifyDecisionReceiptSignature(memory); !ok {
		return false, "memory deny receipt signature did not verify"
	}
	return true, "selected network and memory operate effects deny with signed receipts"
}

func certifyDraftDecision() bool {
	profile := DefaultObserveDraftProfile()
	receipt, err := Decide(profile, decisionRequest("file", "src/example.go"), DecisionOptions{})
	if err != nil {
		return false
	}
	ok, _ := VerifyDecisionReceiptSignature(receipt)
	return receipt.Verdict == contracts.WorkstationVerdictAllow && ok
}

func certifyHighRiskFixtures(root string) (bool, string) {
	memory, err := ImportArtifactDir(filepath.Join(root, "denied-memory"), ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	loop, err := ImportArtifactDir(filepath.Join(root, "denied-recurring-loop"), ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	tainted, err := ImportArtifactDir(filepath.Join(root, "prompt-injection-tainted"), ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	rawMCP, err := ImportArtifactDir(filepath.Join(root, "raw-mcp-tunnel-bypass"), ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	resume, err := ImportArtifactDir(filepath.Join(root, "ambiguous-resume"), ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	sidechain, err := ImportArtifactDir(filepath.Join(root, "subagent-sidechain-summary"), ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	taintedDoc, err := ImportArtifactDir(filepath.Join(root, "tainted-browser-pdf-authorization"), ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	demo, err := ImportArtifactDir(filepath.Join(root, "demo"), ImportOptions{})
	if err != nil {
		return false, err.Error()
	}
	if len(memory.Receipt.MemoryEffects) == 0 || memory.Receipt.MemoryEffects[0].TTLDays == 0 || memory.Receipt.MemoryEffects[0].Sensitivity == "" {
		return false, "memory fixture must include TTL and sensitivity"
	}
	if len(loop.Receipt.RecurringLoopEffects) == 0 {
		return false, "recurring loop fixture missing loop effect"
	}
	l := loop.Receipt.RecurringLoopEffects[0]
	if l.Schedule == "" || l.MaxRuntime == "" || len(l.ToolScope) == 0 || l.ExpiresAt.IsZero() {
		return false, "recurring loop fixture missing schedule, max runtime, tool scope, or expiration"
	}
	if !receiptContainsTaint(tainted.Receipt, "prompt_injection") || len(tainted.Receipt.DeniedEffects) == 0 {
		return false, "tainted-context fixture must preserve taint and denial"
	}
	if !receiptHasDeniedReason(rawMCP.Receipt, "OPERATE_PERMISSIONS_EMPTY") {
		return false, "raw MCP tunnel fixture must deny bypassed operate effects"
	}
	if !receiptHasDeniedReason(resume.Receipt, "OPERATE_PERMISSIONS_EMPTY") {
		return false, "ambiguous resume fixture must deny restored session permissions"
	}
	if !receiptActionHasMetadata(sidechain.Receipt, "evt_subagent_summary", "sidechain_ref") || receiptActionHasMetadata(sidechain.Receipt, "evt_subagent_summary", "raw_transcript") {
		return false, "subagent sidechain fixture must keep summary refs without raw transcript"
	}
	if !receiptContainsTaint(taintedDoc.Receipt, "tainted_context") || !receiptHasDeniedReason(taintedDoc.Receipt, "TAINTED_CONTEXT_REQUIRES_DENY") {
		return false, "tainted browser/PDF fixture must deny operate authorization from tainted context"
	}
	if len(demo.Receipt.ChangedFiles) == 0 || len(demo.Receipt.MemoryEffects) == 0 || len(demo.Receipt.RecurringLoopEffects) == 0 || len(demo.Receipt.DeniedEffects) < 4 {
		return false, "demo fixture must cover draft, denied network, memory, recurring loop, and tainted MCP"
	}
	return true, "memory, recurring loop, taint, raw MCP, resume, and sidechain fixtures are represented as governed effects"
}

func requiredFixtureFilesExist(root, fixture string) bool {
	for _, name := range []string{ManifestFile, DiffSummaryFile, ValidationFile} {
		if _, err := os.Stat(filepath.Join(root, fixture, name)); err != nil {
			return false
		}
	}
	return true
}

func decisionRequest(effectClass, target string) contracts.WorkstationDecisionRequest {
	effectType, effectMode, action, toolID := EffectDefaults(effectClass)
	return contracts.WorkstationDecisionRequest{
		RequestID:   deterministicID("cert", effectClass, target),
		RunID:       "certification-run",
		ToolID:      toolID,
		Action:      action,
		EffectType:  effectType,
		EffectMode:  effectMode,
		Target:      target,
		OccurredAt:  time.Unix(0, 0).UTC(),
		WorkspaceID: defaultWorkspaceID,
	}
}

func allChecksPass(checks []CertificationCheck) bool {
	for _, check := range checks {
		if strings.ToUpper(check.Status) != "PASS" {
			return false
		}
	}
	return true
}

func receiptContainsTaint(receipt *contracts.AgentRunReceipt, label string) bool {
	for _, action := range receipt.ToolActions {
		for _, candidate := range action.TaintLabels {
			if candidate == label {
				return true
			}
		}
	}
	return false
}

func receiptHasDeniedReason(receipt *contracts.AgentRunReceipt, reasonCode string) bool {
	for _, effect := range receipt.DeniedEffects {
		if effect.ReasonCode == reasonCode {
			return true
		}
	}
	return false
}

func receiptActionHasMetadata(receipt *contracts.AgentRunReceipt, actionID, key string) bool {
	for _, action := range receipt.ToolActions {
		if action.ActionID == actionID {
			_, ok := action.Metadata[key]
			return ok
		}
	}
	return false
}
