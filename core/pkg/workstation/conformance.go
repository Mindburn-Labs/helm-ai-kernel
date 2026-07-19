// quantum_posture: workstation conformance uses classical Ed25519 receipt
// material only; it adds no post-quantum control.
package workstation

import (
	"crypto/ed25519"
	"crypto/rand"
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

// mamaFixtureDecisionSigner is the public half of the offline-only signer for
// the checked-in MAMA decision receipt fixture. It is limited to conformance
// data and is never a runtime or production trust anchor.
var mamaFixtureDecisionSigner = ed25519.PublicKey{
	0xff, 0xc8, 0xd9, 0x4c, 0xa1, 0x62, 0xc1, 0x08,
	0x5d, 0xf2, 0x0d, 0xfb, 0x05, 0xac, 0xd1, 0x2b,
	0x15, 0x79, 0xb9, 0xfa, 0xaa, 0xd0, 0x51, 0xf4,
	0x20, 0xd9, 0xc5, 0x00, 0xc4, 0x87, 0x08, 0x12,
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
			"mama-receipt-bound-execution",
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
	seed, err := certificationSigningSeed()
	if err != nil {
		add("signing.ephemeral_fixture_key", false, err.Error())
		result.CertifiedAs = requested
		return result
	}

	observeOK, observeMsg := certifyObserveOnly(fixtureRoot, seed)
	add("observe.deterministic_receipt_replay", observeOK, observeMsg)
	add("observe.schema_artifacts_present", requiredFixtureFilesExist(fixtureRoot, "allowed-observe"), "allowed observe fixture has required artifact set")
	if requested == CertificationObserveOnly {
		result.CertifiedAs = CertificationObserveOnly
		result.Passed = observeOK && requiredFixtureFilesExist(fixtureRoot, "allowed-observe")
		return result
	}

	enforceOK, enforceMsg := certifyEnforceable(seed)
	add("enforce.denies_forbidden_network_and_memory", enforceOK, enforceMsg)
	add("enforce.allows_draft_edit", certifyDraftDecision(seed), "draft edit decision is permitted and signed")
	if requested == CertificationEnforceable {
		result.CertifiedAs = CertificationEnforceable
		result.Passed = allChecksPass(result.Checks)
		return result
	}

	highRiskOK, highRiskMsg := certifyHighRiskFixtures(fixtureRoot, seed)
	add("high_risk.memory_loop_and_taint_fixtures", highRiskOK, highRiskMsg)
	result.CertifiedAs = CertificationHighRiskEffectCapable
	result.Passed = allChecksPass(result.Checks)
	return result
}

func certificationSigningSeed() ([]byte, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate ephemeral certification signing seed: %w", err)
	}
	return seed, nil
}

func certifyObserveOnly(root string, seed []byte) (bool, string) {
	fixture := filepath.Join(root, "allowed-draft")
	first, err := ImportArtifactDir(fixture, ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	second, err := ImportArtifactDir(fixture, ImportOptions{SigningSeed: seed})
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
	trusted := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	ok, err := VerifyReceiptWithTrustedKey(first.Receipt, trusted)
	if err != nil || !ok {
		return false, fmt.Sprintf("receipt signature invalid: %v", err)
	}
	return true, "same artifact set produces identical receipt, ProofGraph hashes, and replay root"
}

func certifyEnforceable(seed []byte) (bool, string) {
	profile := DefaultObserveDraftProfile()
	network, err := Decide(profile, decisionRequest("network", "https://forbidden.example"), DecisionOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	memory, err := Decide(profile, decisionRequest("memory", "memory://repo-rule"), DecisionOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	if network.Verdict != contracts.WorkstationVerdictDeny || memory.Verdict != contracts.WorkstationVerdictDeny {
		return false, "network and memory operate effects must deny under default profile"
	}
	trusted := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if ok, _ := VerifyDecisionReceiptWithTrustedKey(network, trusted); !ok {
		return false, "network deny receipt signature did not verify"
	}
	if ok, _ := VerifyDecisionReceiptWithTrustedKey(memory, trusted); !ok {
		return false, "memory deny receipt signature did not verify"
	}
	return true, "selected network and memory operate effects deny with signed receipts"
}

func certifyDraftDecision(seed []byte) bool {
	profile := DefaultObserveDraftProfile()
	receipt, err := Decide(profile, decisionRequest("file", "src/example.go"), DecisionOptions{SigningSeed: seed})
	if err != nil {
		return false
	}
	trusted := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	ok, _ := VerifyDecisionReceiptWithTrustedKey(receipt, trusted)
	return receipt.Verdict == contracts.WorkstationVerdictAllow && ok
}

func certifyHighRiskFixtures(root string, seed []byte) (bool, string) {
	memory, err := ImportArtifactDir(filepath.Join(root, "denied-memory"), ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	loop, err := ImportArtifactDir(filepath.Join(root, "denied-recurring-loop"), ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	tainted, err := ImportArtifactDir(filepath.Join(root, "prompt-injection-tainted"), ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	rawMCP, err := ImportArtifactDir(filepath.Join(root, "raw-mcp-tunnel-bypass"), ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	resume, err := ImportArtifactDir(filepath.Join(root, "ambiguous-resume"), ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	sidechain, err := ImportArtifactDir(filepath.Join(root, "subagent-sidechain-summary"), ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	taintedDoc, err := ImportArtifactDir(filepath.Join(root, "tainted-browser-pdf-authorization"), ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	mama, err := ImportArtifactDir(filepath.Join(root, "mama-receipt-bound-execution"), ImportOptions{SigningSeed: seed})
	if err != nil {
		return false, err.Error()
	}
	demo, err := ImportArtifactDir(filepath.Join(root, "demo"), ImportOptions{SigningSeed: seed})
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
	if mama.Receipt.AgentSurface != "mama" || len(mama.Receipt.ToolActions) == 0 || len(mama.Receipt.DeniedEffects) != 0 {
		return false, "MAMA fixture must import as a receipt-bound allowed run with no denied effects"
	}
	decision, err := loadReferencedDecisionReceipt(filepath.Join(root, "mama-receipt-bound-execution"), mama.Receipt, "evt_mama_deploy_publish", mamaFixtureDecisionSigner)
	if err != nil {
		return false, err.Error()
	}
	if !decisionMatchesAction(decision, mama.Receipt, "evt_mama_deploy_publish") {
		return false, "MAMA policy decision receipt must match the allowed operate effect"
	}
	if len(demo.Receipt.ChangedFiles) == 0 || len(demo.Receipt.MemoryEffects) == 0 || len(demo.Receipt.RecurringLoopEffects) == 0 || len(demo.Receipt.DeniedEffects) < 4 {
		return false, "demo fixture must cover draft, denied network, memory, recurring loop, and tainted MCP"
	}
	return true, "memory, recurring loop, taint, raw MCP, resume, sidechain, and MAMA receipt-bound fixtures are represented as governed effects"
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

func loadReferencedDecisionReceipt(dir string, receipt *contracts.AgentRunReceipt, actionID string, trusted ed25519.PublicKey) (*contracts.WorkstationPolicyDecisionReceipt, error) {
	ref := receiptActionMetadata(receipt, actionID, "policy_decision_ref")
	if ref == "" {
		return nil, fmt.Errorf("%s missing policy_decision_ref metadata", actionID)
	}
	decision, err := LoadDecisionReceipt(filepath.Join(dir, "receipts", ref+".json"))
	if err != nil {
		return nil, fmt.Errorf("load MAMA policy decision receipt: %w", err)
	}
	if ok, err := VerifyDecisionReceiptWithTrustedKey(decision, trusted); err != nil {
		return nil, fmt.Errorf("verify MAMA policy decision receipt against fixture trust anchor: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("MAMA policy decision receipt signer is not the fixture trust anchor")
	}
	if decision.DecisionID != ref || decision.Verdict != contracts.WorkstationVerdictAllow {
		return nil, fmt.Errorf("MAMA policy decision receipt must be an ALLOW receipt for %s", ref)
	}
	return decision, nil
}

func decisionMatchesAction(decision *contracts.WorkstationPolicyDecisionReceipt, receipt *contracts.AgentRunReceipt, actionID string) bool {
	for _, action := range receipt.ToolActions {
		if action.ActionID == actionID {
			return decision.Request.ToolID == action.ToolID &&
				decision.Request.Action == action.Action &&
				decision.Request.EffectType == action.EffectType &&
				decision.Request.EffectMode == action.EffectMode &&
				decision.Request.Target == action.Target
		}
	}
	return false
}

func receiptActionMetadata(receipt *contracts.AgentRunReceipt, actionID, key string) string {
	for _, action := range receipt.ToolActions {
		if action.ActionID == actionID {
			return action.Metadata[key]
		}
	}
	return ""
}
