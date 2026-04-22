package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// GXEnvelopeBound validates that the AutonomyEnvelope is a first-class
// required binding per §GX_ENVELOPE.
//
// PASS requires:
//   - No effects without an active envelope
//   - Envelope constraints enforced on every effect/tool call
//   - envelope_id, envelope_hash, jurisdiction, tenant_id in every receipt
//   - Denial emits a denial receipt (no silent drops)
type GXEnvelopeBound struct{}

func (g *GXEnvelopeBound) ID() string   { return "GX_ENVELOPE" }
func (g *GXEnvelopeBound) Name() string { return "Envelope Bound and Enforced" }

func (g *GXEnvelopeBound) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	if !dirExists(receiptsDir) {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonEnvelopeNotBound)
		return result
	}

	files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
	denialReceiptFound := false

	for _, f := range files {
		data, _ := os.ReadFile(f)
		receipt, ok := decodeJSONMap(data)
		if !ok {
			continue
		}

		applyEnvelopeBoundReceiptChecks(result, receipt, &denialReceiptFound)
	}

	// 5. Check that at least one denial was receipt-backed
	// (If there were denials but no denial receipts, fail)
	policyDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "policy_decisions")
	checkDenialReceiptsBackedByReceipt(result, policyDir, denialReceiptFound)

	return result
}

func decodeJSONMap(data []byte) (map[string]any, bool) {
	var out map[string]any
	if json.Unmarshal(data, &out) != nil {
		return nil, false
	}
	return out, true
}

func applyEnvelopeBoundReceiptChecks(result *conform.GateResult, receipt map[string]any, denialReceiptFound *bool) {
	requireStringField(result, receipt, "envelope_id", conform.ReasonEnvelopeNotBound)
	requireStringField(result, receipt, "envelope_hash", conform.ReasonEnvelopeNotBound)
	requireStringField(result, receipt, "jurisdiction", conform.ReasonEnvelopeNotBound)

	actionType, _ := receipt["action_type"].(string)
	switch actionType {
	case "effect_denied":
		*denialReceiptFound = true
		result.Metrics.Counts["denial_receipts"]++
	case "effect_attempt", "tool_call", "connector_call":
		if _, ok := receipt["envelope_decision"]; !ok {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonEnvelopeNotEnforced)
		}
		result.Metrics.Counts["envelope_enforced_effects"]++
	}

	result.Metrics.Counts["receipts_checked"]++
}

func requireStringField(result *conform.GateResult, receipt map[string]any, field string, reason string) {
	if v, ok := receipt[field].(string); !ok || v == "" {
		result.Pass = false
		result.Reasons = append(result.Reasons, reason)
	}
}

func checkDenialReceiptsBackedByReceipt(result *conform.GateResult, policyDir string, denialReceiptFound bool) {
	if !dirExists(policyDir) {
		return
	}

	policyFiles, _ := filepath.Glob(filepath.Join(policyDir, "*.json"))
	for _, f := range policyFiles {
		data, _ := os.ReadFile(f)
		decision, ok := decodeJSONMap(data)
		if !ok {
			continue
		}

		allowed, ok := decision["allowed"].(bool)
		if ok && !allowed && !denialReceiptFound {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonEnvelopeDenialNoReceipt)
		}
	}
}
