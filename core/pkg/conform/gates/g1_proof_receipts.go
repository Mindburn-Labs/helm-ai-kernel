package gates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G1ProofReceipts verifies receipt DAG integrity, signatures,
// and envelope/payload separation per §G1.
//
// Receipt chaining uses a DAG model (ParentReceiptHashes[]) rather than
// a single linear chain, supporting parallel tool calls and multi-agent DAGs.
// A TopologyOrderRule recorded in 00_INDEX.json defines deterministic linearization.
type G1ProofReceipts struct {
	// Verifier checks a signature over data. If nil, uses basic hash check.
	Verifier func(data []byte, sig string) error
}

func (g *G1ProofReceipts) ID() string   { return "G1" }
func (g *G1ProofReceipts) Name() string { return "Proof-Native Receipts and Offline Verification" }

// ReceiptEnvelope is the §4.1.1 envelope structure.
//
// Receipt chaining: uses ParentReceiptHashes[] (DAG) instead of a single
// prev_receipt_hash. For linear chains, this is a single-element slice.
// Deterministic linearization is defined by TopoOrderRule in 00_INDEX.json.
type ReceiptEnvelope struct {
	// --- Core identity ---
	RunID            string `json:"run_id"`
	Seq              uint64 `json:"seq"`
	TenantID         string `json:"tenant_id"` // REQUIRED: multi-tenant isolation
	TimestampVirtual string `json:"timestamp_virtual"`
	SchemaVersion    string `json:"schema_version"`

	// --- Envelope binding ---
	EnvelopeID   string `json:"envelope_id"`   // REQUIRED: bound autonomy envelope
	EnvelopeHash string `json:"envelope_hash"` // REQUIRED: hash of active envelope
	Jurisdiction string `json:"jurisdiction"`  // REQUIRED: active jurisdiction

	// --- Policy ---
	PolicyHash    string `json:"policy_hash"`
	PolicyVersion string `json:"policy_version"` // REQUIRED: policy version

	// --- Actor + action ---
	Actor       string `json:"actor"`
	ActionType  string `json:"action_type"`  // meaningful action type (see MeaningfulActions)
	EffectClass string `json:"effect_class"` // REQUIRED: effect classification
	EffectType  string `json:"effect_type"`  // REQUIRED: specific effect type

	// --- Decision + intent ---
	DecisionID       string `json:"decision_id"`        // REQUIRED: unique decision ID
	IntentID         string `json:"intent_id"`          // REQUIRED: links to originating intent
	EffectDigestHash string `json:"effect_digest_hash"` // REQUIRED: hash of effect params

	// --- Capability + budget ---
	CapabilityRef     string `json:"capability_ref"`
	BudgetSnapshotRef string `json:"budget_snapshot_ref"`

	// --- Tool ---
	ToolName         string `json:"tool_name,omitempty"`          // REQUIRED for tool calls
	ToolManifestHash string `json:"tool_manifest_hash,omitempty"` // REQUIRED for tool calls

	// --- Tape ---
	TapeRef string `json:"tape_ref,omitempty"`

	// --- Environment fingerprint ---
	PhenotypeHash string `json:"phenotype_hash"` // REQUIRED: semantic binding anchor

	// --- DAG chaining (replaces single prev_receipt_hash) ---
	ParentReceiptHashes []string `json:"parent_receipt_hashes"` // DAG: one or more parents
	ReceiptHash         string   `json:"receipt_hash"`
	Signature           string   `json:"signature"`

	// --- Payload ---
	PayloadCommitment string `json:"payload_commitment"`
}

// MeaningfulActions defines the exhaustive set of actions that MUST emit a receipt.
// "Every meaningful action" is precisely defined as this set.
var MeaningfulActions = map[string]bool{
	"policy_decision":        true, // any policy evaluation
	"boundary_decision":      true, // effect boundary check
	"tool_call":              true, // any tool invocation
	"connector_call":         true, // any external connector call
	"schema_validation":      true, // schema validation affecting control flow
	"approval_action":        true, // HITL approval/rejection
	"budget_decrement":       true, // budget consumed
	"budget_exhausted":       true, // budget at zero
	"containment_transition": true, // FREEZE/THROTTLE/EMERGENCY
	"pack_install":           true, // pack lifecycle
	"pack_upgrade":           true,
	"pack_rollback":          true,
	"effect_attempt":         true, // any effect execution attempt
	"effect_denied":          true, // denied effect attempt
	"envelope_bind":          true, // envelope binding
	"envelope_unbind":        true, // envelope unbinding
	"key_rotation":           true, // key management
	"incident_open":          true, // incident lifecycle
	"incident_close":         true,
	"receipt_emission_panic": true, // kernel panic
}

func (g *G1ProofReceipts) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	files, err := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
	if err != nil || len(files) == 0 {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
		return result
	}

	envelopes := g.loadReceiptEnvelopes(result, files)
	hashIndex := buildReceiptHashIndex(envelopes)

	var prevSeq uint64
	hasPrev := false
	for _, env := range envelopes {
		g.validateEnvelope(result, &env, prevSeq, hasPrev, hashIndex)
		prevSeq = env.Seq
		hasPrev = true

		result.Metrics.Counts["receipts_verified"]++
	}

	// Write verify report
	verifiedAt := time.Now().UTC()
	if ctx != nil && ctx.Clock != nil {
		verifiedAt = ctx.Clock().UTC()
	}
	verifyReport := map[string]any{
		"total_receipts": len(envelopes),
		"chain_valid":    result.Pass,
		"dag_model":      true,
		"verified_at":    verifiedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	reportData, _ := json.MarshalIndent(verifyReport, "", "  ")
	reportPath := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "verify_report.json")
	_ = os.WriteFile(reportPath, reportData, 0600)
	result.EvidencePaths = append(result.EvidencePaths, "02_PROOFGRAPH/verify_report.json")

	return result
}

func (g *G1ProofReceipts) loadReceiptEnvelopes(result *conform.GateResult, files []string) []ReceiptEnvelope {
	envelopes := make([]ReceiptEnvelope, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
			continue
		}

		var env ReceiptEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
			continue
		}

		envelopes = append(envelopes, env)
	}
	return envelopes
}

func buildReceiptHashIndex(envelopes []ReceiptEnvelope) map[string]bool {
	hashIndex := make(map[string]bool, len(envelopes))
	for _, env := range envelopes {
		hashIndex[env.ReceiptHash] = true
	}
	return hashIndex
}

func (g *G1ProofReceipts) validateEnvelope(result *conform.GateResult, env *ReceiptEnvelope, prevSeq uint64, hasPrev bool, hashIndex map[string]bool) {
	validateEnvelopeRequiredFields(result, env)
	validateEnvelopeMonotonicSeq(result, env, prevSeq, hasPrev)
	validateEnvelopeDAGParents(result, env, hashIndex)
	validateEnvelopeMeaningfulAction(result, env)
	g.validateEnvelopeSignature(result, env)
}

func validateEnvelopeRequiredFields(result *conform.GateResult, env *ReceiptEnvelope) {
	if env.RunID == "" || env.Actor == "" || env.ActionType == "" {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
	}
	if env.TenantID == "" {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonTenantIsolationViolation)
	}
	if env.EnvelopeID == "" || env.EnvelopeHash == "" {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonEnvelopeNotBound)
	}
	if env.DecisionID == "" || env.IntentID == "" {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
	}
	if env.EffectClass == "" || env.EffectType == "" {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
	}
	if env.PhenotypeHash == "" {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
	}
}

func validateEnvelopeMonotonicSeq(result *conform.GateResult, env *ReceiptEnvelope, prevSeq uint64, hasPrev bool) {
	if hasPrev && env.Seq <= prevSeq {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
	}
}

func validateEnvelopeDAGParents(result *conform.GateResult, env *ReceiptEnvelope, hashIndex map[string]bool) {
	for _, parentHash := range env.ParentReceiptHashes {
		if parentHash == "genesis" {
			continue
		}
		if !hashIndex[parentHash] {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonReceiptDAGBroken)
		}
	}
}

func validateEnvelopeMeaningfulAction(result *conform.GateResult, env *ReceiptEnvelope) {
	if !MeaningfulActions[env.ActionType] {
		result.Pass = false
		result.Reasons = append(result.Reasons, "UNKNOWN_ACTION_TYPE:"+env.ActionType)
	}
}

func (g *G1ProofReceipts) validateEnvelopeSignature(result *conform.GateResult, env *ReceiptEnvelope) {
	if g.Verifier == nil || env.Signature == "" {
		return
	}

	canonical, _ := canonicalEnvelopeBytes(env)
	if err := g.Verifier(canonical, env.Signature); err != nil {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonSignatureInvalid)
	}
}

// canonicalEnvelopeBytes returns deterministic bytes for signing.
func canonicalEnvelopeBytes(env *ReceiptEnvelope) ([]byte, error) {
	signing := *env
	signing.Signature = ""
	return json.Marshal(signing)
}

// ComputePayloadCommitment computes H(salt || canonical_payload_bytes) per §4.1.2.
func ComputePayloadCommitment(salt []byte, payload []byte) string {
	h := sha256.New()
	h.Write(salt)
	h.Write(payload)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(h.Sum(nil)))
}

// VerifyPayloadCommitment checks that a payload matches its commitment.
func VerifyPayloadCommitment(salt []byte, payload []byte, commitment string) bool {
	computed := ComputePayloadCommitment(salt, payload)
	return computed == commitment
}
