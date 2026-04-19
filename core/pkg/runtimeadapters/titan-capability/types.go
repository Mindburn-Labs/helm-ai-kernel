package titancapability

import (
	"context"
	"errors"
)

// CapabilityClass is the namespaced identifier of a Titan capability gate.
// Values are pinned in helm-oss/reference_packs/titan_hedge_fund.v1.json
// (capability_classes array) and mirrored here as compile-time constants.
type CapabilityClass string

const (
	ClassTradeExecute          CapabilityClass = "titan.trade_execute"
	ClassResearchPropose       CapabilityClass = "titan.research_propose"
	ClassStrategyPromote       CapabilityClass = "titan.strategy_promote"
	ClassCommitteeVerdict      CapabilityClass = "titan.committee_verdict"
	ClassKillSwitch            CapabilityClass = "titan.kill_switch"
	ClassFactorPromote         CapabilityClass = "titan.factor_promote"
	ClassModelChange           CapabilityClass = "titan.model_change"
	ClassPolicyChange          CapabilityClass = "titan.policy_change"
	ClassDataSourceActivate    CapabilityClass = "titan.data_source_activate"
	ClassAllocatorUpdate       CapabilityClass = "titan.allocator_update"
	ClassExecutionPolicyUpdate CapabilityClass = "titan.execution_policy_update"
	ClassImpactModelUpdate     CapabilityClass = "titan.impact_model_update"
	ClassRiskModelUpdate       CapabilityClass = "titan.risk_model_update"
	ClassStressScenarioRun     CapabilityClass = "titan.stress_scenario_run"
	ClassRegimeClassifier      CapabilityClass = "titan.regime_classifier_update"
	ClassLLMCall               CapabilityClass = "titan.llm_call"
	ClassEmbeddingCall         CapabilityClass = "titan.embedding_call"
	ClassToolInvoke            CapabilityClass = "titan.tool_invoke"
	ClassFeatureRead           CapabilityClass = "titan.feature_read"
	ClassMarketDataStream      CapabilityClass = "titan.market_data_stream"
	ClassEvidenceExport        CapabilityClass = "titan.evidence_export"
)

// Mode is the trading-posture marker carried by every capability envelope.
// "paper" = simulation only, "shadow" = mirror live but no orders sent,
// "live" = real money. Capability adapters MAY restrict mode (e.g. the
// equities adapter MUST refuse "live" until Rust broker adapters exist).
type Mode string

const (
	ModePaper  Mode = "paper"
	ModeShadow Mode = "shadow"
	ModeLive   Mode = "live"
)

// CapabilityEnvelope is the per-call trust envelope every Titan capability
// must present. It is the minimum context the kernel needs to evaluate
// the call against the active titan_hedge_fund.v1 policy bundle.
//
// JCS-canonical JSON; SHA-256 hashed; Ed25519 signed by the calling organ
// before submission to the kernel. Wire format:
//
//	{"policy_bundle_sha":"...", "organ_id":"...", "session_id":"...",
//	 "spend_cap_usd":12.0, "retention_days":2555, "jurisdiction_hint":"US-DE",
//	 "mode":"paper"}
type CapabilityEnvelope struct {
	PolicyBundleSHA  string  `json:"policy_bundle_sha"`
	OrganID          string  `json:"organ_id"`
	SessionID        string  `json:"session_id"`
	SpendCapUSD      float64 `json:"spend_cap_usd"`
	RetentionDays    int     `json:"retention_days"`
	JurisdictionHint string  `json:"jurisdiction_hint"`
	Mode             Mode    `json:"mode"`
}

// EvidencePackHeader is the minimum metadata every learned-artefact
// promotion must carry through HELM. The full EvidencePack body is
// content-addressed by ArtifactSHA and stored separately.
//
// Wire format (JCS-canonical JSON, SHA-256 hashed by the kernel before
// inclusion in the proof-graph CHECKPOINT node):
//
//	{"artifact_sha":"sha256:...", "artifact_kind":"factor|model|policy|...",
//	 "lineage_sha":"sha256:...", "validation_report_sha":"sha256:...",
//	 "policy_bundle_sha":"sha256:...", "signature":"ed25519:..."}
type EvidencePackHeader struct {
	ArtifactSHA         string `json:"artifact_sha"`
	ArtifactKind        string `json:"artifact_kind"`
	LineageSHA          string `json:"lineage_sha"`
	ValidationReportSHA string `json:"validation_report_sha"`
	PolicyBundleSHA     string `json:"policy_bundle_sha"`
	Signature           string `json:"signature"`
}

// Adapter is the contract every Titan capability subpackage implements.
// Class returns the capability-class constant; Validate is called by the
// kernel guardian gate before issuing an EffectPermit. Adapters MUST be
// pure functions of their inputs (no I/O) to preserve determinism.
type Adapter interface {
	Class() CapabilityClass
	Validate(ctx context.Context, env CapabilityEnvelope, header EvidencePackHeader) error
}

// Sentinel errors. Adapter implementations MUST return one of these (or
// wrap one) so the kernel can map to the canonical deny-reason codes.
var (
	ErrEnvelopeIncomplete   = errors.New("titan-capability: capability envelope is incomplete")
	ErrPolicyBundleMismatch = errors.New("titan-capability: policy bundle SHA does not match active bundle")
	ErrEvidencePackInvalid  = errors.New("titan-capability: evidence pack header failed validation")
	ErrModeNotPermitted     = errors.New("titan-capability: mode not permitted for this capability class")
	ErrUnknownArtifactKind  = errors.New("titan-capability: artifact kind is not recognised by this capability class")
)
