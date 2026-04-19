package titancapability

import "context"

// ── titan.model_change ──────────────────────────────────────────────────────
// Promotion of a learned model (PricingEnsemble, neural factor model, regime
// classifier, allocator policy, execution policy, impact model, risk model).
// EvidencePack header MUST carry artifact_kind in the allow-list below.

// ModelChangeAdapter gates titan.model_change.
type ModelChangeAdapter struct{}

// ModelChangeArtifactKinds is the closed set of model kinds the kernel will
// accept under titan.model_change. Keep in sync with titan-model-registry.
var ModelChangeArtifactKinds = []string{
	"model",
	"pricing_ensemble",
	"neural_factor",
	"regime_classifier",
	"allocator_policy",
	"execution_policy",
	"impact_model",
	"risk_model",
	"domain_llm",
}

func (ModelChangeAdapter) Class() CapabilityClass { return ClassModelChange }

func (a ModelChangeAdapter) Validate(_ context.Context, env CapabilityEnvelope, header EvidencePackHeader) error {
	if err := ValidateEnvelope(env, ""); err != nil {
		return err
	}
	return ValidateEvidencePack(header, ModelChangeArtifactKinds)
}

// ── titan.factor_promote ────────────────────────────────────────────────────
// Promotion of a factor (canonical, GP-mined, or neural). EvidencePack header
// MUST carry artifact_kind in the allow-list below + a validation_report_sha
// (the López de Prado validation report — CPCV + DSR + PBO + walk-forward).

// FactorPromoteAdapter gates titan.factor_promote.
type FactorPromoteAdapter struct{}

// FactorPromoteArtifactKinds is the closed set of factor kinds the kernel
// will accept under titan.factor_promote. Keep in sync with titan-factors.
var FactorPromoteArtifactKinds = []string{
	"factor",
	"factor_canonical",
	"factor_gp_mined",
	"factor_neural",
}

func (FactorPromoteAdapter) Class() CapabilityClass { return ClassFactorPromote }

func (a FactorPromoteAdapter) Validate(_ context.Context, env CapabilityEnvelope, header EvidencePackHeader) error {
	if err := ValidateEnvelope(env, ""); err != nil {
		return err
	}
	if err := ValidateEvidencePack(header, FactorPromoteArtifactKinds); err != nil {
		return err
	}
	if header.ValidationReportSHA == "" {
		return ErrEvidencePackInvalid
	}
	return nil
}

// ── titan.data_source_activate ──────────────────────────────────────────────
// Activation of a new ingestion connector or alternative-data feed.
// EvidencePack header MUST carry artifact_kind == "data_source" + a
// signed provenance manifest (lineage_sha is the manifest hash).

// DataSourceActivateAdapter gates titan.data_source_activate.
type DataSourceActivateAdapter struct{}

// DataSourceActivateArtifactKinds is the closed set of data-source kinds.
var DataSourceActivateArtifactKinds = []string{
	"data_source",
	"data_source_market",
	"data_source_altdata",
	"data_source_fundamentals",
	"data_source_news",
}

func (DataSourceActivateAdapter) Class() CapabilityClass { return ClassDataSourceActivate }

func (a DataSourceActivateAdapter) Validate(_ context.Context, env CapabilityEnvelope, header EvidencePackHeader) error {
	if err := ValidateEnvelope(env, ""); err != nil {
		return err
	}
	return ValidateEvidencePack(header, DataSourceActivateArtifactKinds)
}

// ── titan.feature_read ──────────────────────────────────────────────────────
// Read-side gate on the feature store. No EvidencePack required: this gates
// access to a pre-promoted feature, not a new artefact promotion. Envelope
// MUST carry the feature SHA implicitly via session_id (kernel resolves the
// feature-access scope by session, not envelope payload — header is empty).

// FeatureReadAdapter gates titan.feature_read.
type FeatureReadAdapter struct{}

func (FeatureReadAdapter) Class() CapabilityClass { return ClassFeatureRead }

func (a FeatureReadAdapter) Validate(_ context.Context, env CapabilityEnvelope, _ EvidencePackHeader) error {
	return ValidateEnvelope(env, "")
}

// ── titan.market_data_stream ────────────────────────────────────────────────
// Subscription registration on a market-data websocket feed. The kernel
// gates *registration* (one-shot) only; the hot-path is not intercepted.
// No EvidencePack required.

// MarketDataStreamAdapter gates titan.market_data_stream.
type MarketDataStreamAdapter struct{}

func (MarketDataStreamAdapter) Class() CapabilityClass { return ClassMarketDataStream }

func (a MarketDataStreamAdapter) Validate(_ context.Context, env CapabilityEnvelope, _ EvidencePackHeader) error {
	return ValidateEnvelope(env, "")
}

// ── Registry ────────────────────────────────────────────────────────────────
// Phase1Adapters returns every adapter required by the Phase 1 exit gate
// (titan/docs/ai-native-exit-criteria.md AIN-11..AIN-13). Order is stable.

func Phase1Adapters() []Adapter {
	return []Adapter{
		ModelChangeAdapter{},
		FactorPromoteAdapter{},
		DataSourceActivateAdapter{},
		FeatureReadAdapter{},
		MarketDataStreamAdapter{},
	}
}
