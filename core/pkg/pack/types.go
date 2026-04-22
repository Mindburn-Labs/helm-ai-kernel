package pack

import (
	"time"
)

// PackType defines the category of the pack.
type PackType string

const (
	PackTypeFactory   PackType = "factory"   // Base operational configs (org structure, finance)
	PackTypeConnector PackType = "connector" // External system integrations
	PackTypePolicy    PackType = "policy"    // Governance rules (PRG/CEL)
	PackTypeEvidence  PackType = "evidence"  // Compliance reporting templates
)

// PackManifest implementation matches manifest.json schema
type PackManifest struct {
	PackID                   string                    `json:"pack_id"`
	Type                     PackType                  `json:"pack_type"` // New: factory, connector, policy, evidence
	SchemaVersion            string                    `json:"schema_version"`
	Version                  string                    `json:"version"`
	Name                     string                    `json:"name"`
	Description              string                    `json:"description,omitempty"`
	Capabilities             []string                  `json:"capabilities"`
	ApplicabilityConstraints *ApplicabilityConstraints `json:"applicability_constraints,omitempty"`
	EvidenceContract         *EvidenceContract         `json:"evidence_contract"`
	Provenance               *Provenance               `json:"provenance"`
	ToolBindings             []ToolBinding             `json:"tool_bindings,omitempty"`
	PDPHooks                 []PDPHook                 `json:"pdp_hooks,omitempty"`
	Tests                    *TestSpecs                `json:"tests,omitempty"`
	Signatures               []Signature               `json:"signatures,omitempty"`
	Lifecycle                *Lifecycle                `json:"lifecycle,omitempty"`
	ContentHash              string                    `json:"content_hash,omitempty"`
	Metadata                 map[string]interface{}    `json:"metadata,omitempty"`
	SLOs                     *ServiceLevelObjectives   `json:"service_level_objectives,omitempty"` // New: reliability promises
}

type ServiceLevelObjectives struct {
	MaxFailureRate  float64 `json:"max_failure_rate,omitempty"`  // e.g. 0.001 (0.1%)
	MinEvidenceRate float64 `json:"min_evidence_rate,omitempty"` // e.g. 0.99 (99%)
	MaxIncidentRate float64 `json:"max_incident_rate,omitempty"` // e.g. 0.0001 (1 per 10k)
	TargetMTTR      string  `json:"target_mttr,omitempty"`       // e.g. "1h"
}

type ApplicabilityConstraints struct {
	Jurisdictions *JurisdictionConstraints `json:"jurisdictions,omitempty"`
	Industries    *IndustryConstraints     `json:"industries,omitempty"`
	MinAutonomy   string                   `json:"minimum_autonomy_level,omitempty"`
	KernelVersion string                   `json:"kernel_version_constraint,omitempty"` // New: semver constraint
	ReqCaps       []string                 `json:"requires_capabilities,omitempty"`
}

type JurisdictionConstraints struct {
	Allowed    []string `json:"allowed,omitempty"`
	Prohibited []string `json:"prohibited,omitempty"`
}

type IndustryConstraints struct {
	Allowed    []string `json:"allowed,omitempty"`
	Prohibited []string `json:"prohibited,omitempty"`
}

type EvidenceContract struct {
	Produces []EvidenceProduce `json:"produces"`
	Requires []EvidenceRequire `json:"requires"`
}

type EvidenceProduce struct {
	Class     string `json:"evidence_class"`
	Format    string `json:"format,omitempty"`
	Retention int    `json:"retention_days,omitempty"`
}

type EvidenceRequire struct {
	Class  string `json:"evidence_class"`
	Source string `json:"source,omitempty"`
}

type ToolBinding struct {
	ToolID     string `json:"tool_id"`
	Constraint string `json:"tool_version_constraint,omitempty"`
	Required   bool   `json:"required"`
}

type PDPHook struct {
	HookType    string   `json:"hook_type"`
	EffectTypes []string `json:"effect_types,omitempty"`
	PolicyRef   string   `json:"policy_ref,omitempty"`
}

type TestSpecs struct {
	Unit        *TestMetric `json:"unit_tests,omitempty"`
	Integration *TestMetric `json:"integration_tests,omitempty"`
	Replay      *ReplaySpec `json:"replay_tests,omitempty"`
}

type TestMetric struct {
	Count     int      `json:"count,omitempty"`
	Coverage  float64  `json:"coverage_percent,omitempty"`
	Scenarios []string `json:"scenarios,omitempty"`
}

type ReplaySpec struct {
	InputsHash  string `json:"golden_inputs_hash,omitempty"`
	OutputsHash string `json:"expected_outputs_hash,omitempty"`
}

type Signature struct {
	SignerID  string    `json:"signer_id"`
	Signature string    `json:"signature"`
	Algorithm string    `json:"algorithm,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
	KeyID     string    `json:"key_id,omitempty"`
}

type Provenance struct {
	Source    *SourceInfo `json:"source,omitempty"`
	Build     *BuildInfo  `json:"build,omitempty"`
	SBOM      *SBOMInfo   `json:"sbom,omitempty"`
	SLSALevel int         `json:"slsa_level,omitempty"`
}

type SourceInfo struct {
	Repo   string `json:"repository,omitempty"`
	Commit string `json:"commit_hash,omitempty"`
	Tag    string `json:"tag,omitempty"`
}

type BuildInfo struct {
	BuilderID string    `json:"builder_id,omitempty"`
	BuiltAt   time.Time `json:"built_at,omitempty"`
	Hermetic  bool      `json:"hermetic,omitempty"`
	ReproHash string    `json:"reproducible_hash,omitempty"`
}

type SBOMInfo struct {
	Format string `json:"format,omitempty"`
	Hash   string `json:"hash,omitempty"`
	URI    string `json:"uri,omitempty"`
}

type Lifecycle struct {
	Status      string    `json:"status,omitempty"`
	Activation  time.Time `json:"activation_date,omitempty"`
	Deprecation time.Time `json:"deprecation_date,omitempty"`
	SuccessorID string    `json:"successor_pack_id,omitempty"`
}

// Pack represents a deployable capability bundle (runtime representation)
type Pack struct {
	PackID      string                 `json:"pack_id"`
	Manifest    PackManifest           `json:"manifest"` // Embed manifest
	ContentHash string                 `json:"content_hash"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	Signature   string                 `json:"signature,omitempty"`
}

// PackDependency defines a pack dependency.
type PackDependency struct {
	PackName    string `json:"pack_name"`
	VersionSpec string `json:"version_spec"` // semver constraint
	Optional    bool   `json:"optional"`
}

// PackVersion represents a specific version of a pack.
type PackVersion struct {
	PackName    string    `json:"pack_name"`
	Version     string    `json:"version"`
	ContentHash string    `json:"content_hash"`
	ReleasedAt  time.Time `json:"released_at"`
	Deprecated  bool      `json:"deprecated"`
}

// PackGrade represents the maturity level of a pack.
type PackGrade string

const (
	GradeBronze PackGrade = "BRONZE" // Valid signature
	GradeSilver PackGrade = "SILVER" // + Automated Tests passed
	GradeGold   PackGrade = "GOLD"   // + Production Drill passed
)

// GradingReport contains the analysis of a pack's grade.
type GradingReport struct {
	PackID   string    `json:"pack_id"`
	Grade    PackGrade `json:"grade"`
	ScoredAt time.Time `json:"scored_at"`
	Evidence []string  `json:"evidence"`
	Missing  []string  `json:"missing"`
}
