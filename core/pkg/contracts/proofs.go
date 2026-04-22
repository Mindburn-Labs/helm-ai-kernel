package contracts

import "time"

// ProofType identifies the category of proof.
type ProofType string

// ProofType constants.
const (
	ProofTypeDeterminism ProofType = "DETERMINISM"
	ProofTypePolicy      ProofType = "POLICY"
	ProofTypeSim         ProofType = "SIMULATION"
	ProofTypeTest        ProofType = "TEST"
	ProofTypeVisual      ProofType = "VISUAL"
	ProofTypeHostileSim  ProofType = "HOSTILE_SIM"
	ProofTypeProvenance  ProofType = "PROVENANCE"
)

// ProofVerdict represents the outcome of a proof evaluation.
// Note: Court also has a Verdict concept, but this is specific to Evidence/Proofs.
type ProofVerdict string

// ProofVerdict constants.
const (
	ProofVerdictPass ProofVerdict = "PASS"
	ProofVerdictFail ProofVerdict = "FAIL"
	ProofVerdictWarn ProofVerdict = "WARN"
)

// ArtifactRef points to a content-addressed blob.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type ArtifactRef struct {
	Name      string            `json:"name"`
	MediaType string            `json:"media_type"`
	URI       string            `json:"uri"`
	Hash      string            `json:"hash"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ProofPack is a container for verifiable evidence.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type ProofPack struct {
	Type       ProofType      `json:"type"`
	Verdict    ProofVerdict   `json:"verdict"`
	Summary    string         `json:"summary"`
	Artifacts  []ArtifactRef  `json:"artifacts,omitempty"`
	Metrics    map[string]any `json:"metrics,omitempty"`
	InputsHash string         `json:"inputs_hash"`         // Hash of the proposal state used to generate this
	ProducedAt time.Time      `json:"produced_at"`         // Excluded from canonical hash
	Producer   string         `json:"producer"`            // Agent ID / Service Name
	Signature  string         `json:"signature,omitempty"` // Optional producer signature
}

// Bundle represents a cryptographically verifiable proof of a spend event.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type Bundle struct {
	ProposalID       string          `json:"proposal_id"`
	CanonicalJSON    string          `json:"canonical_json"`
	PhenotypeHash    string          `json:"phenotype_hash"`
	PolicyProof      *DecisionRecord `json:"policy_proof"`
	DeterminismProof string          `json:"determinism_proof"`
	Receipt          *EffectReceipt  `json:"receipt"`
	GeneratedAt      time.Time       `json:"generated_at"`
}
